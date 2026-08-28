# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Frozen combined-host build provenance and server-VPN device acceptance."""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import re
import stat
import time
import traceback
import uuid
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from adb import Adb, ensure_device_ui_ready
from final_preflight import load_preflight_receipt, supported_source_digest
from probe import (
    SAFE_RUN_ID,
    SERVER_VPN_CANARY_READY_TIMEOUT_SECONDS,
    SERVER_VPN_PRIMARY_DISPATCH_MAX_DELAY_MS,
    load_run_state,
    run_concurrent_server_vpn,
    run_probe,
    validate_jsonl,
)
from reboot_intent import (
    begin_or_resume,
    clear_intent,
    intent_path,
    load_intent,
    serialized_transition,
)
from reporting import CheckError, DeferredPrivateText, Report
from server_vpn_device import (
    LOCATION_MODULE_DIR,
    LOCATION_MODULE_ID,
    LOCATION_MODULE_UPDATE_DIR,
    SERVER_VPN_RUNTIME_FILES,
    current_pairing,
    exists,
    inspect_server_vpn_poc,
    inspect_server_vpn_stock,
    location_health,
    parse_properties,
    read_text,
    require_unchanged_pairing,
    select_root_adbd,
    stable_system_server,
    validate_server_vpn_status,
    wait_for_boot,
    wait_for_server_vpn_status,
    wait_for_vpn_on,
)
from server_vpn_oracle import evaluate_diagnostics_residual, evaluate_differential

ROOT = Path(__file__).resolve().parents[2]
FINAL_ZIP = ROOT / "dist/zygveil.zip"
FINAL_CONTROLLER = ROOT / "dist/zygveil-location-controller-debug.apk"
FINAL_PRIMARY = ROOT / "dist/zygveil-probe-primary-debug.apk"
FINAL_CANARY = ROOT / "dist/zygveil-probe-canary-debug.apk"
FINAL_PROBE_SOURCE = ROOT / "dist/probe-detector-source.sha256"
FINAL_BUILD_REPORT = ROOT / ".artifacts/reports/location/build-location.txt"
FINAL_CONTROLLER_REPORT = ROOT / ".artifacts/reports/location/build-location-controller.txt"
FINAL_PROBE_REPORT = ROOT / ".artifacts/reports/probe/build-probe.txt"
FINAL_GENERATION = ROOT / ".artifacts/state/server-vpn-final-generation.json"
FINAL_PHASE_DIR = ROOT / ".artifacts/state/server-vpn-final-phases"
FINAL_PROBE_RUN_DIR = ROOT / ".artifacts/reports/probe/runs"
SERVER_VPN_HOOK_CATALOG = ROOT / "components/server-vpn/runtime/hook_catalog.json"
FINAL_REBOOT_INTENT = intent_path("server-vpn-final-reboot")
FINAL_RECOVERY_INTENT = intent_path("server-vpn-final-recover")
PHASE_ID = re.compile(
    r"zygveil-server-vpn-(?P<kind>baseline|active|rollback)-"
    r"(?P<timestamp>[0-9]{8}T[0-9]{6}Z)-[0-9a-f]{8}"
)
BASE_GROUPS = (
    "server-vpn-sync",
    "server-vpn-active",
    "server-vpn-async",
    "server-vpn-link",
    "server-vpn-diagnostics",
)
GROUPS = BASE_GROUPS + tuple(f"secondary-{group}" for group in BASE_GROUPS)
DATA_PLANE_GROUPS = ("data-plane", "secondary-data-plane")
CALLBACK_GROUPS = {
    "server-vpn-active",
    "server-vpn-async",
    "server-vpn-link",
    "secondary-server-vpn-active",
    "secondary-server-vpn-async",
    "secondary-server-vpn-link",
}
PROBE_PACKAGES = {
    "primary": "dev.zygveil.probe.primary",
    "canary": "dev.zygveil.probe.canary",
}
PHASE_WRITE = DeferredPrivateText()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def current_boot_id_sha256(adb: Adb) -> str:
    boot_id = read_text(adb, "/proc/sys/kernel/random/boot_id").strip()
    if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id) is None:
        raise CheckError("current kernel boot identity is invalid")
    return sha256_bytes(boot_id.encode("ascii"))


def wait_for_new_boot(
    adb: Adb,
    report: Report,
    source_boot_id_sha256: str,
    timeout_seconds: int = 300,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        try:
            available = adb.run("wait-for-device", timeout=min(10, remaining), check=False)
        except CheckError:
            continue
        if available.returncode != 0:
            time.sleep(1)
            continue
        boot = adb.shell("cat", "/proc/sys/kernel/random/boot_id", timeout=5, check=False)
        value = boot.stdout.strip()
        if (
            boot.returncode == 0
            and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value) is not None
            and sha256_bytes(value.encode("ascii")) != source_boot_id_sha256
        ):
            report.kv("new_kernel_boot_observed", "true")
            wait_for_boot(adb, report, timeout_seconds=max(1, remaining))
            if current_boot_id_sha256(adb) == source_boot_id_sha256:
                raise CheckError("kernel boot identity regressed during reboot validation")
            return
        time.sleep(1)
    raise CheckError("device did not enter a new kernel boot before timeout")


def parse_report(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise CheckError(f"required final build report is missing: {path.name}")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("[") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    if values.get("exit_status") != "0":
        raise CheckError(f"final build report did not pass: {path.name}")
    return values


def canonical_generation(
    *,
    builder_tag: str,
    dependency_key: str,
    report: Report | None,
    require_materialized_inputs: bool,
) -> dict[str, object]:
    preflight = load_preflight_receipt(
        builder_tag=builder_tag,
        dependency_key=dependency_key,
        report=report,
        require_materialized_inputs=require_materialized_inputs,
    )
    artifacts = (FINAL_ZIP, FINAL_CONTROLLER, FINAL_PRIMARY, FINAL_CANARY, FINAL_PROBE_SOURCE)
    if any(not path.is_file() or path.stat().st_size == 0 for path in artifacts):
        raise CheckError("frozen ZygVeil artifact set is incomplete")
    if not builder_tag or not dependency_key:
        raise CheckError("builder and dependency content keys are required")

    build = parse_report(FINAL_BUILD_REPORT)
    controller = parse_report(FINAL_CONTROLLER_REPORT)
    probe = parse_report(FINAL_PROBE_REPORT)
    zip_digest = sha256_file(FINAL_ZIP)
    if (
        build.get("zip_sha256") != zip_digest
        or build.get("hook_count") != "5"
        or build.get("server_vpn_hook_count") != "14"
        or build.get("engine_owner") != "shared"
        or build.get("deterministic_repeat") != "pass"
        or build.get("server_vpn_packaged_policy") != "present"
    ):
        raise CheckError("combined-host final build provenance mismatch")

    with zipfile.ZipFile(FINAL_ZIP) as archive:
        names = set(archive.namelist())
        if archive.testzip() is not None or not set(SERVER_VPN_RUNTIME_FILES).issubset(names):
            raise CheckError("combined-host final ZIP runtime inventory is incomplete")
        if "server-vpn-config.properties" not in names or any(
            name.endswith(".apk") for name in names
        ):
            raise CheckError("combined-host final ZIP lacks packaged policy or contains an APK")
        module = parse_properties(archive.read("module.prop").decode("ascii"))
        if (
            module.get("id") != LOCATION_MODULE_ID
            or module.get("name") != "ZygVeil"
            or module.get("version") != "0.2.0"
            or module.get("versionCode") != "2"
        ):
            raise CheckError("combined-host final module identity mismatch")
        runtime_members = {
            name: sha256_bytes(archive.read(name)) for name in sorted(SERVER_VPN_RUNTIME_FILES)
        }
        if runtime_members["zygisk/arm64-v8a.so"] != build.get("native_sha256"):
            raise CheckError("combined-host final native identity mismatch")
        if runtime_members["bridge.dex"] != build.get("bridge_dex_sha256"):
            raise CheckError("combined-host final location bridge identity mismatch")
        if runtime_members["server-vpn-bridge.dex"] != build.get("server_vpn_bridge_dex_sha256"):
            raise CheckError("combined-host final server bridge identity mismatch")

    source_line = FINAL_PROBE_SOURCE.read_text(encoding="ascii").strip()
    source_match = re.fullmatch(r"([0-9a-f]{64})  probe-detector-source", source_line)
    if source_match is None or probe.get("detector_source_sha256") != source_match.group(1):
        raise CheckError("universal probe source identity mismatch")
    primary_digest = sha256_file(FINAL_PRIMARY)
    canary_digest = sha256_file(FINAL_CANARY)
    controller_digest = sha256_file(FINAL_CONTROLLER)
    if (
        probe.get("primary_apk_sha256") != primary_digest
        or probe.get("canary_apk_sha256") != canary_digest
        or controller.get("apk_sha256") != controller_digest
    ):
        raise CheckError("final APK build provenance mismatch")

    values: dict[str, object] = {
        "schema_version": 1,
        "artifact_class": "frozen_combined_host",
        "builder_tag": builder_tag,
        "dependency_key": dependency_key,
        "preflight_id": preflight["preflight_id"],
        "source_sha256": supported_source_digest(),
        "zip_sha256": zip_digest,
        "runtime_members": runtime_members,
        "controller_apk_sha256": controller_digest,
        "primary_apk_sha256": primary_digest,
        "canary_apk_sha256": canary_digest,
        "probe_source_sha256": source_match.group(1),
        "server_vpn_hook_catalog_sha256": sha256_file(SERVER_VPN_HOOK_CATALOG),
        "location_hook_count": 5,
        "server_vpn_hook_count": 14,
        "engine_owner": "shared",
    }
    generation_body = json.dumps(values, sort_keys=True, separators=(",", ":")).encode("ascii")
    values["generation_id"] = sha256_bytes(generation_body)
    if report is not None:
        report.kv("generation_id", values["generation_id"])
        report.kv("source_sha256", values["source_sha256"])
        report.kv("zip_sha256", zip_digest)
        report.kv("runtime_member_count", len(runtime_members))
        report.kv("probe_pair", "primary,canary")
        report.kv("engine_owner", "shared")
    return values


def freeze(report: Report, args: argparse.Namespace) -> None:
    values = canonical_generation(
        builder_tag=args.builder_tag,
        dependency_key=args.dependency_key,
        report=report,
        require_materialized_inputs=True,
    )
    PHASE_WRITE.stage(
        FINAL_GENERATION,
        json.dumps(values, sort_keys=True, separators=(",", ":")) + "\n",
    )
    report.kv("manifest", FINAL_GENERATION.relative_to(ROOT))
    report.kv("manifest_mode", "0600")
    report.kv("device_mutation", "none")


def load_generation(report: Report, args: argparse.Namespace) -> dict[str, object]:
    if not FINAL_GENERATION.is_file() or stat.S_IMODE(FINAL_GENERATION.stat().st_mode) != 0o600:
        raise CheckError("frozen generation manifest is missing or not mode 0600")
    try:
        decoded: object = json.loads(FINAL_GENERATION.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CheckError("frozen generation manifest is unreadable") from error
    if not isinstance(decoded, dict):
        raise CheckError("frozen generation manifest is not an object")
    expected = canonical_generation(
        builder_tag=args.builder_tag,
        dependency_key=args.dependency_key,
        report=report,
        require_materialized_inputs=False,
    )
    if decoded != expected:
        raise CheckError("source or artifact input changed after final freeze")
    return cast(dict[str, object], decoded)


def verify_generation(report: Report, args: argparse.Namespace) -> None:
    generation = load_generation(report, args)
    report.kv("generation_id", generation["generation_id"])
    report.kv("frozen_generation_verification", "PASS")
    report.kv("device_mutation", "none")


def remote_sha256(adb: Adb, path: str) -> str:
    result = adb.shell("sha256sum", path, timeout=30, check=False)
    value = result.stdout.split(maxsplit=1)[0] if result.returncode == 0 else ""
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise CheckError("device artifact identity is unavailable")
    return value


def require_installed_generation(adb: Adb, generation: dict[str, object], report: Report) -> None:
    module = parse_properties(read_text(adb, f"{LOCATION_MODULE_DIR}/module.prop"))
    if (
        module.get("id") != LOCATION_MODULE_ID
        or module.get("name") != "ZygVeil"
        or module.get("version") != "0.2.0"
        or module.get("versionCode") != "2"
        or exists(adb, f"{LOCATION_MODULE_UPDATE_DIR}/module.prop")
    ):
        raise CheckError("installed combined-host generation identity mismatch")
    expected = cast(dict[str, str], generation["runtime_members"])
    observed = {
        relative: remote_sha256(adb, f"{LOCATION_MODULE_DIR}/{relative}")
        for relative in sorted(expected)
    }
    if observed != expected:
        raise CheckError("installed combined-host runtime differs from frozen generation")
    aggregate = sha256_bytes(
        json.dumps(observed, sort_keys=True, separators=(",", ":")).encode("ascii")
    )
    report.kv("installed_runtime_set_sha256", aggregate)
    report.kv("installed_runtime_member_count", len(observed))


def installed_generation_matches(adb: Adb, generation: dict[str, object]) -> bool:
    module = parse_properties(read_text(adb, f"{LOCATION_MODULE_DIR}/module.prop"))
    if (
        module.get("id") != LOCATION_MODULE_ID
        or module.get("name") != "ZygVeil"
        or module.get("version") != "0.2.0"
        or module.get("versionCode") != "2"
        or exists(adb, f"{LOCATION_MODULE_UPDATE_DIR}/module.prop")
    ):
        return False
    expected = cast(dict[str, str], generation["runtime_members"])
    for relative, digest in expected.items():
        path = f"{LOCATION_MODULE_DIR}/{relative}"
        if not exists(adb, path) or remote_sha256(adb, path) != digest:
            return False
    return True


def require_installed_probes(adb: Adb, generation: dict[str, object], report: Report) -> None:
    for variant, package in PROBE_PACKAGES.items():
        result = adb.shell("pm", "path", package, timeout=15, check=False)
        paths = [line.removeprefix("package:") for line in result.stdout.splitlines()]
        if result.returncode != 0 or len(paths) != 1 or not paths[0].startswith("/data/app/"):
            raise CheckError(f"frozen {variant} universal probe is not installed")
        expected = cast(str, generation[f"{variant}_apk_sha256"])
        if remote_sha256(adb, paths[0]) != expected:
            raise CheckError(f"installed {variant} universal probe identity mismatch")
    report.kv("installed_probe_pair", "exact")


def require_staged_generation(adb: Adb, generation: dict[str, object], report: Report) -> None:
    module = parse_properties(read_text(adb, f"{LOCATION_MODULE_UPDATE_DIR}/module.prop"))
    if (
        module.get("id") != LOCATION_MODULE_ID
        or module.get("name") != "ZygVeil"
        or module.get("version") != "0.2.0"
        or module.get("versionCode") != "2"
    ):
        raise CheckError("staged combined-host generation identity mismatch")
    expected = cast(dict[str, str], generation["runtime_members"])
    observed = {
        relative: remote_sha256(adb, f"{LOCATION_MODULE_UPDATE_DIR}/{relative}")
        for relative in sorted(expected)
    }
    if observed != expected:
        raise CheckError("staged combined-host runtime differs from frozen generation")
    report.kv("staged_runtime_member_count", len(observed))


def install(report: Report, args: argparse.Namespace) -> None:
    generation = load_generation(report, args)
    adb = select_root_adbd(report, args)
    report.kv("vpn_precondition", "not_required_for_install")
    live = exists(adb, f"{LOCATION_MODULE_DIR}/module.prop")
    staged = exists(adb, f"{LOCATION_MODULE_UPDATE_DIR}/module.prop")
    preserved_location_config = (
        read_text(adb, f"{LOCATION_MODULE_DIR}/config.properties") if live else None
    )
    if staged:
        require_staged_generation(adb, generation, report)
    elif live and installed_generation_matches(adb, generation):
        require_installed_generation(adb, generation, report)
        was_disabled = exists(adb, f"{LOCATION_MODULE_DIR}/disable")
        removed = adb.shell("rm", "-f", f"{LOCATION_MODULE_DIR}/disable", check=False)
        if removed.returncode != 0 or exists(adb, f"{LOCATION_MODULE_DIR}/disable"):
            raise CheckError("could not retain production-enabled module state")
        report.kv("post_install_state", "pending_reboot_enabled" if was_disabled else "enabled")
        report.kv("packaged_vpn_policy", "present")
        report.kv("install_resume", "semantic_noop")
        report.kv("reboot_required", str(was_disabled).lower())
        report.kv("device_mutation", "Magisk disable marker removed" if was_disabled else "none")
        return
    if not staged:
        remote = f"/data/local/tmp/zygveil-final-{uuid.uuid4().hex[:12]}.zip"
        if adb.run("push", str(FINAL_ZIP), remote, timeout=120, check=False).returncode != 0:
            raise CheckError("could not upload the frozen combined-host ZIP")
        try:
            result = adb.shell("magisk", "--install-module", remote, timeout=180, check=False)
            if result.returncode != 0:
                raise CheckError("Magisk rejected the frozen combined-host ZIP")
        finally:
            adb.shell("rm", "-f", remote, check=False)
    install_dir = (
        LOCATION_MODULE_UPDATE_DIR
        if exists(adb, f"{LOCATION_MODULE_UPDATE_DIR}/module.prop")
        else LOCATION_MODULE_DIR
    )
    if (
        preserved_location_config is not None
        and read_text(adb, f"{install_dir}/config.properties") != preserved_location_config
    ):
        raise CheckError("frozen update changed the persistent location configuration")
    if install_dir == LOCATION_MODULE_UPDATE_DIR:
        require_staged_generation(adb, generation, report)
    else:
        require_installed_generation(adb, generation, report)
    removed = adb.shell("rm", "-f", f"{install_dir}/disable", check=False)
    if removed.returncode != 0 or exists(adb, f"{install_dir}/disable"):
        raise CheckError("final installation did not retain production enablement")
    report.kv("post_install_state", "pending_reboot_enabled")
    report.kv("packaged_vpn_policy", "present")
    report.kv("reboot_required", "true")
    report.kv("device_mutation", "production-enabled frozen combined-host installation")


def set_module_enablement(
    report: Report,
    args: argparse.Namespace,
    generation: dict[str, object],
    *,
    enabled: bool,
) -> None:
    adb = select_root_adbd(report, args)
    staged = exists(adb, f"{LOCATION_MODULE_UPDATE_DIR}/module.prop")
    if staged:
        require_staged_generation(adb, generation, report)
        directories = tuple(
            directory
            for directory in (LOCATION_MODULE_DIR, LOCATION_MODULE_UPDATE_DIR)
            if exists(adb, f"{directory}/module.prop")
        )
    else:
        require_installed_generation(adb, generation, report)
        directories = (LOCATION_MODULE_DIR,)
    for directory in directories:
        marker = f"{directory}/disable"
        result = (
            adb.shell("rm", "-f", marker, check=False)
            if enabled
            else adb.shell("touch", marker, check=False)
        )
        if result.returncode != 0 or exists(adb, marker) == enabled:
            raise CheckError("could not set explicit combined-host development enablement")
    report.kv("module_state", "pending_reboot_enabled" if enabled else "pending_reboot_disabled")
    report.kv("location_config", "preserved")
    report.kv("packaged_vpn_policy", "preserved")
    report.kv("reboot_required", "true")
    report.kv(
        "device_mutation",
        "explicit development module enable" if enabled else "explicit development module disable",
    )


def enable_module(report: Report, args: argparse.Namespace) -> None:
    generation = load_generation(report, args)
    set_module_enablement(report, args, generation, enabled=True)


def disable_module(report: Report, args: argparse.Namespace) -> None:
    generation = load_generation(report, args)
    set_module_enablement(report, args, generation, enabled=False)


@serialized_transition
def reboot(report: Report, args: argparse.Namespace) -> None:
    generation = load_generation(report, args)
    generation_id = cast(str, generation["generation_id"])
    pending = load_intent(
        FINAL_REBOOT_INTENT,
        operation="server-vpn-final-reboot",
        expected_state=args.expected,
        context_id=generation_id,
    )
    adb = select_root_adbd(report, args)
    if pending is not None:
        wait_for_boot(adb, report)
    current_identity = stable_system_server(adb, report)
    current_boot_digest = current_boot_id_sha256(adb)
    resumed = pending is not None and pending["source_boot_id_sha256"] != current_boot_digest
    if not resumed:
        staged = exists(adb, f"{LOCATION_MODULE_UPDATE_DIR}/module.prop")
        if staged:
            require_staged_generation(adb, generation, report)
            marker = f"{LOCATION_MODULE_UPDATE_DIR}/disable"
        else:
            require_installed_generation(adb, generation, report)
            marker = f"{LOCATION_MODULE_DIR}/disable"
        if exists(adb, marker) == (args.expected == "active"):
            raise CheckError("final reboot expected state/module enablement mismatch")
    intent, resumed = begin_or_resume(
        report,
        FINAL_REBOOT_INTENT,
        operation="server-vpn-final-reboot",
        expected_state=args.expected,
        context_id=generation_id,
        current_boot_id_sha256=current_boot_digest,
        current_system_server_pid=current_identity[0],
        current_system_server_start_ticks=current_identity[1],
    )
    if not resumed:
        if adb.run("reboot", timeout=30, check=False).returncode != 0:
            raise CheckError("final combined-host reboot command failed")
        wait_for_new_boot(
            adb,
            report,
            cast(str, intent["source_boot_id_sha256"]),
        )
    wait_for_vpn_on(adb)
    require_installed_generation(adb, generation, report)
    if args.expected == "active":
        inspect_server_vpn_poc(adb, report, expected="active")
    else:
        inspect_server_vpn_stock(adb, report)
    after = stable_system_server(adb, report)
    after_boot_digest = current_boot_id_sha256(adb)
    if after_boot_digest == intent["source_boot_id_sha256"]:
        raise CheckError("final combined-host reboot did not enter a new kernel boot")
    report.kv("boot_id_sha256", after_boot_digest)
    before = (
        str(intent["source_system_server_pid"]),
        str(intent["source_system_server_start_ticks"]),
    )
    report.kv("system_server_restarted_by_reboot", str(before != after).lower())
    clear_intent(FINAL_REBOOT_INTENT)
    report.kv("device_mutation", "explicit frozen combined-host reboot")


def status(report: Report, args: argparse.Namespace) -> None:
    generation = load_generation(report, args)
    adb = select_root_adbd(report, args)
    require_installed_generation(adb, generation, report)
    if args.expected == "active":
        inspect_server_vpn_poc(adb, report, expected="active")
    else:
        inspect_server_vpn_stock(adb, report)
    report.kv("device_mutation", "none")


def probe_args(
    args: argparse.Namespace, *, variant: str, group: str, active: bool
) -> argparse.Namespace:
    return argparse.Namespace(
        adb_serial=args.adb_serial,
        variant=variant,
        vpn_expected="on",
        module_expected="on" if active else "off",
        group=group,
        run_id="",
        raw_gnss_mode="",
        observation_window_ms=20_000,
        location_oracle="",
        poc=False,
        reuse_process=False,
        poc_no_oracle=False,
        expected_spatial_mismatch=False,
    )


def force_stop_probes(adb: Adb) -> None:
    for package in PROBE_PACKAGES.values():
        adb.shell("am", "force-stop", package, check=False)


def data_plane(
    adb: Adb,
    report: Report,
    args: argparse.Namespace,
    *,
    active: bool,
    label: str,
) -> dict[str, dict[str, str]]:
    runs: dict[str, dict[str, str]] = {}
    for group in DATA_PLANE_GROUPS:
        runs[group] = {
            variant: run_probe(
                report,
                probe_args(args, variant=variant, group=group, active=active),
            )
            for variant in ("primary", "canary")
        }
        force_stop_probes(adb)
    report.kv(f"{label}_data_plane", "dns_tls_https_pass")
    return runs


def crash_buffer(adb: Adb) -> str:
    result = adb.shell("logcat", "-b", "crash", "-d", "-v", "brief", timeout=30, check=False)
    if result.returncode != 0:
        raise CheckError("crash-buffer stability check is unavailable")
    return result.stdout


def new_phase_id(kind: str) -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"zygveil-server-vpn-{kind}-{timestamp}-{uuid.uuid4().hex[:8]}"


def phase_path(identifier: str) -> Path:
    if PHASE_ID.fullmatch(identifier) is None:
        raise CheckError("final server-VPN phase ID is invalid")
    return FINAL_PHASE_DIR / f"{identifier}.json"


def write_phase(values: dict[str, object]) -> None:
    identifier = cast(str, values["phase_id"])
    PHASE_WRITE.stage(
        phase_path(identifier),
        json.dumps(values, sort_keys=True, separators=(",", ":")) + "\n",
    )


def phase_timestamp(identifier: str) -> datetime:
    match = PHASE_ID.fullmatch(identifier)
    if match is None:
        raise CheckError("final server-VPN phase ID is invalid")
    return datetime.strptime(match.group("timestamp"), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)


def phase_manifest(
    *,
    kind: str,
    generation: dict[str, object],
    pairing: dict[str, str],
    runs: dict[str, dict[str, str]],
    stress_runs: dict[str, dict[str, str]],
    data_plane_runs: dict[str, dict[str, dict[str, str]]],
    status_values: dict[str, str],
    config_sha256: str,
    location_state: str,
    location_hook_count: int,
    stress_rounds: int,
) -> dict[str, object]:
    identifier = new_phase_id(kind)
    return {
        "schema_version": 1,
        "phase_id": identifier,
        "phase_kind": kind,
        "generation_id": generation["generation_id"],
        "groups": runs,
        "stress_runs": stress_runs,
        "data_plane_runs": data_plane_runs,
        "vpn_state": "on",
        "vpn_epoch_sha256": pairing["vpn_epoch_sha256"],
        "vpn_agent_unchanged": True,
        "boot_id_sha256": pairing["boot_id_sha256"],
        "system_server_pid": pairing["system_server_pid"],
        "system_server_start_ticks": pairing["system_server_start_ticks"],
        "server_vpn_state": status_values["state"],
        "server_vpn_hook_count": status_values["hook_count"],
        "config_generation": status_values["config_generation"],
        "config_sha256": config_sha256,
        "target_set_sha256": status_values["target_set_sha256"],
        "engine_owner": status_values.get("engine_owner", "shared"),
        "location_state": location_state,
        "location_hook_count": location_hook_count,
        "stress_rounds": stress_rounds,
        "data_plane": "dns_tls_https_pass",
        "crash_buffer_unchanged": True,
    }


def stock_status(adb: Adb, report: Report) -> tuple[dict[str, str], dict[str, str]]:
    pairing = inspect_server_vpn_stock(adb, report)
    status_values = {
        "state": pairing["server_vpn_state"],
        "hook_count": "0",
        "config_generation": "0",
        "target_set_sha256": "0" * 64,
        "engine_owner": "shared",
    }
    return pairing, status_values


def stock_suite(report: Report, args: argparse.Namespace) -> None:
    if args.phase_kind not in {"baseline", "rollback"}:
        raise CheckError("final stock suite requires baseline or rollback phase kind")
    generation = load_generation(report, args)
    adb = select_root_adbd(report, args)
    require_installed_generation(adb, generation, report)
    require_installed_probes(adb, generation, report)
    before, status_values = stock_status(adb, report)
    crash_before = crash_buffer(adb)
    data_plane_runs = {"before": data_plane(adb, report, args, active=False, label="before")}
    runs: dict[str, dict[str, str]] = {}
    try:
        for group in GROUPS:
            run_id = run_probe(
                report,
                probe_args(args, variant="primary", group=group, active=False),
            )
            runs[group] = {"primary": run_id}
            force_stop_probes(adb)
    finally:
        force_stop_probes(adb)
    data_plane_runs["after"] = data_plane(adb, report, args, active=False, label="after")
    after, after_status = stock_status(adb, report)
    require_unchanged_pairing(before, after, report)
    if status_values != after_status or crash_buffer(adb) != crash_before:
        raise CheckError("stock suite changed runtime state or crash buffer")
    values = phase_manifest(
        kind=args.phase_kind,
        generation=generation,
        pairing=before,
        runs=runs,
        stress_runs={},
        data_plane_runs=data_plane_runs,
        status_values=status_values,
        config_sha256="0" * 64,
        location_state="disabled",
        location_hook_count=0,
        stress_rounds=1,
    )
    write_phase(values)
    report.kv("phase_id", values["phase_id"])
    report.kv("group_count", len(runs))
    report.kv("device_mutation", "bounded universal probe sessions")


def active_suite(report: Report, args: argparse.Namespace) -> None:
    generation = load_generation(report, args)
    adb = select_root_adbd(report, args)
    require_installed_generation(adb, generation, report)
    require_installed_probes(adb, generation, report)
    status_values = inspect_server_vpn_poc(adb, report, expected="active")
    before = {
        "vpn_epoch_sha256": status_values["_vpn_epoch_sha256"],
        "system_server_pid": status_values["system_server_pid"],
        "system_server_start_ticks": status_values["system_server_start_ticks"],
        "boot_id": status_values["boot_id"],
        "boot_id_sha256": sha256_bytes(status_values["boot_id"].encode("ascii")),
    }
    expected_policy_sha256 = cast(dict[str, str], generation["runtime_members"])[
        "server-vpn-config.properties"
    ]
    if (
        remote_sha256(adb, f"{LOCATION_MODULE_DIR}/server-vpn-config.properties")
        != expected_policy_sha256
    ):
        raise CheckError("active final packaged policy differs from the frozen generation")
    location_config = parse_properties(read_text(adb, f"{LOCATION_MODULE_DIR}/config.properties"))
    location_state = "active" if location_config.get("enabled") == "true" else "waiting"
    crash_before = crash_buffer(adb)
    data_plane_runs = {"before": data_plane(adb, report, args, active=True, label="before")}
    runs: dict[str, dict[str, str]] = {}
    stress_runs: dict[str, dict[str, str]] = {}
    try:
        for group in GROUPS:
            if group in CALLBACK_GROUPS:
                run_ids = run_concurrent_server_vpn(
                    report,
                    argparse.Namespace(adb_serial=args.adb_serial, group=group, poc=False),
                )
            else:
                run_ids = {
                    variant: run_probe(
                        report,
                        probe_args(args, variant=variant, group=group, active=True),
                    )
                    for variant in ("primary", "canary")
                }
            runs[group] = run_ids
            force_stop_probes(adb)
        for group in sorted(CALLBACK_GROUPS):
            stress_runs[group] = run_concurrent_server_vpn(
                report,
                argparse.Namespace(adb_serial=args.adb_serial, group=group, poc=False),
            )
            force_stop_probes(adb)
    finally:
        force_stop_probes(adb)
    data_plane_runs["after"] = data_plane(adb, report, args, active=True, label="after")
    after = current_pairing(adb, report, stable=True)
    require_unchanged_pairing(before, after, report)
    final_status = validate_server_vpn_status(wait_for_server_vpn_status(adb))
    for key in (
        "state",
        "hook_count",
        "config_generation",
        "target_set_sha256",
        "engine_owner",
        "system_server_pid",
        "system_server_start_ticks",
        "boot_id",
    ):
        if final_status[key] != status_values[key]:
            raise CheckError(f"active final runtime changed during suite: {key}")
    location_health(adb, report)
    if crash_buffer(adb) != crash_before:
        raise CheckError("active suite changed the crash buffer")
    values = phase_manifest(
        kind="active",
        generation=generation,
        pairing=before,
        runs=runs,
        stress_runs=stress_runs,
        data_plane_runs=data_plane_runs,
        status_values=status_values,
        config_sha256=expected_policy_sha256,
        location_state=location_state,
        location_hook_count=5,
        stress_rounds=2,
    )
    write_phase(values)
    report.kv("phase_id", values["phase_id"])
    report.kv("group_count", len(runs))
    report.kv("callback_stress_rounds", 2)
    report.kv("device_mutation", "bounded universal probe sessions")


def isolation(report: Report, args: argparse.Namespace) -> None:
    generation = load_generation(report, args)
    adb = select_root_adbd(report, args)
    require_installed_generation(adb, generation, report)
    require_installed_probes(adb, generation, report)
    ensure_device_ui_ready(adb, report)
    started: list[str] = []
    try:
        for package in PROBE_PACKAGES.values():
            launch = adb.shell(
                "am",
                "start",
                "-W",
                "-n",
                f"{package}/dev.zygveil.probe.ProbeActivity",
                timeout=30,
                check=False,
            )
            if launch.returncode != 0:
                raise CheckError("final isolation probe could not start")
            started.append(package)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if all(adb.shell("pidof", package, check=False).stdout.strip() for package in started):
                break
            time.sleep(0.5)
        else:
            raise CheckError("final isolation probe processes did not remain live")
        values = inspect_server_vpn_poc(adb, report, expected="active")
        if values["engine_owner"] != "shared":
            raise CheckError("final isolation lost the shared hook-engine owner")
        report.kv("application_isolation", "PASS")
    finally:
        force_stop_probes(adb)
    report.kv("probe_processes_restored", "stopped")
    report.kv("device_mutation", "controlled probe launch and force-stop")


@serialized_transition
def recover(report: Report, args: argparse.Namespace) -> None:
    generation = load_generation(report, args)
    generation_id = cast(str, generation["generation_id"])
    pending = load_intent(
        FINAL_RECOVERY_INTENT,
        operation="server-vpn-final-recover",
        expected_state="inactive",
        context_id=generation_id,
    )
    adb = select_root_adbd(report, args)
    if pending is not None:
        wait_for_boot(adb, report)
    require_installed_generation(adb, generation, report)
    current_identity = stable_system_server(adb, report)
    current_boot_digest = current_boot_id_sha256(adb)
    intent, resumed = begin_or_resume(
        report,
        FINAL_RECOVERY_INTENT,
        operation="server-vpn-final-recover",
        expected_state="inactive",
        context_id=generation_id,
        current_boot_id_sha256=current_boot_digest,
        current_system_server_pid=current_identity[0],
        current_system_server_start_ticks=current_identity[1],
    )
    report.kv("vpn_precondition", "not_required_for_recovery")
    if not resumed:
        marker = f"{LOCATION_MODULE_DIR}/disable"
        if adb.shell("touch", marker, check=False).returncode != 0 or not exists(adb, marker):
            raise CheckError("final recovery could not disable the combined host")
        if adb.run("reboot", timeout=30, check=False).returncode != 0:
            raise CheckError("final recovery reboot failed")
        wait_for_new_boot(
            adb,
            report,
            cast(str, intent["source_boot_id_sha256"]),
        )
    inspect_server_vpn_stock(adb, report, require_vpn=False)
    require_installed_generation(adb, generation, report)
    after_boot_digest = current_boot_id_sha256(adb)
    if after_boot_digest == intent["source_boot_id_sha256"]:
        raise CheckError("final recovery did not enter a new kernel boot")
    report.kv("boot_id_sha256", after_boot_digest)
    report.kv("location_config", "preserved")
    report.kv("packaged_vpn_policy", "preserved")
    clear_intent(FINAL_RECOVERY_INTENT)
    clear_intent(FINAL_REBOOT_INTENT)
    report.kv("recovery_status", "PASS")
    report.kv("device_mutation", "explicit module disable and one recovery reboot")


def validate_stress_run_inventory(value: object, kind: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CheckError("final server-VPN stress run inventory is not an object")
    expected_groups = CALLBACK_GROUPS if kind == "active" else set()
    if set(value) != expected_groups:
        raise CheckError("final server-VPN stress run inventory mismatch")
    for run_ids in value.values():
        if not isinstance(run_ids, dict) or set(run_ids) != {"primary", "canary"}:
            raise CheckError("final server-VPN stress role inventory mismatch")
        if any(
            not isinstance(run_id, str) or SAFE_RUN_ID.fullmatch(run_id) is None
            for run_id in run_ids.values()
        ):
            raise CheckError("final server-VPN stress run identity mismatch")
    return cast(dict[str, object], value)


def load_phase(identifier: str, generation_id: str) -> dict[str, object]:
    path = phase_path(identifier)
    if not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise CheckError("final server-VPN phase manifest is missing or not mode 0600")
    try:
        decoded: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CheckError("final server-VPN phase manifest is unreadable") from error
    if not isinstance(decoded, dict):
        raise CheckError("final server-VPN phase manifest is not an object")
    values = cast(dict[str, object], decoded)
    match = PHASE_ID.fullmatch(identifier)
    groups = values.get("groups")
    stress_runs = values.get("stress_runs")
    data_plane_runs = values.get("data_plane_runs")
    boot_id_sha256 = values.get("boot_id_sha256")
    vpn_epoch_sha256 = values.get("vpn_epoch_sha256")
    system_server_pid = values.get("system_server_pid")
    system_server_start_ticks = values.get("system_server_start_ticks")
    if (
        match is None
        or values.get("schema_version") != 1
        or values.get("phase_id") != identifier
        or values.get("phase_kind") != match.group("kind")
        or values.get("generation_id") != generation_id
        or values.get("vpn_state") != "on"
        or values.get("vpn_agent_unchanged") is not True
        or values.get("engine_owner") != "shared"
        or values.get("data_plane") != "dns_tls_https_pass"
        or values.get("crash_buffer_unchanged") is not True
        or not isinstance(boot_id_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", boot_id_sha256) is None
        or not isinstance(vpn_epoch_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", vpn_epoch_sha256) is None
        or not isinstance(system_server_pid, str)
        or not system_server_pid.isdigit()
        or int(system_server_pid) <= 0
        or not isinstance(system_server_start_ticks, str)
        or not system_server_start_ticks.isdigit()
        or int(system_server_start_ticks) <= 0
        or not isinstance(groups, dict)
        or set(groups) != set(GROUPS)
        or not isinstance(stress_runs, dict)
        or not isinstance(data_plane_runs, dict)
        or set(data_plane_runs) != {"before", "after"}
    ):
        raise CheckError("final server-VPN phase manifest identity mismatch")
    kind = cast(str, values["phase_kind"])
    expected_variants = {"primary", "canary"} if kind == "active" else {"primary"}
    for run_ids in groups.values():
        if not isinstance(run_ids, dict) or set(run_ids) != expected_variants:
            raise CheckError("final server-VPN phase run inventory mismatch")
        if any(
            not isinstance(run_id, str) or SAFE_RUN_ID.fullmatch(run_id) is None
            for run_id in run_ids.values()
        ):
            raise CheckError("final server-VPN phase run identity mismatch")
    validate_stress_run_inventory(stress_runs, kind)
    for checkpoint in cast(dict[str, object], data_plane_runs).values():
        if not isinstance(checkpoint, dict) or set(checkpoint) != set(DATA_PLANE_GROUPS):
            raise CheckError("final data-plane checkpoint group inventory mismatch")
        for run_ids in checkpoint.values():
            if not isinstance(run_ids, dict) or set(run_ids) != {"primary", "canary"}:
                raise CheckError("final data-plane checkpoint role inventory mismatch")
            if any(
                not isinstance(run_id, str) or SAFE_RUN_ID.fullmatch(run_id) is None
                for run_id in run_ids.values()
            ):
                raise CheckError("final data-plane checkpoint run identity mismatch")
    if kind == "active":
        config_generation = values.get("config_generation")
        config_sha256 = values.get("config_sha256")
        target_set_sha256 = values.get("target_set_sha256")
        if (
            values.get("server_vpn_state") != "active"
            or values.get("server_vpn_hook_count") != "14"
            or not isinstance(config_generation, str)
            or not config_generation.isdigit()
            or int(config_generation) <= 0
            or not isinstance(config_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", config_sha256) is None
            or config_sha256 == "0" * 64
            or not isinstance(target_set_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", target_set_sha256) is None
            or target_set_sha256 == "0" * 64
            or values.get("stress_rounds") != 2
            or values.get("location_state") not in {"waiting", "active"}
            or values.get("location_hook_count") != 5
        ):
            raise CheckError("final active phase state mismatch")
    elif (
        values.get("server_vpn_state") not in {"absent", "inactive"}
        or values.get("server_vpn_hook_count") != "0"
        or values.get("config_generation") != "0"
        or values.get("config_sha256") != "0" * 64
        or values.get("target_set_sha256") != "0" * 64
        or values.get("stress_rounds") != 1
        or values.get("location_state") != "disabled"
        or values.get("location_hook_count") != 0
    ):
        raise CheckError("final stock phase state mismatch")
    return values


def select_latest_phase_sequence(
    phases: list[dict[str, object]],
) -> tuple[str, str, str]:
    ordered: list[tuple[datetime, str, str]] = []
    seen: set[str] = set()
    for phase in phases:
        kind = phase.get("phase_kind")
        identifier = phase.get("phase_id")
        if kind not in {"baseline", "active", "rollback"} or not isinstance(identifier, str):
            raise CheckError("final server-VPN phase selection input is invalid")
        if identifier in seen:
            raise CheckError("final server-VPN phase selection contains a duplicate identity")
        seen.add(identifier)
        ordered.append((phase_timestamp(identifier), identifier, kind))
    ordered.sort()
    baseline_id: str | None = None
    active_id: str | None = None
    selected: tuple[str, str, str] | None = None
    for _timestamp, identifier, kind in ordered:
        if kind == "baseline":
            baseline_id = identifier
            active_id = None
        elif kind == "active":
            active_id = None if baseline_id is None else identifier
        elif baseline_id is not None and active_id is not None:
            selected = (baseline_id, active_id, identifier)
        else:
            baseline_id = None
            active_id = None
    if selected is not None:
        return selected
    raise CheckError(
        "no complete ordered baseline/active/rollback sequence exists for the frozen generation"
    )


def discover_phase_sequence(generation_id: str) -> tuple[str, str, str]:
    if not FINAL_PHASE_DIR.is_dir():
        raise CheckError("final server-VPN phase directory is missing")
    phases: list[dict[str, object]] = []
    for path in sorted(FINAL_PHASE_DIR.glob("*.json")):
        identifier = path.stem
        match = PHASE_ID.fullmatch(identifier)
        if match is None:
            raise CheckError("final server-VPN phase directory contains an invalid manifest name")
        try:
            decoded: object = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise CheckError(
                "final server-VPN phase directory contains unreadable evidence"
            ) from error
        if not isinstance(decoded, dict):
            raise CheckError("final server-VPN phase directory contains invalid evidence")
        header = cast(dict[str, object], decoded)
        if (
            header.get("schema_version") != 1
            or header.get("phase_id") != identifier
            or header.get("phase_kind") != match.group("kind")
            or not isinstance(header.get("generation_id"), str)
        ):
            raise CheckError("final server-VPN phase directory contains invalid evidence identity")
        if header["generation_id"] == generation_id:
            phases.append(load_phase(identifier, generation_id))
    return select_latest_phase_sequence(phases)


def resolve_phase_sequence(
    args: argparse.Namespace,
    generation_id: str,
) -> tuple[tuple[str, str, str], tuple[dict[str, object], dict[str, object], dict[str, object]]]:
    explicit = (args.baseline_phase, args.active_phase, args.rollback_phase)
    supplied = tuple(bool(value) for value in explicit)
    if any(supplied) and not all(supplied):
        raise CheckError("final server-VPN phase overrides require all three phase IDs")
    identifiers = cast(
        tuple[str, str, str],
        explicit if all(supplied) else discover_phase_sequence(generation_id),
    )
    if len(set(identifiers)) != 3:
        raise CheckError("three distinct final server-VPN phase IDs are required")
    timestamps = tuple(phase_timestamp(value) for value in identifiers)
    if not timestamps[0] < timestamps[1] < timestamps[2]:
        raise CheckError("final server-VPN phases are not in baseline/active/rollback order")
    phases = tuple(load_phase(identifier, generation_id) for identifier in identifiers)
    return identifiers, cast(tuple[dict[str, object], dict[str, object], dict[str, object]], phases)


def run_records(run_id: object, group: str, variant: str) -> list[dict[str, object]]:
    if not isinstance(run_id, str):
        raise CheckError("final server-VPN phase lacks a required probe run")
    metadata = load_run_state(run_id, poc=False)
    if (
        metadata.get("poc") is not False
        or metadata.get("variant") != variant
        or metadata.get("requested_group") != group
    ):
        raise CheckError("final server-VPN phase/run metadata mismatch")
    path = FINAL_PROBE_RUN_DIR / f"{run_id}.jsonl"
    if not path.is_file():
        raise CheckError("final server-VPN phase JSONL is missing")
    records, _verdict = validate_jsonl(path.read_text(encoding="utf-8"), metadata)
    return records


def validate_concurrent_launch_metadata(
    metadata_by_variant: dict[str, dict[str, object]],
    run_ids: dict[str, object],
    group: str,
) -> tuple[int, int, int]:
    if set(run_ids) != {"primary", "canary"}:
        raise CheckError("final concurrent server-VPN pair role inventory mismatch")
    if set(metadata_by_variant) != {"primary", "canary"}:
        raise CheckError("final concurrent server-VPN metadata role inventory mismatch")
    ready_latency_values: set[int] = set()
    dispatch_delay_values: set[int] = set()
    start_target_values: set[int] = set()
    for variant in ("primary", "canary"):
        run_id = run_ids[variant]
        partner = "canary" if variant == "primary" else "primary"
        if not isinstance(run_id, str) or not isinstance(run_ids[partner], str):
            raise CheckError("final concurrent server-VPN pair run identity mismatch")
        metadata = metadata_by_variant[variant]
        ready_latency = metadata.get("concurrent_canary_ready_latency_ms")
        dispatch_delay = metadata.get("concurrent_primary_dispatch_delay_ms")
        start_target = metadata.get("concurrent_start_elapsed_realtime_ms")
        if (
            metadata.get("poc") is not False
            or metadata.get("variant") != variant
            or metadata.get("requested_group") != group
            or metadata.get("concurrent_launch_mode")
            != "canary_ready_then_primary_nonblocking_activity"
            or metadata.get("concurrent_partner_run_id") != run_ids[partner]
            or type(ready_latency) is not int
            or type(dispatch_delay) is not int
            or type(start_target) is not int
        ):
            raise CheckError("final concurrent server-VPN launch metadata mismatch")
        if not 0 <= ready_latency <= SERVER_VPN_CANARY_READY_TIMEOUT_SECONDS * 1_000:
            raise CheckError("final concurrent server-VPN canary readiness is out of bounds")
        if not 0 <= dispatch_delay <= SERVER_VPN_PRIMARY_DISPATCH_MAX_DELAY_MS:
            raise CheckError("final concurrent server-VPN primary dispatch is out of bounds")
        if start_target <= 0:
            raise CheckError("final concurrent server-VPN start rendezvous is invalid")
        ready_latency_values.add(ready_latency)
        dispatch_delay_values.add(dispatch_delay)
        start_target_values.add(start_target)
    if (
        len(ready_latency_values) != 1
        or len(dispatch_delay_values) != 1
        or len(start_target_values) != 1
    ):
        raise CheckError("final concurrent server-VPN pair has inconsistent launch timing")
    return (
        next(iter(ready_latency_values)),
        next(iter(dispatch_delay_values)),
        next(iter(start_target_values)),
    )


def concurrent_pair_launch_timing(
    phase: dict[str, object], inventory_name: str, group: str
) -> tuple[int, int, int]:
    inventory = cast(dict[str, object], phase[inventory_name])
    run_ids = cast(dict[str, object], inventory[group])
    metadata_by_variant: dict[str, dict[str, object]] = {}
    for variant in ("primary", "canary"):
        run_id = run_ids.get(variant)
        if not isinstance(run_id, str):
            raise CheckError("final concurrent server-VPN pair run identity mismatch")
        metadata_by_variant[variant] = load_run_state(run_id, poc=False)
    return validate_concurrent_launch_metadata(metadata_by_variant, run_ids, group)


def phase_records(phase: dict[str, object], group: str, variant: str) -> list[dict[str, object]]:
    groups = cast(dict[str, object], phase["groups"])
    run_ids = cast(dict[str, object], groups[group])
    return run_records(run_ids.get(variant), group, variant)


def stress_records(phase: dict[str, object], group: str, variant: str) -> list[dict[str, object]]:
    groups = cast(dict[str, object], phase["stress_runs"])
    run_ids = cast(dict[str, object], groups[group])
    return run_records(run_ids.get(variant), group, variant)


def phase_run_ids(phase: dict[str, object]) -> set[str]:
    identifiers: list[object] = []
    for inventory_name in ("groups", "stress_runs"):
        inventory = cast(dict[str, object], phase[inventory_name])
        for run_ids in inventory.values():
            identifiers.extend(cast(dict[str, object], run_ids).values())
    checkpoints = cast(dict[str, object], phase["data_plane_runs"])
    for groups in checkpoints.values():
        for run_ids in cast(dict[str, object], groups).values():
            identifiers.extend(cast(dict[str, object], run_ids).values())
    if any(
        not isinstance(identifier, str) or SAFE_RUN_ID.fullmatch(identifier) is None
        for identifier in identifiers
    ):
        raise CheckError("final server-VPN phase contains an invalid run identity")
    result = set(cast(list[str], identifiers))
    if len(result) != len(identifiers):
        raise CheckError("final server-VPN phase reuses a probe run identity")
    return result


def validate_data_plane_records(phase: dict[str, object]) -> int:
    checkpoints = cast(dict[str, object], phase["data_plane_runs"])
    validated = 0
    for groups in checkpoints.values():
        for group, run_ids in cast(dict[str, object], groups).items():
            for variant, run_id in cast(dict[str, object], run_ids).items():
                if not isinstance(run_id, str):
                    raise CheckError("final data-plane run identity is invalid")
                metadata = load_run_state(run_id, poc=False)
                if (
                    metadata.get("poc") is not False
                    or metadata.get("variant") != variant
                    or metadata.get("requested_group") != group
                    or metadata.get("detector_group") != "data-plane"
                ):
                    raise CheckError("final data-plane phase/run metadata mismatch")
                path = FINAL_PROBE_RUN_DIR / f"{run_id}.jsonl"
                if not path.is_file():
                    raise CheckError("final data-plane JSONL is missing")
                records, verdict = validate_jsonl(path.read_text(encoding="utf-8"), metadata)
                detectors = [record for record in records if record["record_type"] == "detector"]
                if verdict != "NO_PUBLIC_VPN_SIGNAL" or any(
                    record["status"] != "NEGATIVE" for record in detectors
                ):
                    raise CheckError("final data-plane oracle did not pass")
                validated += 1
    return validated


def acceptance(report: Report, args: argparse.Namespace) -> None:
    generation = load_generation(report, args)
    generation_id = cast(str, generation["generation_id"])
    identifiers, phases = resolve_phase_sequence(args, generation_id)
    baseline, active, rollback = phases
    if (
        baseline["phase_kind"] != "baseline"
        or active["phase_kind"] != "active"
        or rollback["phase_kind"] != "rollback"
        or len(
            {
                baseline["boot_id_sha256"],
                active["boot_id_sha256"],
                rollback["boot_id_sha256"],
            }
        )
        != 3
    ):
        raise CheckError("final server-VPN phase sequence mismatch")
    phase_run_inventories = [phase_run_ids(phase) for phase in phases]
    if len(set().union(*phase_run_inventories)) != sum(
        len(inventory) for inventory in phase_run_inventories
    ):
        raise CheckError("final server-VPN sequence reuses a probe run identity")
    total_detectors = 0
    residual_detectors = 0
    stress_detectors = 0
    data_plane_run_count = sum(
        validate_data_plane_records(phase) for phase in (baseline, active, rollback)
    )
    for group in GROUPS:
        if group in CALLBACK_GROUPS:
            ready_latency_ms, dispatch_delay_ms, start_target_ms = concurrent_pair_launch_timing(
                active, "groups", group
            )
            report.kv(f"group.{group}.canary_ready_latency_ms", ready_latency_ms)
            report.kv(f"group.{group}.primary_dispatch_delay_ms", dispatch_delay_ms)
            report.kv(f"group.{group}.start_elapsed_realtime_ms", start_target_ms)
        if group.removeprefix("secondary-") == "server-vpn-diagnostics":
            result = evaluate_diagnostics_residual(
                phase_records(baseline, group, "primary"),
                phase_records(active, group, "primary"),
                phase_records(active, group, "canary"),
                phase_records(rollback, group, "primary"),
            )
            if result.get("residual") != "PASS":
                raise CheckError(f"final server-VPN diagnostics residual failed for {group}")
            residual_detectors += cast(int, result["detector_count"])
            report.kv(f"group.{group}.permission_bounded_residual", "PASS")
            continue
        result = evaluate_differential(
            phase_records(baseline, group, "primary"),
            phase_records(active, group, "primary"),
            phase_records(active, group, "canary"),
            phase_records(rollback, group, "primary"),
        )
        if result.get("differential") != "PASS":
            raise CheckError(f"final server-VPN differential failed for {group}")
        total_detectors += cast(int, result["detector_count"])
        report.kv(f"group.{group}.differential", "PASS")
        if result.get("overlap_required") is True:
            report.kv(f"group.{group}.overlap_ms", result["overlap_ms"])
    for group in sorted(CALLBACK_GROUPS):
        ready_latency_ms, dispatch_delay_ms, start_target_ms = concurrent_pair_launch_timing(
            active, "stress_runs", group
        )
        report.kv(f"stress.{group}.canary_ready_latency_ms", ready_latency_ms)
        report.kv(f"stress.{group}.primary_dispatch_delay_ms", dispatch_delay_ms)
        report.kv(f"stress.{group}.start_elapsed_realtime_ms", start_target_ms)
        result = evaluate_differential(
            phase_records(baseline, group, "primary"),
            stress_records(active, group, "primary"),
            stress_records(active, group, "canary"),
            phase_records(rollback, group, "primary"),
        )
        if result.get("differential") != "PASS" or result.get("overlap_required") is not True:
            raise CheckError(f"final server-VPN stress differential failed for {group}")
        stress_detectors += cast(int, result["detector_count"])
        report.kv(f"stress.{group}.differential", "PASS")
        report.kv(f"stress.{group}.overlap_ms", result["overlap_ms"])
    report.kv("generation_id", generation_id)
    report.kv("phase_selection", "explicit" if args.baseline_phase else "automatic")
    report.kv("baseline_phase", identifiers[0])
    report.kv("active_phase", identifiers[1])
    report.kv("rollback_phase", identifiers[2])
    report.kv("group_count", len(GROUPS))
    report.kv("differential_detector_count", total_detectors)
    report.kv("permission_bounded_residual_detector_count", residual_detectors)
    report.kv("stress_detector_count", stress_detectors)
    report.kv("stress_run_count", len(CALLBACK_GROUPS) * 2)
    report.kv("data_plane_run_count", data_plane_run_count)
    report.kv("unique_probe_run_count", sum(len(value) for value in phase_run_inventories))
    report.kv("vpn_state", "on_in_each_rebooted_phase")
    report.kv("cross_boot_agent_equality", "not_required")
    report.kv("server_vpn_acceptance", "PASS")
    report.kv("device_mutation", "none")


COMMANDS: dict[str, Callable[[Report, argparse.Namespace], None]] = {
    "final-acceptance": acceptance,
    "final-active-suite": active_suite,
    "final-disable": disable_module,
    "final-enable": enable_module,
    "final-freeze": freeze,
    "final-install": install,
    "final-isolation": isolation,
    "final-reboot": reboot,
    "final-recover": recover,
    "final-status": status,
    "final-stock-suite": stock_suite,
    "final-verify": verify_generation,
}


def state_machine_self_test() -> None:
    for transition in (reboot, recover):
        required = {"begin_or_resume", "wait_for_new_boot", "clear_intent"}
        missing = required - set(inspect.unwrap(transition).__code__.co_names)
        if missing:
            raise CheckError(f"{transition.__name__} lacks durable reboot steps: {sorted(missing)}")
    sample_run_ids = {
        group: {
            "primary": f"probe-20260826T000000Z-{index:08x}",
            "canary": f"probe-20260826T000001Z-{index:08x}",
        }
        for index, group in enumerate(sorted(CALLBACK_GROUPS), start=1)
    }
    validate_stress_run_inventory(sample_run_ids, "active")
    validate_stress_run_inventory({}, "baseline")
    for invalid in (
        {},
        {**sample_run_ids, "server-vpn-diagnostics": sample_run_ids[next(iter(sample_run_ids))]},
        {**sample_run_ids, next(iter(sample_run_ids)): {"primary": "invalid"}},
    ):
        try:
            validate_stress_run_inventory(invalid, "active")
        except CheckError:
            pass
        else:
            raise CheckError("final server-VPN stress inventory self-test accepted a mismatch")
    concurrent_run_ids: dict[str, object] = {
        "primary": "probe-20260826T000010Z-00000010",
        "canary": "probe-20260826T000011Z-00000011",
    }
    concurrent_metadata = {
        variant: {
            "poc": False,
            "variant": variant,
            "requested_group": "server-vpn-link",
            "concurrent_launch_mode": "canary_ready_then_primary_nonblocking_activity",
            "concurrent_partner_run_id": concurrent_run_ids[
                "canary" if variant == "primary" else "primary"
            ],
            "concurrent_canary_ready_latency_ms": 100,
            "concurrent_primary_dispatch_delay_ms": 1,
            "concurrent_start_elapsed_realtime_ms": 123_000,
        }
        for variant in ("primary", "canary")
    }
    if validate_concurrent_launch_metadata(
        concurrent_metadata, concurrent_run_ids, "server-vpn-link"
    ) != (100, 1, 123_000):
        raise CheckError("final concurrent launch metadata self-test failed")
    for variant, key, value in (
        ("primary", "concurrent_launch_mode", "sequential"),
        ("primary", "concurrent_partner_run_id", concurrent_run_ids["primary"]),
        ("primary", "concurrent_canary_ready_latency_ms", "pending"),
        ("canary", "concurrent_canary_ready_latency_ms", 101),
        ("canary", "concurrent_start_elapsed_realtime_ms", 123_001),
        (
            "primary",
            "concurrent_primary_dispatch_delay_ms",
            SERVER_VPN_PRIMARY_DISPATCH_MAX_DELAY_MS + 1,
        ),
    ):
        invalid_metadata = cast(
            dict[str, dict[str, object]], json.loads(json.dumps(concurrent_metadata))
        )
        invalid_metadata[variant][key] = value
        try:
            validate_concurrent_launch_metadata(
                invalid_metadata, concurrent_run_ids, "server-vpn-link"
            )
        except CheckError:
            pass
        else:
            raise CheckError("final concurrent launch metadata self-test accepted a mismatch")
    phase_samples: list[dict[str, object]] = [
        {
            "phase_kind": kind,
            "phase_id": f"zygveil-server-vpn-{kind}-20260826T00000{index}Z-0000000{index}",
        }
        for index, kind in enumerate(("baseline", "active", "rollback"))
    ]
    phase_samples.append(
        {
            "phase_kind": "baseline",
            "phase_id": "zygveil-server-vpn-baseline-20260826T000003Z-00000003",
        }
    )
    phase_samples.append(
        {
            "phase_kind": "rollback",
            "phase_id": "zygveil-server-vpn-rollback-20260826T000004Z-00000004",
        }
    )
    if select_latest_phase_sequence(phase_samples) != tuple(
        cast(str, phase["phase_id"]) for phase in phase_samples[:3]
    ):
        raise CheckError("final server-VPN automatic phase selection self-test failed")
    try:
        select_latest_phase_sequence(phase_samples[:2])
    except CheckError:
        pass
    else:
        raise CheckError("final server-VPN phase selection accepted an incomplete sequence")
    prohibited_vpn_dependencies = {
        "require_vpn_on",
        "wait_for_vpn_on",
        "current_pairing",
        "inspect_server_vpn_poc",
    }
    for operation in (install, enable_module, disable_module, recover):
        found = prohibited_vpn_dependencies.intersection(
            inspect.unwrap(operation).__code__.co_names
        )
        if found:
            raise CheckError(
                f"{operation.__name__} unexpectedly depends on VPN readiness: {sorted(found)}"
            )
    for operation in (
        install,
        enable_module,
        disable_module,
        reboot,
        status,
        stock_suite,
        active_suite,
        isolation,
        recover,
        acceptance,
        verify_generation,
    ):
        if "load_generation" not in inspect.unwrap(operation).__code__.co_names:
            raise CheckError(f"{operation.__name__} has no frozen-generation precondition")
    if "ensure_device_ui_ready" not in isolation.__code__.co_names:
        raise CheckError("final server-VPN isolation has no device UI readiness gate")
    expected_callback_groups = {
        "server-vpn-active",
        "server-vpn-async",
        "server-vpn-link",
        "secondary-server-vpn-active",
        "secondary-server-vpn-async",
        "secondary-server-vpn-link",
    }
    if (
        len(GROUPS) != 10
        or expected_callback_groups != CALLBACK_GROUPS
        or DATA_PLANE_GROUPS != ("data-plane", "secondary-data-plane")
    ):
        raise CheckError("final server-VPN suite inventory self-test failed")
    source = Path(__file__).read_text(encoding="utf-8")
    prohibited_tokens = ("ls" + "posed", "mig" + "ration", "/system/bin/" + "curl")
    for prohibited in prohibited_tokens:
        if prohibited in source:
            raise CheckError(f"final server-VPN flow contains a prohibited path: {prohibited}")
    data_plane_source = (
        ROOT / "components/probe/src/main/java/dev/zygveil/probe/detector/DataPlaneDetectors.java"
    ).read_text(encoding="utf-8")
    for marker in (
        "data_plane.dns",
        "data_plane.tls_https",
        "data_plane.lifecycle",
        "InetAddress.getAllByName",
        "HttpsURLConnection",
    ):
        if marker not in data_plane_source:
            raise CheckError(f"universal data-plane oracle marker is missing: {marker}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--adb-serial", default="")
    parser.add_argument("--builder-tag", required=True)
    parser.add_argument("--dependency-key", required=True)
    parser.add_argument("--expected", choices=("active", "inactive"), default="active")
    parser.add_argument("--phase-kind", choices=("baseline", "rollback"), default="baseline")
    parser.add_argument("--baseline-phase", default="")
    parser.add_argument("--active-phase", default="")
    parser.add_argument("--rollback-phase", default="")
    parser.add_argument("command", choices=sorted(COMMANDS))
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    try:
        with Report(ROOT / args.report_dir, args.command) as report:
            try:
                COMMANDS[args.command](report, args)
            finally:
                report.assert_redacted(
                    [
                        r"(?i)\b(?:address|route|dns|interface|gateway|latitude|longitude)=",
                        r"\.state/",
                        r"connectivitycheck",
                        r"\$[A-Z]",
                    ]
                )
        PHASE_WRITE.commit()
    except CheckError:
        PHASE_WRITE.discard()
        return 1
    except Exception:
        PHASE_WRITE.discard()
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
