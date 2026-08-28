# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Make-wrapped ZygVeil system-server VPN POC lifecycle."""

from __future__ import annotations

import argparse
import hashlib
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

from adb import Adb, ensure_device_ui_ready, system_server_process_identity
from baseline import parse_vpn_agents
from probe import (
    SAFE_RUN_ID,
    SERVER_VPN_GROUPS,
    load_run_state,
    run_concurrent_server_vpn,
    run_probe,
    validate_jsonl,
    write_private_text,
)
from reporting import CheckError, Report
from server_vpn_oracle import evaluate_diagnostics_residual, evaluate_differential

ROOT = Path(__file__).resolve().parents[2]
LOCATION_MODULE_ID = "zygveil"
LOCATION_MODULE_DIR = f"/data/adb/modules/{LOCATION_MODULE_ID}"
LOCATION_MODULE_UPDATE_DIR = f"/data/adb/modules_update/{LOCATION_MODULE_ID}"
SERVER_VPN_POC_ZIP = ROOT / ".artifacts/poc/server-vpn/zygveil-poc.zip"
SERVER_VPN_PHASE_DIR = ROOT / ".artifacts/poc/state/server-vpn-phases"
SERVER_VPN_PROBE_RUN_DIR = ROOT / ".artifacts/poc/reports/probe/runs"
SERVER_VPN_PRODUCT_POLICY = ROOT / "components/server-vpn/runtime/policy.properties"
SAFE_PHASE_ID = re.compile(
    r"server-vpn-(?P<kind>stock|active)-(?P<timestamp>[0-9]{8}T[0-9]{6}Z)-[0-9a-f]{8}"
)
PROC_MAP_PATTERN = re.compile(
    r"^(?P<start>[0-9a-f]+)-(?P<end>[0-9a-f]+)\s+(?P<perms>\S+)\s+"
    r"(?P<offset>[0-9a-f]+)\s+(?P<device>\S+)\s+(?P<inode>\d+)\s*(?P<path>.*)$"
)
SERVER_VPN_CONFIG_KEYS = (
    "schema_version",
    "backend_id",
    "catalog_version",
    "config_generation",
    "target_mode",
)
SERVER_VPN_RUNTIME_FILES = {
    "zygisk/arm64-v8a.so": 0o755,
    "locationctl": 0o755,
    "bridge.dex": 0o644,
    "server-vpn-bridge.dex": 0o644,
    "libshadowhook_nothing.so": 0o644,
    "server-vpn-config.properties": 0o644,
}


def select_root_adbd(report: Report, args: argparse.Namespace) -> Adb:
    adb = Adb.select(args.adb_serial, report)
    identity = adb.shell("id", timeout=10, check=False)
    report.kv("root_escalation_attempted", "false")
    if identity.returncode != 0 or "uid=0" not in identity.stdout:
        raise CheckError("rooted adbd is required; run make adb-root")
    report.kv("adbd_state", "root")
    return adb


def exists(adb: Adb, path: str) -> bool:
    return adb.shell("test", "-e", path, check=False).returncode == 0


def read_text(adb: Adb, path: str, *, required: bool = True) -> str:
    result = adb.shell("cat", path, timeout=15, check=False)
    if required and result.returncode != 0:
        raise CheckError(f"required device file is unavailable: {path}")
    return result.stdout if result.returncode == 0 else ""


def require_vpn_on(adb: Adb, report: Report) -> str:
    connectivity = adb.shell("dumpsys", "connectivity", timeout=30, check=False)
    if connectivity.returncode != 0:
        raise CheckError("VPN-ON validation could not read Connectivity state")
    agents = parse_vpn_agents(connectivity.stdout)
    if len(agents) != 1:
        raise CheckError("server-VPN workflow requires exactly one active VPN agent")
    report.kv("vpn_state", "owner_declared_on")
    report.kv("active_vpn_agent_count", 1)
    report.kv("vpn_state_mutation", "none")
    report.kv("raw_connectivity_dump_persisted", "false")
    identity = {
        "network": agents[0]["network"],
        "owner_uid": agents[0]["owner_uid"],
    }
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def wait_for_vpn_on(adb: Adb, timeout_seconds: int = 90) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        connectivity = adb.shell("dumpsys", "connectivity", timeout=30, check=False)
        if connectivity.returncode == 0:
            agents = parse_vpn_agents(connectivity.stdout)
            if len(agents) == 1:
                return
            if len(agents) > 1:
                raise CheckError("post-reboot state has multiple active VPN agents")
        time.sleep(2)
    raise CheckError("one active VPN agent did not appear after completed boot")


def parse_properties(content: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in content.splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise CheckError("device properties contain a malformed line")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+", key) or key in values:
            raise CheckError("device properties contain an invalid or duplicate key")
        values[key] = value
    return values


def canonical_server_vpn_config(path: Path) -> tuple[bytes, dict[str, str]]:
    if not path.is_absolute():
        path = ROOT / path
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise CheckError("server-VPN next-boot configuration is unavailable") from None
    if resolved != SERVER_VPN_PRODUCT_POLICY.resolve():
        raise CheckError("server-VPN policy input must be the tracked immutable product policy")
    try:
        raw = path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise CheckError("server-VPN policy is not strict ASCII") from error
    if not 0 < len(raw.encode("ascii")) <= 8192:
        raise CheckError("server-VPN policy is missing or oversized")
    lines = [line for line in raw.splitlines() if line and not line.startswith("#")]
    body = "".join(f"{line}\n" for line in lines)
    values = parse_properties(body)
    if tuple(values) != SERVER_VPN_CONFIG_KEYS:
        raise CheckError("server-VPN configuration key order or inventory mismatch")
    if (
        values["schema_version"] != "2"
        or values["backend_id"] != "zygveil_server_vpn"
        or values["catalog_version"] != "1"
        or values["target_mode"] != "eligible_user0_apps"
    ):
        raise CheckError("server-VPN configuration fixed identity mismatch")
    generation = values["config_generation"]
    if not generation.isdigit() or not 1 <= int(generation) <= (1 << 62) - 1:
        raise CheckError("server-VPN configuration generation is invalid")
    if "enabled" in values or "mode" in values:
        raise CheckError("server-VPN configuration contains a feature switch")
    return body.encode("ascii"), values


def validate_server_vpn_status(content: str) -> dict[str, str]:
    values = parse_properties(content)
    expected = {
        "schema_version",
        "feature",
        "state",
        "reason",
        "system_server_pid",
        "system_server_start_ticks",
        "boot_id",
        "artifact_generation",
        "config_generation",
        "catalog_version",
        "catalog_hook_count",
        "hook_count",
        "target_set_sha256",
        "engine_owner",
        "owner_generation",
    }
    if set(values) != expected:
        raise CheckError("server-VPN runtime status schema mismatch")
    if (
        values["schema_version"] != "1"
        or values["feature"] != "server_vpn"
        or values["artifact_generation"] != "1"
        or values["catalog_version"] != "1"
        or values["catalog_hook_count"] != "14"
        or values["engine_owner"] != "shared"
        or values["owner_generation"] != "1"
        or re.fullmatch(r"[0-9a-f]{64}", values["target_set_sha256"]) is None
    ):
        raise CheckError("server-VPN runtime status identity mismatch")
    numeric_limits = {
        "system_server_pid": (1 << 32) - 1,
        "system_server_start_ticks": (1 << 64) - 1,
        "config_generation": (1 << 62) - 1,
        "hook_count": 14,
    }
    numeric: dict[str, int] = {}
    for key, maximum in numeric_limits.items():
        value = values[key]
        if not value.isdigit() or int(value) > maximum:
            raise CheckError("server-VPN runtime status number is invalid")
        numeric[key] = int(value)
    if (
        numeric["system_server_pid"] == 0
        or numeric["system_server_start_ticks"] == 0
        or values["state"] not in {"arming", "active", "inactive"}
        or re.fullmatch(r"[a-z0-9_:.-]{1,128}", values["reason"]) is None
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            values["boot_id"],
        )
        is None
    ):
        raise CheckError("server-VPN runtime status lifecycle identity is invalid")
    active = values["state"] == "active"
    if (
        active
        and (
            numeric["config_generation"] == 0
            or numeric["hook_count"] != 14
            or values["target_set_sha256"] == "0" * 64
        )
    ) or (not active and numeric["hook_count"] != 0):
        raise CheckError("server-VPN runtime status activation is partial")
    prohibited = {"package", "certificate", "address", "route", "dns", "interface"}
    if prohibited.intersection(values):
        raise CheckError("server-VPN runtime status exposes prohibited data")
    return values


def state_machine_self_test() -> None:
    _body, config = canonical_server_vpn_config(SERVER_VPN_PRODUCT_POLICY)
    if config["config_generation"] != "2" or config["target_mode"] != "eligible_user0_apps":
        raise CheckError("server-VPN example configuration self-test failed")
    prohibited_vpn_dependencies = {"require_vpn_on", "wait_for_vpn_on", "current_pairing"}
    for operation in (poc_install, poc_recover):
        found = prohibited_vpn_dependencies.intersection(operation.__code__.co_names)
        if found:
            raise CheckError(
                f"{operation.__name__} unexpectedly depends on VPN readiness: {sorted(found)}"
            )
    if "ensure_device_ui_ready" not in poc_isolation.__code__.co_names:
        raise CheckError("server-VPN POC isolation has no device UI readiness gate")
    if ("require_vpn", "allow_incomplete_runtime") not in poc_recover.__code__.co_consts:
        raise CheckError("server-VPN recovery no-VPN inspection arguments are missing")
    status = "\n".join(
        (
            "schema_version=1",
            "feature=server_vpn",
            "state=active",
            "reason=active",
            "system_server_pid=123",
            "system_server_start_ticks=456",
            "boot_id=12345678-1234-1234-1234-123456789abc",
            "artifact_generation=1",
            "config_generation=2",
            "catalog_version=1",
            "catalog_hook_count=14",
            "hook_count=14",
            f"target_set_sha256={'1' * 64}",
            "engine_owner=shared",
            "owner_generation=1",
            "",
        )
    )
    validate_server_vpn_status(status)
    for source, replacement in (
        ("hook_count=14", "hook_count=13"),
        ("state=active", "state=unknown"),
        ("system_server_pid=123", "system_server_pid=0"),
        ("reason=active", "reason=unsafe value"),
    ):
        try:
            validate_server_vpn_status(status.replace(source, replacement))
        except CheckError:
            pass
        else:
            raise CheckError("server-VPN status self-test accepted malformed state")
    phase_manifest_self_test()


def location_health(adb: Adb, report: Report) -> tuple[str, str]:
    properties = parse_properties(read_text(adb, f"{LOCATION_MODULE_DIR}/module.prop"))
    if properties.get("id") != LOCATION_MODULE_ID:
        raise CheckError("accepted location module identity is unavailable")
    if exists(adb, f"{LOCATION_MODULE_DIR}/disable"):
        raise CheckError("ZygVeil host is disabled")
    runtime = parse_properties(read_text(adb, f"{LOCATION_MODULE_DIR}/runtime-status.properties"))
    pid, start_ticks = system_server_process_identity(adb)
    if (
        runtime.get("state") != "ready"
        or runtime.get("hook_count") != "5"
        or runtime.get("system_server_pid") != pid
        or runtime.get("system_server_start_ticks") != start_ticks
    ):
        raise CheckError("accepted location runtime is not healthy and current")
    location_config = parse_properties(read_text(adb, f"{LOCATION_MODULE_DIR}/config.properties"))
    report.kv("location_state", "active" if location_config.get("enabled") == "true" else "waiting")
    report.kv("location_hook_count", 5)
    report.kv("location_runtime_identity_current", "true")
    return pid, start_ticks


def stable_system_server(adb: Adb, report: Report, seconds: int = 12) -> tuple[str, str]:
    samples: list[tuple[str, str]] = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        samples.append(system_server_process_identity(adb))
        time.sleep(3)
    if len(samples) < 3 or len(set(samples)) != 1:
        raise CheckError("system_server identity changed during observation")
    report.kv("system_server_pid", samples[0][0])
    report.kv("system_server_start_ticks", samples[0][1])
    report.kv("system_server_stable", "true")
    return samples[0]


def current_pairing(adb: Adb, report: Report, *, stable: bool) -> dict[str, str]:
    vpn_epoch = require_vpn_on(adb, report)
    pid, start_ticks = (
        stable_system_server(adb, report) if stable else system_server_process_identity(adb)
    )
    boot_id = read_text(adb, "/proc/sys/kernel/random/boot_id").strip()
    if re.fullmatch(r"[0-9a-f-]{36}", boot_id) is None:
        raise CheckError("device boot identity is invalid")
    return {
        "vpn_epoch_sha256": vpn_epoch,
        "system_server_pid": pid,
        "system_server_start_ticks": start_ticks,
        "boot_id": boot_id,
        "boot_id_sha256": hashlib.sha256(boot_id.encode("ascii")).hexdigest(),
    }


def require_unchanged_pairing(
    before: dict[str, str], after: dict[str, str], report: Report
) -> None:
    for key in (
        "vpn_epoch_sha256",
        "system_server_pid",
        "system_server_start_ticks",
        "boot_id",
    ):
        if before[key] != after[key]:
            raise CheckError(f"server-VPN probe pairing changed during collection: {key}")
    report.kv("vpn_agent_fingerprint_unchanged", "true")
    report.kv("system_server_identity_unchanged", "true")
    report.kv("boot_identity_unchanged", "true")


def phase_id(kind: str) -> str:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"server-vpn-{kind}-{timestamp}-{uuid.uuid4().hex[:8]}"


def phase_path(identifier: str) -> Path:
    if SAFE_PHASE_ID.fullmatch(identifier) is None:
        raise CheckError("server-VPN phase ID has an invalid format")
    return SERVER_VPN_PHASE_DIR / f"{identifier}.json"


def phase_timestamp(identifier: str) -> datetime:
    match = SAFE_PHASE_ID.fullmatch(identifier)
    if match is None:
        raise CheckError("server-VPN phase ID has an invalid format")
    return datetime.strptime(match.group("timestamp"), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)


def write_phase(values: dict[str, object]) -> None:
    identifier = cast(str, values["phase_id"])
    destination = phase_path(identifier)
    write_private_text(
        destination,
        json.dumps(values, sort_keys=True, separators=(",", ":")) + "\n",
    )


def load_phase(identifier: str) -> dict[str, object]:
    path = phase_path(identifier)
    if not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise CheckError("server-VPN phase manifest is missing or not mode 0600")
    try:
        decoded: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CheckError("server-VPN phase manifest is unreadable") from error
    if not isinstance(decoded, dict):
        raise CheckError("server-VPN phase manifest is not an object")
    return validate_phase_manifest(cast(dict[str, object], decoded), identifier)


def validate_phase_manifest(values: dict[str, object], identifier: str) -> dict[str, object]:
    if set(values) != {
        "schema_version",
        "phase_id",
        "phase_kind",
        "group",
        "process_role",
        "run_ids",
        "vpn_state",
        "vpn_epoch_sha256",
        "vpn_agent_unchanged",
        "boot_id_sha256",
        "system_server_pid",
        "system_server_start_ticks",
        "server_vpn_state",
        "server_vpn_hook_count",
        "config_generation",
        "target_set_sha256",
    }:
        raise CheckError("server-VPN phase manifest schema mismatch")
    identifier_match = SAFE_PHASE_ID.fullmatch(identifier)
    if identifier_match is None:
        raise CheckError("server-VPN phase manifest ID mismatch")
    phase_kind = values["phase_kind"]
    run_ids = values["run_ids"]
    if (
        values["schema_version"] != 1
        or values["phase_id"] != identifier
        or phase_kind not in {"stock", "active"}
        or identifier_match.group("kind") != phase_kind
        or values["group"] not in SERVER_VPN_GROUPS
        or values["process_role"] not in {"main", "secondary"}
        or values["vpn_state"] != "on"
        or values["vpn_agent_unchanged"] is not True
        or not isinstance(run_ids, dict)
        or set(run_ids) != ({"primary", "canary"} if phase_kind == "active" else {"primary"})
        or any(
            not isinstance(run_id, str) or SAFE_RUN_ID.fullmatch(run_id) is None
            for run_id in run_ids.values()
        )
        or re.fullmatch(r"[0-9a-f]{64}", cast(str, values["vpn_epoch_sha256"])) is None
        or re.fullmatch(r"[0-9a-f]{64}", cast(str, values["boot_id_sha256"])) is None
        or re.fullmatch(r"[0-9a-f]{64}", cast(str, values["target_set_sha256"])) is None
        or not cast(str, values["system_server_pid"]).isdigit()
        or not cast(str, values["system_server_start_ticks"]).isdigit()
        or not cast(str, values["config_generation"]).isdigit()
    ):
        raise CheckError("server-VPN phase manifest identity mismatch")
    if phase_kind == "active" and (
        values["server_vpn_state"] != "active"
        or values["server_vpn_hook_count"] != "14"
        or values["config_generation"] == "0"
        or values["target_set_sha256"] == "0" * 64
    ):
        raise CheckError("active server-VPN phase manifest state mismatch")
    if phase_kind == "stock" and (
        values["server_vpn_state"] not in {"absent", "inactive"}
        or values["server_vpn_hook_count"] != "0"
        or values["config_generation"] != "0"
        or values["target_set_sha256"] != "0" * 64
    ):
        raise CheckError("stock server-VPN phase manifest state mismatch")
    return values


def phase_manifest_self_test() -> None:
    identifier = "server-vpn-active-20260826T000001Z-01234567"
    valid: dict[str, object] = {
        "schema_version": 1,
        "phase_id": identifier,
        "phase_kind": "active",
        "group": "server-vpn-async",
        "process_role": "main",
        "run_ids": {
            "primary": "probe-20260826T000000Z-01234567",
            "canary": "probe-20260826T000000Z-89abcdef",
        },
        "vpn_state": "on",
        "vpn_epoch_sha256": "1" * 64,
        "vpn_agent_unchanged": True,
        "boot_id_sha256": "2" * 64,
        "system_server_pid": "123",
        "system_server_start_ticks": "456",
        "server_vpn_state": "active",
        "server_vpn_hook_count": "14",
        "config_generation": "2",
        "target_set_sha256": "3" * 64,
    }
    validate_phase_manifest(valid, identifier)
    for key, bad_value in (
        ("vpn_state", "off"),
        ("vpn_agent_unchanged", False),
        ("target_set_sha256", "invalid"),
    ):
        invalid = {**valid, key: bad_value}
        try:
            validate_phase_manifest(invalid, identifier)
        except CheckError:
            pass
        else:
            raise CheckError(f"server-VPN phase self-test accepted invalid {key}")
    if not (
        phase_timestamp("server-vpn-stock-20260826T000000Z-01234567")
        < phase_timestamp(identifier)
        < phase_timestamp("server-vpn-stock-20260826T000002Z-89abcdef")
    ):
        raise CheckError("server-VPN phase chronology self-test failed")
    baseline = {
        **valid,
        "phase_id": "server-vpn-stock-20260826T000000Z-01234567",
        "phase_kind": "stock",
        "run_ids": {"primary": "probe-20260826T000000Z-01234567"},
        "boot_id_sha256": "4" * 64,
        "server_vpn_state": "absent",
        "server_vpn_hook_count": "0",
        "config_generation": "0",
        "target_set_sha256": "0" * 64,
    }
    rollback = {
        **baseline,
        "phase_id": "server-vpn-stock-20260826T000002Z-89abcdef",
        "run_ids": {"primary": "probe-20260826T000002Z-89abcdef"},
        "boot_id_sha256": "5" * 64,
    }
    validate_phase_manifest(baseline, cast(str, baseline["phase_id"]))
    validate_phase_manifest(rollback, cast(str, rollback["phase_id"]))
    validate_phase_sequence(baseline, valid, rollback)
    invalid_active = {**valid, "boot_id_sha256": baseline["boot_id_sha256"]}
    try:
        validate_phase_sequence(baseline, invalid_active, rollback)
    except CheckError:
        pass
    else:
        raise CheckError("server-VPN phase sequence accepted a reused boot")
    if require_server_vpn_group("secondary-server-vpn-async", concurrent=True) != (
        "server-vpn-async",
        "secondary",
    ):
        raise CheckError("server-VPN phase group self-test failed")
    if require_server_vpn_group("server-vpn-diagnostics", concurrent=False) != (
        "server-vpn-diagnostics",
        "main",
    ):
        raise CheckError("server-VPN diagnostics residual group self-test failed")
    try:
        require_server_vpn_group("server-vpn-diagnostics", concurrent=True)
    except CheckError:
        pass
    else:
        raise CheckError("server-VPN diagnostics residual accepted concurrent calibration")


def wait_for_boot(adb: Adb, report: Report, timeout_seconds: int = 300) -> None:
    if adb.run("wait-for-device", timeout=timeout_seconds, check=False).returncode != 0:
        raise CheckError("device did not return after reboot")
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        completed = adb.shell("getprop", "sys.boot_completed", check=False).stdout.strip()
        bootanim = adb.shell("getprop", "init.svc.bootanim", check=False).stdout.strip()
        if completed == "1" and bootanim == "stopped":
            report.kv("sys.boot_completed", completed)
            report.kv("init.svc.bootanim", bootanim)
            break
        time.sleep(2)
    else:
        raise CheckError("Android did not complete boot")
    identity = adb.shell("id", check=False)
    if identity.returncode != 0 or "uid=0" not in identity.stdout:
        root = adb.run("root", timeout=30, check=False)
        report.kv("adb_root_after_reboot_exit", root.returncode)
        if (
            root.returncode != 0
            or adb.run("wait-for-device", timeout=60, check=False).returncode != 0
        ):
            raise CheckError("rooted adbd did not return after reboot")
        identity = adb.shell("id", check=False)
    if identity.returncode != 0 or "uid=0" not in identity.stdout:
        raise CheckError("adbd is not uid 0 after reboot")


def require_server_vpn_poc(report: Report) -> Path:
    if not SERVER_VPN_POC_ZIP.is_file() or SERVER_VPN_POC_ZIP.stat().st_size == 0:
        raise CheckError("server-VPN POC is missing; run make server-vpn-poc-build")
    with zipfile.ZipFile(SERVER_VPN_POC_ZIP) as archive:
        if archive.testzip() is not None or not set(SERVER_VPN_RUNTIME_FILES).issubset(
            archive.namelist()
        ):
            raise CheckError("server-VPN POC ZIP runtime inventory is incomplete")
        module = parse_properties(archive.read("module.prop").decode("ascii"))
        if (
            module.get("id") != LOCATION_MODULE_ID
            or module.get("name") != "ZygVeil POC"
            or module.get("version") != "0.2.0-poc"
        ):
            raise CheckError("server-VPN POC generic host identity mismatch")
        if "server-vpn-config.properties" not in archive.namelist() or any(
            name.endswith(".apk") for name in archive.namelist()
        ):
            raise CheckError("server-VPN POC lacks packaged policy or contains an APK")
    report.kv("artifact_class", "non_attestable_combined_host_poc")
    report.kv("hash_attestation", "skipped")
    report.kv("reproducibility", "skipped")
    return SERVER_VPN_POC_ZIP


def poc_install(report: Report, args: argparse.Namespace) -> None:
    artifact = require_server_vpn_poc(report)
    adb = select_root_adbd(report, args)
    report.kv("vpn_precondition", "not_required_for_install")
    report.kv("vpn_state_mutation", "none")
    live = exists(adb, f"{LOCATION_MODULE_DIR}/module.prop")
    staged = exists(adb, f"{LOCATION_MODULE_UPDATE_DIR}/module.prop")
    preserved_location_config = (
        read_text(adb, f"{LOCATION_MODULE_DIR}/config.properties") if live else None
    )
    if not staged:
        remote = f"/data/local/tmp/zygveil-poc-{uuid.uuid4().hex[:12]}.zip"
        if adb.run("push", str(artifact), remote, timeout=120, check=False).returncode != 0:
            raise CheckError("could not upload the combined-host POC ZIP")
        try:
            result = adb.shell("magisk", "--install-module", remote, timeout=180, check=False)
            report.kv("magisk_install_exit", result.returncode)
            if result.returncode != 0:
                raise CheckError("Magisk rejected the combined-host POC ZIP")
        finally:
            adb.shell("rm", "-f", remote, check=False)
    install_dir = (
        LOCATION_MODULE_UPDATE_DIR
        if exists(adb, f"{LOCATION_MODULE_UPDATE_DIR}/module.prop")
        else LOCATION_MODULE_DIR
    )
    properties = parse_properties(read_text(adb, f"{install_dir}/module.prop"))
    location_config = parse_properties(read_text(adb, f"{install_dir}/config.properties"))
    if (
        preserved_location_config is not None
        and read_text(adb, f"{install_dir}/config.properties") != preserved_location_config
    ):
        raise CheckError("combined-host POC update changed the persistent location configuration")
    guard = parse_properties(read_text(adb, f"{install_dir}/guard-status.properties"))
    required_files = (
        "zygisk/arm64-v8a.so",
        "locationctl",
        "bridge.dex",
        "server-vpn-bridge.dex",
        "server-vpn-config.properties",
    )
    if (
        properties.get("id") != LOCATION_MODULE_ID
        or properties.get("name") != "ZygVeil POC"
        or properties.get("version") != "0.2.0-poc"
        or location_config.get("schema_version") != "1"
        or location_config.get("enabled") not in {"false", "true"}
        or guard.get("state") != "valid"
        or any(not exists(adb, f"{install_dir}/{relative}") for relative in required_files)
    ):
        raise CheckError("installed combined-host POC identity or production state is invalid")
    if exists(adb, f"{install_dir}/disable"):
        raise CheckError("combined-host POC install unexpectedly created a disable marker")
    policy_body = read_text(adb, f"{install_dir}/server-vpn-config.properties")
    _, expected_policy = canonical_server_vpn_config(SERVER_VPN_PRODUCT_POLICY)
    if parse_properties(policy_body) != expected_policy:
        raise CheckError("combined-host POC packaged policy mismatch")
    report.kv("install_mode", "resume" if staged else "update" if live else "new")
    report.kv("magisk_staging", str(install_dir == LOCATION_MODULE_UPDATE_DIR).lower())
    report.kv("post_install_state", "pending_reboot_enabled")
    report.kv("packaged_vpn_policy", "present")
    report.kv("reboot_required", "true")
    report.kv("device_mutation", "production-state combined-host POC installation")


def wait_for_server_vpn_status(adb: Adb, timeout_seconds: int = 30) -> str:
    path = f"{LOCATION_MODULE_DIR}/server-vpn-runtime-status.properties"
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        content = read_text(adb, path, required=False)
        if content:
            try:
                validate_server_vpn_status(content)
                return content
            except CheckError:
                pass
        time.sleep(1)
    raise CheckError("current server-VPN runtime status did not become available")


def inspect_server_vpn_poc(adb: Adb, report: Report, *, expected: str) -> dict[str, str]:
    vpn_epoch = require_vpn_on(adb, report)
    pid, start_ticks = stable_system_server(adb, report)
    location_health(adb, report)
    if exists(adb, f"{LOCATION_MODULE_DIR}/disable") or exists(
        adb, f"{LOCATION_MODULE_UPDATE_DIR}/module.prop"
    ):
        raise CheckError("combined host is disabled or has a pending update")
    status = validate_server_vpn_status(wait_for_server_vpn_status(adb))
    boot_id = read_text(adb, "/proc/sys/kernel/random/boot_id").strip()
    if (
        status["system_server_pid"] != pid
        or status["system_server_start_ticks"] != start_ticks
        or status["boot_id"] != boot_id
        or status["config_generation"] == "0"
        or status["target_set_sha256"] == "0" * 64
    ):
        raise CheckError("server-VPN runtime status is stale or unbound")
    if expected == "active":
        if status["state"] != "active" or status["hook_count"] != "14":
            raise CheckError("server-VPN runtime is not completely active")
    elif expected == "any":
        if (status["state"] == "active" and status["hook_count"] != "14") or (
            status["state"] != "active" and status["hook_count"] != "0"
        ):
            raise CheckError("server-VPN runtime exposes a partial hook state")
    else:
        raise CheckError("unsupported server-VPN POC expected state")

    file_identity = adb.shell(
        "stat",
        "-c",
        "%u:%g:%a:%h:%F",
        f"{LOCATION_MODULE_DIR}/server-vpn-runtime-status.properties",
        check=False,
    ).stdout.strip()
    config_identity = adb.shell(
        "stat",
        "-c",
        "%u:%g:%a:%h:%F",
        f"{LOCATION_MODULE_DIR}/server-vpn-config.properties",
        check=False,
    ).stdout.strip()
    if file_identity != "0:0:644:1:regular file" or config_identity != ("0:0:644:1:regular file"):
        raise CheckError("server-VPN status/config file boundary mismatch")
    if not exists(adb, f"{LOCATION_MODULE_DIR}/server-vpn-bridge.dex"):
        raise CheckError("server-VPN server-only bridge is missing")

    maps = read_text(adb, f"/proc/{pid}/maps")
    independent_owner_present = any(
        marker in maps
        for marker in (
            "libzygveil_server_vpn_shadowhook.so",
            "aaa_zygveil_server_vpn_gate",
            "zzz_zygveil_server_vpn_gate",
        )
    )
    if independent_owner_present:
        raise CheckError("a second hook-engine owner is mapped in system_server")
    controlled_pids: list[str] = []
    for package in ("dev.zygveil.probe.primary", "dev.zygveil.probe.canary"):
        result = adb.shell("pidof", package, check=False)
        controlled_pids.extend(value for value in result.stdout.split() if value.isdigit())
    leaked_status_descriptors = 0
    location_control_processes = 0
    forbidden_vpn_mappings = 0
    for application_pid in sorted(set(controlled_pids)):
        application_maps = read_text(adb, f"/proc/{application_pid}/maps")
        control_mappings = [
            match
            for line in application_maps.splitlines()
            if (match := PROC_MAP_PATTERN.fullmatch(line)) is not None
            and match["path"] == f"{LOCATION_MODULE_DIR}/.app-control"
        ]
        location_control_valid = (
            len(control_mappings) == 1
            and control_mappings[0]["perms"].startswith("r--")
            and "w" not in control_mappings[0]["perms"]
            and int(control_mappings[0]["offset"], 16) == 0
            and int(control_mappings[0]["end"], 16) - int(control_mappings[0]["start"], 16) == 4096
        )
        location_control_processes += int(location_control_valid)
        if not location_control_valid:
            raise CheckError("controlled application lacks the exact read-only location page")
        forbidden_vpn_mappings += sum(
            marker in line
            for line in application_maps.splitlines()
            for marker in (
                "libzygveil_server_vpn",
                "zygveil_server_vpn",
                "server-vpn-bridge.dex",
                "zygveil-server-vpn-status",
            )
        )
        scan = adb.shell_input(
            "/system/bin/sh",
            input_text=(
                f"for f in /proc/{application_pid}/fd/*; do "
                'readlink "$f" 2>/dev/null || true; done\n'
            ),
            timeout=10,
            check=False,
        )
        if scan.returncode != 0:
            raise CheckError("controlled application descriptor scan failed")
        leaked_status_descriptors += sum(
            marker in line
            for line in scan.stdout.splitlines()
            for marker in (
                "zygveil-server-vpn-status",
                "server-vpn-config.properties",
                "server-vpn-bridge.dex",
            )
        )
        threads = adb.shell_input(
            "/system/bin/sh",
            input_text=f"cat /proc/{application_pid}/task/*/comm 2>/dev/null || true\n",
            timeout=10,
            check=False,
        )
        if "ZygVeilHookInit" in threads.stdout:
            raise CheckError("server-VPN initialization thread escaped to an application")
    if leaked_status_descriptors != 0:
        raise CheckError("server-VPN descriptor escaped to a controlled application")
    if forbidden_vpn_mappings != 0:
        raise CheckError("server-VPN backing identity escaped to a controlled application")

    report.kv("server_vpn_state", status["state"])
    report.kv("server_vpn_reason", status["reason"])
    report.kv("server_vpn_hook_count", status["hook_count"])
    report.kv("catalog_hook_count", status["catalog_hook_count"])
    report.kv("engine_owner", status["engine_owner"])
    report.kv("boot_id_sha256", hashlib.sha256(boot_id.encode("ascii")).hexdigest())
    report.kv("status_file_identity", "root_0644_single_link")
    report.kv("config_file_identity", "root_0644_single_link")
    report.kv("controlled_application_processes", len(set(controlled_pids)))
    report.kv("controlled_application_location_control_processes", location_control_processes)
    report.kv("common_elf_digest_attestation", "deferred_to_final_location_acceptance")
    report.kv("controlled_application_forbidden_vpn_mappings", forbidden_vpn_mappings)
    report.kv("controlled_application_vpn_descriptor_count", leaked_status_descriptors)
    report.kv("independent_owner_mapping_present", "false")
    report.kv("authorization_set_identity", "digest_only")
    status["_vpn_epoch_sha256"] = vpn_epoch
    return status


def poc_reboot(report: Report, args: argparse.Namespace) -> None:
    adb = select_root_adbd(report, args)
    module_dir = (
        LOCATION_MODULE_UPDATE_DIR
        if exists(adb, f"{LOCATION_MODULE_UPDATE_DIR}/module.prop")
        else LOCATION_MODULE_DIR
    )
    required = [
        "server-vpn-bridge.dex",
        "server-vpn-config.properties",
    ]
    for relative in required:
        if not exists(adb, f"{module_dir}/{relative}"):
            raise CheckError("server-VPN POC runtime set is not staged")
    if exists(adb, f"{module_dir}/disable"):
        raise CheckError("server-VPN POC reboot refused a disabled combined host")
    before = system_server_process_identity(adb)
    if adb.run("reboot", timeout=30, check=False).returncode != 0:
        raise CheckError("server-VPN POC reboot command failed")
    wait_for_boot(adb, report)
    wait_for_vpn_on(adb)
    inspect_server_vpn_poc(adb, report, expected=args.expected)
    after = system_server_process_identity(adb)
    report.kv("system_server_restarted", str(before != after).lower())
    report.kv("device_mutation", "explicit combined-host POC reboot and focused status")


def poc_status(report: Report, args: argparse.Namespace) -> None:
    adb = select_root_adbd(report, args)
    inspect_server_vpn_poc(adb, report, expected=args.expected)
    report.kv("device_mutation", "none")


def poc_isolation(report: Report, args: argparse.Namespace) -> None:
    adb = select_root_adbd(report, args)
    packages = ("dev.zygveil.probe.primary", "dev.zygveil.probe.canary")
    for package in packages:
        if adb.shell("pm", "path", package, check=False).returncode != 0:
            raise CheckError("controlled isolation probe is not installed")
    ensure_device_ui_ready(adb, report)
    started: list[str] = []
    try:
        for package in packages:
            component = f"{package}/dev.zygveil.probe.ProbeActivity"
            launch = adb.shell("am", "start", "-W", "-n", component, check=False)
            if launch.returncode != 0:
                raise CheckError("controlled isolation probe could not start")
            started.append(package)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            running = 0
            for package in packages:
                pids = adb.shell("pidof", package, check=False).stdout.split()
                running += int(any(value.isdigit() for value in pids))
            if running == len(packages):
                break
            time.sleep(0.5)
        else:
            raise CheckError("controlled isolation probe processes did not remain live")
        status = inspect_server_vpn_poc(adb, report, expected=args.expected)
        if status["engine_owner"] != "shared":
            raise CheckError("controlled isolation run lost shared ownership")
        report.kv("application_isolation", "PASS")
    finally:
        for package in started:
            adb.shell("am", "force-stop", package, check=False)
    report.kv("probe_processes_restored", "stopped")
    report.kv("device_mutation", "controlled probe launch, isolation scan, and force-stop")


def inspect_server_vpn_stock(
    adb: Adb,
    report: Report,
    *,
    stable: bool = True,
    require_vpn: bool = True,
    allow_incomplete_runtime: bool = False,
) -> dict[str, str]:
    if require_vpn:
        pairing = current_pairing(adb, report, stable=stable)
    else:
        pid, start_ticks = (
            stable_system_server(adb, report) if stable else system_server_process_identity(adb)
        )
        boot_id = read_text(adb, "/proc/sys/kernel/random/boot_id").strip()
        if re.fullmatch(r"[0-9a-f-]{36}", boot_id) is None:
            raise CheckError("device boot identity is invalid")
        pairing = {
            "vpn_epoch_sha256": "not_required_for_recovery",
            "system_server_pid": pid,
            "system_server_start_ticks": start_ticks,
            "boot_id": boot_id,
            "boot_id_sha256": hashlib.sha256(boot_id.encode("ascii")).hexdigest(),
        }
        report.kv("vpn_state", "not_required_for_recovery")
        report.kv("vpn_state_mutation", "none")
    properties = parse_properties(read_text(adb, f"{LOCATION_MODULE_DIR}/module.prop"))
    if (
        properties.get("id") != LOCATION_MODULE_ID
        or not exists(adb, f"{LOCATION_MODULE_DIR}/disable")
        or exists(adb, f"{LOCATION_MODULE_UPDATE_DIR}/module.prop")
    ):
        raise CheckError("stock probe requires the exact disabled combined host")
    policy = parse_properties(read_text(adb, f"{LOCATION_MODULE_DIR}/server-vpn-config.properties"))
    _, expected_policy = canonical_server_vpn_config(SERVER_VPN_PRODUCT_POLICY)
    if policy != expected_policy:
        raise CheckError("stock probe found a changed packaged server-VPN policy")
    status_present = exists(adb, f"{LOCATION_MODULE_DIR}/server-vpn-runtime-status.properties")
    if status_present:
        status = validate_server_vpn_status(wait_for_server_vpn_status(adb))
        if (
            status["system_server_pid"] == pairing["system_server_pid"]
            and status["system_server_start_ticks"] == pairing["system_server_start_ticks"]
            and status["boot_id"] == pairing["boot_id"]
        ):
            raise CheckError("disabled combined host published current server-VPN runtime state")
    maps = read_text(adb, f"/proc/{pairing['system_server_pid']}/maps")
    if f"{LOCATION_MODULE_DIR}/zygisk/" in maps or "libzygveil.so" in maps:
        raise CheckError("disabled combined host remains mapped in system_server")
    server_state = "absent"
    host_state = "combined_host_disabled"
    pairing["server_vpn_state"] = server_state
    report.kv("server_vpn_state", server_state)
    report.kv("server_vpn_hook_count", 0)
    report.kv("combined_host_state", host_state)
    report.kv("stale_status_present", str(status_present).lower())
    report.kv("location_state", "disabled")
    report.kv("location_hook_count", 0)
    return pairing


def probe_arguments(
    args: argparse.Namespace, *, variant: str, module_expected: bool
) -> argparse.Namespace:
    return argparse.Namespace(
        adb_serial=args.adb_serial,
        variant=variant,
        vpn_expected="on",
        module_expected="on" if module_expected else "off",
        group=args.group,
        run_id="",
        raw_gnss_mode="",
        observation_window_ms=20_000,
        location_oracle="",
        poc=True,
        reuse_process=False,
        poc_no_oracle=False,
        expected_spatial_mismatch=False,
    )


def require_server_vpn_group(group: str, *, concurrent: bool) -> tuple[str, str]:
    secondary = group.startswith("secondary-")
    detector_group = group.removeprefix("secondary-")
    allowed = (
        {
            "server-vpn-active",
            "server-vpn-async",
            "server-vpn-link",
        }
        if concurrent
        else SERVER_VPN_GROUPS
    )
    if detector_group not in allowed:
        kind = "callback-bearing " if concurrent else ""
        raise CheckError(f"server-VPN phase requires a {kind}universal-probe group")
    return detector_group, "secondary" if secondary else "main"


def write_probe_phase(
    *,
    kind: str,
    group: str,
    run_ids: dict[str, str],
    pairing: dict[str, str],
    server_state: str,
    hook_count: str,
    config_generation: str,
    target_set_sha256: str,
    report: Report,
) -> str:
    detector_group, process_role = require_server_vpn_group(group, concurrent=False)
    identifier = phase_id(kind)
    write_phase(
        {
            "schema_version": 1,
            "phase_id": identifier,
            "phase_kind": kind,
            "group": detector_group,
            "process_role": process_role,
            "run_ids": run_ids,
            "vpn_state": "on",
            "vpn_epoch_sha256": pairing["vpn_epoch_sha256"],
            "vpn_agent_unchanged": True,
            "boot_id_sha256": pairing["boot_id_sha256"],
            "system_server_pid": pairing["system_server_pid"],
            "system_server_start_ticks": pairing["system_server_start_ticks"],
            "server_vpn_state": server_state,
            "server_vpn_hook_count": hook_count,
            "config_generation": config_generation,
            "target_set_sha256": target_set_sha256,
        }
    )
    report.kv("phase_id", identifier)
    report.kv("phase_kind", kind)
    report.kv("group", detector_group)
    report.kv("process_role", process_role)
    report.kv("phase_manifest", "private_mode_0600")
    return identifier


def poc_stock_probe(report: Report, args: argparse.Namespace) -> None:
    require_server_vpn_group(args.group, concurrent=False)
    adb = select_root_adbd(report, args)
    before = inspect_server_vpn_stock(adb, report)
    run_id = run_probe(
        report,
        probe_arguments(args, variant="primary", module_expected=False),
    )
    after = inspect_server_vpn_stock(adb, report, stable=False)
    require_unchanged_pairing(before, after, report)
    if before["server_vpn_state"] != after["server_vpn_state"]:
        raise CheckError("server-VPN stock state changed during probe collection")
    write_probe_phase(
        kind="stock",
        group=args.group,
        run_ids={"primary": run_id},
        pairing=before,
        server_state=before["server_vpn_state"],
        hook_count="0",
        config_generation="0",
        target_set_sha256="0" * 64,
        report=report,
    )
    report.kv("artifact_class", "non_attestable_poc")
    report.kv("host_state_mutation", "none")


def poc_active_probe(report: Report, args: argparse.Namespace) -> None:
    detector_group, _process_role = require_server_vpn_group(args.group, concurrent=False)
    if detector_group != "server-vpn-diagnostics":
        require_server_vpn_group(args.group, concurrent=True)
    adb = select_root_adbd(report, args)
    status = inspect_server_vpn_poc(adb, report, expected="active")
    before = {
        "vpn_epoch_sha256": status["_vpn_epoch_sha256"],
        "system_server_pid": status["system_server_pid"],
        "system_server_start_ticks": status["system_server_start_ticks"],
        "boot_id": status["boot_id"],
        "boot_id_sha256": hashlib.sha256(status["boot_id"].encode("ascii")).hexdigest(),
    }
    if detector_group == "server-vpn-diagnostics":
        run_ids = {
            variant: run_probe(
                report,
                probe_arguments(args, variant=variant, module_expected=True),
            )
            for variant in ("primary", "canary")
        }
        report.kv("paired_collection", "permission_bounded_residual")
    else:
        run_ids = run_concurrent_server_vpn(
            report,
            argparse.Namespace(
                adb_serial=args.adb_serial,
                group=args.group,
                poc=True,
            ),
        )
        report.kv("paired_collection", "measured_overlap")
    after = current_pairing(adb, report, stable=False)
    require_unchanged_pairing(before, after, report)
    after_status = validate_server_vpn_status(wait_for_server_vpn_status(adb))
    for key in (
        "state",
        "hook_count",
        "catalog_hook_count",
        "config_generation",
        "target_set_sha256",
        "engine_owner",
        "system_server_pid",
        "system_server_start_ticks",
        "boot_id",
    ):
        if after_status[key] != status[key]:
            raise CheckError(f"server-VPN runtime changed during paired probe: {key}")
    location_health(adb, report)
    write_probe_phase(
        kind="active",
        group=args.group,
        run_ids=run_ids,
        pairing=before,
        server_state=status["state"],
        hook_count=status["hook_count"],
        config_generation=status["config_generation"],
        target_set_sha256=status["target_set_sha256"],
        report=report,
    )
    report.kv("artifact_class", "non_attestable_poc")
    report.kv("host_state_mutation", "none")


def phase_records(phase: dict[str, object], variant: str) -> list[dict[str, object]]:
    run_ids = cast(dict[str, object], phase["run_ids"])
    run_id = run_ids.get(variant)
    if not isinstance(run_id, str):
        raise CheckError(f"server-VPN phase lacks the {variant} probe run")
    metadata = load_run_state(run_id, poc=True)
    if (
        metadata.get("poc") is not True
        or metadata.get("variant") != variant
        or metadata.get("detector_group") != phase["group"]
    ):
        raise CheckError("server-VPN phase/run metadata mismatch")
    path = SERVER_VPN_PROBE_RUN_DIR / f"{run_id}.jsonl"
    if not path.is_file():
        raise CheckError("server-VPN phase JSONL is missing")
    records, _verdict = validate_jsonl(path.read_text(encoding="utf-8"), metadata)
    return records


def validate_phase_sequence(
    baseline: dict[str, object], active: dict[str, object], rollback: dict[str, object]
) -> None:
    if (
        baseline["phase_kind"] != "stock"
        or active["phase_kind"] != "active"
        or rollback["phase_kind"] != "stock"
        or active["server_vpn_state"] != "active"
        or active["server_vpn_hook_count"] != "14"
        or baseline["server_vpn_hook_count"] != "0"
        or rollback["server_vpn_hook_count"] != "0"
    ):
        raise CheckError("server-VPN differential phase state mismatch")
    if (
        len({baseline["group"], active["group"], rollback["group"]}) != 1
        or len({baseline["process_role"], active["process_role"], rollback["process_role"]}) != 1
    ):
        raise CheckError("server-VPN differential phase group/role mismatch")
    if (
        len(
            {
                baseline["boot_id_sha256"],
                active["boot_id_sha256"],
                rollback["boot_id_sha256"],
            }
        )
        != 3
    ):
        raise CheckError("server-VPN differential phases do not bind three rebooted boots")
    if (
        set(cast(dict[str, object], baseline["run_ids"])) != {"primary"}
        or set(cast(dict[str, object], rollback["run_ids"])) != {"primary"}
        or set(cast(dict[str, object], active["run_ids"])) != {"primary", "canary"}
    ):
        raise CheckError("server-VPN differential phase role inventory mismatch")


def poc_differential(report: Report, args: argparse.Namespace) -> None:
    identifiers = (args.baseline_phase, args.active_phase, args.rollback_phase)
    if any(not identifier for identifier in identifiers) or len(set(identifiers)) != 3:
        raise CheckError("three distinct server-VPN phase IDs are required")
    timestamps = tuple(phase_timestamp(identifier) for identifier in identifiers)
    if not timestamps[0] < timestamps[1] < timestamps[2]:
        raise CheckError("server-VPN phase IDs are not in baseline/active/rollback order")
    baseline = load_phase(args.baseline_phase)
    active = load_phase(args.active_phase)
    rollback = load_phase(args.rollback_phase)
    validate_phase_sequence(baseline, active, rollback)

    evaluate = (
        evaluate_diagnostics_residual
        if baseline["group"] == "server-vpn-diagnostics"
        else evaluate_differential
    )
    result = evaluate(
        phase_records(baseline, "primary"),
        phase_records(active, "primary"),
        phase_records(active, "canary"),
        phase_records(rollback, "primary"),
    )
    report.kv("baseline_phase", args.baseline_phase)
    report.kv("active_phase", args.active_phase)
    report.kv("rollback_phase", args.rollback_phase)
    for key, value in result.items():
        report.kv(key, value)
    report.kv("vpn_state", "on_in_each_rebooted_phase")
    report.kv("cross_boot_agent_equality", "not_required")
    report.kv("device_mutation", "none")


def poc_recover(report: Report, args: argparse.Namespace) -> None:
    adb = select_root_adbd(report, args)
    properties = parse_properties(read_text(adb, f"{LOCATION_MODULE_DIR}/module.prop"))
    if properties.get("id") != LOCATION_MODULE_ID or exists(
        adb, f"{LOCATION_MODULE_UPDATE_DIR}/module.prop"
    ):
        raise CheckError("combined-host POC recovery precondition is not satisfied")
    report.kv("vpn_precondition", "not_required_for_recovery")
    marker = f"{LOCATION_MODULE_DIR}/disable"
    if adb.shell("touch", marker, check=False).returncode != 0 or not exists(adb, marker):
        raise CheckError("combined-host POC recovery could not disable the module")
    if adb.run("reboot", timeout=30, check=False).returncode != 0:
        raise CheckError("combined-host recovery reboot failed")
    wait_for_boot(adb, report)
    stock = inspect_server_vpn_stock(
        adb,
        report,
        require_vpn=False,
        allow_incomplete_runtime=True,
    )
    if stock["server_vpn_state"] != "absent":
        raise CheckError("combined-host POC recovery did not reach disabled stock")
    report.kv("recovery_status", "PASS")
    report.kv("location_config", "preserved")
    report.kv("packaged_vpn_policy", "preserved")
    report.kv("device_mutation", "explicit module disable and one recovery reboot")


COMMANDS: dict[str, Callable[[Report, argparse.Namespace], None]] = {
    "poc-active-probe": poc_active_probe,
    "poc-differential": poc_differential,
    "poc-install": poc_install,
    "poc-recover": poc_recover,
    "poc-isolation": poc_isolation,
    "poc-reboot": poc_reboot,
    "poc-status": poc_status,
    "poc-stock-probe": poc_stock_probe,
}


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--adb-serial", default="")
    parser.add_argument("--expected", default="any")
    parser.add_argument("--group", default="server-vpn-async")
    parser.add_argument("--baseline-phase", default="")
    parser.add_argument("--active-phase", default="")
    parser.add_argument("--rollback-phase", default="")
    parser.add_argument("command", choices=sorted(COMMANDS))
    args = parser.parse_args()
    if args.expected not in {
        "any",
        "active",
        "disabled",
        "inactive",
    }:
        parser.error("unsupported expected POC state")
    return args


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
                        r"\$[A-Z]",
                    ]
                )
    except CheckError:
        return 1
    except Exception:
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
