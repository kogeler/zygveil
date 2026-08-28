# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Make-wrapped Zygisk location module device lifecycle."""

from __future__ import annotations

import argparse
import collections
import contextlib
import hashlib
import inspect
import math
import os
import re
import stat
import tempfile
import time
import traceback
import uuid
import zipfile
from collections.abc import Callable
from pathlib import Path

from adb import Adb, system_server_process_identity
from location_live_control import parse_status as parse_live_status
from reboot_intent import (
    begin_or_resume,
    clear_intent,
    intent_path,
    load_intent,
    serialized_transition,
)
from reporting import CheckError, Report

ROOT = Path(__file__).resolve().parents[2]
MODULE_ID = "zygveil"
MODULE_DIR = f"/data/adb/modules/{MODULE_ID}"
MODULE_UPDATE_DIR = f"/data/adb/modules_update/{MODULE_ID}"
POC_CANARY_PACKAGE = "dev.zygveil.probe.canary"
MODULE_ZIP = ROOT / "dist/zygveil.zip"
BUILD_REPORT = ROOT / ".artifacts/reports/location/build-location.txt"
POC_NATIVE = ROOT / ".artifacts/poc/location/libzygveil.so"
POC_HELPER = ROOT / ".artifacts/poc/location/locationctl"
SERVER_VPN_POC_HELPER = ROOT / ".artifacts/poc/server-vpn/combined-host/locationctl"
POC_BRIDGE = ROOT / ".artifacts/poc/location/bridge.dex"
POC_SHADOWHOOK_HELPER = ROOT / ".artifacts/poc/location/libshadowhook_nothing.so"
LOCATION_REBOOT_INTENT = intent_path("location-reboot")
LOCATION_RECOVERY_INTENT = intent_path("location-recover")
HELPER = f"{MODULE_DIR}/locationctl"
CONFIG_KEYS = (
    "schema_version",
    "enabled",
    "raw_gnss_mode",
    "center_latitude_deg",
    "center_longitude_deg",
    "altitude_ellipsoid_m",
    "altitude_msl_m",
    "horizontal_jitter_sigma_m",
    "horizontal_jitter_radius_m",
    "horizontal_correlation_time_s",
    "vertical_jitter_sigma_m",
    "accuracy_correlation_time_s",
    "speed_deadband_mps",
    "speed_max_mps",
    "bearing_min_speed_mps",
    "random_seed",
    "config_generation",
)
BOOT_INPUT_KEYS = tuple(key for key in CONFIG_KEYS if key not in {"enabled", "config_generation"})
MAX_CONFIG_GENERATION = 2**62 - 1
REBOOT_SOURCE_STATES = {
    "active": {"active", "pending_reboot_enabled", "staged_pending_reboot_enabled"},
    "waiting": {"waiting", "pending_reboot_enabled", "staged_pending_reboot_enabled"},
    "disabled": {
        "disabled",
        "pending_reboot_disabled",
        "staged_pending_reboot_disabled",
    },
    "absent": {"remove_pending"},
    "any": {
        "active",
        "waiting",
        "disabled",
        "pending_reboot_disabled",
        "pending_reboot_enabled",
        "staged_pending_reboot_enabled",
        "staged_pending_reboot_disabled",
    },
}
RUNTIME_KEYS = {
    "schema_version",
    "state",
    "reason",
    "raw_gnss_mode",
    "hook_count",
    "system_server_pid",
    "system_server_start_ticks",
    "config_generation",
    "boot_id",
    "control_fd",
    "control_owner_pid",
    "control_owner_start_ticks",
}
FLOAT_KEYS = {
    "center_latitude_deg",
    "center_longitude_deg",
    "altitude_ellipsoid_m",
    "altitude_msl_m",
    "horizontal_jitter_sigma_m",
    "horizontal_jitter_radius_m",
    "horizontal_correlation_time_s",
    "vertical_jitter_sigma_m",
    "accuracy_correlation_time_s",
    "speed_deadband_mps",
    "speed_max_mps",
    "bearing_min_speed_mps",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def current_boot_id_sha256(adb: Adb) -> str:
    boot_id = read_text(adb, "/proc/sys/kernel/random/boot_id").strip()
    if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id) is None:
        raise CheckError("current kernel boot identity is invalid")
    return hashlib.sha256(boot_id.encode("ascii")).hexdigest()


def report_values(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise CheckError(f"required report is missing: {path.relative_to(ROOT)}")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def require_artifact(report: Report) -> str:
    if not MODULE_ZIP.is_file():
        raise CheckError("location module artifact is missing; run make location-build")
    digest = sha256(MODULE_ZIP)
    build = report_values(BUILD_REPORT)
    if build.get("zip_sha256") != digest or build.get("deterministic_repeat") != "pass":
        raise CheckError("location module artifact/build report mismatch")
    with zipfile.ZipFile(MODULE_ZIP) as archive:
        if archive.testzip() is not None:
            raise CheckError("location module ZIP integrity check failed")
        required = {
            "module.prop",
            "config.properties",
            "libshadowhook_nothing.so",
            "live-control.properties",
            "locationctl",
            "server-vpn-config.properties",
            "zygisk/arm64-v8a.so",
        }
        if not required.issubset(archive.namelist()):
            raise CheckError("location module ZIP is incomplete")
        if b"enabled=false" not in archive.read("config.properties"):
            raise CheckError("location module ZIP does not contain the waiting location default")
        control_metadata = (
            b"schema_version=1\n"
            b"page_bytes=4096\n"
            b"page_name=zygveil-location-control\n"
            b"page_storage=sealed_memfd\n"
            b"page_mode=0777\n"
            b"page_seals=grow,shrink,seal\n"
            b"helper_name=locationctl\n"
            b"input_transport=stdin\n"
        )
        if archive.read("live-control.properties") != control_metadata:
            raise CheckError("location module live-control metadata mismatch")
        executable = {
            "customize.sh",
            "guard.sh",
            "locationctl",
            "post-fs-data.sh",
            "zygisk/arm64-v8a.so",
        }
        for info in archive.infolist():
            mode = (info.external_attr >> 16) & 0o7777
            expected_mode = (
                0o600
                if info.filename == "config.properties"
                else 0o755
                if info.filename in executable
                else 0o644
            )
            if mode != expected_mode:
                raise CheckError(f"location module ZIP mode mismatch: {info.filename}")
        if (
            build.get("control_page_schema") != "1"
            or build.get("control_page_bytes") != "4096"
            or build.get("control_page_name") != "zygveil-location-control"
            or build.get("control_page_storage") != "sealed_memfd"
            or build.get("control_page_mode") != "0777"
            or build.get("control_page_seals") != "grow,shrink,seal"
            or build.get("config_mode") != "0600"
            or build.get("locationctl_mode") != "0755"
            or re.fullmatch(r"[0-9a-f]{64}", build.get("locationctl_sha256", "")) is None
        ):
            raise CheckError("location module live-control build metadata mismatch")
    report.kv("artifact", MODULE_ZIP.relative_to(ROOT))
    report.kv("artifact_sha256", digest)
    return digest


def require_app_poc(report: Report) -> None:
    runtime_set = (POC_NATIVE, POC_HELPER, POC_BRIDGE, POC_SHADOWHOOK_HELPER)
    if any(not path.is_file() or path.stat().st_size == 0 for path in runtime_set):
        raise CheckError("location application POC is missing; run make location-poc-build")
    report.kv("poc_runtime_set", [path.relative_to(ROOT) for path in runtime_set])
    report.kv("poc_artifact_class", "non_attestable_poc")
    report.kv("poc_application_scope", "global_unfiltered")
    report.kv("poc_configuration_delivery", "shared_applied_generation")
    report.kv("poc_build_report_validation", "skipped")
    report.kv("poc_hash_attestation", "skipped")
    report.kv("poc_reproducibility", "skipped")


def device_file_matches(adb: Adb, remote: str, local: Path) -> bool:
    result = adb.shell("sha256sum", remote, timeout=60, check=False)
    fields = result.stdout.split()
    return result.returncode == 0 and len(fields) >= 1 and fields[0] == sha256(local)


def select_root_adbd(report: Report, args: argparse.Namespace) -> Adb:
    adb = Adb.select(args.adb_serial, report)
    identity = adb.shell("id", timeout=10, check=False)
    report.kv("root_escalation_attempted", "false")
    if identity.returncode != 0 or "uid=0" not in identity.stdout:
        raise CheckError("rooted adbd is required; run make adb-root (no su fallback is used)")
    report.kv("adbd_state", "root")
    return adb


def select_recovery_adbd(report: Report, args: argparse.Namespace) -> Adb:
    adb = Adb.select(args.adb_serial, report)
    identity = adb.shell("id", timeout=10, check=False)
    if identity.returncode == 0 and "uid=0" in identity.stdout:
        report.kv("adbd_state", "root")
        report.kv("root_escalation_attempted", "false")
        return adb
    report.kv("adbd_state_before_recovery_root", "shell_or_unknown")
    root = adb.run("root", timeout=30, check=False)
    report.kv("adb_root_exit", root.returncode)
    report.kv("root_escalation_attempted", "adb root")
    if root.returncode != 0 or adb.run("wait-for-device", timeout=60, check=False).returncode != 0:
        raise CheckError("recovery could not restart rooted-debugging adbd")
    identity = adb.shell("id", timeout=10, check=False)
    if identity.returncode != 0 or "uid=0" not in identity.stdout:
        raise CheckError("recovery adbd is not uid 0 (no su fallback is used)")
    report.kv("adbd_state", "root")
    return adb


def exists(adb: Adb, path: str) -> bool:
    return adb.shell("test", "-e", path, check=False).returncode == 0


def module_payload_present(adb: Adb, directory: str) -> bool:
    return exists(adb, f"{directory}/module.prop")


def read_text(adb: Adb, path: str, *, required: bool = True) -> str:
    result = adb.shell("cat", path, timeout=30, check=False)
    if result.returncode != 0:
        if required:
            raise CheckError(f"device file is unavailable: {path}")
        return ""
    return result.stdout


def parse_properties(text: str, *, exact_config: bool = False) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise CheckError(f"property line {line_number} has no equals sign")
        key, value = (part.strip() for part in line.split("=", 1))
        if not key or not value or key in values:
            raise CheckError(f"invalid or duplicate property at line {line_number}")
        values[key] = value
    if exact_config and set(values) != set(CONFIG_KEYS):
        raise CheckError(
            "location config key mismatch: "
            f"missing={sorted(set(CONFIG_KEYS) - set(values))}, "
            f"unexpected={sorted(set(values) - set(CONFIG_KEYS))}"
        )
    return values


def validate_config(values: dict[str, str]) -> None:
    if set(values) != set(CONFIG_KEYS) or values["schema_version"] != "1":
        raise CheckError("location config schema/key set mismatch")
    if values["enabled"] not in {"true", "false"}:
        raise CheckError("location config enabled value is invalid")
    if values["raw_gnss_mode"] not in {"blocked", "passthrough"}:
        raise CheckError("only blocked or diagnostic passthrough Raw GNSS mode is supported")
    parsed: dict[str, float] = {}
    for key in FLOAT_KEYS:
        try:
            parsed[key] = float(values[key])
        except ValueError as error:
            raise CheckError(f"location config value is not numeric: {key}") from error
        if not math.isfinite(parsed[key]):
            raise CheckError(f"location config value is not finite: {key}")
    if not -90.0 <= parsed["center_latitude_deg"] <= 90.0:
        raise CheckError("location latitude is outside [-90, 90]")
    if not -180.0 <= parsed["center_longitude_deg"] <= 180.0:
        raise CheckError("location longitude is outside [-180, 180]")
    for key in {"altitude_ellipsoid_m", "altitude_msl_m"}:
        if not -12_000.0 <= parsed[key] <= 100_000.0:
            raise CheckError(f"location altitude is outside its supported range: {key}")
    for key in {
        "horizontal_jitter_sigma_m",
        "horizontal_jitter_radius_m",
        "vertical_jitter_sigma_m",
        "speed_deadband_mps",
        "speed_max_mps",
        "bearing_min_speed_mps",
    }:
        if parsed[key] < 0:
            raise CheckError(f"location config value must be non-negative: {key}")
    for key in {
        "horizontal_jitter_sigma_m",
        "horizontal_jitter_radius_m",
        "vertical_jitter_sigma_m",
    }:
        if parsed[key] > 10_000.0:
            raise CheckError(f"location jitter value exceeds supported maximum: {key}")
    for key in {"horizontal_correlation_time_s", "accuracy_correlation_time_s"}:
        if not 0 < parsed[key] <= 86_400.0:
            raise CheckError(f"location correlation time is outside its supported range: {key}")
    for key in {"speed_deadband_mps", "speed_max_mps", "bearing_min_speed_mps"}:
        if parsed[key] > 1_000.0:
            raise CheckError(f"location speed value exceeds supported maximum: {key}")
    if not (
        parsed["speed_deadband_mps"] <= parsed["bearing_min_speed_mps"] <= parsed["speed_max_mps"]
    ):
        raise CheckError("location speed thresholds are not ordered")
    try:
        seed = int(values["random_seed"])
        generation = int(values["config_generation"])
    except ValueError as error:
        raise CheckError("location seed/generation is not an integer") from error
    if seed < 0 or seed > 2**64 - 1 or generation < 1 or generation > MAX_CONFIG_GENERATION:
        raise CheckError("location seed/generation is outside its supported range")


def validate_boot_input(values: dict[str, str]) -> None:
    if set(values) != set(BOOT_INPUT_KEYS):
        raise CheckError(
            "location boot input key mismatch: "
            f"missing={sorted(set(BOOT_INPUT_KEYS) - set(values))}, "
            f"unexpected={sorted(set(values) - set(BOOT_INPUT_KEYS))}"
        )
    candidate = dict(values)
    candidate["enabled"] = "true"
    candidate["config_generation"] = "1"
    validate_config(candidate)


def resolve_boot_config(
    requested: dict[str, str], current: dict[str, str]
) -> tuple[dict[str, str], bool]:
    validate_boot_input(requested)
    validate_config(current)
    if all(current[key] == requested[key] for key in BOOT_INPUT_KEYS):
        return dict(current), False
    generation = int(current["config_generation"])
    if generation >= MAX_CONFIG_GENERATION:
        raise CheckError("installed config generation is exhausted")
    candidate = dict(requested)
    candidate["enabled"] = current["enabled"]
    candidate["config_generation"] = str(generation + 1)
    validate_config(candidate)
    return candidate, True


def validate_runtime_status(values: dict[str, str]) -> None:
    if set(values) != RUNTIME_KEYS or values.get("schema_version") != "4":
        raise CheckError("location runtime status schema/key set mismatch")
    if values["state"] not in {"ready", "arming", "inactive"}:
        raise CheckError("location runtime state is invalid")
    if values["raw_gnss_mode"] not in {"blocked", "passthrough", "unknown"}:
        raise CheckError("location runtime Raw GNSS mode is invalid")
    reason = values["reason"]
    forbidden_reason_tokens = {
        "=",
        "center_latitude_deg",
        "center_longitude_deg",
        "altitude_ellipsoid_m",
        "altitude_msl_m",
        "$",
    }
    if (
        not 1 <= len(reason) <= 256
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in reason)
        or any(token in reason for token in forbidden_reason_tokens)
    ):
        raise CheckError("location runtime reason is not bounded coordinate-free ASCII")
    for key in (
        "hook_count",
        "system_server_pid",
        "system_server_start_ticks",
        "config_generation",
        "control_fd",
        "control_owner_pid",
        "control_owner_start_ticks",
    ):
        if not values[key].isdigit():
            raise CheckError(f"location runtime integer is invalid: {key}")
    if (
        int(values["hook_count"]) > 2**32 - 1
        or int(values["system_server_pid"]) > 2**32 - 1
        or int(values["system_server_start_ticks"]) > 2**64 - 1
        or int(values["config_generation"]) > 2**62 - 1
        or int(values["control_fd"]) > 2**31 - 1
        or int(values["control_owner_pid"]) > 2**32 - 1
        or int(values["control_owner_start_ticks"]) > 2**64 - 1
    ):
        raise CheckError("location runtime integer exceeds its wire range")
    if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", values["boot_id"]) is None:
        raise CheckError("location runtime boot identity is invalid")
    ready = values["state"] == "ready"
    if ready and (
        int(values["system_server_pid"]) == 0
        or int(values["system_server_start_ticks"]) == 0
        or (
            values["hook_count"] != "5"
            or int(values["config_generation"]) == 0
            or int(values["control_fd"]) < 3
            or int(values["control_owner_pid"]) == 0
            or int(values["control_owner_start_ticks"]) == 0
            or values["raw_gnss_mode"] == "unknown"
        )
    ):
        raise CheckError("location ready runtime identity is invalid")
    if (int(values["system_server_pid"]) == 0) != (int(values["system_server_start_ticks"]) == 0):
        raise CheckError("location runtime process identity is inconsistent")
    if (int(values["control_owner_pid"]) == 0) != (int(values["control_owner_start_ticks"]) == 0):
        raise CheckError("location runtime control-owner identity is inconsistent")
    if not ready and (
        values["hook_count"] != "0"
        or values["control_fd"] != "0"
        or values["control_owner_pid"] != "0"
        or values["control_owner_start_ticks"] != "0"
    ):
        raise CheckError("location inactive runtime control identity is invalid")


def render_config(values: dict[str, str]) -> str:
    validate_config(values)
    return "".join(f"{key}={values[key]}\n" for key in CONFIG_KEYS)


def read_private_config(path_text: str) -> dict[str, str]:
    path = Path(path_text)
    if not path.is_absolute():
        path = ROOT / path
    state_root = (ROOT / ".state").resolve()
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise CheckError("private boot configuration is unavailable") from None
    if not resolved.is_relative_to(state_root) or path.is_symlink():
        raise CheckError("boot configuration must be a regular file below ignored .state")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        raise CheckError("private boot configuration could not be opened safely") from None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > 32 * 1024
        ):
            raise CheckError("boot configuration owner/mode/type/size is invalid")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 4096))
            if not block:
                raise CheckError("boot configuration changed while being read")
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise CheckError("boot configuration changed while being read")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise CheckError("boot configuration changed while being read")
    finally:
        os.close(descriptor)
    try:
        text = b"".join(chunks).decode("ascii")
    except UnicodeDecodeError:
        raise CheckError("boot configuration must contain only ASCII") from None
    values = parse_properties(text)
    validate_boot_input(values)
    return values


def write_module_text(adb: Adb, name: str, content: str) -> None:
    if name != "config.properties":
        raise CheckError("unsupported private module write")
    script = (
        "set -eu; umask 077; "
        f"directory={MODULE_DIR}; "
        'temporary="$(mktemp "$directory/.config.properties.tmp.XXXXXX")"; '
        "trap 'rm -f \"$temporary\"' EXIT; "
        'cat > "$temporary"; chown 0:0 "$temporary"; chmod 0600 "$temporary"; '
        'sync "$temporary"; mv -f "$temporary" "$directory/config.properties"; sync; '
        "trap - EXIT"
    )
    result = adb.shell_input(
        "/system/bin/sh", "-c", script, input_text=content, timeout=60, check=False
    )
    if result.returncode != 0:
        raise CheckError("atomic private location configuration write failed")
    identity = adb.shell(
        "stat", "-c", "%F:%a:%u:%g:%h", f"{MODULE_DIR}/config.properties", check=False
    )
    if identity.returncode != 0 or identity.stdout.strip() != "regular file:600:0:0:1":
        raise CheckError("installed location configuration identity is invalid")


def system_server_identity(adb: Adb) -> tuple[str, str, bool]:
    pid, start_ticks = system_server_process_identity(adb)
    maps = adb.shell("cat", f"/proc/{pid}/maps", timeout=30, check=False)
    if maps.returncode != 0:
        raise CheckError("system_server maps are unavailable to rooted adbd")
    if system_server_process_identity(adb) != (pid, start_ticks):
        raise CheckError("system_server identity changed during inspection")
    location_tokens = (
        "libzygveil.so",
        "/zygveil/zygisk/arm64-v8a.so",
    )
    return pid, start_ticks, any(token in maps.stdout for token in location_tokens)


def live_status_matches_runtime(
    config: dict[str, str],
    runtime: dict[str, str],
    helper_status: dict[str, str],
    pid: str,
    boot_id: str,
) -> bool:
    expected_state = "active" if config.get("enabled") == "true" else "waiting"
    return (
        helper_status.get("module_state") == expected_state
        and helper_status.get("runtime_state") == expected_state
        and helper_status.get("raw_gnss_mode") == config.get("raw_gnss_mode")
        and helper_status.get("boot_config_generation") == runtime.get("config_generation")
        and helper_status.get("persisted_generation") == config.get("config_generation")
        and helper_status.get("system_server_pid") == pid
        and helper_status.get("system_server_start_ticks")
        == runtime.get("system_server_start_ticks")
        and helper_status.get("boot_id") == boot_id
    )


def process_start_ticks(adb: Adb, pid: str) -> str:
    result = adb.shell("cat", f"/proc/{pid}/stat", timeout=10, check=False)
    body = result.stdout.strip()
    command_end = body.rfind(")")
    fields = body[command_end + 2 :].split() if command_end >= 0 else []
    if result.returncode != 0 or len(fields) < 20 or not fields[19].isdigit():
        return "unavailable"
    return fields[19]


def inspect_live_control(
    adb: Adb,
    report: Report,
    config: dict[str, str],
    runtime: dict[str, str],
    pid: str,
    boot_id: str,
    expected_helper_digests: set[str] | None = None,
) -> tuple[bool, dict[str, str], str]:
    helper_status: dict[str, str] = {}
    error = ""
    module_stat = adb.shell("stat", "-c", "%F:%a:%u:%g", MODULE_DIR, check=False)
    module_directory_identity = (
        module_stat.returncode == 0 and module_stat.stdout.strip() == "directory:755:0:0"
    )
    helper_stat = adb.shell("stat", "-c", "%F:%a:%u:%g:%h", HELPER, check=False)
    helper_identity = helper_stat.returncode == 0 and helper_stat.stdout.strip() == (
        "regular file:755:0:0:1"
    )
    control_fd = runtime.get("control_fd", "0")
    control_owner_pid = runtime.get("control_owner_pid", "0")
    control_owner_start_ticks = runtime.get("control_owner_start_ticks", "0")
    owner_identity = (
        control_owner_pid.isdigit()
        and int(control_owner_pid) > 0
        and process_start_ticks(adb, control_owner_pid) == control_owner_start_ticks
    )
    proc_path = f"/proc/{control_owner_pid}/fd/{control_fd}"
    memfd_target = adb.shell("readlink", proc_path, check=False)
    memfd_stat = adb.shell("stat", "-L", "-c", "%F:%a:%u:%g:%h:%s", proc_path, check=False)
    fdinfo = adb.shell("cat", f"/proc/{control_owner_pid}/fdinfo/{control_fd}", check=False)
    flags_match = re.search(r"(?m)^flags:\s*([0-7]+)$", fdinfo.stdout)
    descriptor_flags = int(flags_match.group(1), 8) if flags_match is not None else 0
    memfd_identity = (
        memfd_target.returncode == 0
        and memfd_target.stdout.strip() == "/memfd:zygveil-location-control (deleted)"
        and memfd_stat.returncode == 0
        and memfd_stat.stdout.strip() == "regular file:777:0:0:0:4096"
        and fdinfo.returncode == 0
        and flags_match is not None
        and descriptor_flags & os.O_ACCMODE == os.O_RDWR
        and descriptor_flags & os.O_CLOEXEC != 0
    )
    build = report_values(BUILD_REPORT)
    expected_helpers = expected_helper_digests or {build.get("locationctl_sha256", "")}
    helper_digest = adb.shell("sha256sum", HELPER, timeout=60, check=False)
    fields = helper_digest.stdout.split()
    helper_hash_matches = (
        helper_digest.returncode == 0
        and len(fields) == 2
        and all(re.fullmatch(r"[0-9a-f]{64}", value) is not None for value in expected_helpers)
        and fields[0] in expected_helpers
    )
    if not module_directory_identity:
        error = "module_directory_identity_mismatch"
    elif not helper_identity:
        error = "helper_identity_mismatch"
    elif not helper_hash_matches:
        error = "helper_hash_mismatch"
    else:
        status_result = adb.shell(HELPER, "status", timeout=15, check=False)
        if status_result.returncode == 0:
            try:
                helper_status = parse_live_status(status_result.stdout)
            except CheckError:
                error = "invalid_status"
        else:
            error = "status_unavailable"
    control_attested = (
        not error
        and module_directory_identity
        and helper_identity
        and helper_hash_matches
        and owner_identity
        and memfd_identity
        and live_status_matches_runtime(config, runtime, helper_status, pid, boot_id)
    )
    report.kv("live_module_directory_identity", str(module_directory_identity).lower())
    report.kv("live_helper_identity", str(helper_identity).lower())
    report.kv("live_helper_hash_match", str(helper_hash_matches).lower())
    report.kv("live_control_owner_identity", str(owner_identity).lower())
    report.kv("live_control_memfd_identity", str(memfd_identity).lower())
    report.kv("live_control_status_valid", str(not error).lower())
    report.kv("live_control_attested", str(control_attested).lower())
    if error:
        report.kv("live_control_error", error)
    for key in (
        "module_state",
        "runtime_state",
        "control_state",
        "reason",
        "boot_config_generation",
        "persisted_generation",
        "published_generation",
        "applied_generation",
    ):
        if key in helper_status:
            report.kv(f"live.{key}", helper_status[key])
    return control_attested, helper_status, error


def inspect_module(adb: Adb, report: Report, *, poc: bool = False) -> dict[str, object]:
    live_installed = module_payload_present(adb, MODULE_DIR)
    staged_installed = module_payload_present(adb, MODULE_UPDATE_DIR)
    installed = live_installed or staged_installed
    report.kv("module_installed", str(installed).lower())
    report.kv("module_live_installed", str(live_installed).lower())
    report.kv("module_update_staged", str(staged_installed).lower())
    pid, current_start_ticks, native_mapped = system_server_identity(adb)
    report.kv("system_server_pid", pid)
    report.kv("system_server_start_ticks", current_start_ticks)
    boot_id_digest = current_boot_id_sha256(adb)
    report.kv("boot_id_sha256", boot_id_digest)
    executable = adb.shell("readlink", f"/proc/{pid}/exe", check=False)
    report.kv(
        "system_server_executable",
        executable.stdout.strip() if executable.returncode == 0 else "unavailable",
    )
    report.kv("zygote_mode", adb.getprop("ro.zygote"))
    denylist_status = adb.shell("magisk", "--denylist", "status", check=False)
    denylist_query = adb.shell(
        "magisk",
        "--sqlite",
        "\"SELECT COUNT(*) AS count FROM denylist WHERE process='system_server';\"",
        check=False,
    )
    denylist_match = re.search(r"count=(\d+)", denylist_query.stdout)
    report.kv("denylist_status_exit", denylist_status.returncode)
    report.kv("denylist_status", denylist_status.stdout.strip() or "no-output")
    report.kv("system_server_denylist_query_exit", denylist_query.returncode)
    report.kv(
        "system_server_denylist_entries",
        denylist_match.group(1) if denylist_match is not None else "unavailable",
    )
    for name, path in {
        "module_dir": MODULE_DIR,
        "config": f"{MODULE_DIR}/config.properties",
        "guard": f"{MODULE_DIR}/.guard",
        "bridge": f"{MODULE_DIR}/bridge.dex",
        "native": f"{MODULE_DIR}/zygisk/arm64-v8a.so",
        "application_control": f"{MODULE_DIR}/.app-control",
    }.items():
        context = adb.shell("ls", "-Zd", path, check=False)
        report.kv(
            f"selinux_context.{name}",
            context.stdout.strip() if context.returncode == 0 else "unavailable",
        )
    application_control_identity = adb.shell(
        "stat", "-c", "%F:%a:%u:%g:%h:%s", f"{MODULE_DIR}/.app-control", check=False
    )
    report.kv(
        "application_control_identity",
        application_control_identity.stdout.strip()
        if application_control_identity.returncode == 0
        else "absent",
    )
    report.kv("native_library_mapped", str(native_mapped).lower())
    if not installed:
        state: dict[str, object] = {
            "state": "absent",
            "installed": False,
            "native_mapped": native_mapped,
            "pid": pid,
            "system_server_start_ticks": current_start_ticks,
            "boot_id_sha256": boot_id_digest,
        }
        report.kv("state", state["state"])
        return state

    module_dir = MODULE_UPDATE_DIR if staged_installed else MODULE_DIR
    module_properties = parse_properties(
        read_text(adb, f"{module_dir}/module.prop", required=False)
    )
    disabled = exists(adb, f"{module_dir}/disable")
    remove_pending = exists(adb, f"{module_dir}/remove")
    config_text = read_text(adb, f"{module_dir}/config.properties", required=False)
    config_error = ""
    config: dict[str, str] = {}
    try:
        config = parse_properties(config_text, exact_config=True)
        validate_config(config)
    except CheckError as error:
        config_error = str(error)
    runtime: dict[str, str] = {}
    runtime_error = ""
    try:
        runtime = parse_properties(
            read_text(adb, f"{module_dir}/runtime-status.properties", required=False)
        )
        validate_runtime_status(runtime)
    except CheckError as error:
        runtime_error = str(error)
    guard = parse_properties(
        read_text(adb, f"{module_dir}/guard-status.properties", required=False)
    )
    current_boot_id = read_text(adb, "/proc/sys/kernel/random/boot_id").strip()
    runtime_attested = (
        not runtime_error
        and not config_error
        and runtime.get("system_server_pid") == pid
        and runtime.get("system_server_start_ticks") == current_start_ticks
        and runtime.get("boot_id") == current_boot_id
        and runtime.get("config_generation", "").isdigit()
        and int(runtime["config_generation"]) > 0
        and runtime.get("control_fd", "").isdigit()
        and runtime.get("control_owner_pid", "").isdigit()
        and int(runtime.get("control_owner_pid", "0")) > 0
        and runtime.get("control_owner_start_ticks", "").isdigit()
        and int(runtime.get("control_owner_start_ticks", "0")) > 0
        and process_start_ticks(adb, runtime.get("control_owner_pid", "0"))
        == runtime.get("control_owner_start_ticks")
    )
    runtime_ready = (
        runtime_attested
        and guard.get("state") == "valid"
        and runtime.get("state") == "ready"
        and runtime.get("hook_count") == "5"
        and int(runtime.get("control_fd", "0")) >= 3
        and runtime.get("raw_gnss_mode") == config.get("raw_gnss_mode")
    )
    live_control_attested = False
    live_status: dict[str, str] = {}
    live_control_error = ""
    if live_installed and not staged_installed and runtime_ready:
        poc_helper_digests = {
            sha256(path) for path in (POC_HELPER, SERVER_VPN_POC_HELPER) if path.is_file()
        }
        live_control_attested, live_status, live_control_error = inspect_live_control(
            adb,
            report,
            config,
            runtime,
            pid,
            current_boot_id,
            poc_helper_digests if poc or module_properties.get("name") == "ZygVeil POC" else None,
        )

    if staged_installed:
        if disabled and not config_error and guard.get("state") == "valid":
            state_name = "staged_pending_reboot_disabled"
        elif not config_error and guard.get("state") == "valid":
            state_name = "staged_pending_reboot_enabled"
        else:
            state_name = "invalid_staged_payload"
    elif remove_pending:
        state_name = "remove_pending"
    elif disabled and (runtime_attested or native_mapped):
        state_name = "pending_reboot_disabled"
    elif disabled:
        state_name = "disabled"
    elif config_error:
        state_name = "invalid_config"
    elif runtime_ready and live_control_attested and config.get("enabled") == "false":
        state_name = "waiting"
    elif runtime_ready and live_control_attested:
        state_name = "active"
    elif runtime_ready:
        state_name = "active_control_failure"
    elif runtime_attested and runtime.get("state") in {"ready", "inactive"}:
        state_name = "inactive_failure"
    else:
        state_name = "pending_reboot_enabled"

    report.kv("state", state_name)
    report.kv("disable_marker", str(disabled).lower())
    report.kv("remove_marker", str(remove_pending).lower())
    report.kv(
        "zygisk_unloaded_marker",
        str(exists(adb, f"{module_dir}/zygisk/unloaded")).lower(),
    )
    report.kv("runtime_prerequisites_valid", str(guard.get("state") == "valid").lower())
    report.kv("config_valid", str(not config_error).lower())
    if config_error:
        report.kv("config_error", config_error)
    else:
        report.kv("config_enabled", config["enabled"])
        report.kv("raw_gnss_mode", config["raw_gnss_mode"])
        report.kv("config_generation", config["config_generation"])
        report.kv("coordinates", "redacted")
    report.kv("runtime_status_valid", str(not runtime_error).lower())
    if runtime_error:
        report.kv("runtime_status_error", runtime_error)
    report.kv("runtime_current_boot_attested", str(runtime_attested).lower())
    for key in [
        "state",
        "reason",
        "raw_gnss_mode",
        "hook_count",
        "system_server_pid",
        "system_server_start_ticks",
        "config_generation",
    ]:
        if key in runtime:
            report.kv(f"runtime.{key}", runtime[key])
    if "boot_id" in runtime:
        report.kv("runtime.boot_id_match", str(runtime["boot_id"] == current_boot_id).lower())
    for key in ["state", "mismatches"]:
        if key in guard:
            report.kv(f"guard.{key}", guard[key])
    return {
        "state": state_name,
        "installed": installed,
        "disabled": disabled,
        "native_mapped": native_mapped,
        "runtime_attested": runtime_attested,
        "live_control_attested": live_control_attested,
        "live_control_error": live_control_error,
        "live_status": live_status,
        "config": config,
        "config_error": config_error,
        "runtime": runtime,
        "guard": guard,
        "pid": pid,
        "system_server_start_ticks": current_start_ticks,
        "boot_id_sha256": boot_id_digest,
        "module_dir": module_dir,
        "live_installed": live_installed,
        "staged_installed": staged_installed,
    }


def status(report: Report, args: argparse.Namespace) -> None:
    adb = select_root_adbd(report, args)
    state = inspect_module(adb, report)
    if args.expected_state != "any" and state["state"] != args.expected_state:
        raise CheckError(
            f"location module state mismatch: expected {args.expected_state}, got {state['state']}"
        )
    report.kv("device_mutation", "none")


def install_module(report: Report, args: argparse.Namespace, *, update: bool) -> None:
    require_artifact(report)
    adb = select_root_adbd(report, args)
    live_installed = module_payload_present(adb, MODULE_DIR)
    staged_installed = module_payload_present(adb, MODULE_UPDATE_DIR)
    if update and not live_installed:
        raise CheckError("location module is not installed; use make location-install")
    if update and staged_installed:
        raise CheckError("a location module update is already staged; reboot or recover first")
    if not update and live_installed and not staged_installed:
        raise CheckError("location module already exists; use make location-update")
    preserved_config: dict[str, str] | None = None
    if update:
        current = inspect_module(adb, report)
        if current["state"] not in {"waiting", "active"} or not current.get("runtime_attested"):
            raise CheckError("location update requires a healthy ready module")
        current_config = current.get("config")
        if not isinstance(current_config, dict):
            raise CheckError("location update cannot read the configuration to preserve")
        preserved_config = dict(current_config)

    resumed = not update and staged_installed
    if not resumed:
        remote = f"/data/local/tmp/{MODULE_ID}-{uuid.uuid4().hex[:12]}.zip"
        push = adb.run("push", str(MODULE_ZIP), remote, timeout=120, check=False)
        if push.returncode != 0:
            raise CheckError("could not push location module ZIP")
        try:
            result = adb.shell("magisk", "--install-module", remote, timeout=180, check=False)
            report.kv("magisk_install_exit", result.returncode)
            if result.returncode != 0:
                raise CheckError("Magisk rejected the location module ZIP")
        finally:
            adb.shell("rm", "-f", remote, check=False)
    install_dir = (
        MODULE_UPDATE_DIR if module_payload_present(adb, MODULE_UPDATE_DIR) else MODULE_DIR
    )
    if not module_payload_present(adb, install_dir):
        raise CheckError("Magisk did not publish a live or staged location module payload")
    if exists(adb, f"{install_dir}/disable"):
        raise CheckError("location module install unexpectedly created a disable marker")
    config = parse_properties(read_text(adb, f"{install_dir}/config.properties"), exact_config=True)
    validate_config(config)
    if not update and config["enabled"] != "false":
        raise CheckError("fresh location module does not contain the waiting default")
    if preserved_config is not None and config != preserved_config:
        raise CheckError("location update changed the persistent activation or coordinates")
    guard = parse_properties(read_text(adb, f"{install_dir}/guard-status.properties"))
    if guard.get("state") != "valid":
        mismatches = guard.get("mismatches", "unknown")
        raise CheckError(f"installed runtime prerequisites failed: {mismatches}")
    report.kv("install_mode", "update" if update else "resume" if resumed else "new")
    report.kv("magisk_staging", str(install_dir == MODULE_UPDATE_DIR).lower())
    report.kv("post_install_state", "pending_reboot_enabled")
    report.kv("reboot_required", "true")
    report.kv("device_mutation", "Magisk module staging with production enable state")


def install(report: Report, args: argparse.Namespace) -> None:
    install_module(report, args, update=False)


def update(report: Report, args: argparse.Namespace) -> None:
    install_module(report, args, update=True)


def stage_app_poc(report: Report, args: argparse.Namespace) -> None:
    require_app_poc(report)
    adb = select_root_adbd(report, args)
    properties = parse_properties(read_text(adb, f"{MODULE_DIR}/module.prop"))
    if properties.get("id") != MODULE_ID:
        raise CheckError("location-poc-stage refused an unexpected module identity")
    config = parse_properties(read_text(adb, f"{MODULE_DIR}/config.properties"), exact_config=True)
    validate_config(config)
    if config.get("enabled") != "true":
        raise CheckError("location-poc-stage requires the live module configuration to be enabled")
    if exists(adb, f"{MODULE_UPDATE_DIR}/module.prop"):
        raise CheckError("location-poc-stage refused a pending Magisk module update")

    nonce = uuid.uuid4().hex[:12]
    remote = f"/data/local/tmp/{MODULE_ID}-app-poc-{nonce}.so"
    helper_remote = f"/data/local/tmp/{MODULE_ID}-app-poc-{nonce}.ctl"
    bridge_remote = f"/data/local/tmp/{MODULE_ID}-app-poc-{nonce}.dex"
    linker_helper_remote = f"/data/local/tmp/{MODULE_ID}-app-poc-{nonce}.linker.so"
    push = adb.run("push", str(POC_NATIVE), remote, timeout=120, check=False)
    helper_push = adb.run("push", str(POC_HELPER), helper_remote, timeout=120, check=False)
    bridge_push = adb.run("push", str(POC_BRIDGE), bridge_remote, timeout=120, check=False)
    linker_helper_push = adb.run(
        "push", str(POC_SHADOWHOOK_HELPER), linker_helper_remote, timeout=120, check=False
    )
    remotes = (remote, helper_remote, bridge_remote, linker_helper_remote)
    if any(
        result.returncode != 0 for result in (push, helper_push, bridge_push, linker_helper_push)
    ):
        adb.shell("rm", "-f", *remotes, check=False)
        raise CheckError("location application POC runtime-set upload failed")
    script = (
        "set -eu; "
        f"directory={MODULE_DIR}/zygisk; source={remote}; helper_source={helper_remote}; "
        f"bridge_source={bridge_remote}; linker_source={linker_helper_remote}; "
        f"helper_directory={MODULE_DIR}; "
        'temporary="$directory/.arm64-v8a.so.app-poc.tmp"; '
        'helper_temporary="$helper_directory/.locationctl.app-poc.tmp"; '
        'bridge_temporary="$helper_directory/.bridge.dex.app-poc.tmp"; '
        'linker_temporary="$helper_directory/.libshadowhook_nothing.so.app-poc.tmp"; '
        'trap \'rm -f "$temporary" "$helper_temporary" "$bridge_temporary" '
        '"$linker_temporary" "$source" "$helper_source" "$bridge_source" '
        '"$linker_source"\' EXIT; '
        f"test -f {MODULE_DIR}/module.prop; test -f {MODULE_DIR}/config.properties; "
        'test -s "$source"; test -s "$helper_source"; test -s "$bridge_source"; '
        'test -s "$linker_source"; '
        'cp "$source" "$temporary"; chown 0:0 "$temporary"; chmod 0755 "$temporary"; '
        'cp "$helper_source" "$helper_temporary"; chown 0:0 "$helper_temporary"; '
        'chmod 0755 "$helper_temporary"; '
        'cp "$bridge_source" "$bridge_temporary"; chown 0:0 "$bridge_temporary"; '
        'chmod 0644 "$bridge_temporary"; '
        'cp "$linker_source" "$linker_temporary"; chown 0:0 "$linker_temporary"; '
        'chmod 0644 "$linker_temporary"; '
        'sync "$temporary"; mv -f "$temporary" "$directory/arm64-v8a.so"; '
        'sync "$helper_temporary"; mv -f "$helper_temporary" "$helper_directory/locationctl"; '
        'sync "$bridge_temporary"; mv -f "$bridge_temporary" "$helper_directory/bridge.dex"; '
        'sync "$linker_temporary"; '
        'mv -f "$linker_temporary" "$helper_directory/libshadowhook_nothing.so"; '
        'sync "$directory"; sync "$helper_directory"; '
        'test -x "$directory/arm64-v8a.so"; test -x "$helper_directory/locationctl"; '
        'test -r "$helper_directory/bridge.dex"; '
        'test -r "$helper_directory/libshadowhook_nothing.so"; '
        'rm -f "$source" "$helper_source" "$bridge_source" "$linker_source"; trap - EXIT'
    )
    try:
        replace = adb.shell("/system/bin/sh", "-c", script, timeout=120, check=False)
        if replace.returncode != 0:
            raise CheckError("location application POC runtime-set staging failed")
    finally:
        adb.shell("rm", "-f", *remotes, check=False)

    report.kv("poc_fast_path", "true")
    report.kv("artifact_hash_comparison", "skipped")
    report.kv("runtime_attestation", "skipped")
    report.kv("active_application_control", "preserved_until_reboot")
    report.kv("reboot_required", "true")
    report.kv("device_mutation", "bounded POC runtime-set replacement")


def uninstall(report: Report, args: argparse.Namespace) -> None:
    adb = select_root_adbd(report, args)
    current = inspect_module(adb, report)
    if current.get("state") == "remove_pending":
        if (
            not current.get("live_installed")
            or current.get("staged_installed")
            or current.get("native_mapped")
            or current.get("runtime_attested")
        ):
            raise CheckError("resumable location-uninstall state is inconsistent")
        properties = parse_properties(read_text(adb, f"{MODULE_DIR}/module.prop"))
        if properties.get("id") != MODULE_ID:
            raise CheckError("location-uninstall refused an unexpected module identity")
        report.kv("state", "remove_pending")
        report.kv("reboot_required", "true")
        report.kv("uninstall_resume", "semantic_noop")
        report.kv("device_mutation", "none")
        return
    if (
        current.get("state") != "disabled"
        or current.get("runtime_attested")
        or not current.get("live_installed")
        or current.get("staged_installed")
    ):
        raise CheckError("location-uninstall requires one fully disabled live module")
    properties = parse_properties(read_text(adb, f"{MODULE_DIR}/module.prop"))
    if properties.get("id") != MODULE_ID:
        raise CheckError("location-uninstall refused an unexpected module identity")
    marker = adb.shell("touch", f"{MODULE_DIR}/remove", check=False)
    if marker.returncode != 0 or not exists(adb, f"{MODULE_DIR}/remove"):
        raise CheckError("could not create the location module remove marker")
    report.kv("state", "remove_pending")
    report.kv("reboot_required", "true")
    report.kv("device_mutation", "location module Magisk remove marker created")


def set_location(report: Report, args: argparse.Namespace) -> None:
    requested = read_private_config(args.config_file)
    adb = select_root_adbd(report, args)
    current = inspect_module(adb, report)
    if (
        current["state"] != "disabled"
        or current.get("runtime_attested")
        or not current.get("live_installed")
        or current.get("staged_installed")
    ):
        raise CheckError("location-set requires the module disabled and absent from system_server")
    current_config = current["config"]
    if not isinstance(current_config, dict):
        raise CheckError("installed location config is unavailable")
    values, changed = resolve_boot_config(requested, current_config)
    previous_generation = current_config["config_generation"]
    content = render_config(values)
    if changed:
        write_module_text(adb, "config.properties", content)
    installed_text = read_text(adb, f"{MODULE_DIR}/config.properties")
    installed = parse_properties(installed_text, exact_config=True)
    validate_config(installed)
    if installed != values:
        raise CheckError("installed location config differs from the requested config")
    report.kv("config_sha256", hashlib.sha256(installed_text.encode()).hexdigest())
    report.kv("previous_config_generation", previous_generation)
    report.kv("config_generation", values["config_generation"])
    report.kv("config_changed", str(changed).lower())
    report.kv("generation_assignment", "incremented" if changed else "retained")
    report.kv("raw_gnss_mode", values["raw_gnss_mode"])
    report.kv("coordinates", "absent")
    report.kv("remote_staging", "none")
    report.kv("module_state", "disabled")
    if values["raw_gnss_mode"] == "passthrough":
        report.kv("warning", "physical Raw GNSS observations will remain visible")
    report.kv(
        "device_mutation",
        "atomic private location config replacement" if changed else "none",
    )


def enable(report: Report, args: argparse.Namespace) -> None:
    adb = select_root_adbd(report, args)
    current = inspect_module(adb, report)
    if current["state"] == "pending_reboot_enabled":
        config = current.get("config")
        guard = current.get("guard")
        if (
            not current.get("live_installed")
            or current.get("staged_installed")
            or current.get("disabled")
            or current.get("native_mapped")
            or not isinstance(config, dict)
            or config.get("enabled") not in {"false", "true"}
            or not isinstance(guard, dict)
            or guard.get("state") != "valid"
        ):
            raise CheckError("resumable location-enable state is inconsistent")
        report.kv("state", "pending_reboot_enabled")
        report.kv("reboot_required", "true")
        report.kv("enable_resume", "semantic_noop")
        report.kv("device_mutation", "none")
        return
    if current["state"] != "disabled" or current.get("runtime_attested"):
        raise CheckError("location-enable requires a fully disabled post-reboot module")
    guard = adb.shell(
        "/system/bin/sh",
        f"{MODULE_DIR}/post-fs-data.sh",
        timeout=180,
        check=False,
    )
    report.kv("guard_exit", guard.returncode)
    if guard.returncode != 0:
        status_values = parse_properties(
            read_text(adb, f"{MODULE_DIR}/guard-status.properties", required=False)
        )
        raise CheckError(
            f"runtime prerequisites rejected enable: {status_values.get('mismatches')}"
        )
    status_values = parse_properties(
        read_text(adb, f"{MODULE_DIR}/guard-status.properties", required=False)
    )
    if status_values.get("state") != "valid":
        raise CheckError(
            f"runtime prerequisites rejected enable: {status_values.get('mismatches')}"
        )
    cleanup = adb.shell(
        "rm",
        "-f",
        f"{MODULE_DIR}/.guard",
        f"{MODULE_DIR}/runtime-status.properties",
        check=False,
    )
    if cleanup.returncode != 0:
        raise CheckError("could not reset pre-boot location runtime state")
    remove = adb.shell("rm", "-f", f"{MODULE_DIR}/disable", check=False)
    if remove.returncode != 0 or exists(adb, f"{MODULE_DIR}/disable"):
        restored = adb.shell("touch", f"{MODULE_DIR}/disable", check=False)
        if restored.returncode != 0 or not exists(adb, f"{MODULE_DIR}/disable"):
            raise CheckError("location enable rollback could not restore the disable marker")
        raise CheckError("could not remove the location module disable marker")
    report.kv("state", "pending_reboot_enabled")
    report.kv("reboot_required", "true")
    report.kv("device_mutation", "Magisk disable marker removed; location config preserved")


def disable_module(adb: Adb) -> None:
    module_dirs = [
        directory
        for directory in (MODULE_DIR, MODULE_UPDATE_DIR)
        if module_payload_present(adb, directory)
    ]
    if not module_dirs:
        raise CheckError("location module is not installed")
    for directory in module_dirs:
        marker = adb.shell("touch", f"{directory}/disable", check=False)
        if marker.returncode != 0 or not exists(adb, f"{directory}/disable"):
            raise CheckError("could not create the location module disable marker")


def disable(report: Report, args: argparse.Namespace) -> None:
    adb = select_root_adbd(report, args)
    current = inspect_module(adb, report)
    runtime_attested = bool(current.get("runtime_attested"))
    runtime_present = runtime_attested or bool(current.get("native_mapped"))
    staged = bool(current.get("staged_installed"))
    disable_module(adb)
    report.kv("runtime_attested_before_reboot", str(runtime_attested).lower())
    if staged:
        state = "staged_pending_reboot_disabled"
    elif runtime_present:
        state = "pending_reboot_disabled"
    else:
        state = "disabled"
    report.kv("state", state)
    report.kv("reboot_required", str(runtime_present or staged).lower())
    report.kv("device_mutation", "Magisk disable marker created; location config preserved")


def wait_for_boot(adb: Adb, report: Report, timeout_seconds: int = 240) -> None:
    wait = adb.run("wait-for-device", timeout=timeout_seconds, check=False)
    if wait.returncode != 0:
        raise CheckError("device did not return to ADB after reboot")
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        completed_result = adb.shell("getprop", "sys.boot_completed", check=False)
        bootanim_result = adb.shell("getprop", "init.svc.bootanim", check=False)
        completed = completed_result.stdout.strip()
        bootanim = bootanim_result.stdout.strip()
        if completed == "1" and bootanim == "stopped":
            report.kv("sys.boot_completed", completed)
            report.kv("init.svc.bootanim", bootanim)
            break
        time.sleep(2)
    else:
        raise CheckError("Android did not reach completed boot state")
    identity = adb.shell("id", check=False)
    if identity.returncode != 0 or "uid=0" not in identity.stdout:
        root = adb.run("root", timeout=30, check=False)
        report.kv("adb_root_after_reboot_exit", root.returncode)
        if root.returncode != 0:
            raise CheckError("rooted adbd did not return after reboot")
        if adb.run("wait-for-device", timeout=60, check=False).returncode != 0:
            raise CheckError("device did not return after rooted adbd restart")
        identity = adb.shell("id", check=False)
    if identity.returncode != 0 or "uid=0" not in identity.stdout:
        raise CheckError("adbd is not uid 0 after reboot")
    report.kv("adbd_state_after_reboot", "root")


def wait_for_new_boot(
    adb: Adb,
    report: Report,
    source_boot_id_sha256: str,
    timeout_seconds: int = 240,
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
            and hashlib.sha256(value.encode("ascii")).hexdigest() != source_boot_id_sha256
        ):
            report.kv("new_kernel_boot_observed", "true")
            wait_for_boot(adb, report, timeout_seconds=max(1, remaining))
            if current_boot_id_sha256(adb) == source_boot_id_sha256:
                raise CheckError("kernel boot identity regressed during reboot validation")
            return
        time.sleep(1)
    raise CheckError("device did not enter a new kernel boot before timeout")


def process_identity_samples_stable(samples: list[tuple[str, str]]) -> bool:
    return len(samples) >= 3 and len(set(samples)) == 1


def verify_system_server_stability(adb: Adb, report: Report, seconds: int = 15) -> None:
    samples: list[tuple[str, str]] = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        pid, start_ticks, _ = system_server_identity(adb)
        samples.append((pid, start_ticks))
        time.sleep(3)
    stable = process_identity_samples_stable(samples)
    report.kv("system_server_pid_samples", [pid for pid, _ in samples])
    report.kv("system_server_start_ticks_samples", [ticks for _, ticks in samples])
    report.kv("system_server_stable", str(stable).lower())
    if not stable:
        raise CheckError(
            "system_server PID/start-time identity changed during the stability window"
        )


def report_lifecycle(adb: Adb, report: Report) -> None:
    result = adb.run(
        "logcat",
        "-d",
        "-v",
        "threadtime",
        "ZygVeil:V",
        "*:S",
        timeout=30,
        check=False,
    )
    lines = result.stdout.splitlines()[-200:]
    events: collections.Counter[str] = collections.Counter()
    for line in lines:
        event_match = re.search(r"\bevent=([a-z0-9_]+)", line)
        if event_match is not None:
            events[event_match.group(1)] += 1
    report.section("location-lifecycle")
    report.kv("lifecycle_log_exit", result.returncode)
    report.kv("lifecycle_event_count", sum(events.values()))
    report.kv("lifecycle_event_counts", dict(sorted(events.items())))
    for line in lines:
        report.line(sanitize_log_line(line))


@serialized_transition
def reboot_device(report: Report, args: argparse.Namespace) -> None:
    pending = load_intent(
        LOCATION_REBOOT_INTENT,
        operation="location-reboot",
        expected_state=args.expected_state,
        context_id="location",
    )
    adb = select_root_adbd(report, args)
    if pending is not None:
        wait_for_boot(adb, report)
    current_pid, current_start_ticks, _ = system_server_identity(adb)
    current_boot_digest = current_boot_id_sha256(adb)
    resumed = pending is not None and pending["source_boot_id_sha256"] != current_boot_digest
    if not resumed:
        source_state = inspect_module(adb, report)["state"]
        allowed = REBOOT_SOURCE_STATES[args.expected_state]
        if source_state not in allowed:
            raise CheckError(
                f"location reboot source state cannot reach {args.expected_state}: {source_state}"
            )
    intent, resumed = begin_or_resume(
        report,
        LOCATION_REBOOT_INTENT,
        operation="location-reboot",
        expected_state=args.expected_state,
        context_id="location",
        current_boot_id_sha256=current_boot_digest,
        current_system_server_pid=current_pid,
        current_system_server_start_ticks=current_start_ticks,
    )
    if not resumed:
        reboot_result = adb.run("reboot", timeout=30, check=False)
        if reboot_result.returncode != 0:
            raise CheckError("ADB reboot command failed")
        wait_for_new_boot(
            adb,
            report,
            str(intent["source_boot_id_sha256"]),
        )
    verify_system_server_stability(adb, report)
    state = inspect_module(adb, report)
    if current_boot_id_sha256(adb) == intent["source_boot_id_sha256"]:
        raise CheckError("location reboot did not enter a new kernel boot")
    report.kv("system_server_pid_before_reboot", intent["source_system_server_pid"])
    report.kv(
        "system_server_start_ticks_before_reboot",
        intent["source_system_server_start_ticks"],
    )
    report_lifecycle(adb, report)
    if args.expected_state != "any" and state["state"] != args.expected_state:
        raise CheckError(
            f"post-reboot state mismatch: expected {args.expected_state}, got {state['state']}"
        )
    if args.expected_state == "absent" and state.get("native_mapped"):
        raise CheckError("post-uninstall reboot retained the location native runtime")
    clear_intent(LOCATION_REBOOT_INTENT)
    report.kv("device_mutation", "explicit ADB reboot and completed-boot validation")


def reboot_app_poc(report: Report, args: argparse.Namespace) -> None:
    adb = select_root_adbd(report, args)
    target = f"{MODULE_DIR}/zygisk/arm64-v8a.so"
    staged = adb.shell("test", "-x", target, "-a", "-x", HELPER, check=False)
    if staged.returncode != 0:
        raise CheckError("location application POC is not staged; run make location-poc-stage")
    reboot_result = adb.run("reboot", timeout=30, check=False)
    if reboot_result.returncode != 0:
        raise CheckError("ADB reboot command failed for location application POC")
    wait_for_boot(adb, report)
    report.kv("poc_fast_path", "true")
    report.kv("artifact_hash_comparison", "skipped")
    report.kv("runtime_attestation", "deferred_to_canary")
    report.kv("poc_application_scope", "global_unfiltered")
    report.kv("device_mutation", "explicit POC reboot and completed-boot wait")


def app_poc_smoke(report: Report, args: argparse.Namespace) -> None:
    adb = select_root_adbd(report, args)
    runtime = parse_properties(read_text(adb, f"{MODULE_DIR}/runtime-status.properties"))
    validate_runtime_status(runtime)
    if runtime["state"] != "ready":
        raise CheckError("location runtime is not ready for the application POC smoke")
    owner_fds = adb.shell("ls", "-l", f"/proc/{runtime['control_owner_pid']}/fd", check=False)
    pidfd_count = owner_fds.stdout.count("anon_inode:[pidfd]")
    if owner_fds.returncode != 0 or pidfd_count != 1:
        raise CheckError("application delivery companion does not retain exactly one pidfd")
    pid_result = adb.shell("pidof", POC_CANARY_PACKAGE, check=False)
    pids = [value for value in pid_result.stdout.split() if value.isdigit()]
    if pid_result.returncode != 0 or len(pids) != 1:
        raise CheckError("focused canary process is not running; run the POC canary first")
    pid = pids[0]
    maps_result = adb.shell("cat", f"/proc/{pid}/maps", timeout=15, check=False)
    executable_result = adb.shell("readlink", f"/proc/{pid}/exe", check=False)
    if maps_result.returncode != 0 or executable_result.returncode != 0:
        raise CheckError("focused canary process mappings are unavailable")
    native_mapped = f"{MODULE_DIR}/zygisk/arm64-v8a.so" in maps_result.stdout
    control_mapped = f"{MODULE_DIR}/.app-control" in maps_result.stdout
    relevant_mappings = sorted(
        {
            line.split()[-1]
            for line in maps_result.stdout.splitlines()
            if line.split()
            and any(marker in line.lower() for marker in ("zygisk", "zygveil", ".app-control"))
        }
    )
    log_result = adb.run(
        "logcat",
        "-d",
        "-v",
        "brief",
        "ZygVeil:V",
        "*:S",
        timeout=15,
        check=False,
    )
    report.kv("canary_process", "running")
    report.kv("canary_executable", executable_result.stdout.strip())
    report.kv("poc_native_mapped", str(native_mapped).lower())
    report.kv("poc_application_control_mapped", str(control_mapped).lower())
    report.kv("application_delivery_liveness", "companion_pidfd")
    report.kv("companion_pidfd_count", pidfd_count)
    report.kv("relevant_mapping_names", relevant_mappings)
    pre_app_ready_events = sum(
        log_result.stdout.count(marker)
        for marker in ("event=pre_app_poc_ready", "event=pre_app_delivery_ready")
    )
    report.kv("pre_app_ready_events", pre_app_ready_events)
    inactive_reasons = sorted(
        set(
            re.findall(
                r"event=pre_app_(?:poc|delivery)_inactive reason=([a-z0-9_:.-]+)",
                log_result.stdout,
            )
        )
    )
    pre_app_inactive_events = sum(
        log_result.stdout.count(marker)
        for marker in ("event=pre_app_poc_inactive", "event=pre_app_delivery_inactive")
    )
    report.kv("pre_app_inactive_events", pre_app_inactive_events)
    report.kv("pre_app_inactive_reasons", inactive_reasons)
    post_app_result_events = sum(
        log_result.stdout.count(marker)
        for marker in ("event=post_app_poc_result", "event=post_app_delivery_result")
    )
    report.kv("post_app_result_events", post_app_result_events)
    active_result_events = sum(
        log_result.stdout.count(marker)
        for marker in (
            "event=post_app_poc_result active=true",
            "event=post_app_delivery_result active=true",
        )
    )
    report.kv("post_app_active_events", active_result_events)
    report.kv("artifact_hash_comparison", "skipped")
    report.kv("coordinates", "absent")
    report.kv("device_mutation", "none")
    if not control_mapped or active_result_events == 0:
        raise CheckError("global application POC did not remain mapped in the focused canary")


def sanitize_log_line(line: str) -> str:
    sanitized = re.sub(r"[^\x20-\x7e]+", "<binary-redacted>", line)
    sanitized = re.sub(r"\$[A-Z]{2}[A-Z]{3}(?:,\S+)?", "<nmea-redacted>", sanitized)
    sanitized = re.sub(
        r"\$[A-Z][A-Z0-9_]*",
        "<dollar-token-redacted>",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"(?:Location|GnssMeasurementsEvent|GnssNavigationMessage)\[[^]]*]",
        "<location-object-redacted>",
        sanitized,
    )
    sanitized = re.sub(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "<address-redacted>",
        sanitized,
    )
    sanitized = re.sub(
        r"\b(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}\b",
        "<address-redacted>",
        sanitized,
    )
    sanitized = re.sub(
        r"\b(?:wlan|rmnet|tun|wg|eth|p2p|dummy)\d+\b",
        "<interface-redacted>",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        r"(?i)\b(?:center_latitude_deg|center_longitude_deg|"
        r"altitude_ellipsoid_m|altitude_msl_m)\s*[:=]\s*[^\s,;]+",
        "<location-config-redacted>",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)\b(?:latitude|longitude|lat|lon|location)\s*[:=]\s*[^\s,;]+",
        "<location-redacted>",
        sanitized,
    )
    sanitized = re.sub(r"(?<![A-Za-z0-9_])-?\d+(?:\.\d+)?(?![A-Za-z0-9_])", "<n>", sanitized)
    sanitized = re.sub(r"\b[0-9A-Fa-f]{16,}\b", "<hex-redacted>", sanitized)
    return sanitized[:2000]


def configuration_self_test() -> None:
    for transition in (reboot_device, recover):
        required = {"begin_or_resume", "wait_for_new_boot", "clear_intent"}
        missing = required - set(inspect.unwrap(transition).__code__.co_names)
        if missing:
            raise CheckError(f"{transition.__name__} lacks durable reboot steps: {sorted(missing)}")
    if REBOOT_SOURCE_STATES.get("absent") != {"remove_pending"} or "remove_pending" in set().union(
        *(states for expected, states in REBOOT_SOURCE_STATES.items() if expected != "absent")
    ):
        raise CheckError("location uninstall reboot source-state self-test failed")
    valid = {
        "schema_version": "1",
        "enabled": "true",
        "raw_gnss_mode": "blocked",
        "center_latitude_deg": "0.0",
        "center_longitude_deg": "0.0",
        "altitude_ellipsoid_m": "35.0",
        "altitude_msl_m": "5.0",
        "horizontal_jitter_sigma_m": "1.2",
        "horizontal_jitter_radius_m": "4.0",
        "horizontal_correlation_time_s": "40.0",
        "vertical_jitter_sigma_m": "1.5",
        "accuracy_correlation_time_s": "30.0",
        "speed_deadband_mps": "0.04",
        "speed_max_mps": "0.35",
        "bearing_min_speed_mps": "0.20",
        "random_seed": "20260824",
        "config_generation": "1",
    }
    rendered = render_config(valid)
    if parse_properties(rendered, exact_config=True) != valid:
        raise CheckError("location config render/parse self-test failed")
    invalid_mode = dict(valid, raw_gnss_mode="unsupported")
    try:
        validate_config(invalid_mode)
    except CheckError:
        pass
    else:
        raise CheckError("unsupported Raw GNSS mode self-test failed")
    invalid_thresholds = dict(valid, speed_deadband_mps="0.30", bearing_min_speed_mps="0.20")
    try:
        validate_config(invalid_thresholds)
    except CheckError:
        pass
    else:
        raise CheckError("location threshold self-test failed")
    boot_input = {key: valid[key] for key in BOOT_INPUT_KEYS}
    unchanged, changed = resolve_boot_config(boot_input, valid)
    if changed or unchanged != valid:
        raise CheckError("identical boot configuration was not a semantic no-op")
    passthrough_input = dict(boot_input, raw_gnss_mode="passthrough")
    next_config, changed = resolve_boot_config(passthrough_input, valid)
    if (
        not changed
        or next_config["config_generation"] != "2"
        or next_config["enabled"] != "true"
        or next_config["raw_gnss_mode"] != "passthrough"
        or valid["config_generation"] != "1"
    ):
        raise CheckError("changed boot configuration did not receive exactly the next generation")
    try:
        resolve_boot_config(
            passthrough_input,
            dict(valid, config_generation=str(MAX_CONFIG_GENERATION)),
        )
    except CheckError:
        pass
    else:
        raise CheckError("exhausted boot configuration generation self-test failed")
    for altitude_key in ("altitude_ellipsoid_m", "altitude_msl_m"):
        try:
            validate_config(dict(valid, **{altitude_key: "100000.001"}))
        except CheckError:
            pass
        else:
            raise CheckError("location altitude range self-test failed")
    runtime = {
        "schema_version": "4",
        "state": "ready",
        "reason": "active:blocked",
        "raw_gnss_mode": "blocked",
        "hook_count": "5",
        "system_server_pid": "1234",
        "system_server_start_ticks": "424242",
        "config_generation": "1",
        "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
        "control_fd": "42",
        "control_owner_pid": "5678",
        "control_owner_start_ticks": "434343",
    }
    validate_runtime_status(runtime)
    if not process_identity_samples_stable([("1234", "424242")] * 3):
        raise CheckError("stable system_server identity self-test failed")
    if process_identity_samples_stable(
        [("1234", "424242"), ("1234", "424243"), ("1234", "424243")]
    ):
        raise CheckError("PID-reuse system_server identity self-test failed")
    live_config = dict(valid, enabled="true", config_generation="8")
    live_status = {
        "module_state": "active",
        "runtime_state": "active",
        "raw_gnss_mode": "blocked",
        "boot_config_generation": "1",
        "persisted_generation": "8",
        "system_server_pid": "1234",
        "system_server_start_ticks": "424242",
        "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
    }
    if not live_status_matches_runtime(
        live_config,
        runtime,
        live_status,
        "1234",
        "01234567-89ab-cdef-0123-456789abcdef",
    ):
        raise CheckError("live/boot generation attestation self-test failed")
    if live_status_matches_runtime(
        live_config,
        runtime,
        dict(live_status, boot_config_generation="8"),
        "1234",
        "01234567-89ab-cdef-0123-456789abcdef",
    ):
        raise CheckError("live attestation accepted a non-boot runtime generation")
    try:
        validate_runtime_status(dict(runtime, schema_version="1"))
    except CheckError:
        pass
    else:
        raise CheckError("stale location runtime schema self-test failed")
    try:
        validate_runtime_status(dict(runtime, reason="center_latitude_deg=1"))
    except CheckError:
        pass
    else:
        raise CheckError("coordinate-bearing runtime reason self-test failed")
    try:
        validate_runtime_status(dict(runtime, reason="$GLGGA"))
    except CheckError:
        pass
    else:
        raise CheckError("NMEA-bearing runtime reason self-test failed")
    sanitized = sanitize_log_line(
        "Location[gps 60.123456,24.654321] $GPGGA,raw*00 192.0.2.1 wlan0 1234 "
        "center_latitude_deg=60.123456 altitude_msl_m=12.345 "
        "$GLGGA $MODPATH $callback $MixedCase123" + "\x00" + chr(0xFFFD)
    )
    unsafe_tokens = {
        "60.123456",
        "24.654321",
        "12.345",
        "$GPGGA",
        "$GLGGA",
        "$MODPATH",
        "$callback",
        "$MixedCase123",
        "192.0.2.1",
        "wlan0",
        "1234",
        "center_latitude_deg",
        "altitude_msl_m",
    }
    if any(token in sanitized for token in unsafe_tokens):
        raise CheckError("location log sanitizer self-test failed")
    if any(ord(character) < 32 or ord(character) > 126 for character in sanitized):
        raise CheckError("location log sanitizer emitted non-printable text")
    if sanitize_log_line(sanitized) != sanitized:
        raise CheckError("location log sanitizer is not idempotent")
    state_root = ROOT / ".state"
    state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".boot-config-self-test-", dir=state_root)
    path = Path(name)
    link = path.with_name(path.name + ".link")
    try:
        os.fchmod(descriptor, 0o600)
        boot_input_text = "".join(f"{key}={boot_input[key]}\n" for key in BOOT_INPUT_KEYS)
        os.write(descriptor, boot_input_text.encode("ascii"))
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if read_private_config(str(path)) != boot_input:
            raise CheckError("private boot configuration self-test changed input")
        path.write_text(rendered, encoding="ascii")
        os.chmod(path, 0o600)
        try:
            read_private_config(str(path))
        except CheckError:
            pass
        else:
            raise CheckError("private boot configuration accepted caller-managed generation")
        path.write_text(boot_input_text, encoding="ascii")
        os.chmod(path, 0o640)
        try:
            read_private_config(str(path))
        except CheckError:
            pass
        else:
            raise CheckError("private boot configuration mode self-test failed")
        os.chmod(path, 0o600)
        link.symlink_to(path)
        try:
            read_private_config(str(link))
        except CheckError:
            pass
        else:
            raise CheckError("private boot configuration symlink self-test failed")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        link.unlink(missing_ok=True)
        path.unlink(missing_ok=True)


def collect_logs(adb: Adb, report: Report) -> int:
    patterns = re.compile(
        r"zygveil|shadowhook|zygisk|system_server|watchdog|"
        r"androidruntime|fatal signal",
        re.IGNORECASE,
    )
    crash_lines = 0
    report.section("current-boot-logcat")
    logcat = adb.run("logcat", "-b", "all", "-d", "-v", "threadtime", "-t", "1600", check=False)
    current_lines = [line for line in logcat.stdout.splitlines() if patterns.search(line)][-500:]
    for line in current_lines:
        sanitized = sanitize_log_line(line)
        report.line(sanitized)
        if re.search(r"watchdog|fatal signal|system_server.*crash", sanitized, re.IGNORECASE):
            crash_lines += 1
    report.kv("current_log_match_count", len(current_lines))

    report.section("magisk-runtime-log")
    magisk_pattern = re.compile(
        r"zygveil|zygisk|dlopen|cannot load|failed to load",
        re.IGNORECASE,
    )
    magisk_match_count = 0
    for path in ("/cache/magisk.log", "/data/adb/magisk.log"):
        content = adb.shell("tail", "-n", "2400", path, timeout=30, check=False)
        if content.returncode != 0:
            continue
        matches = [line for line in content.stdout.splitlines() if magisk_pattern.search(line)][
            -400:
        ]
        if matches:
            report.line(f"source={path}")
            for line in matches:
                report.line(sanitize_log_line(line))
            magisk_match_count += len(matches)
    report.kv("magisk_runtime_match_count", magisk_match_count)

    report.section("module-native-metadata")
    native_path = f"{MODULE_DIR}/zygisk/arm64-v8a.so"
    native_metadata = adb.shell("stat", "-c", "%a:%u:%g:%s", native_path, timeout=30, check=False)
    native_digest = adb.shell("sha256sum", native_path, timeout=60, check=False)
    report.kv("native_stat_exit", native_metadata.returncode)
    report.kv("native_stat", native_metadata.stdout.strip())
    report.kv("native_sha256_exit", native_digest.returncode)
    report.kv(
        "native_sha256",
        native_digest.stdout.split()[0] if native_digest.returncode == 0 else "unavailable",
    )
    helper_path = f"{MODULE_DIR}/locationctl"
    helper_metadata = adb.shell("stat", "-c", "%a:%u:%g:%h:%s", helper_path, check=False)
    helper_digest = adb.shell("sha256sum", helper_path, timeout=60, check=False)
    report.kv("helper_stat_exit", helper_metadata.returncode)
    report.kv("helper_stat", helper_metadata.stdout.strip())
    report.kv("helper_sha256_exit", helper_digest.returncode)
    report.kv(
        "helper_sha256",
        helper_digest.stdout.split()[0] if helper_digest.returncode == 0 else "unavailable",
    )

    report.section("kernel-log")
    kernel = adb.shell("dmesg", timeout=30, check=False)
    kernel_lines = [line for line in kernel.stdout.splitlines() if patterns.search(line)][-300:]
    for line in kernel_lines:
        report.line(sanitize_log_line(line))
    report.kv("kernel_log_match_count", len(kernel_lines))

    report.section("previous-boot-pstore")
    listing = adb.shell("ls", "-1", "/sys/fs/pstore", check=False)
    pstore_count = 0
    if listing.returncode == 0:
        for name in listing.stdout.splitlines():
            if re.fullmatch(r"[A-Za-z0-9._-]+", name) is None:
                continue
            content = adb.shell("head", "-c", "262144", f"/sys/fs/pstore/{name}", check=False)
            matches = [line for line in content.stdout.splitlines() if patterns.search(line)][-200:]
            if matches:
                report.line(f"file={name}")
                for line in matches:
                    report.line(sanitize_log_line(line))
                pstore_count += 1
    report.kv("previous_boot_pstore_files_with_matches", pstore_count)
    report.kv("fatal_or_watchdog_match_count", crash_lines)
    return crash_lines


def logs(report: Report, args: argparse.Namespace) -> None:
    adb = select_root_adbd(report, args)
    collect_logs(adb, report)
    report.kv("coordinates", "redacted")
    report.kv("device_mutation", "none")


@serialized_transition
def recover(report: Report, args: argparse.Namespace) -> None:
    report.kv(
        "recovery_host_artifact_sha256",
        sha256(MODULE_ZIP) if MODULE_ZIP.is_file() else "unavailable",
    )
    pending = load_intent(
        LOCATION_RECOVERY_INTENT,
        operation="location-recover",
        expected_state="disabled",
        context_id="location",
    )
    adb = select_recovery_adbd(report, args)
    if pending is not None:
        wait_for_boot(adb, report)
    before_pid = "unavailable"
    before_start_ticks = "unavailable"
    mapped_before = False
    with contextlib.suppress(CheckError):
        before_pid, before_start_ticks, mapped_before = system_server_identity(adb)
    current_boot_digest = current_boot_id_sha256(adb)
    resumed = pending is not None and pending["source_boot_id_sha256"] != current_boot_digest
    if not resumed:
        disable_module(adb)
    intent, resumed = begin_or_resume(
        report,
        LOCATION_RECOVERY_INTENT,
        operation="location-recover",
        expected_state="disabled",
        context_id="location",
        current_boot_id_sha256=current_boot_digest,
        current_system_server_pid=before_pid if before_pid.isdigit() else "0",
        current_system_server_start_ticks=(
            before_start_ticks if before_start_ticks.isdigit() else "0"
        ),
    )
    report.kv("system_server_pid_before_recovery", intent["source_system_server_pid"])
    report.kv(
        "system_server_start_ticks_before_recovery",
        intent["source_system_server_start_ticks"],
    )
    report.kv("native_library_mapped_before_recovery", str(mapped_before).lower())
    if not resumed:
        reboot_result = adb.run("reboot", timeout=30, check=False)
        if reboot_result.returncode != 0:
            raise CheckError("recovery reboot command failed")
        wait_for_new_boot(
            adb,
            report,
            str(intent["source_boot_id_sha256"]),
        )
    verify_system_server_stability(adb, report, seconds=20)
    recovered = inspect_module(adb, report)
    if recovered["state"] != "disabled" or recovered.get("runtime_attested"):
        raise CheckError("recovery did not reach a fully disabled module state")
    if current_boot_id_sha256(adb) == intent["source_boot_id_sha256"]:
        raise CheckError("location recovery did not enter a new kernel boot")
    collect_logs(adb, report)
    clear_intent(LOCATION_RECOVERY_INTENT)
    clear_intent(LOCATION_REBOOT_INTENT)
    report.kv("recovery_status", "PASS")
    report.kv(
        "device_mutation",
        "disable marker, preserved location config, reboot, and recovery validation",
    )


COMMANDS: dict[str, Callable[[Report, argparse.Namespace], None]] = {
    "location-disable": disable,
    "location-enable": enable,
    "location-install": install,
    "location-logs": logs,
    "location-poc-reboot": reboot_app_poc,
    "location-poc-smoke": app_poc_smoke,
    "location-poc-stage": stage_app_poc,
    "location-reboot": reboot_device,
    "location-recover": recover,
    "location-set": set_location,
    "location-status": status,
    "location-uninstall": uninstall,
    "location-update": update,
}


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--adb-serial", default="")
    parser.add_argument("--expected-state", default="any")
    parser.add_argument("--config-file", default="")
    parser.add_argument("command", choices=sorted(COMMANDS))
    args = parser.parse_args()
    if args.command == "location-set" and not args.config_file:
        parser.error("location-set requires --config-file")
    if args.expected_state not in {
        "any",
        "absent",
        "disabled",
        "pending_reboot_disabled",
        "pending_reboot_enabled",
        "staged_pending_reboot_enabled",
        "staged_pending_reboot_disabled",
        "active_control_failure",
        "waiting",
        "active",
    }:
        parser.error("unsupported expected state")
    if args.command == "location-reboot" and args.expected_state not in {
        "any",
        "absent",
        "active",
        "waiting",
        "disabled",
    }:
        parser.error("location-reboot supports only any, absent, waiting, active, or disabled")
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
                        r"(?i)\b(?:center_latitude_deg|center_longitude_deg|"
                        r"altitude_ellipsoid_m|altitude_msl_m)\s*=",
                        r"\$[A-Z]",
                        r"\.state/",
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
