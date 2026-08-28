# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Privacy-safe Make wrapper for the fixed native location live-control helper."""

from __future__ import annotations

import argparse
import os
import re
import stat
import tempfile
import time
import traceback
from collections.abc import Callable
from decimal import Decimal, InvalidOperation
from pathlib import Path

from adb import Adb, system_server_process_identity
from reporting import CheckError, Report, contains_private_decimal_values

ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = "/data/adb/modules/zygveil"
HELPER = f"{MODULE_DIR}/locationctl"
CONFIG = f"{MODULE_DIR}/config.properties"
BUILD_REPORT = ROOT / ".artifacts/reports/location/build-location.txt"
LIVE_KEYS = (
    "schema_version",
    "center_latitude_deg",
    "center_longitude_deg",
    "altitude_ellipsoid_m",
    "altitude_msl_m",
)
STATUS_KEYS = {
    "schema_version",
    "module_state",
    "runtime_state",
    "control_state",
    "reason",
    "raw_gnss_mode",
    "boot_config_generation",
    "persisted_generation",
    "published_generation",
    "applied_generation",
    "system_server_pid",
    "system_server_start_ticks",
    "boot_id",
}
CONTROL_EXPECTATIONS = {
    "any",
    "accepted",
    "awaiting_first_coordinates",
    "applied",
    "saved_pending_upstream",
    "saved_pending_reboot",
    "recovery_required",
    "rejected",
    "unavailable",
}


def report_values(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise CheckError(f"required report is missing: {path.relative_to(ROOT)}")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def read_private_file(path_text: str) -> bytes:
    path = Path(path_text)
    if not path.is_absolute():
        path = ROOT / path
    state_root = (ROOT / ".state").resolve()
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise CheckError("live configuration is unavailable") from None
    if not resolved.is_relative_to(state_root) or path.is_symlink():
        raise CheckError("live configuration must be a regular file below ignored .state")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        raise CheckError("live configuration could not be opened safely") from None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > 1024
        ):
            raise CheckError("live configuration owner/mode/type/size is invalid")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 256))
            if not block:
                raise CheckError("live configuration changed while being read")
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise CheckError("live configuration changed while being read")
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
            raise CheckError("live configuration changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def parse_properties(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "=" not in stripped:
            raise CheckError("live configuration has an invalid line")
        key, value = (part.strip() for part in stripped.split("=", 1))
        if not key or not value or key in values:
            raise CheckError("live configuration has an invalid or duplicate field")
        values[key] = value
    return values


def validate_decimal(value: str, *, fraction_digits: int, minimum: str, maximum: str) -> None:
    if re.fullmatch(r"-?[0-9]+(?:\.[0-9]+)?", value) is None:
        raise CheckError("live configuration contains a non-canonical decimal")
    fraction = value.partition(".")[2]
    if len(fraction) > fraction_digits:
        raise CheckError("live configuration decimal precision is too large")
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        raise CheckError("live configuration contains an invalid decimal") from None
    if parsed < Decimal(minimum) or parsed > Decimal(maximum):
        raise CheckError("live configuration decimal is outside its supported range")


def validate_live_input(data: bytes) -> str:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise CheckError("live configuration must contain only ASCII") from None
    values = parse_properties(text)
    if set(values) != set(LIVE_KEYS) or values.get("schema_version") != "1":
        raise CheckError("live configuration schema/key set mismatch")
    validate_decimal(values["center_latitude_deg"], fraction_digits=8, minimum="-90", maximum="90")
    validate_decimal(
        values["center_longitude_deg"],
        fraction_digits=8,
        minimum="-180",
        maximum="180",
    )
    for key in ("altitude_ellipsoid_m", "altitude_msl_m"):
        validate_decimal(values[key], fraction_digits=3, minimum="-12000", maximum="100000")
    return "".join(f"{key}={values[key]}\n" for key in LIVE_KEYS)


def parse_status(text: str) -> dict[str, str]:
    if not text or len(text.encode("utf-8")) > 16 * 1024 or "\x00" in text:
        raise CheckError("live helper status size is invalid")
    values = parse_properties(text)
    if set(values) != STATUS_KEYS or values.get("schema_version") != "1":
        raise CheckError("live helper status schema/key set mismatch")
    for key in (
        "boot_config_generation",
        "persisted_generation",
        "published_generation",
        "applied_generation",
        "system_server_pid",
        "system_server_start_ticks",
    ):
        if not values[key].isdigit():
            raise CheckError(f"live helper status integer is invalid: {key}")
    allowed = {
        "module_state": {"waiting", "active", "inactive"},
        "runtime_state": {
            "unavailable",
            "uninitialized",
            "arming",
            "waiting",
            "active",
            "inactive",
        },
        "control_state": {
            "unavailable",
            "awaiting_first_coordinates",
            "saved_pending_upstream",
            "saved_pending_reboot",
            "recovery_required",
            "applied",
            "rejected",
        },
        "raw_gnss_mode": {"blocked", "passthrough"},
    }
    for key, choices in allowed.items():
        if values[key] not in choices:
            raise CheckError(f"live helper status token is invalid: {key}")
    if re.fullmatch(r"[a-z_]{1,64}", values["reason"]) is None or any(
        token in values["reason"]
        for token in (
            "center_latitude_deg",
            "center_longitude_deg",
            "altitude_ellipsoid_m",
            "altitude_msl_m",
        )
    ):
        raise CheckError("live helper status reason is invalid")
    if (
        values["boot_id"] != "unavailable"
        and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", values["boot_id"]) is None
    ):
        raise CheckError("live helper status boot identity is invalid")
    boot = int(values["boot_config_generation"])
    persisted = int(values["persisted_generation"])
    published = int(values["published_generation"])
    applied = int(values["applied_generation"])
    system_server_pid = int(values["system_server_pid"])
    system_server_start_ticks = int(values["system_server_start_ticks"])
    if (
        any(value > 2**62 - 1 for value in (boot, persisted, published, applied))
        or system_server_pid > 2**32 - 1
        or system_server_start_ticks > 2**64 - 1
    ):
        raise CheckError("live helper status integer exceeds its wire range")
    active = values["module_state"] == "active" and values["runtime_state"] == "active"
    waiting = values["module_state"] == "waiting" and values["runtime_state"] == "waiting"
    if (active or waiting) and (
        system_server_pid == 0
        or system_server_start_ticks == 0
        or values["boot_id"] == "unavailable"
    ):
        raise CheckError("live helper active identity is inconsistent")
    if (system_server_pid == 0) != (system_server_start_ticks == 0):
        raise CheckError("live helper process identity is inconsistent")
    error_envelope = (
        values["module_state"] == "inactive"
        and values["runtime_state"] == "unavailable"
        and values["control_state"] == "rejected"
        and values["reason"] != "none"
        and values["boot_id"] == "unavailable"
        and all(
            values[key] == "0"
            for key in (
                "boot_config_generation",
                "persisted_generation",
                "published_generation",
                "applied_generation",
                "system_server_pid",
                "system_server_start_ticks",
            )
        )
    )
    if (
        values["control_state"]
        in {
            "applied",
            "saved_pending_upstream",
            "saved_pending_reboot",
            "recovery_required",
            "rejected",
        }
        and not active
        and not waiting
        and not error_envelope
    ):
        raise CheckError("live helper status has an impossible active transition")
    if values["control_state"] == "unavailable" and (active or values["reason"] == "none"):
        raise CheckError("live helper unavailable state is inconsistent")
    if values["control_state"] == "awaiting_first_coordinates" and not (
        waiting
        and values["reason"] == "none"
        and boot > 0
        and persisted == published == applied == boot
    ):
        raise CheckError("live helper waiting generations are inconsistent")
    if values["control_state"] == "applied" and not (
        values["reason"] == "none"
        and boot > 0
        and persisted == published == applied
        and applied >= boot
    ):
        raise CheckError("live helper applied generations are inconsistent")
    if values["control_state"] == "saved_pending_upstream" and not (
        values["reason"] == "none" and boot > 0 and persisted == published > applied >= boot
    ):
        raise CheckError("live helper pending generations are inconsistent")
    if values["control_state"] == "saved_pending_reboot" and not (
        boot > 0
        and persisted > published >= applied >= boot
        and values["reason"] == "publish_unavailable"
    ):
        raise CheckError("live helper reboot-pending generations are inconsistent")
    if values["control_state"] == "recovery_required":
        rejected_persistence = (
            values["reason"] in {"persisted_runtime_rejection", "rollback_failed"}
            and persisted == published > applied
        )
        uncertain_rollback = (
            values["reason"] == "rollback_persistence_uncertain"
            and persisted == applied < published
        )
        uncertain_persistence = (
            values["reason"] == "persistence_uncertain" and persisted > published == applied
        )
        if not (
            boot > 0
            and applied >= boot
            and (rejected_persistence or uncertain_rollback or uncertain_persistence)
        ):
            raise CheckError("live helper recovery generations are inconsistent")
    if (
        values["control_state"] == "rejected"
        and not error_envelope
        and not (
            values["reason"] != "none"
            and boot > 0
            and published > applied >= boot
            and persisted == applied
        )
    ):
        raise CheckError("live helper rejected generations are inconsistent")
    return values


def require_expected_control(
    values: dict[str, str], expected: str, *, command_exit: int | None = None
) -> None:
    if expected not in CONTROL_EXPECTATIONS:
        raise CheckError("unsupported expected live control state")
    state = values["control_state"]
    matched = expected == "any" or state == expected
    if expected == "accepted":
        matched = state in {"applied", "saved_pending_upstream", "saved_pending_reboot"}
    if command_exit is not None:
        if expected in {"recovery_required", "rejected", "unavailable"}:
            matched = matched and command_exit != 0
        elif expected != "any":
            matched = matched and command_exit == 0
        else:
            matched = matched and (
                command_exit == 0 or (command_exit != 0 and state in {"rejected", "unavailable"})
            )
    if not matched:
        raise CheckError(f"live control state mismatch: expected {expected}, got {state}")


def select_root_adbd(report: Report, args: argparse.Namespace) -> Adb:
    adb = Adb.select(args.adb_serial, report)
    identity = adb.shell("id", timeout=10, check=False)
    report.kv("root_escalation_attempted", "false")
    if identity.returncode != 0 or "uid=0" not in identity.stdout:
        raise CheckError("rooted adbd is required; run make adb-root (no su fallback is used)")
    report.kv("adbd_state", "root")
    return adb


def device_digest(adb: Adb, path: str) -> str:
    result = adb.shell("sha256sum", path, timeout=60, check=False)
    fields = result.stdout.split()
    if (
        result.returncode != 0
        or len(fields) != 2
        or re.fullmatch(r"[0-9a-f]{64}", fields[0]) is None
    ):
        raise CheckError("device live-control file digest is unavailable")
    return fields[0]


def require_identity(
    adb: Adb, report: Report, *, require_active: bool, poc: bool
) -> tuple[dict[str, str], str]:
    build = {} if poc else report_values(BUILD_REPORT)
    expected_helper = "" if poc else build.get("locationctl_sha256", "")
    if not poc and re.fullmatch(r"[0-9a-f]{64}", expected_helper) is None:
        raise CheckError("location helper build identity is unavailable; run make location-build")
    module_stat = adb.shell("stat", "-c", "%F:%a:%u:%g", MODULE_DIR, check=False)
    if module_stat.returncode != 0 or module_stat.stdout.strip() != "directory:755:0:0":
        raise CheckError("installed location module directory identity mismatch")
    helper_stat = adb.shell("stat", "-c", "%F:%a:%u:%g:%h", HELPER, check=False)
    if helper_stat.returncode != 0 or helper_stat.stdout.strip() != "regular file:755:0:0:1":
        raise CheckError("installed location helper type/mode/owner/link identity mismatch")
    if not poc and device_digest(adb, HELPER) != expected_helper:
        raise CheckError("installed location helper hash mismatch")
    status_result = adb.shell(HELPER, "status", timeout=15, check=False)
    if status_result.returncode != 0:
        raise CheckError("redacted location helper status failed")
    status = parse_status(status_result.stdout)
    current_boot = adb.shell("cat", "/proc/sys/kernel/random/boot_id").stdout.strip()
    current_pid, current_start_ticks = system_server_process_identity(adb)
    status_has_boot_identity = (
        status["boot_id"] != "unavailable"
        or status["system_server_pid"] != "0"
        or status["system_server_start_ticks"] != "0"
    )
    if status_has_boot_identity and (
        status["boot_id"] != current_boot
        or status["system_server_pid"] != current_pid
        or status["system_server_start_ticks"] != current_start_ticks
    ):
        raise CheckError("live helper status is not bound to the current boot/system_server")
    active = status["module_state"] == "active" and status["runtime_state"] == "active"
    waiting = status["module_state"] == "waiting" and status["runtime_state"] == "waiting"
    if active and adb.shell("test", "-e", f"{MODULE_DIR}/disable", check=False).returncode == 0:
        raise CheckError("active live configuration found an unexpected disable marker")
    if require_active and not (active or waiting):
        raise CheckError("live configuration requires a ready location runtime")
    if poc:
        report.kv("helper_hash_comparison", "skipped")
    else:
        report.kv("helper_sha256", expected_helper)
    report.kv("artifact_class", "non_attestable_poc" if poc else "release_candidate")
    report.kv("module_directory_identity", "true")
    report.kv("boot_id_match", "true" if status_has_boot_identity else "not_applicable")
    report.kv("system_server_pid", status["system_server_pid"])
    report.kv("system_server_start_ticks", status["system_server_start_ticks"])
    return status, current_start_ticks


def report_status(report: Report, values: dict[str, str]) -> None:
    for key in (
        "module_state",
        "runtime_state",
        "control_state",
        "reason",
        "raw_gnss_mode",
        "boot_config_generation",
        "persisted_generation",
        "published_generation",
        "applied_generation",
        "system_server_pid",
        "system_server_start_ticks",
    ):
        report.kv(key, values[key])


def live_status(report: Report, args: argparse.Namespace) -> None:
    adb = select_root_adbd(report, args)
    values, _ = require_identity(adb, report, require_active=False, poc=args.poc)
    require_expected_control(values, args.expected_control_state or "any")
    report_status(report, values)
    report.kv("coordinates", "absent")
    report.kv("device_mutation", "none")


def live_set(report: Report, args: argparse.Namespace) -> None:
    raw_input = read_private_file(args.input_file)
    helper_input = validate_live_input(raw_input)
    adb = select_root_adbd(report, args)
    before, before_start_ticks = require_identity(adb, report, require_active=True, poc=args.poc)
    before_config_digest = "" if args.poc else device_digest(adb, CONFIG)
    started = time.monotonic()
    result = adb.shell_input(HELPER, "apply", input_text=helper_input, timeout=15, check=False)
    elapsed_ms = round((time.monotonic() - started) * 1000)
    response = parse_status(result.stdout)
    after, after_start_ticks = require_identity(adb, report, require_active=True, poc=args.poc)
    after_config_digest = "" if args.poc else device_digest(adb, CONFIG)
    if (
        before["raw_gnss_mode"] != after["raw_gnss_mode"]
        or before["module_state"] != after["module_state"]
        or before["system_server_pid"] != after["system_server_pid"]
        or before["system_server_start_ticks"] != after["system_server_start_ticks"]
        or before_start_ticks != after_start_ticks
        or response["system_server_pid"] != after["system_server_pid"]
        or response["system_server_start_ticks"] != after["system_server_start_ticks"]
        or response["boot_id"] != after["boot_id"]
    ):
        raise CheckError("live update changed a boot-only state or system_server identity")
    if args.poc:
        report.kv("persistent_config_hash_comparison", "skipped")
    else:
        report.kv("persistent_config_sha256_before", before_config_digest)
        report.kv("persistent_config_sha256_after", after_config_digest)
    report.kv("helper_exit", result.returncode)
    report.kv("elapsed_wait_ms", elapsed_ms)
    report_status(report, response)
    report.kv("post_control_state", after["control_state"])
    report.kv("post_persisted_generation", after["persisted_generation"])
    report.kv("post_published_generation", after["published_generation"])
    report.kv("post_applied_generation", after["applied_generation"])
    report.kv("module_state_unchanged", "true")
    report.kv("raw_gnss_mode_unchanged", "true")
    report.kv("system_server_pid_unchanged", "true")
    report.kv("system_server_start_ticks_unchanged", "true")
    report.kv("remote_staging", "none")
    report.kv("coordinates", "absent")
    accepted = response["control_state"] in {
        "applied",
        "saved_pending_upstream",
        "saved_pending_reboot",
    }
    if accepted and (
        (not args.poc and before_config_digest == after_config_digest)
        or response["persisted_generation"] != after["persisted_generation"]
        or int(after["persisted_generation"]) <= int(before["persisted_generation"])
    ):
        raise CheckError("accepted live update did not persist exactly one current generation")
    if response["control_state"] == "rejected" and (
        (not args.poc and before_config_digest != after_config_digest)
        or before["persisted_generation"] != after["persisted_generation"]
        or before["applied_generation"] != after["applied_generation"]
    ):
        raise CheckError("rejected live update changed the last valid persisted/applied generation")
    require_expected_control(
        response,
        args.expected_control_state or "accepted",
        command_exit=result.returncode,
    )
    report.kv("device_mutation", "fixed helper stdin update")


def privacy_self_test() -> None:
    sentinel = (
        b"schema_version=1\ncenter_latitude_deg=66.12345678\n"
        b"center_longitude_deg=-11.87654321\naltitude_ellipsoid_m=123.125\n"
        b"altitude_msl_m=99.875\n"
    )
    validate_live_input(sentinel)
    private_decimals = ("66.12345678", "-11.87654321", "123.125", "99.875")
    nested_candidate = '{"outer":[{"value":66.12345678}]}'
    if not contains_private_decimal_values(nested_candidate, private_decimals):
        raise CheckError("live-control recursive decimal privacy self-test failed")
    if not contains_private_decimal_values('{"value":66.12}', ("66.12000000",)):
        raise CheckError("live-control normalized decimal privacy self-test failed")
    if not contains_private_decimal_values('{"value":66.123456779999998}', ("66.12345678",)):
        raise CheckError("live-control binary64 decimal privacy self-test failed")
    if contains_private_decimal_values('{"distance":66.1234}', private_decimals):
        raise CheckError("live-control decimal privacy self-test rejected a derived metric")
    if any(key in HELPER for key in LIVE_KEYS) or re.search(r"[;&|`$]", HELPER):
        raise CheckError("live-control privacy/fixed-command self-test failed")
    invalid_inputs = (
        sentinel.replace(b"66.12345678", b"66.123456789"),
        sentinel.replace(b"66.12345678", b"91"),
        sentinel.replace(b"-11.87654321", b"NaN"),
        sentinel + b"unknown=1\n",
        sentinel + b"center_latitude_deg=1\n",
        sentinel.replace(b"schema_version=1", b"schema_version=2"),
        sentinel.replace(b"66.12345678", b"\xff"),
    )
    for invalid in invalid_inputs:
        try:
            validate_live_input(invalid)
        except CheckError as error:
            if "66.12345678" in str(error) or "-11.87654321" in str(error):
                raise CheckError("live-control validation error exposed private input") from None
        else:
            raise CheckError("live-control invalid-input self-test failed")
    valid_status = (
        "schema_version=1\nmodule_state=active\nruntime_state=active\n"
        "control_state=applied\nreason=none\nraw_gnss_mode=blocked\n"
        "boot_config_generation=6\npersisted_generation=8\npublished_generation=8\n"
        "applied_generation=8\nsystem_server_pid=1234\n"
        "system_server_start_ticks=424242\n"
        "boot_id=12345678-1234-1234-1234-123456789abc\n"
    )
    parse_status(valid_status)
    pending_reboot = (
        valid_status.replace("control_state=applied", "control_state=saved_pending_reboot")
        .replace("reason=none", "reason=publish_unavailable")
        .replace("persisted_generation=8", "persisted_generation=9")
    )
    parse_status(pending_reboot)
    recovery_required = (
        valid_status.replace("control_state=applied", "control_state=recovery_required")
        .replace("reason=none", "reason=persisted_runtime_rejection")
        .replace("applied_generation=8", "applied_generation=7")
    )
    parse_status(recovery_required)
    require_expected_control(parse_status(recovery_required), "recovery_required", command_exit=4)
    uncertain_rollback = recovery_required.replace(
        "reason=persisted_runtime_rejection", "reason=rollback_persistence_uncertain"
    ).replace("persisted_generation=8", "persisted_generation=7")
    parse_status(uncertain_rollback)
    uncertain_persistence = recovery_required.replace(
        "reason=persisted_runtime_rejection", "reason=persistence_uncertain"
    ).replace("published_generation=8", "published_generation=7")
    parse_status(uncertain_persistence)
    error_envelope = (
        "schema_version=1\nmodule_state=inactive\nruntime_state=unavailable\n"
        "control_state=rejected\nreason=invalid_input_shape\nraw_gnss_mode=blocked\n"
        "boot_config_generation=0\npersisted_generation=0\npublished_generation=0\n"
        "applied_generation=0\nsystem_server_pid=0\nsystem_server_start_ticks=0\n"
        "boot_id=unavailable\n"
    )
    parse_status(error_envelope)
    require_expected_control(parse_status(valid_status), "accepted", command_exit=0)
    require_expected_control(parse_status(error_envelope), "rejected", command_exit=2)
    for invalid_status in (
        valid_status.replace("control_state=applied", "control_state=unknown"),
        valid_status.replace("system_server_pid=1234", "system_server_pid=0"),
        valid_status.replace("system_server_start_ticks=424242", "system_server_start_ticks=0"),
        valid_status.replace("boot_id=12345678-1234-1234-1234-123456789abc", "boot_id=unavailable"),
        valid_status.replace("persisted_generation=8", "persisted_generation=4611686018427387904"),
        valid_status.replace("applied_generation=8", "applied_generation=7"),
        valid_status.replace("module_state=active", "module_state=inactive"),
        valid_status.replace("reason=none", "reason=checksum_mismatch"),
        valid_status.replace("reason=none", "reason=center_latitude_deg"),
        valid_status.replace("control_state=applied", "control_state=unavailable"),
        valid_status + "center_latitude_deg=1\n",
        pending_reboot.replace("persisted_generation=9", "persisted_generation=8"),
    ):
        try:
            parse_status(invalid_status)
        except CheckError:
            pass
        else:
            raise CheckError("live-control invalid-status self-test failed")
    state_root = ROOT / ".state"
    state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".live-self-test-", dir=state_root)
    path = Path(name)
    link = path.with_name(path.name + ".link")
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, sentinel)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if read_private_file(str(path)) != sentinel:
            raise CheckError("live-control private-file self-test changed input")
        os.chmod(path, 0o640)
        try:
            read_private_file(str(path))
        except CheckError:
            pass
        else:
            raise CheckError("live-control private-file mode self-test failed")
        os.chmod(path, 0o600)
        link.symlink_to(path)
        try:
            read_private_file(str(link))
        except CheckError:
            pass
        else:
            raise CheckError("live-control private-file symlink self-test failed")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        link.unlink(missing_ok=True)
        path.unlink(missing_ok=True)


COMMANDS: dict[str, Callable[[Report, argparse.Namespace], None]] = {
    "location-live-set": live_set,
    "location-live-status": live_status,
}


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--adb-serial", default="")
    parser.add_argument("--input-file", default="")
    parser.add_argument("--expected-control-state", default="")
    parser.add_argument("--poc", action="store_true")
    parser.add_argument("command", choices=sorted(COMMANDS))
    args = parser.parse_args()
    if args.command == "location-live-set" and not args.input_file:
        parser.error("location-live-set requires --input-file")
    if args.expected_control_state and args.expected_control_state not in CONTROL_EXPECTATIONS:
        parser.error("unsupported expected live control state")
    return args


def main() -> int:
    args = parse_arguments()
    try:
        privacy_self_test()
        with Report(ROOT / args.report_dir, args.command) as report:
            private_decimals: tuple[str, ...] = ()
            try:
                if args.command == "location-live-set":
                    private_input = validate_live_input(read_private_file(args.input_file))
                    private_values = parse_properties(private_input)
                    private_decimals = tuple(private_values[key] for key in LIVE_KEYS[1:])
                COMMANDS[args.command](report, args)
            finally:
                report.assert_redacted(
                    [
                        r"(?i)\b(?:latitude|longitude|altitude|center_[a-z_]+)\s*=",
                        r"\$[A-Z]",
                        r"\.state/",
                        r"/data/local/tmp/",
                    ],
                    [lambda content: contains_private_decimal_values(content, private_decimals)],
                )
    except CheckError:
        return 1
    except Exception:
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
