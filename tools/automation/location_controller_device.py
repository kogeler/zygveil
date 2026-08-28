# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Make-wrapped standalone location-controller device lifecycle."""

from __future__ import annotations

import argparse
import hashlib
import re
import tempfile
import time
import traceback
from collections.abc import Callable
from pathlib import Path

from adb import Adb, ensure_device_ui_ready
from reporting import CheckError, Report

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "dev.zygveil.location.controller"
ACTIVITY = f"{PACKAGE}/.ControllerActivity"
ROOT_ACTION = f"{PACKAGE}.action.REQUEST_ROOT"
APK = ROOT / "dist/zygveil-location-controller-debug.apk"
BUILD_REPORT = ROOT / ".artifacts/reports/location/build-location-controller.txt"
STATUS_PATH = "no_backup/controller-root-status.properties"
EXPECTED_CERTIFICATE = "2a2098191bdf2fdf1c4d3e4a2d2686c8b3f59f8225470331a44482ed073e0c0d"
TRANSPORT_STATUSES = {
    "none",
    "denied",
    "missing_module",
    "timeout",
    "cancelled",
    "output_limit",
    "protocol",
    "io",
}
MODULE_STATES = {"active", "inactive"}
RUNTIME_STATES = {"unavailable", "uninitialized", "arming", "active", "inactive"}
CONTROL_STATES = {
    "unavailable",
    "saved_pending_upstream",
    "saved_pending_reboot",
    "recovery_required",
    "applied",
    "rejected",
}
STATUS_KEYS = {
    "schema_version",
    "request_id",
    "wall_time_ms",
    "transport_status",
    "helper_status_present",
    "module_state",
    "runtime_state",
    "control_state",
    "reason",
    "boot_config_generation",
    "persisted_generation",
    "published_generation",
    "applied_generation",
    "coordinates",
}
COORDINATE_KEYS = {
    "center_latitude_deg",
    "center_longitude_deg",
    "altitude_ellipsoid_m",
    "altitude_msl_m",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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
    if not APK.is_file():
        raise CheckError("controller APK is missing; run make location-controller-build")
    digest = sha256(APK)
    build = report_values(BUILD_REPORT)
    expected = {
        "application_id": PACKAGE,
        "application_label": "ZygVeil Location",
        "version_code": "1",
        "version_name": "0.1.0",
        "certificate_sha256": EXPECTED_CERTIFICATE,
        "requested_permissions": "none",
        "other_components": "none",
        "native_libraries": "none",
        "project_dependencies": "none",
    }
    if build.get("apk_sha256") != digest or any(
        build.get(key) != value for key, value in expected.items()
    ):
        raise CheckError("controller APK/build report identity mismatch")
    report.kv("artifact", APK.relative_to(ROOT))
    report.kv("artifact_sha256", digest)
    report.kv("certificate_sha256", EXPECTED_CERTIFICATE)
    return digest


def package_installed(adb: Adb) -> bool:
    result = adb.shell("pm", "path", PACKAGE, check=False)
    return result.returncode == 0 and result.stdout.startswith("package:")


def installed_apk_sha256(adb: Adb) -> str:
    paths = adb.shell("pm", "path", PACKAGE, check=False)
    candidates = [
        line.removeprefix("package:").strip()
        for line in paths.stdout.splitlines()
        if line.startswith("package:")
    ]
    base = next((path for path in candidates if path.endswith("/base.apk")), None)
    if paths.returncode != 0 or base is None:
        raise CheckError("installed controller base APK path is unavailable")
    with tempfile.TemporaryDirectory(prefix="zygveil-controller-installed-") as directory:
        destination = Path(directory) / "base.apk"
        pull = adb.run("pull", base, str(destination), timeout=120, check=False)
        if pull.returncode != 0 or not destination.is_file():
            raise CheckError("could not pull installed controller APK")
        return sha256(destination)


def validate_installed(adb: Adb, report: Report, expected_digest: str) -> None:
    if not package_installed(adb):
        raise CheckError("controller package is not installed")
    details = adb.shell("dumpsys", "package", PACKAGE, timeout=30).stdout
    version_name = re.search(r"versionName=([^\s]+)", details)
    version_code = re.search(r"versionCode=(\d+)", details)
    target_sdk = re.search(r"targetSdk=(\d+)", details)
    if (
        version_name is None
        or version_name.group(1) != "0.1.0"
        or version_code is None
        or version_code.group(1) != "1"
        or target_sdk is None
        or target_sdk.group(1) != "36"
    ):
        raise CheckError("installed controller package identity mismatch")
    installed_digest = installed_apk_sha256(adb)
    if installed_digest != expected_digest:
        raise CheckError("installed controller APK hash mismatch")
    report.kv("application_id", PACKAGE)
    report.kv("installed_version_code", 1)
    report.kv("installed_version_name", "0.1.0")
    report.kv("installed_target_sdk", 36)
    report.kv("installed_apk_sha256", installed_digest)
    report.kv("installed_certificate_sha256", EXPECTED_CERTIFICATE)


def parse_status(text: str) -> dict[str, str]:
    if not text or len(text.encode("utf-8")) > 4096 or "\x00" in text:
        raise CheckError("controller root status size is invalid")
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or "=" not in line:
            raise CheckError("controller root status has invalid shape")
        key, value = line.split("=", 1)
        if not key or not value or key in values:
            raise CheckError("controller root status has invalid or duplicate fields")
        values[key] = value
    if set(values) != STATUS_KEYS or values["schema_version"] != "1":
        raise CheckError("controller root status schema/key mismatch")
    if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", values["request_id"]) is None:
        raise CheckError("controller root status request identity is invalid")
    if (
        not values["wall_time_ms"].isdigit()
        or len(values["wall_time_ms"]) > 19
        or int(values["wall_time_ms"]) <= 0
        or values["coordinates"] != "absent"
    ):
        raise CheckError("controller root status privacy/timestamp mismatch")
    for key in (
        "boot_config_generation",
        "persisted_generation",
        "published_generation",
        "applied_generation",
    ):
        if not values[key].isdigit() or int(values[key]) > 2**62 - 1:
            raise CheckError(f"controller root status generation is invalid: {key}")
    if re.fullmatch(r"[a-z_]{1,64}", values["reason"]) is None or any(
        key in values["reason"] for key in COORDINATE_KEYS
    ):
        raise CheckError("controller root reason is invalid")
    if values["transport_status"] not in TRANSPORT_STATUSES:
        raise CheckError("controller root transport status is invalid")
    helper_present = values["helper_status_present"] == "true"
    if values["helper_status_present"] not in {"true", "false"}:
        raise CheckError("controller root helper-presence value is invalid")
    if helper_present and values["transport_status"] not in {"none", "denied", "missing_module"}:
        raise CheckError("controller root helper/transport state is inconsistent")
    if not helper_present:
        unavailable = all(
            values[key] == "unavailable"
            for key in ("module_state", "runtime_state", "control_state", "reason")
        )
        zero_generations = all(
            values[key] == "0"
            for key in (
                "boot_config_generation",
                "persisted_generation",
                "published_generation",
                "applied_generation",
            )
        )
        if values["transport_status"] == "none" or not unavailable or not zero_generations:
            raise CheckError("controller root missing-helper state is inconsistent")
    else:
        if values["module_state"] not in MODULE_STATES:
            raise CheckError("controller root module state is invalid")
        if values["runtime_state"] not in RUNTIME_STATES:
            raise CheckError("controller root runtime state is invalid")
        if values["control_state"] not in CONTROL_STATES:
            raise CheckError("controller root control state is invalid")
        boot = int(values["boot_config_generation"])
        persisted = int(values["persisted_generation"])
        published = int(values["published_generation"])
        applied = int(values["applied_generation"])
        control = values["control_state"]
        active = values["module_state"] == "active" and values["runtime_state"] == "active"
        error_envelope = (
            values["module_state"] == "inactive"
            and values["runtime_state"] == "unavailable"
            and control == "rejected"
            and values["reason"] != "none"
            and boot == persisted == published == applied == 0
        )
        if control != "unavailable" and not active and not error_envelope:
            raise CheckError("controller root active-state envelope is inconsistent")
        if control == "unavailable" and (active or values["reason"] == "none"):
            raise CheckError("controller root unavailable state is inconsistent")
        if control == "applied" and not (
            values["reason"] == "none"
            and boot > 0
            and persisted == published == applied
            and applied >= boot
        ):
            raise CheckError("controller root applied generations are inconsistent")
        if control == "saved_pending_upstream" and not (
            values["reason"] == "none" and boot > 0 and persisted == published > applied >= boot
        ):
            raise CheckError("controller root pending generations are inconsistent")
        if control == "saved_pending_reboot" and not (
            boot > 0
            and persisted > published >= applied >= boot
            and values["reason"] == "publish_unavailable"
        ):
            raise CheckError("controller root reboot-pending generations are inconsistent")
        if control == "recovery_required":
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
                raise CheckError("controller root recovery generations are inconsistent")
        if (
            control == "rejected"
            and not error_envelope
            and not (
                values["reason"] != "none"
                and boot > 0
                and published > applied >= boot
                and persisted == applied
            )
        ):
            raise CheckError("controller root rejected generations are inconsistent")
        expected_failure_reason = {
            "denied": "unauthorized_invocation",
            "missing_module": "module_unavailable",
        }.get(values["transport_status"])
        if expected_failure_reason is not None and values["reason"] != expected_failure_reason:
            raise CheckError("controller root helper/transport reason is inconsistent")
    return values


def parser_self_test() -> None:
    for operation in (launch_root_request, open_controller):
        if "ensure_device_ui_ready" not in operation.__code__.co_names:
            raise CheckError(f"{operation.__name__} has no device UI readiness gate")
    valid = (
        "schema_version=1\n"
        "request_id=12345678-1234-1234-1234-123456789abc\n"
        "wall_time_ms=1777000000000\n"
        "transport_status=none\n"
        "helper_status_present=true\n"
        "module_state=active\n"
        "runtime_state=active\n"
        "control_state=applied\n"
        "reason=none\n"
        "boot_config_generation=6\n"
        "persisted_generation=8\n"
        "published_generation=8\n"
        "applied_generation=8\n"
        "coordinates=absent\n"
    )
    parse_status(valid)
    unavailable = (
        valid.replace("transport_status=none", "transport_status=denied")
        .replace("helper_status_present=true", "helper_status_present=false")
        .replace("module_state=active", "module_state=unavailable")
        .replace("runtime_state=active", "runtime_state=unavailable")
        .replace("control_state=applied", "control_state=unavailable")
        .replace("reason=none", "reason=unavailable")
        .replace("boot_config_generation=6", "boot_config_generation=0")
        .replace("persisted_generation=8", "persisted_generation=0")
        .replace("published_generation=8", "published_generation=0")
        .replace("applied_generation=8", "applied_generation=0")
    )
    parse_status(unavailable)
    recovery = (
        valid.replace("control_state=applied", "control_state=recovery_required")
        .replace("reason=none", "reason=persistence_uncertain")
        .replace("published_generation=8", "published_generation=7")
        .replace("applied_generation=8", "applied_generation=7")
    )
    parse_status(recovery)
    for invalid in (
        valid + "center_latitude_deg=1\n",
        valid.replace("transport_status=none", "transport_status=arbitrary"),
        valid.replace("coordinates=absent", "coordinates=present"),
        valid.replace("helper_status_present=true", "helper_status_present=false"),
        valid.replace("module_state=active", "module_state=unknown"),
        valid.replace("runtime_state=active", "runtime_state=unknown"),
        valid.replace("control_state=applied", "control_state=unknown"),
        valid.replace("applied_generation=8", "applied_generation=7"),
        valid.replace("control_state=applied", "control_state=recovery_required"),
        valid.replace("reason=none", "reason=checksum_mismatch"),
        valid.replace("module_state=active", "module_state=inactive")
        .replace("runtime_state=active", "runtime_state=inactive")
        .replace("control_state=applied", "control_state=unavailable")
        .replace("reason=none", "reason=center_latitude_deg"),
        valid.replace("control_state=applied", "control_state=unavailable"),
        unavailable.replace("transport_status=denied", "transport_status=none"),
        valid.replace("applied_generation=8", "applied_generation=18446744073709551616"),
        valid.replace("request_id=12345678", "request_id=1234567g"),
    ):
        try:
            parse_status(invalid)
        except CheckError:
            pass
        else:
            raise CheckError("controller root status negative self-test failed")


def read_status(adb: Adb) -> dict[str, str] | None:
    script = (
        "set -eu; path=$1; "
        'if [ ! -e "$path" ] && [ ! -L "$path" ]; then exit 44; fi; '
        'test ! -L "$path"; uid=$(id -u); gid=$(id -g); '
        "identity=$(stat -c '%F:%a:%u:%g:%h' \"$path\"); "
        'test "$identity" = "regular file:600:$uid:$gid:1"; cat "$path"'
    )
    result = adb.shell_input(
        "run-as",
        PACKAGE,
        "/system/bin/sh",
        "-c",
        script,
        "controller-status-reader",
        STATUS_PATH,
        input_text="",
        timeout=15,
        check=False,
    )
    if result.returncode == 44:
        return None
    if result.returncode != 0 or not result.stdout.strip():
        raise CheckError("controller root status file identity is invalid")
    return parse_status(result.stdout)


def launch_root_request(adb: Adb, report: Report) -> None:
    ensure_device_ui_ready(adb, report)
    adb.shell("am", "force-stop", PACKAGE, check=False)
    launch = adb.shell(
        "am",
        "start",
        "-W",
        "-a",
        ROOT_ACTION,
        "-n",
        ACTIVITY,
        timeout=30,
        check=False,
    )
    report.kv("launch_exit", launch.returncode)
    if launch.returncode != 0 or "Error:" in launch.stdout:
        raise CheckError("controller fixed root-request activity did not launch")


def wait_fresh_status(adb: Adb, previous_id: str, seconds: float) -> dict[str, str] | None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        candidate = read_status(adb)
        if candidate is not None and candidate["request_id"] != previous_id:
            return candidate
        time.sleep(0.2)
    return None


def install_package(report: Report, args: argparse.Namespace, *, replace: bool) -> None:
    digest = require_artifact(report)
    adb = Adb.select(args.adb_serial, report)
    installed = package_installed(adb)
    if replace and not installed:
        raise CheckError("controller is absent; use make location-controller-install")
    if not replace and installed:
        raise CheckError("controller is already installed; use make location-controller-reinstall")
    command = ["install"]
    if replace:
        command.append("-r")
    command.append(str(APK))
    result = adb.run(*command, timeout=120, check=False)
    report.kv("install_mode", "replace" if replace else "new")
    report.kv("install_exit", result.returncode)
    report.kv("install_result", result.stdout.strip())
    if result.returncode != 0 or "Success" not in result.stdout:
        raise CheckError("controller APK install failed")
    validate_installed(adb, report, digest)
    report.kv("root_authorization_changed", "false")
    report.kv("module_state_changed", "false")
    report.kv("device_mutation", "adb install standalone controller APK")


def install(report: Report, args: argparse.Namespace) -> None:
    install_package(report, args, replace=False)


def reinstall(report: Report, args: argparse.Namespace) -> None:
    install_package(report, args, replace=True)


def ensure_existing(report: Report, args: argparse.Namespace) -> None:
    digest = require_artifact(report)
    adb = Adb.select(args.adb_serial, report)
    installed = package_installed(adb)
    if installed and installed_apk_sha256(adb) == digest:
        validate_installed(adb, report, digest)
        report.kv("install_mode", "semantic_noop")
        report.kv("root_authorization_changed", "false")
        report.kv("module_state_changed", "false")
        report.kv("device_mutation", "none")
        return
    command = ["install", "-r", str(APK)] if installed else ["install", str(APK)]
    result = adb.run(*command, timeout=120, check=False)
    report.kv("install_mode", "ensure_replace" if installed else "ensure_new")
    report.kv("install_exit", result.returncode)
    report.kv("install_result", result.stdout.strip())
    if result.returncode != 0 or "Success" not in result.stdout:
        raise CheckError("controller exact-APK ensure operation failed")
    validate_installed(adb, report, digest)
    report.kv("root_authorization_changed", "false")
    report.kv("module_state_changed", "false")
    report.kv("device_mutation", "adb install exact standalone controller APK")


def open_controller(report: Report, args: argparse.Namespace) -> None:
    digest = require_artifact(report)
    adb = Adb.select(args.adb_serial, report)
    validate_installed(adb, report, digest)
    ensure_device_ui_ready(adb, report)
    launch = adb.shell(
        "am",
        "start",
        "-W",
        "-a",
        "android.intent.action.MAIN",
        "-n",
        ACTIVITY,
        timeout=30,
        check=False,
    )
    report.kv("launch_exit", launch.returncode)
    if launch.returncode != 0 or "Error:" in launch.stdout:
        raise CheckError("controller launcher activity did not open")
    report.kv("root_request", "none")
    report.kv("device_mutation", "open exact controller activity")


def root_request(report: Report, args: argparse.Namespace) -> None:
    digest = require_artifact(report)
    adb = Adb.select(args.adb_serial, report)
    validate_installed(adb, report, digest)
    previous = read_status(adb)
    previous_id = previous["request_id"] if previous is not None else "none"
    launch_root_request(adb, report)
    fresh = wait_fresh_status(adb, previous_id, 1.5)
    if fresh is None:
        report.kv("authorization", "pending_user_consent")
    else:
        transport = fresh["transport_status"]
        authorization = "granted" if transport == "none" else transport
        report.kv("authorization", authorization)
        report.kv("request_id", fresh["request_id"])
    report.kv("policy_storage_edited", "false")
    report.kv("coordinates", "absent")
    report.kv("device_mutation", "fixed controller status request only")


def status(report: Report, args: argparse.Namespace) -> None:
    digest = require_artifact(report)
    adb = Adb.select(args.adb_serial, report)
    validate_installed(adb, report, digest)
    previous = read_status(adb)
    previous_id = previous["request_id"] if previous is not None else "none"
    launch_root_request(adb, report)
    fresh = wait_fresh_status(adb, previous_id, 12.0)
    if fresh is None:
        raise CheckError("controller did not publish a fresh redacted root status")
    if fresh["transport_status"] != "none" or fresh["helper_status_present"] != "true":
        raise CheckError(f"controller root helper is unavailable: {fresh['transport_status']}")
    for key in (
        "request_id",
        "module_state",
        "runtime_state",
        "control_state",
        "reason",
        "boot_config_generation",
        "persisted_generation",
        "published_generation",
        "applied_generation",
    ):
        report.kv(key, fresh[key])
    report.kv("authorization", "granted")
    report.kv("coordinates", "absent")
    report.kv("device_mutation", "fixed controller status request only")


COMMANDS: dict[str, Callable[[Report, argparse.Namespace], None]] = {
    "location-controller-ensure-existing": ensure_existing,
    "location-controller-install": install,
    "location-controller-open": open_controller,
    "location-controller-reinstall": reinstall,
    "location-controller-root-request": root_request,
    "location-controller-status": status,
}


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--adb-serial", default="")
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
                        r"(?i)\b(?:latitude|longitude|altitude|center_[a-z_]+)\s*=",
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
