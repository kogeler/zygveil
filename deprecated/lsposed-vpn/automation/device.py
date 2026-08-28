# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Make-wrapped production install, scope status, process, and log workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
import time
import traceback
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import cast

from adb import Adb
from reporting import CheckError, Report

ROOT = Path(__file__).resolve().parents[2]
MODULE_PACKAGE = "dev.zygveil.module"
PRIMARY_PACKAGE = "dev.zygveil.probe.primary"
CANARY_PACKAGE = "dev.zygveil.probe.canary"
EXACT_SCOPE = (PRIMARY_PACKAGE, CANARY_PACKAGE)
MODULE_APK = ROOT / "dist/zygveil-legacy-vpn-debug.apk"
PROBE_APKS = {
    PRIMARY_PACKAGE: ROOT / "dist/zygveil-probe-primary-debug.apk",
    CANARY_PACKAGE: ROOT / "dist/zygveil-probe-canary-debug.apk",
}
MODULE_CHECKSUM = ROOT / "dist/zygveil-legacy-vpn-debug.apk.sha256"
BUILD_REPORT = ROOT / ".artifacts/reports/build/build.txt"
CAPTURE_ACTION = "dev.zygveil.module.action.CAPTURE_STATUS"
CAPTURE_ID_EXTRA = "capture_id"


def restart_adbd(report: Report, args: argparse.Namespace, *, root: bool) -> None:
    adb = Adb.select(args.adb_serial, report)
    before = adb.shell("id", check=False)
    report.kv("before_id", before.stdout.strip())
    action = "root" if root else "unroot"
    result = adb.run(action, timeout=30, check=False)
    report.kv("adb_action", action)
    report.kv("adb_action_exit", result.returncode)
    report.kv("adb_action_result", result.stdout.strip())
    if result.returncode != 0:
        raise CheckError(f"adb {action} failed")
    wait = adb.run("wait-for-device", timeout=60, check=False)
    report.kv("wait_for_device_exit", wait.returncode)
    if wait.returncode != 0:
        raise CheckError("device did not return after adbd restart")
    after = adb.shell("id", timeout=15, check=False)
    report.kv("after_id", after.stdout.strip())
    expected_uid = "uid=0" if root else "uid=2000"
    if after.returncode != 0 or expected_uid not in after.stdout:
        raise CheckError(f"adbd did not enter the requested {action} state")
    report.kv("device_mutation", f"adb {action} restarted adbd")


def adb_root(report: Report, args: argparse.Namespace) -> None:
    restart_adbd(report, args, root=True)


def adb_unroot(report: Report, args: argparse.Namespace) -> None:
    restart_adbd(report, args, root=False)


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


def validate_artifact(report: Report) -> str:
    if not MODULE_APK.is_file() or not MODULE_CHECKSUM.is_file():
        raise CheckError("production artifact is missing; run make apk")
    fields = MODULE_CHECKSUM.read_text(encoding="utf-8").split()
    if len(fields) < 2 or fields[1] != MODULE_APK.name:
        raise CheckError("production checksum file is malformed")
    expected = fields[0]
    actual = sha256(MODULE_APK)
    build = report_values(BUILD_REPORT)
    report.kv("artifact", MODULE_APK.relative_to(ROOT))
    report.kv("artifact_sha256", actual)
    if actual != expected or actual != build.get("apk_sha256"):
        raise CheckError("production artifact checksum/build-report mismatch")
    expected_identity = {
        "application_id": MODULE_PACKAGE,
        "application_label": "ZygVeil Legacy VPN",
        "version_name": "0.1.0",
        "scope_defaults": "empty",
    }
    if any(build.get(key) != value for key, value in expected_identity.items()):
        raise CheckError("production artifact identity report mismatch")
    return actual


def package_installed(adb: Adb, package: str) -> bool:
    result = adb.shell("pm", "path", package, check=False)
    return result.returncode == 0 and result.stdout.startswith("package:")


def installed_apk_sha256(adb: Adb, package: str) -> str:
    paths = adb.shell("pm", "path", package, check=False)
    candidates = [
        line.removeprefix("package:").strip()
        for line in paths.stdout.splitlines()
        if line.startswith("package:")
    ]
    base = next((path for path in candidates if path.endswith("/base.apk")), None)
    if paths.returncode != 0 or base is None:
        raise CheckError(f"installed base APK path is unavailable: {package}")
    with tempfile.TemporaryDirectory(prefix="vpn-mask-installed-") as directory:
        destination = Path(directory) / "base.apk"
        pull = adb.run("pull", base, str(destination), timeout=120, check=False)
        if pull.returncode != 0 or not destination.is_file():
            raise CheckError(f"could not pull installed base APK: {package}")
        return sha256(destination)


def install_package(report: Report, args: argparse.Namespace, replace: bool) -> None:
    validate_artifact(report)
    adb = Adb.select(args.adb_serial, report)
    command = ["install"]
    if replace:
        command.append("-r")
    command.append(str(MODULE_APK))
    result = adb.run(*command, timeout=120, check=False)
    report.kv("install_mode", "replace" if replace else "new")
    report.kv("install_exit", result.returncode)
    report.kv("install_result", result.stdout.strip())
    if result.returncode != 0 or "Success" not in result.stdout:
        raise CheckError("production module install failed")
    if not package_installed(adb, MODULE_PACKAGE):
        raise CheckError("production module package is absent after install")
    details = adb.shell("dumpsys", "package", MODULE_PACKAGE).stdout
    version = re.search(r"versionName=([^\s]+)", details)
    target = re.search(r"targetSdk=([^\s]+)", details)
    report.kv("installed_version_name", version.group(1) if version else "unknown")
    report.kv("installed_target_sdk", target.group(1) if target else "unknown")
    if version is None or version.group(1) != "0.1.0":
        raise CheckError("installed module version identity mismatch")
    adb.shell("am", "force-stop", MODULE_PACKAGE, check=False)
    launch = adb.shell(
        "am",
        "start",
        "-W",
        "-f",
        "0x20000000",
        "-a",
        CAPTURE_ACTION,
        "-n",
        f"{MODULE_PACKAGE}/.StatusActivity",
        timeout=30,
        check=False,
    )
    report.kv("module_launch_exit", launch.returncode)
    if launch.returncode != 0:
        raise CheckError("module Activity did not launch after install")
    report.kv("scope_mutation", "false")
    report.kv("device_mutation", "adb install and module-app process restart")


def install(report: Report, args: argparse.Namespace) -> None:
    install_package(report, args, replace=False)


def reinstall(report: Report, args: argparse.Namespace) -> None:
    install_package(report, args, replace=True)


def read_snapshot(adb: Adb) -> dict[str, object] | None:
    result = adb.shell("run-as", MODULE_PACKAGE, "cat", "files/framework.json", check=False)
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        decoded: object = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CheckError("module framework snapshot is invalid JSON") from error
    if not isinstance(decoded, dict) or not all(isinstance(key, str) for key in decoded):
        raise CheckError("module framework snapshot is not an object")
    return cast(dict[str, object], decoded)


def string_list(snapshot: dict[str, object], key: str) -> list[str]:
    value = snapshot.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise CheckError(f"snapshot field {key} is not a string list")
    return cast(list[str], value)


def scope_status(report: Report, args: argparse.Namespace) -> None:
    validate_artifact(report)
    adb = Adb.select(args.adb_serial, report)
    if not package_installed(adb, MODULE_PACKAGE):
        raise CheckError("production module is not installed; run make reinstall")
    for package in EXACT_SCOPE:
        if not package_installed(adb, package):
            raise CheckError(f"required probe package is not installed: {package}")
    capture_id = f"scope-status-{uuid.uuid4().hex[:12]}"
    deadline = time.monotonic() + 20.0
    snapshot: dict[str, object] | None = None
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        launch = adb.shell(
            "am",
            "start",
            "-W",
            "-f",
            "0x20000000",
            "-a",
            CAPTURE_ACTION,
            "-n",
            f"{MODULE_PACKAGE}/.StatusActivity",
            "--es",
            CAPTURE_ID_EXTRA,
            capture_id,
            timeout=30,
            check=False,
        )
        if launch.returncode != 0:
            report.kv("capture_launch_exit", launch.returncode)
            raise CheckError("framework status Activity did not launch")
        time.sleep(0.5)
        candidate = read_snapshot(adb)
        if candidate is not None and candidate.get("capture_id") == capture_id:
            snapshot = candidate
            break
        time.sleep(0.5)
    report.kv("capture_id", capture_id)
    report.kv("capture_attempts", attempts)
    if snapshot is None:
        raise CheckError("fresh framework scope snapshot was not published")
    if snapshot.get("schema_version") != 3:
        raise CheckError("framework scope snapshot schema is not 3")
    if snapshot.get("state") != "bound":
        raise CheckError("libxposed service is not bound")
    for key in ["api_version", "framework_name", "framework_version", "framework_version_code"]:
        report.kv(key, snapshot.get(key, "missing"))
    current_scope = sorted(string_list(snapshot, "scope"))
    expected_scope = sorted(EXACT_SCOPE)
    missing = sorted(set(expected_scope) - set(current_scope))
    unexpected = sorted(set(current_scope) - set(expected_scope))
    report.kv("scope", current_scope)
    report.kv("scope_count", len(current_scope))
    report.kv("scope_sha256", hashlib.sha256("\n".join(current_scope).encode()).hexdigest())
    report.kv("expected_scope", expected_scope)
    report.kv("missing", missing)
    report.kv("unexpected", unexpected)
    report.kv("scope_exact", str(not missing and not unexpected).lower())
    report.kv("scope_mutation", "false")
    report.kv("device_mutation", "status Activity launch only")
    if missing or unexpected:
        report.kv(
            "manual_required",
            "configure exactly the primary and canary probes in the LSPosed manager",
        )
        raise CheckError(
            "LSPosed scope is not exactly the two probes; configure it manually, then rerun "
            "make scope-status"
        )


def target_restart(report: Report, args: argparse.Namespace) -> None:
    validate_artifact(report)
    adb = Adb.select(args.adb_serial, report)
    for package, artifact in PROBE_APKS.items():
        if not artifact.is_file():
            raise CheckError("probe artifacts are missing; run make build-probe")
        expected = sha256(artifact)
        actual = installed_apk_sha256(adb, package)
        report.kv(f"probe.{package}.artifact_sha256", expected)
        report.kv(f"probe.{package}.installed_sha256", actual)
        if actual != expected:
            remediation = "run make probe-install probe-install-canary"
            raise CheckError(f"installed probe mismatch; {remediation}")
    adb.shell("am", "force-stop", PRIMARY_PACKAGE, check=False)
    launch = adb.shell(
        "am",
        "start",
        "-W",
        "-n",
        f"{PRIMARY_PACKAGE}/dev.zygveil.probe.ProbeActivity",
        "--ez",
        "load_only",
        "true",
        timeout=30,
        check=False,
    )
    report.kv("primary_launch_exit", launch.returncode)
    report.kv("primary_launch_result", launch.stdout.strip()[:1000])
    if launch.returncode != 0:
        raise CheckError("primary load-only Activity did not launch")
    required = [PRIMARY_PACKAGE, f"{PRIMARY_PACKAGE}:secondary"]
    deadline = time.monotonic() + 20
    attempts = 0
    capture = None
    target_objects: list[dict[str, object]] = []
    by_process: dict[str, dict[str, object]] = {}
    while time.monotonic() < deadline:
        attempts += 1
        capture = adb.shell(
            "am",
            "start",
            "-W",
            "-f",
            "0x20000000",
            "-a",
            CAPTURE_ACTION,
            "-n",
            f"{MODULE_PACKAGE}/.StatusActivity",
            timeout=30,
            check=False,
        )
        if capture.returncode != 0:
            break
        time.sleep(0.5)
        snapshot = read_snapshot(adb)
        if snapshot is not None:
            targets = snapshot.get("running_targets")
            if isinstance(targets, list) and all(isinstance(item, dict) for item in targets):
                target_objects = cast(list[dict[str, object]], targets)
                by_process = {}
                for item in target_objects:
                    process = item.get("process")
                    if isinstance(process, str):
                        by_process[process] = item
                if all(process in by_process for process in required):
                    break
        time.sleep(1)
    report.kv("capture_attempts", attempts)
    if capture is None:
        raise CheckError("module target capture was not attempted")
    report.kv("capture_launch_exit", capture.returncode)
    report.kv("capture_launch_result", capture.stdout.strip()[:1000])
    for process in required:
        pid = adb.shell("pidof", process, check=False)
        report.kv(f"pid.{process}", pid.stdout.strip() if pid.returncode == 0 else "absent")
    if capture.returncode != 0:
        raise CheckError("module target capture did not launch")
    if not target_objects:
        raise CheckError("API 102 running-target list is unavailable")
    report.kv("running_target_count", len(target_objects))
    for process in required:
        target = by_process.get(process)
        report.kv(f"target.{process}.present", str(target is not None).lower())
        if target is None:
            raise CheckError(f"module load target is absent: {process}")
        report.kv(f"target.{process}.state", target.get("state", "unknown"))
        loaded = target.get("loaded_version_code", -1)
        report.kv(f"target.{process}.loaded_version_code", loaded)
        if target.get("state") != "UP_TO_DATE" or loaded != 1:
            raise CheckError(f"module target has unexpected generation: {process}")
    for excluded in [MODULE_PACKAGE, "com.wireguard.android", "com.topjohnwu.magisk"]:
        if excluded in by_process:
            raise CheckError(f"excluded package appears as hooked target: {excluded}")
    report.kv("detector_tests", "not run")
    report.kv("device_mutation", "force-stop and load-only restart of primary probe")


def logs(report: Report, args: argparse.Namespace) -> None:
    adb = Adb.select(args.adb_serial, report)
    result = adb.run(
        "logcat",
        "-d",
        "-v",
        "threadtime",
        "-t",
        "1000",
        "ZygVeil:V",
        "LSPosed:V",
        "libxposed:V",
        "*:S",
        timeout=30,
        check=False,
    )
    report.kv("logcat_exit", result.returncode)
    for line in result.stdout.splitlines()[-1000:]:
        report.line(line)
    if result.returncode != 0:
        raise CheckError("filtered log capture failed")
    report.kv("device_mutation", "none")


def logs_clear(report: Report, args: argparse.Namespace) -> None:
    adb = Adb.select(args.adb_serial, report)
    result = adb.run("logcat", "-c", check=False)
    report.kv("logcat_clear_exit", result.returncode)
    if result.returncode != 0:
        raise CheckError("Android log buffers could not be cleared")
    report.kv("device_mutation", "adb logcat -c")


COMMANDS: dict[str, Callable[[Report, argparse.Namespace], None]] = {
    "adb-root": adb_root,
    "adb-unroot": adb_unroot,
    "install": install,
    "reinstall": reinstall,
    "scope-status": scope_status,
    "target-restart": target_restart,
    "logs": logs,
    "logs-clear": logs_clear,
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
            COMMANDS[args.command](report, args)
    except CheckError:
        return 1
    except Exception:
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
