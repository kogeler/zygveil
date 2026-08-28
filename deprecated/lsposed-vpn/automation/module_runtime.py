# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Read-only module state and exact test-artifact oracles."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import cast

from adb import Adb
from adb import installed_apk_sha256
from reporting import CheckError, Report

ROOT = Path(__file__).resolve().parents[2]
MODULE_PACKAGE = "dev.zygveil.module"
PRIMARY_PACKAGE = "dev.zygveil.probe.primary"
CANARY_PACKAGE = "dev.zygveil.probe.canary"
EXACT_SCOPE = sorted([PRIMARY_PACKAGE, CANARY_PACKAGE])
CAPTURE_ACTION = "dev.zygveil.module.action.CAPTURE_STATUS"
MODULE_APK = ROOT / "dist/zygveil-legacy-vpn-debug.apk"
PROBE_APKS = {
    PRIMARY_PACKAGE: ROOT / "dist/zygveil-probe-primary-debug.apk",
    CANARY_PACKAGE: ROOT / "dist/zygveil-probe-canary-debug.apk",
}
DETECTOR_SOURCE_HASH = ROOT / "dist/probe-detector-source.sha256"


def file_sha256(path: Path) -> str:
    if not path.is_file():
        raise CheckError(f"artifact is missing: {path.relative_to(ROOT)}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def detector_source_sha256() -> str:
    if not DETECTOR_SOURCE_HASH.is_file():
        raise CheckError("detector source hash is missing; run make build-probe")
    fields = DETECTOR_SOURCE_HASH.read_text(encoding="utf-8").split()
    if len(fields) != 2 or fields[1] != "probe-detector-source" or len(fields[0]) != 64:
        raise CheckError("detector source hash file is invalid")
    return fields[0].lower()


def artifact_identity() -> dict[str, str]:
    return {
        "module_apk_sha256": file_sha256(MODULE_APK),
        "primary_apk_sha256": file_sha256(PROBE_APKS[PRIMARY_PACKAGE]),
        "canary_apk_sha256": file_sha256(PROBE_APKS[CANARY_PACKAGE]),
        "detector_source_sha256": detector_source_sha256(),
    }


def validate_installed_artifacts(adb: Adb, report: Report) -> dict[str, str]:
    artifacts = artifact_identity()
    packages = {
        MODULE_PACKAGE: ("module_apk_sha256", MODULE_APK, "make reinstall"),
        PRIMARY_PACKAGE: (
            "primary_apk_sha256",
            PROBE_APKS[PRIMARY_PACKAGE],
            "make probe-install",
        ),
        CANARY_PACKAGE: (
            "canary_apk_sha256",
            PROBE_APKS[CANARY_PACKAGE],
            "make probe-install-canary",
        ),
    }
    for package, (key, _, remediation) in packages.items():
        installed = installed_apk_sha256(adb, package)
        report.kv(f"artifact.{package}.expected_sha256", artifacts[key])
        report.kv(f"artifact.{package}.installed_sha256", installed)
        if installed != artifacts[key]:
            raise CheckError(f"installed artifact differs from dist: {package}; run {remediation}")
    report.kv("artifact.detector_source_sha256", artifacts["detector_source_sha256"])
    return artifacts


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


def capture_snapshot(adb: Adb, report: Report, prefix: str) -> dict[str, object]:
    removed = adb.shell("run-as", MODULE_PACKAGE, "rm", "-f", "files/framework.json", check=False)
    report.kv(f"{prefix}.snapshot_remove_exit", removed.returncode)
    if removed.returncode != 0:
        raise CheckError("could not invalidate the prior private framework snapshot")
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
    report.kv(f"{prefix}.capture_exit", launch.returncode)
    report.kv(f"{prefix}.capture_result", launch.stdout.strip()[:1000])
    if launch.returncode != 0 or "Error:" in launch.stdout:
        raise CheckError("module status capture did not launch")
    deadline = time.monotonic() + 8
    snapshot = None
    while time.monotonic() < deadline:
        snapshot = read_snapshot(adb)
        if snapshot is not None:
            break
        time.sleep(0.25)
    if snapshot is None:
        raise CheckError("fresh API-102 module snapshot was not published")
    if snapshot.get("schema_version") != 3 or snapshot.get("api_version") != 102:
        raise CheckError("module snapshot schema/API mismatch")
    scope = snapshot.get("scope")
    if not isinstance(scope, list) or not all(isinstance(item, str) for item in scope):
        raise CheckError("module snapshot scope is invalid")
    normalized_scope = sorted(cast(list[str], scope))
    report.kv(f"{prefix}.scope", normalized_scope)
    if normalized_scope != EXACT_SCOPE:
        raise CheckError("module scope is not the immutable exact two-probe set")
    targets = snapshot.get("running_targets")
    if not isinstance(targets, list) or not all(isinstance(item, dict) for item in targets):
        raise CheckError("API-102 running-target list is unavailable")
    report.kv(f"{prefix}.running_target_count", len(targets))
    return snapshot


def process_pid(adb: Adb, process: str) -> int:
    result = adb.shell("pidof", process, check=False)
    values = result.stdout.split()
    if result.returncode != 0 or len(values) != 1 or not values[0].isdigit():
        raise CheckError(f"expected one running probe PID: {process}")
    return int(values[0])


def target_records(snapshot: dict[str, object]) -> list[dict[str, object]]:
    value = snapshot.get("running_targets")
    if not isinstance(value, list):
        raise CheckError("running targets are invalid")
    return [cast(dict[str, object], item) for item in value if isinstance(item, dict)]


def assert_module_state(adb: Adb, report: Report, expected: str, process: str, prefix: str) -> None:
    if expected not in {"on", "off"}:
        raise CheckError("MODULE_EXPECTED must be on or off")
    pid = process_pid(adb, process)
    report.kv(f"{prefix}.process", process)
    report.kv(f"{prefix}.pid", pid)
    if expected == "off":
        time.sleep(0.5)
        logs = adb.run(
            "logcat",
            "-d",
            "--pid",
            str(pid),
            "-v",
            "brief",
            "ZygVeil:V",
            "*:S",
            timeout=15,
            check=False,
        )
        report.kv(f"{prefix}.logcat_exit", logs.returncode)
        lifecycle = [
            line
            for line in logs.stdout.splitlines()
            if "event=module_loaded" in line or "event=hook_install" in line
        ]
        report.kv(f"{prefix}.lifecycle_count", len(lifecycle))
        for line in lifecycle:
            report.line(line[:1000])
        if logs.returncode != 0:
            raise CheckError(f"could not inspect module lifecycle for process: {process}")
        if lifecycle:
            raise CheckError(f"module is active in an expected-off process: {process}")
        report.kv(f"{prefix}.state", "ORIGIN_ONLY_NO_MODULE_LIFECYCLE")
        return
    attempts = 5 if expected == "on" else 3
    for attempt in range(1, attempts + 1):
        snapshot = capture_snapshot(adb, report, f"{prefix}.capture_{attempt}")
        matching = [
            item
            for item in target_records(snapshot)
            if item.get("process") == process and item.get("pid") == pid
        ]
        report.kv(f"{prefix}.capture_{attempt}.matching_count", len(matching))
        if matching:
            target = matching[0]
            state = target.get("state", "unknown")
            loaded_version = target.get("loaded_version_code", "unknown")
            report.kv(f"{prefix}.state", state)
            report.kv(f"{prefix}.loaded_version_code", loaded_version)
            if expected == "off":
                raise CheckError(f"module is active in an expected-off process: {process}")
            if state != "UP_TO_DATE" or loaded_version != 1:
                raise CheckError(f"module target generation mismatch: {process}")
            report.kv(f"{prefix}.module_state", "on")
            return
        time.sleep(0.4)
    if expected == "on":
        raise CheckError(f"current module target did not appear: {process}")
    report.kv(f"{prefix}.module_state", "off")
