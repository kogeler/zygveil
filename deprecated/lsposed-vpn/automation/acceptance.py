# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Make-wrapped data-plane, rollback, and acceptance evidence orchestration."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import stat
import traceback
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from adb import Adb
from module_runtime import (
    PRIMARY_PACKAGE,
    artifact_identity,
    assert_module_state,
    validate_installed_artifacts,
)
from module_tests import (
    ASYNC_DETECTOR_GROUPS,
    LINK_DETECTOR_GROUPS,
    MODULE_SCHEMA_VERSION,
    SYNC_DETECTOR_GROUPS,
    select_native_pair,
)
from native_tests import (
    atomic_json,
    capture_vpn_state,
    differential_summary,
    load_detector_summary,
    raw_hash,
    read_summary,
    signal_status,
)
from reporting import CheckError, Report

from probe import EXPECTED_TEST_IDS, run_probe

ROOT = Path(__file__).resolve().parents[2]
MODULE_PACKAGE = "dev.zygveil.module"
PROVIDER_PACKAGE = "com.wireguard.android"
HMAC_KEY = ROOT / ".state/data-plane-hmac.key"
SAFE_PHASE_ID = re.compile(r"data-plane-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}")
SAFE_ROLLBACK_ID = re.compile(r"rollback-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}")
DATA_SCHEMA_VERSION = 2
ROLLBACK_SCHEMA_VERSION = 2
IP_CANDIDATE_PATTERN = re.compile(
    r"(?<![0-9A-Za-z_])([0-9A-Fa-f:.]+(?:%[0-9A-Za-z_.-]+)?)(?![0-9A-Za-z_])"
)
DYNAMIC_ROUTE_FIELDS = frozenset({"age", "expires", "used"})
ROUTE_SNAPSHOT_COUNT = 3
ROLLBACK_GROUPS = ("sync", *ASYNC_DETECTOR_GROUPS)
ROLLBACK_LINK_GROUPS = LINK_DETECTOR_GROUPS
ROLLBACK_DYNAMIC_LINK_IDS = frozenset({"link.all.routes", "link.callback.broad.routes"})
ROLLBACK_LINK_DISCRIMINATOR_COUNT = 33
VALIDATION_CONTRACT = ROOT / "docs/contracts/VALIDATION.md"
AUTOMATION_CONTRACT = ROOT / "docs/contracts/AUTOMATION.md"


def hmac_key() -> bytes:
    HMAC_KEY.parent.mkdir(parents=True, exist_ok=True)
    if not HMAC_KEY.exists():
        temporary = HMAC_KEY.with_name(f".{HMAC_KEY.name}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(secrets.token_bytes(32))
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(HMAC_KEY)
    mode = stat.S_IMODE(HMAC_KEY.stat().st_mode)
    value = HMAC_KEY.read_bytes()
    if mode != 0o600 or len(value) != 32:
        raise CheckError("private data-plane HMAC key has invalid mode or length")
    return value


def private_marker(key: bytes, value: str) -> str:
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()


def contains_ip_address(content: str) -> bool:
    for match in IP_CANDIDATE_PATTERN.finditer(content):
        candidate = match.group(1).split("%", 1)[0]
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return True
    return False


def privacy_oracle_self_test() -> None:
    safe = [
        "started_utc=2026-08-21T15:43:10Z",
        "egress_hmac=abcdef0123456789abcdef0123456789",
        "route_marker_schema=canonical-lifetime-v2",
    ]
    unsafe = [
        "value=192.0.2.1",
        "value=2001:db8:0:0:0:0:0:1",
        "value=2001:db8::1",
        "value=fe80::1%wlan0",
        "value=::ffff:192.0.2.1",
    ]
    if any(contains_ip_address(value) for value in safe):
        raise CheckError("address privacy self-test rejected safe report content")
    if not all(contains_ip_address(value) for value in unsafe):
        raise CheckError("address privacy self-test accepted an IP literal")


def canonical_route_inventory(raw: str) -> str:
    rows: list[str] = []
    for line in raw.splitlines():
        tokens = line.split()
        if not tokens:
            continue
        for index, token in enumerate(tokens):
            if token not in DYNAMIC_ROUTE_FIELDS:
                continue
            if index + 1 == len(tokens):
                raise CheckError(f"route lifetime field has no value: {token}")
            tokens[index + 1] = "<dynamic>"
        rows.append(" ".join(tokens))
    if not rows:
        raise CheckError("route inventory is empty")
    return "\n".join(sorted(rows))


def stable_route_marker(adb: Adb, key: bytes) -> str:
    markers: set[str] = set()
    for _ in range(ROUTE_SNAPSHOT_COUNT):
        result = adb.shell("ip", "-o", "route", "show", "table", "all", check=False)
        if result.returncode != 0:
            raise CheckError("route inventory is unavailable")
        markers.add(private_marker(key, canonical_route_inventory(result.stdout)))
    if len(markers) != 1:
        raise CheckError("canonical route inventory is unstable")
    return next(iter(markers))


def route_oracle_self_test() -> None:
    first = "\n".join(
        [
            "default via 192.0.2.1 dev tun0 expires 4sec metric 12",
            "local 192.0.2.2 dev tun0 table local used 7",
        ]
    )
    lifetime_changed = "\n".join(
        [
            "local 192.0.2.2 dev tun0 table local used 8",
            "default via 192.0.2.1 dev tun0 expires 3sec metric 12",
        ]
    )
    if canonical_route_inventory(first) != canonical_route_inventory(lifetime_changed):
        raise CheckError("route lifetime normalization self-test failed")
    for changed in [
        first.replace("metric 12", "metric 13"),
        first.replace("192.0.2.2", "192.0.2.3"),
        first.splitlines()[0],
    ]:
        if canonical_route_inventory(first) == canonical_route_inventory(changed):
            raise CheckError("route static-change self-test failed")
    try:
        canonical_route_inventory("default dev tun0 expires")
    except CheckError:
        return
    raise CheckError("malformed route lifetime self-test failed")


def provider_pid(adb: Adb) -> int:
    result = adb.shell("pidof", PROVIDER_PACKAGE, check=False)
    values = result.stdout.split()
    if result.returncode != 0 or len(values) != 1 or not values[0].isdigit():
        raise CheckError("expected one running VPN provider process")
    return int(values[0])


def verify_probe_uid_curl(adb: Adb, report: Report) -> None:
    identity = adb.shell("run-as", PRIMARY_PACKAGE, "id", check=False)
    if identity.returncode != 0:
        raise CheckError("could not enter the primary probe UID")
    uid = re.search(r"uid=(\d+)\(", identity.stdout)
    context = re.search(r"context=([^\s]+)", identity.stdout)
    if uid is None or "3003(inet)" not in identity.stdout:
        raise CheckError("primary probe UID lacks the Android inet group")
    if context is None or not context.group(1).startswith("u:r:runas_app:"):
        raise CheckError("primary probe run-as SELinux context is unexpected")
    curl = adb.shell("run-as", PRIMARY_PACKAGE, "/system/bin/curl", "--version", check=False)
    if curl.returncode != 0 or "Protocols:" not in curl.stdout or "https" not in curl.stdout:
        raise CheckError("Android curl does not provide HTTPS under the probe UID")
    report.kv("probe_uid", uid.group(1))
    report.kv("probe_uid_inet", "yes")
    report.kv("probe_uid_context", "runas_app")
    report.kv("curl_https", "yes")


def launch_load_only(adb: Adb, report: Report) -> None:
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
    report.kv("load_only_exit", launch.returncode)
    report.kv("load_only_result", launch.stdout.strip()[:1000])
    if launch.returncode != 0 or "Error:" in launch.stdout:
        raise CheckError("primary probe load-only launch failed")


def endpoint_marker(adb: Adb, endpoint: str) -> str | None:
    urls = {
        "ipify": "https://api.ipify.org",
        "cloudflare": "https://cloudflare.com/cdn-cgi/trace",
    }
    result = adb.shell(
        "run-as",
        PRIMARY_PACKAGE,
        "/system/bin/curl",
        "--silent",
        "--show-error",
        "--fail",
        "--ipv4",
        "--connect-timeout",
        "8",
        "--max-time",
        "15",
        urls[endpoint],
        timeout=25,
        check=False,
    )
    if result.returncode != 0:
        return None
    candidate = result.stdout.strip()
    if endpoint == "cloudflare":
        values = {
            key: value
            for line in candidate.splitlines()
            if "=" in line
            for key, value in [line.split("=", 1)]
        }
        candidate = values.get("ip", "")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def collect_egress(adb: Adb, report: Report, key: bytes) -> tuple[str, list[str]]:
    markers: dict[str, str] = {}
    for endpoint in ["ipify", "cloudflare"]:
        value = endpoint_marker(adb, endpoint)
        report.kv(f"endpoint.{endpoint}", "pass" if value is not None else "unavailable")
        if value is not None:
            markers[endpoint] = value
    if not markers:
        raise CheckError("all independent HTTPS data-plane endpoints are unavailable")
    if len(set(markers.values())) != 1:
        raise CheckError("independent endpoints observed different IPv4 egress markers")
    marker = private_marker(key, next(iter(markers.values())))
    return marker, sorted(markers)


def compatible_data_plane(
    current: dict[str, object], directory: Path
) -> tuple[dict[str, object], Path] | None:
    expected_module = "off" if current["module_expected"] == "on" else "on"
    candidates: list[tuple[dict[str, object], Path]] = []
    for path in sorted(directory.glob("data-plane-*/summary.json")):
        summary = read_summary(path)
        if summary is None:
            continue
        if (
            summary.get("schema_version") != DATA_SCHEMA_VERSION
            or summary.get("vpn_expected") != "on"
            or summary.get("module_expected") != expected_module
            or summary.get("artifacts") != current.get("artifacts")
            or summary.get("hmac_key_id") != current.get("hmac_key_id")
        ):
            continue
        candidates.append((summary, path))
    if not candidates:
        return None
    compatible = [
        item
        for item in candidates
        if item[0].get("egress_hmac") == current.get("egress_hmac")
        and item[0].get("route_hmac") == current.get("route_hmac")
    ]
    if not compatible:
        raise CheckError("opposite data-plane phase changed egress or route inventory")
    return compatible[-1]


def test_data_plane(report: Report, args: argparse.Namespace) -> None:
    if args.vpn_expected != "on":
        raise CheckError("test-data-plane requires VPN_EXPECTED=on")
    if args.module_expected not in {"on", "off"}:
        raise CheckError("MODULE_EXPECTED must be on or off")
    phase_id = datetime.now(UTC).strftime("data-plane-%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    if SAFE_PHASE_ID.fullmatch(phase_id) is None:
        raise CheckError("data-plane phase ID is invalid")
    run_directory = ROOT / args.report_dir / "data-plane" / phase_id
    run_directory.mkdir(parents=True)
    report.kv("phase_id", phase_id)
    report.kv("vpn_expected", "on")
    report.kv("module_expected", args.module_expected)

    adb = Adb.select(args.adb_serial, report)
    artifacts = validate_installed_artifacts(adb, report)
    key = hmac_key()
    key_id = hashlib.sha256(key).hexdigest()[:16]
    verify_probe_uid_curl(adb, report)
    before_vpn, before_report = capture_vpn_state(run_directory, "before", args.adb_serial, "on")
    provider_before = provider_pid(adb)
    route_before = stable_route_marker(adb, key)
    launch_load_only(adb, report)
    assert_module_state(
        adb,
        report,
        args.module_expected,
        PRIMARY_PACKAGE,
        "module_before_https",
    )
    egress_hmac, endpoints = collect_egress(adb, report, key)
    assert_module_state(
        adb,
        report,
        args.module_expected,
        PRIMARY_PACKAGE,
        "module_after_https",
    )
    route_after = stable_route_marker(adb, key)
    provider_after = provider_pid(adb)
    after_vpn, after_report = capture_vpn_state(run_directory, "after", args.adb_serial, "on")
    if before_vpn != after_vpn:
        raise CheckError("VPN state changed during data-plane phase")
    if provider_before != provider_after:
        raise CheckError("VPN provider process restarted during data-plane phase")
    if route_before != route_after:
        raise CheckError("route inventory changed during data-plane phase")

    summary: dict[str, object] = {
        "schema_version": DATA_SCHEMA_VERSION,
        "phase_id": phase_id,
        "vpn_expected": "on",
        "module_expected": args.module_expected,
        "artifacts": artifacts,
        "hmac_key_id": key_id,
        "egress_hmac": egress_hmac,
        "route_hmac": route_after,
        "route_marker_schema": "canonical-lifetime-v2",
        "route_snapshot_count": ROUTE_SNAPSHOT_COUNT,
        "successful_endpoints": endpoints,
        "provider_package": PROVIDER_PACKAGE,
        "provider_pid_stable": True,
        "state_before": before_vpn,
        "state_after": after_vpn,
        "vpn_reports": [
            str(before_report.relative_to(ROOT)),
            str(after_report.relative_to(ROOT)),
        ],
    }
    pairing = compatible_data_plane(summary, run_directory.parent)
    if pairing is None:
        summary["pairing"] = {
            "status": "WAITING_OPPOSITE_MODULE_STATE",
            "required_module_expected": "off" if args.module_expected == "on" else "on",
        }
        report.kv("pairing_status", "waiting_opposite_module_state")
    else:
        opposite, opposite_path = pairing
        complete_path = run_directory / "complete-data-plane.json"
        complete = {
            "schema_version": DATA_SCHEMA_VERSION,
            "status": "PASS",
            "artifacts": artifacts,
            "hmac_key_id": key_id,
            "module_on_phase_id": (
                phase_id if args.module_expected == "on" else opposite["phase_id"]
            ),
            "module_off_phase_id": (
                phase_id if args.module_expected == "off" else opposite["phase_id"]
            ),
            "egress_equal": True,
            "route_equal": True,
            "route_marker_schema": "canonical-lifetime-v2",
            "https_dns_tls": "PASS",
        }
        atomic_json(complete_path, complete)
        summary["pairing"] = {
            "status": "PAIRED",
            "opposite_summary": str(opposite_path.relative_to(ROOT)),
            "complete_data_plane": str(complete_path.relative_to(ROOT)),
        }
        report.kv("pairing_status", "paired")
        report.kv("complete_data_plane", complete_path.relative_to(ROOT))
    destination = run_directory / "summary.json"
    atomic_json(destination, summary)
    report.kv("successful_endpoint_count", len(endpoints))
    report.kv("egress_hmac", egress_hmac)
    report.kv("route_hmac", route_after)
    report.kv("route_marker_schema", "canonical-lifetime-v2")
    report.kv("route_snapshot_count", ROUTE_SNAPSHOT_COUNT)
    report.kv("provider_pid_stable", "yes")
    report.kv("summary", destination.relative_to(ROOT))
    report.kv("raw_network_values_persisted", "no")
    report.kv("device_mutation", "bounded force-stop/load-only launch of primary probe")
    report.assert_redacted([], [contains_ip_address])


def detector_map(detectors: list[dict[str, object]], run_id: str) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for detector in detectors:
        test_id = detector.get("test_id")
        if not isinstance(test_id, str) or test_id in result:
            raise CheckError(f"invalid rollback detector identity in {run_id}")
        result[test_id] = detector
    return result


def validate_native_on_reference(
    run_id: str,
    group: str,
    verdict: str,
    detectors: list[dict[str, object]],
    native_on: dict[str, object],
) -> tuple[int, list[dict[str, str]]]:
    runs = native_on.get("runs")
    if not isinstance(runs, list):
        raise CheckError("native ON run catalog is invalid")
    verdicts: set[str] = set()
    for item in runs:
        if not isinstance(item, dict) or item.get("group") != group:
            continue
        value = item.get("verdict")
        if not isinstance(value, str):
            raise CheckError(f"native ON verdict is invalid for {group}")
        verdicts.add(value)
    if verdicts != {"VPN_DETECTED"} or verdict != "VPN_DETECTED":
        raise CheckError(f"rollback did not restore VPN_DETECTED for {group}: {verdict}")
    native_signals_value = native_on.get("signals")
    if not isinstance(native_signals_value, dict):
        raise CheckError("native ON signal catalog is invalid")
    native_signals = cast(dict[str, object], native_signals_value)
    observed = detector_map(detectors, run_id)
    base_group = group.removeprefix("secondary-")
    expected_ids = EXPECTED_TEST_IDS[base_group]
    if set(observed) != expected_ids:
        raise CheckError(f"rollback detector catalog mismatch in {run_id}")
    mandatory_positive = 0
    optional_variations: list[dict[str, str]] = []
    for test_id in sorted(expected_ids):
        native_test_id = f"secondary::{test_id}" if group.startswith("secondary-") else test_id
        if native_test_id not in native_signals:
            raise CheckError(f"native ON signal is missing: {native_test_id}")
        expected_status, expected_mandatory, _ = signal_status(
            native_signals[native_test_id], native_test_id
        )
        detector = observed[test_id]
        observed_status = detector.get("status")
        if detector.get("mandatory") != expected_mandatory:
            raise CheckError(f"rollback mandatory flag mismatch in {run_id}: {test_id}")
        if expected_mandatory and observed_status != expected_status:
            raise CheckError(f"rollback mandatory status mismatch in {run_id}: {test_id}")
        if expected_mandatory and expected_status == "POSITIVE":
            mandatory_positive += 1
        if not expected_mandatory and observed_status != expected_status:
            if not isinstance(observed_status, str):
                raise CheckError(f"rollback optional status is invalid in {run_id}: {test_id}")
            optional_variations.append(
                {
                    "test_id": test_id,
                    "native_on_status": expected_status,
                    "rollback_status": observed_status,
                }
            )
    if mandatory_positive == 0:
        raise CheckError(f"rollback group has no restored mandatory positives: {group}")
    return mandatory_positive, optional_variations


def validate_native_link_on_reference(
    run_id: str,
    group: str,
    verdict: str,
    detectors: list[dict[str, object]],
    native_off: dict[str, object],
    native_on: dict[str, object],
) -> int:
    runs = native_on.get("runs")
    if not isinstance(runs, list):
        raise CheckError("native ON link run catalog is invalid")
    native_verdicts = {
        item.get("verdict")
        for item in runs
        if isinstance(item, dict) and item.get("group") == group
    }
    if len(native_verdicts) != 1 or verdict not in native_verdicts:
        raise CheckError(f"rollback link verdict mismatch for {group}: {verdict}")
    native_signals_value = native_on.get("signals")
    if not isinstance(native_signals_value, dict):
        raise CheckError("native ON link signal catalog is invalid")
    native_signals = cast(dict[str, object], native_signals_value)
    native_off_signals_value = native_off.get("signals")
    if not isinstance(native_off_signals_value, dict):
        raise CheckError("native OFF link signal catalog is invalid")
    native_off_signals = cast(dict[str, object], native_off_signals_value)
    observed = detector_map(detectors, run_id)
    expected_ids = EXPECTED_TEST_IDS["link"]
    if set(observed) != expected_ids:
        raise CheckError(f"rollback link detector catalog mismatch in {run_id}")
    prefix = "secondary::" if group.startswith("secondary-") else ""
    restored = 0
    for test_id in sorted(expected_ids):
        native_test_id = f"{prefix}{test_id}"
        if native_test_id not in native_signals or native_test_id not in native_off_signals:
            raise CheckError(f"native ON link signal is missing: {native_test_id}")
        expected_status, expected_mandatory, expected_hashes = signal_status(
            native_signals[native_test_id], native_test_id
        )
        _, _, off_hashes = signal_status(native_off_signals[native_test_id], native_test_id)
        detector = observed[test_id]
        if detector.get("status") == "ERROR":
            raise CheckError(f"rollback link detector error in {run_id}: {test_id}")
        calibrated = off_hashes != expected_hashes
        if not calibrated or test_id in ROLLBACK_DYNAMIC_LINK_IDS:
            continue
        if (
            detector.get("status") != expected_status
            or detector.get("mandatory") != expected_mandatory
        ):
            raise CheckError(f"rollback link status mismatch in {run_id}: {test_id}")
        if expected_hashes != [raw_hash(detector.get("raw_observations"))]:
            raise CheckError(f"rollback link structure mismatch in {run_id}: {test_id}")
        restored += 1
    return restored


def rollback_oracle_self_test() -> None:
    group = "async"
    test_ids = sorted(EXPECTED_TEST_IDS[group])
    mandatory_id, optional_id = test_ids[:2]
    signals: dict[str, object] = {
        test_id: {"statuses": ["NEGATIVE"], "mandatory": False, "raw_hashes": ["self-test"]}
        for test_id in test_ids
    }
    signals[mandatory_id] = {
        "statuses": ["POSITIVE"],
        "mandatory": True,
        "raw_hashes": ["self-test"],
    }
    detectors: list[dict[str, object]] = [
        {
            "test_id": test_id,
            "status": "POSITIVE" if test_id in {mandatory_id, optional_id} else "NEGATIVE",
            "mandatory": test_id == mandatory_id,
        }
        for test_id in test_ids
    ]
    native_on: dict[str, object] = {
        "runs": [{"group": group, "verdict": "VPN_DETECTED"}],
        "signals": signals,
    }
    restored, variations = validate_native_on_reference(
        "self-test-optional-variation", group, "VPN_DETECTED", detectors, native_on
    )
    if restored != 1 or [item["test_id"] for item in variations] != [optional_id]:
        raise CheckError("rollback optional variation self-test failed")
    secondary_native_on: dict[str, object] = {
        "runs": [{"group": "secondary-async", "verdict": "VPN_DETECTED"}],
        "signals": {f"secondary::{test_id}": value for test_id, value in signals.items()},
    }
    secondary_restored, _ = validate_native_on_reference(
        "self-test-secondary", "secondary-async", "VPN_DETECTED", detectors, secondary_native_on
    )
    if secondary_restored != 1:
        raise CheckError("rollback secondary native mapping self-test failed")
    missing = [dict(detector) for detector in detectors]
    for detector in missing:
        if detector["test_id"] == mandatory_id:
            detector["status"] = "NEGATIVE"
    try:
        validate_native_on_reference(
            "self-test-missing-mandatory", group, "VPN_DETECTED", missing, native_on
        )
    except CheckError:
        pass
    else:
        raise CheckError("rollback missing mandatory-positive self-test failed")

    link_raw = {"comparison": {"specified": False}, "diagnostic": {"value": -(2**31)}}
    link_signals = {
        test_id: {
            "statuses": ["NEGATIVE"],
            "mandatory": False,
            "raw_hashes": [raw_hash(link_raw)],
        }
        for test_id in EXPECTED_TEST_IDS["link"]
    }
    link_detectors = [
        {
            "test_id": test_id,
            "status": "NEGATIVE",
            "mandatory": False,
            "raw_observations": link_raw,
        }
        for test_id in EXPECTED_TEST_IDS["link"]
    ]
    link_on: dict[str, object] = {
        "runs": [{"group": "link", "verdict": "NO_PUBLIC_VPN_SIGNAL"}],
        "signals": link_signals,
    }
    link_off: dict[str, object] = {
        "signals": {
            test_id: {
                "statuses": ["NEGATIVE"],
                "mandatory": False,
                "raw_hashes": ["different-off-hash"],
            }
            for test_id in EXPECTED_TEST_IDS["link"]
        }
    }
    if validate_native_link_on_reference(
        "self-test-link-rollback",
        "link",
        "NO_PUBLIC_VPN_SIGNAL",
        link_detectors,
        link_off,
        link_on,
    ) != len(EXPECTED_TEST_IDS["link"] - ROLLBACK_DYNAMIC_LINK_IDS):
        raise CheckError("rollback link structural count self-test failed")


def test_rollback(report: Report, args: argparse.Namespace) -> None:
    if args.vpn_expected != "on" or args.module_expected != "off":
        raise CheckError("test-rollback requires VPN_EXPECTED=on MODULE_EXPECTED=off")
    if args.repeat < 2 or args.repeat > 10:
        raise CheckError("REPEAT must be between 2 and 10")
    rollback_id = datetime.now(UTC).strftime("rollback-%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    if SAFE_ROLLBACK_ID.fullmatch(rollback_id) is None:
        raise CheckError("rollback ID is invalid")
    run_directory = ROOT / args.report_dir / "rollback" / rollback_id
    run_directory.mkdir(parents=True)
    report.kv("rollback_id", rollback_id)
    report.kv("vpn_expected", "on")
    report.kv("module_expected", "off")
    report.kv("repeat", args.repeat)
    adb = Adb.select(args.adb_serial, report)
    artifacts = validate_installed_artifacts(adb, report)
    _, sync_on, _, sync_on_path = select_native_pair(
        ROOT / args.native_report_dir, "sync", SYNC_DETECTOR_GROUPS
    )
    _, async_on, _, async_on_path = select_native_pair(
        ROOT / args.native_report_dir, "async", ASYNC_DETECTOR_GROUPS
    )
    link_off, link_on, _, link_on_path = select_native_pair(
        ROOT / args.native_report_dir, "link", LINK_DETECTOR_GROUPS
    )
    native_by_group = {
        "sync": sync_on,
        **{group: async_on for group in ASYNC_DETECTOR_GROUPS},
        **{group: link_on for group in LINK_DETECTOR_GROUPS},
    }
    report.kv("native_sync_on", sync_on_path.relative_to(ROOT))
    report.kv("native_async_on", async_on_path.relative_to(ROOT))
    report.kv("native_link_on", link_on_path.relative_to(ROOT))
    before_state, before_report = capture_vpn_state(run_directory, "before", args.adb_serial, "on")
    run_summaries: list[dict[str, object]] = []
    restored_counts: dict[str, set[int]] = {group: set() for group in ROLLBACK_GROUPS}
    restored_link_counts: dict[str, set[int]] = {group: set() for group in ROLLBACK_LINK_GROUPS}
    optional_variation_total = 0
    for group in (*ROLLBACK_GROUPS, *ROLLBACK_LINK_GROUPS):
        for index in range(1, args.repeat + 1):
            child_name = f"{group}-run-{index}"
            child_args = argparse.Namespace(
                adb_serial=args.adb_serial,
                variant="primary",
                vpn_expected="on",
                module_expected="off",
                group=group,
            )
            child_path = run_directory / f"{child_name}.txt"
            with Report(run_directory, child_name) as child_report:
                run_probe(child_report, child_args)
                process = (
                    f"{PRIMARY_PACKAGE}:secondary"
                    if group.startswith("secondary-")
                    else PRIMARY_PACKAGE
                )
                assert_module_state(
                    adb,
                    child_report,
                    "off",
                    process,
                    "module_oracle",
                )
            run_id = report_value(child_path, "run_id")
            verdict, detectors = load_detector_summary(run_id)
            run_summary: dict[str, object] = {
                "group": group,
                "index": index,
                "run_id": run_id,
                "verdict": verdict,
            }
            if group in ROLLBACK_LINK_GROUPS:
                count = validate_native_link_on_reference(
                    run_id, group, verdict, detectors, link_off, native_by_group[group]
                )
                if count != ROLLBACK_LINK_DISCRIMINATOR_COUNT:
                    raise CheckError(
                        f"rollback calibrated LinkProperties count mismatch: {group}: {count}"
                    )
                restored_link_counts[group].add(count)
                run_summary["structural_match_count"] = count
                report.kv(f"{group}.{index}.structural_match_count", count)
            else:
                count, optional_variations = validate_native_on_reference(
                    run_id, group, verdict, detectors, native_by_group[group]
                )
                restored_counts[group].add(count)
                optional_variation_total += len(optional_variations)
                run_summary["mandatory_positive_count"] = count
                run_summary["optional_status_variations"] = optional_variations
                report.kv(f"{group}.{index}.mandatory_positive_count", count)
                report.kv(f"{group}.{index}.optional_variation_count", len(optional_variations))
            run_summaries.append(run_summary)
            report.kv(f"{group}.{index}.id", run_id)
    if any(len(values) != 1 for values in restored_counts.values()):
        raise CheckError("rollback mandatory-positive counts are unstable")
    if any(len(values) != 1 for values in restored_link_counts.values()):
        raise CheckError("rollback LinkProperties structural counts are unstable")
    restored_by_group = {group: next(iter(values)) for group, values in restored_counts.items()}
    restored_link_by_group = {
        group: next(iter(values)) for group, values in restored_link_counts.items()
    }
    async_mandatory_total = sum(restored_by_group[group] for group in ASYNC_DETECTOR_GROUPS)
    after_state, after_report = capture_vpn_state(run_directory, "after", args.adb_serial, "on")
    if before_state != after_state:
        raise CheckError("VPN state changed during rollback verification")
    summary = {
        "schema_version": ROLLBACK_SCHEMA_VERSION,
        "rollback_id": rollback_id,
        "status": "PASS",
        "vpn_expected": "on",
        "module_expected": "off",
        "artifacts": artifacts,
        "native_sync_on_id": sync_on["baseline_id"],
        "native_async_on_id": async_on["baseline_id"],
        "native_link_on_id": link_on["baseline_id"],
        "repeat": args.repeat,
        "runs": run_summaries,
        "restored_mandatory_positive_counts": restored_by_group,
        "restored_link_structural_counts": restored_link_by_group,
        "restored_mandatory_positive_totals": {
            "sync": restored_by_group["sync"],
            "async": async_mandatory_total,
        },
        "optional_status_variation_total": optional_variation_total,
        "state_before": before_state,
        "state_after": after_state,
        "vpn_reports": [
            str(before_report.relative_to(ROOT)),
            str(after_report.relative_to(ROOT)),
        ],
        "scope_policy": "exact two-probe scope retained",
    }
    destination = run_directory / "summary.json"
    atomic_json(destination, summary)
    for group in ROLLBACK_GROUPS:
        report.kv(f"restored.{group}.mandatory_positive", restored_by_group[group])
    for group in ROLLBACK_LINK_GROUPS:
        report.kv(f"restored.{group}.structural", restored_link_by_group[group])
    report.kv("restored_sync_mandatory_positive", restored_by_group["sync"])
    report.kv("restored_async_mandatory_positive", async_mandatory_total)
    report.kv("optional_status_variation_total", optional_variation_total)
    report.kv("summary", destination.relative_to(ROOT))
    report.kv("device_mutation", "bounded force-stop/launch of exact primary probe only")


def report_value(path: Path, key: str) -> str:
    prefix = key + "="
    values = [
        line.removeprefix(prefix)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.startswith(prefix)
    ]
    if len(values) != 1:
        raise CheckError(f"expected one {key} in {path.relative_to(ROOT)}")
    return values[0]


def current_native_pairs(report: Report, native_directory: Path) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for group, detector_groups in [
        ("sync", SYNC_DETECTOR_GROUPS),
        ("async", ASYNC_DETECTOR_GROUPS),
        ("link", LINK_DETECTOR_GROUPS),
    ]:
        off, on, off_path, on_path = select_native_pair(native_directory, group, detector_groups)
        off_id = cast(str, off["baseline_id"])
        on_id = cast(str, on["baseline_id"])
        differential = differential_summary(off, on)
        result[group] = (off_id, on_id)
        report.kv(f"native.{group}.off_id", off_id)
        report.kv(f"native.{group}.on_id", on_id)
        report.kv(f"native.{group}.off_summary", off_path.relative_to(ROOT))
        report.kv(f"native.{group}.on_summary", on_path.relative_to(ROOT))
        report.kv(f"native.{group}.signal_count", differential["signal_count"])
        report.kv(
            f"native.{group}.calibrated_mandatory_count",
            differential["calibrated_mandatory_count"],
        )
    return result


def latest_complete(
    directory: Path,
    pattern: str,
    artifacts: dict[str, str],
    expected_count: int | None = None,
) -> tuple[dict[str, object], Path]:
    candidates: list[tuple[dict[str, object], Path]] = []
    for path in sorted(directory.glob(pattern)):
        summary = read_summary(path)
        if summary is None or summary.get("status") != "PASS":
            continue
        if summary.get("artifacts") != artifacts:
            continue
        if expected_count is not None and summary.get("signal_count") != expected_count:
            continue
        candidates.append((summary, path))
    if not candidates:
        raise CheckError(f"compatible complete evidence is missing: {pattern}")
    return candidates[-1]


def verify_baseline(report: Report, args: argparse.Namespace) -> dict[str, tuple[str, str]]:
    pairs = current_native_pairs(report, ROOT / args.native_report_dir)
    report.kv("native_pair_count", len(pairs))
    return pairs


def verify_device(report: Report, args: argparse.Namespace) -> dict[str, dict[str, object]]:
    artifacts = artifact_identity()
    sync, sync_path = latest_complete(
        ROOT / args.module_report_dir / "sync",
        "module-sync-*/complete-matrix.json",
        artifacts,
        84,
    )
    asynchronous, async_path = latest_complete(
        ROOT / args.module_report_dir / "async",
        "module-async-*/complete-matrix.json",
        artifacts,
        48,
    )
    link, link_path = latest_complete(
        ROOT / args.module_report_dir / "link",
        "module-link-*/complete-matrix.json",
        artifacts,
        138,
    )
    data_plane, data_path = latest_complete(
        ROOT / args.report_dir / "data-plane",
        "data-plane-*/complete-data-plane.json",
        artifacts,
    )
    for group, summary, count in [
        ("sync", sync, 84),
        ("async", asynchronous, 48),
        ("link", link, 138),
    ]:
        if (
            summary.get("schema_version") != MODULE_SCHEMA_VERSION
            or summary.get("group") != group
            or summary.get("module_expected") != "on"
            or summary.get("signal_count") != count
            or not all(
                isinstance(summary.get(key), str)
                for key in ["vpn_off_matrix_id", "vpn_on_matrix_id"]
            )
        ):
            raise CheckError(f"complete module {group} evidence has invalid fields")
    if link.get("covered_signal_count") != 69 or link.get("residual_signal_count") != 69:
        raise CheckError("complete module link coverage counts are invalid")
    if (
        data_plane.get("schema_version") != DATA_SCHEMA_VERSION
        or data_plane.get("https_dns_tls") != "PASS"
        or data_plane.get("egress_equal") is not True
        or data_plane.get("route_equal") is not True
        or data_plane.get("route_marker_schema") != "canonical-lifetime-v2"
        or not isinstance(data_plane.get("hmac_key_id"), str)
        or re.fullmatch(r"[0-9a-f]{16}", cast(str, data_plane["hmac_key_id"])) is None
    ):
        raise CheckError("complete data-plane evidence has invalid fields")
    report.kv("module_sync_complete", sync_path.relative_to(ROOT))
    report.kv("module_async_complete", async_path.relative_to(ROOT))
    report.kv("module_link_complete", link_path.relative_to(ROOT))
    report.kv("data_plane_complete", data_path.relative_to(ROOT))
    report.kv("module_sync_signal_count", sync["signal_count"])
    report.kv("module_async_signal_count", asynchronous["signal_count"])
    report.kv("module_link_signal_count", link["signal_count"])
    report.kv("module_link_covered_signal_count", link["covered_signal_count"])
    report.kv("module_link_residual_signal_count", link["residual_signal_count"])
    report.kv("data_plane_egress_equal", data_plane["egress_equal"])
    report.kv("data_plane_route_equal", data_plane["route_equal"])
    return {"sync": sync, "async": asynchronous, "link": link, "data_plane": data_plane}


def verify_rollback(report: Report, args: argparse.Namespace) -> dict[str, object]:
    summary, path = latest_complete(
        ROOT / args.report_dir / "rollback",
        "rollback-*/summary.json",
        artifact_identity(),
    )
    counts = summary.get("restored_mandatory_positive_counts")
    link_counts = summary.get("restored_link_structural_counts")
    runs = summary.get("runs")
    if (
        summary.get("schema_version") != ROLLBACK_SCHEMA_VERSION
        or summary.get("vpn_expected") != "on"
        or summary.get("module_expected") != "off"
        or summary.get("repeat") != 3
        or summary.get("state_before") != "yes"
        or summary.get("state_after") != "yes"
        or not isinstance(runs, list)
        or len(runs) != 3 * (len(ROLLBACK_GROUPS) + len(ROLLBACK_LINK_GROUPS))
    ):
        raise CheckError("rollback state/run evidence is invalid")
    for group in ROLLBACK_GROUPS:
        group_runs = [
            item for item in runs if isinstance(item, dict) and item.get("group") == group
        ]
        if (
            len(group_runs) != 3
            or {item.get("index") for item in group_runs} != {1, 2, 3}
            or any(item.get("verdict") != "VPN_DETECTED" for item in group_runs)
        ):
            raise CheckError(f"rollback repetitions are invalid for {group}")
    for group in ROLLBACK_LINK_GROUPS:
        group_runs = [
            item for item in runs if isinstance(item, dict) and item.get("group") == group
        ]
        if (
            len(group_runs) != 3
            or {item.get("index") for item in group_runs} != {1, 2, 3}
            or any(
                item.get("structural_match_count") != ROLLBACK_LINK_DISCRIMINATOR_COUNT
                for item in group_runs
            )
        ):
            raise CheckError(f"rollback LinkProperties repetitions are invalid for {group}")
    if (
        not isinstance(counts, dict)
        or set(counts) != set(ROLLBACK_GROUPS)
        or not all(isinstance(value, int) and value > 0 for value in counts.values())
    ):
        raise CheckError("rollback mandatory-positive evidence is invalid")
    if (
        not isinstance(link_counts, dict)
        or set(link_counts) != set(ROLLBACK_LINK_GROUPS)
        or any(value != ROLLBACK_LINK_DISCRIMINATOR_COUNT for value in link_counts.values())
    ):
        raise CheckError("rollback LinkProperties structural evidence is invalid")
    totals = summary.get("restored_mandatory_positive_totals")
    if not isinstance(totals, dict) or totals != {
        "sync": counts["sync"],
        "async": sum(counts[group] for group in ASYNC_DETECTOR_GROUPS),
    }:
        raise CheckError("rollback mandatory-positive totals are invalid")
    report.kv("rollback_summary", path.relative_to(ROOT))
    report.kv("rollback_restored_counts", cast(dict[str, object], counts))
    report.kv("rollback_link_structural_counts", cast(dict[str, object], link_counts))
    report.kv("rollback_restored_totals", cast(dict[str, object], totals))
    return summary


def verify_matrix(
    report: Report, args: argparse.Namespace
) -> tuple[
    dict[str, tuple[str, str]],
    dict[str, dict[str, object]],
    dict[str, object],
]:
    pairs = verify_baseline(report, args)
    device = verify_device(report, args)
    rollback = verify_rollback(report, args)
    for group in ["sync", "async", "link"]:
        oracle = device[group].get("native_oracle")
        expected = {"off_id": pairs[group][0], "on_id": pairs[group][1]}
        if not isinstance(oracle, dict) or any(
            oracle.get(key) != value for key, value in expected.items()
        ):
            raise CheckError(f"module {group} evidence does not bind the selected native pair")
        calibrated = oracle.get("calibrated_mandatory_count")
        structural = oracle.get("structural_differential_count")
        if group == "link":
            if calibrated != 0 or not isinstance(structural, int) or structural <= 0:
                raise CheckError("module link native oracle lacks structural calibration")
        elif not isinstance(calibrated, int) or calibrated <= 0:
            raise CheckError(f"module {group} native oracle has no calibrated mandatory signal")
        report.kv(f"module.{group}.native_pair_bound", "true")
    if (
        rollback.get("native_sync_on_id") != pairs["sync"][1]
        or rollback.get("native_async_on_id") != pairs["async"][1]
        or rollback.get("native_link_on_id") != pairs["link"][1]
    ):
        raise CheckError("rollback evidence does not bind the selected native ON references")
    report.kv("rollback.native_on_bound", "true")
    report.kv("matrix_status", "PASS")
    return pairs, device, rollback


def verify_repository_check(report: Report, args: argparse.Namespace) -> None:
    native_pairs, device, rollback = verify_matrix(report, args)
    if not VALIDATION_CONTRACT.is_file():
        raise CheckError("validation contract is missing")
    validation = VALIDATION_CONTRACT.read_text(encoding="utf-8")
    for label, digest in artifact_identity().items():
        if digest not in validation:
            raise CheckError(f"validation contract omits current artifact hash: {label}")
        report.kv(f"artifact.{label}", digest)

    evidence_ids: dict[str, object] = {
        "native_sync_off": native_pairs["sync"][0],
        "native_sync_on": native_pairs["sync"][1],
        "native_async_off": native_pairs["async"][0],
        "native_async_on": native_pairs["async"][1],
        "native_link_off": native_pairs["link"][0],
        "native_link_on": native_pairs["link"][1],
        "module_sync_off": device["sync"].get("vpn_off_matrix_id"),
        "module_sync_on": device["sync"].get("vpn_on_matrix_id"),
        "module_async_off": device["async"].get("vpn_off_matrix_id"),
        "module_async_on": device["async"].get("vpn_on_matrix_id"),
        "module_link_off": device["link"].get("vpn_off_matrix_id"),
        "module_link_on": device["link"].get("vpn_on_matrix_id"),
        "data_plane_on": device["data_plane"].get("module_on_phase_id"),
        "data_plane_off": device["data_plane"].get("module_off_phase_id"),
        "rollback": rollback.get("rollback_id"),
    }
    for label, evidence_id in evidence_ids.items():
        if not isinstance(evidence_id, str) or evidence_id not in validation:
            raise CheckError(f"validation contract omits selected evidence ID: {label}")
        report.kv(f"evidence.{label}", evidence_id)

    required_reports = [
        Path(".artifacts/reports/baseline/docs-check.txt"),
        Path(".artifacts/reports/baseline/syntax.txt"),
        Path(".artifacts/reports/quality/format-check.txt"),
        Path(".artifacts/reports/quality/lint.txt"),
        Path(".artifacts/reports/quality/static-analysis.txt"),
        Path(".artifacts/reports/policy/test-unit.txt"),
        Path(".artifacts/reports/container/signing-info.txt"),
        Path(".artifacts/reports/container/network-block.txt"),
        Path(".artifacts/reports/container/confinement.txt"),
    ]
    for relative in required_reports:
        path = ROOT / relative
        if not path.is_file() or "exit_status=0" not in path.read_text(encoding="utf-8"):
            raise CheckError(f"required successful report is missing: {relative}")
        report.kv(f"gate.{path.stem}", relative)

    if not AUTOMATION_CONTRACT.is_file():
        raise CheckError("automation contract is missing")
    signing_report = ROOT / ".artifacts/reports/container/signing-info.txt"
    certificate = report_value(signing_report, "certificate_sha256")
    if certificate not in AUTOMATION_CONTRACT.read_text(encoding="utf-8"):
        raise CheckError("automation contract omits current signing certificate")
    report.kv("signing_certificate", certificate)
    report.kv("check_status", "PASS")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--native-report-dir", required=True)
    parser.add_argument("--module-report-dir", required=True)
    parser.add_argument("--adb-serial", default="")
    parser.add_argument("--vpn-expected", default="")
    parser.add_argument("--module-expected", default="")
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument(
        "command",
        choices=[
            "test-data-plane",
            "test-rollback",
            "test-baseline",
            "test-device",
            "test-matrix",
            "check",
        ],
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    commands = {
        "test-data-plane": test_data_plane,
        "test-rollback": test_rollback,
        "test-baseline": verify_baseline,
        "test-device": verify_device,
        "test-matrix": verify_matrix,
        "check": verify_repository_check,
    }
    try:
        with Report(ROOT / args.report_dir, args.command) as report:
            commands[args.command](report, args)
    except CheckError:
        return 1
    except Exception:
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
