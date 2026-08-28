# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Make-wrapped post-hook differential orchestration."""

from __future__ import annotations

import argparse
import re
import traceback
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from adb import Adb
from module_runtime import (
    PRIMARY_PACKAGE,
    assert_module_state,
    validate_installed_artifacts,
)
from native_tests import (
    SUMMARY_SCHEMA_VERSION as NATIVE_SCHEMA_VERSION,
)
from native_tests import (
    artifact_identity as native_artifact_identity,
)
from native_tests import (
    atomic_json,
    capture_vpn_state,
    differential_summary,
    load_detector_summary,
    raw_hash,
    read_summary,
    run_native_baseline,
    signal_status,
)
from reporting import CheckError, Report

from probe import EXPECTED_TEST_IDS, run_probe

ROOT = Path(__file__).resolve().parents[2]
SAFE_MATRIX_ID = re.compile(r"module-(?:sync|async|link)-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}")
MODULE_SCHEMA_VERSION = 2
CANARY_PACKAGE = "dev.zygveil.probe.canary"
SYNC_DETECTOR_GROUPS = ("sync",)
ASYNC_DETECTOR_GROUPS = ("async", "active", "secondary-async", "secondary-active")
LINK_DETECTOR_GROUPS = ("link", "secondary-link")
SYNC_ROLES = (
    ("primary_main", "primary", "sync", PRIMARY_PACKAGE),
    ("primary_secondary", "primary", "secondary-sync", f"{PRIMARY_PACKAGE}:secondary"),
    ("canary_main", "canary", "sync", CANARY_PACKAGE),
)
ASYNC_ROLES = (
    ("primary_main_async", "primary", "async", PRIMARY_PACKAGE),
    ("primary_main_active", "primary", "active", PRIMARY_PACKAGE),
    (
        "primary_secondary_async",
        "primary",
        "secondary-async",
        f"{PRIMARY_PACKAGE}:secondary",
    ),
    (
        "primary_secondary_active",
        "primary",
        "secondary-active",
        f"{PRIMARY_PACKAGE}:secondary",
    ),
    ("canary_main_async", "canary", "async", CANARY_PACKAGE),
    ("canary_main_active", "canary", "active", CANARY_PACKAGE),
)
LINK_ROLES = (
    ("primary_main", "primary", "link", PRIMARY_PACKAGE),
    ("primary_secondary", "primary", "secondary-link", f"{PRIMARY_PACKAGE}:secondary"),
    ("canary_main", "canary", "link", CANARY_PACKAGE),
)
LINK_COVERED_PREFIXES = ("link.active.", "link.callback.broad.")
LINK_RESIDUAL_PREFIXES = ("link.all.", "link.callback.default.")


def expected_native_signal_ids(detector_groups: tuple[str, ...]) -> set[str]:
    expected: set[str] = set()
    for group in detector_groups:
        base_group = group.removeprefix("secondary-")
        test_ids = EXPECTED_TEST_IDS.get(base_group)
        if test_ids is None:
            raise CheckError(f"unsupported native detector group: {group}")
        prefix = "secondary::" if group.startswith("secondary-") else ""
        group_ids = {f"{prefix}{test_id}" for test_id in test_ids}
        if expected & group_ids:
            raise CheckError(f"native detector groups overlap: {group}")
        expected.update(group_ids)
    return expected


def select_native_pair(
    directory: Path,
    baseline_group: str,
    detector_groups: tuple[str, ...],
) -> tuple[dict[str, object], dict[str, object], Path, Path]:
    identity = native_artifact_identity()
    expected_signals = expected_native_signal_ids(detector_groups)
    states: dict[str, list[tuple[dict[str, object], Path]]] = {"off": [], "on": []}
    for path in sorted(
        (directory / baseline_group).glob(f"native-{baseline_group}-*/summary.json")
    ):
        summary = read_summary(path)
        if summary is None:
            continue
        state = summary.get("vpn_expected")
        if state not in states:
            continue
        signals = summary.get("signals")
        if (
            summary.get("schema_version") != NATIVE_SCHEMA_VERSION
            or summary.get("group") != baseline_group
            or summary.get("detector_groups") != list(detector_groups)
            or summary.get("module_expected") != "off"
            or summary.get("artifacts") != identity
            or not isinstance(signals, dict)
            or set(signals) != expected_signals
        ):
            continue
        states[state].append((summary, path))
    if not states["off"] or not states["on"]:
        missing = [state for state, values in states.items() if not values]
        raise CheckError(
            f"current-artifact native {baseline_group} reference is incomplete; run "
            f"make test-module-{baseline_group} MODULE_EXPECTED=off for VPN states: {missing}"
        )
    off, off_path = states["off"][-1]
    compatible_on = [
        item
        for item in states["on"]
        if item[0].get("signals") is not None
        and set(cast(dict[str, object], item[0]["signals"]))
        == set(cast(dict[str, object], off["signals"]))
    ]
    if not compatible_on:
        raise CheckError(f"current native {baseline_group} OFF/ON catalogs are incompatible")
    on, on_path = compatible_on[-1]
    return off, on, off_path, on_path


def detector_map(detectors: list[dict[str, object]], run_id: str) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for detector in detectors:
        test_id = detector.get("test_id")
        if not isinstance(test_id, str) or test_id in result:
            raise CheckError(f"invalid detector identity in {run_id}")
        result[test_id] = detector
    return result


def validate_against_native_off(
    run_id: str,
    group: str,
    verdict: str,
    detectors: list[dict[str, object]],
    native_off: dict[str, object],
) -> None:
    base_group = group.removeprefix("secondary-")
    native_groups = native_off.get("detector_groups")
    if not isinstance(native_groups, list) or not all(
        isinstance(item, str) for item in native_groups
    ):
        raise CheckError("native OFF detector-group summary is invalid")
    if group in native_groups:
        native_group = group
        prefix = "secondary::" if group.startswith("secondary-") else ""
    elif group == "secondary-sync" and base_group in native_groups:
        native_group = base_group
        prefix = ""
    else:
        raise CheckError(f"native OFF detector group is missing: {group}")
    runs_value = native_off.get("runs")
    if not isinstance(runs_value, list):
        raise CheckError("native OFF run summary is invalid")
    native_verdicts: set[str] = set()
    for item in runs_value:
        if not isinstance(item, dict) or item.get("group") != native_group:
            continue
        native_verdict = item.get("verdict")
        if not isinstance(native_verdict, str):
            raise CheckError(f"native OFF verdict is invalid for group {group}")
        native_verdicts.add(native_verdict)
    if len(native_verdicts) != 1:
        raise CheckError(f"native OFF verdict is unstable or missing for group {group}")
    expected_verdict = next(iter(native_verdicts))
    if verdict != expected_verdict:
        raise CheckError(
            f"module/native OFF verdict mismatch in {run_id}: "
            f"expected {expected_verdict}, observed {verdict}"
        )
    native_signals_value = native_off.get("signals")
    if not isinstance(native_signals_value, dict):
        raise CheckError("native OFF signal summary is invalid")
    native_signals = cast(dict[str, object], native_signals_value)
    observed = detector_map(detectors, run_id)
    expected_ids = EXPECTED_TEST_IDS.get(base_group)
    if expected_ids is None or set(observed) != expected_ids:
        raise CheckError(f"module/native detector catalog mismatch in {run_id}")
    for test_id, detector in observed.items():
        native_test_id = f"{prefix}{test_id}"
        if native_test_id not in native_signals:
            raise CheckError(f"native OFF signal is missing: {native_test_id}")
        expected_status, expected_mandatory, expected_raw_hashes = signal_status(
            native_signals[native_test_id], native_test_id
        )
        status = detector.get("status")
        if status == "ERROR":
            raise CheckError(f"module detector error in {run_id}: {test_id}")
        if status != expected_status or detector.get("mandatory") != expected_mandatory:
            raise CheckError(
                f"module/native OFF mismatch in {run_id}: {test_id}: "
                f"expected {expected_status}, observed {status}"
            )
        if base_group == "link" and test_id.startswith(LINK_COVERED_PREFIXES):
            observed_hash = raw_hash(detector.get("raw_observations"))
            if expected_raw_hashes != [observed_hash]:
                raise CheckError(f"module/native OFF structural mismatch in {run_id}: {test_id}")


def compatible_module_summary(
    current: dict[str, object], directory: Path, baseline_group: str
) -> tuple[dict[str, object], Path] | None:
    expected_state = "off" if current["vpn_expected"] == "on" else "on"
    candidates: list[tuple[dict[str, object], Path]] = []
    for path in sorted(directory.glob(f"module-{baseline_group}-*/summary.json")):
        summary = read_summary(path)
        if summary is None:
            continue
        if (
            summary.get("schema_version") != MODULE_SCHEMA_VERSION
            or summary.get("group", "sync") != baseline_group
            or summary.get("module_expected") != "on"
            or summary.get("vpn_expected") != expected_state
            or summary.get("artifacts") != current.get("artifacts")
            or summary.get("native_oracle") != current.get("native_oracle")
            or summary.get("roles") != current.get("roles")
        ):
            continue
        candidates.append((summary, path))
    if not candidates:
        return None
    current_projection = signal_projection(current)
    compatible = [item for item in candidates if signal_projection(item[0]) == current_projection]
    if not compatible:
        raise CheckError("opposite module phase has a detector catalog/status mismatch")
    return compatible[-1]


def signal_projection(summary: dict[str, object]) -> dict[str, str]:
    signals_value = summary.get("signals")
    if not isinstance(signals_value, dict):
        raise CheckError("module phase signal summary is invalid")
    projection: dict[str, str] = {}
    for test_id, value in signals_value.items():
        if not isinstance(test_id, str) or not isinstance(value, dict):
            raise CheckError("module phase signal entry is invalid")
        status = value.get("status")
        if not isinstance(status, str):
            raise CheckError(f"module phase signal status is invalid: {test_id}")
        projection[test_id] = status
    return projection


def run_module_on(
    report: Report,
    args: argparse.Namespace,
    baseline_group: str,
    detector_groups: tuple[str, ...],
    roles: tuple[tuple[str, str, str, str], ...],
) -> None:
    if args.vpn_expected not in {"on", "off"}:
        raise CheckError("VPN_EXPECTED must be on or off")
    if args.repeat < 2 or args.repeat > 10:
        raise CheckError("REPEAT must be between 2 and 10")
    matrix_id = (
        datetime.now(UTC).strftime(f"module-{baseline_group}-%Y%m%dT%H%M%SZ-")
        + uuid.uuid4().hex[:8]
    )
    if SAFE_MATRIX_ID.fullmatch(matrix_id) is None:
        raise CheckError("module matrix ID has an invalid format")
    run_directory = ROOT / args.report_dir / baseline_group / matrix_id
    if run_directory.exists():
        raise CheckError(f"module matrix run already exists: {matrix_id}")
    run_directory.mkdir(parents=True)

    report.kv("matrix_id", matrix_id)
    report.kv("vpn_expected", args.vpn_expected)
    report.kv("module_expected", "on")
    report.kv("repeat", args.repeat)
    report.kv("detector_groups", list(detector_groups))
    adb = Adb.select(args.adb_serial, report)
    artifacts = validate_installed_artifacts(adb, report)
    native_off, native_on, native_off_path, native_on_path = select_native_pair(
        ROOT / args.native_report_dir,
        baseline_group,
        detector_groups,
    )
    native_differential = differential_summary(native_off, native_on)
    report.kv("native_off", native_off_path.relative_to(ROOT))
    report.kv("native_on", native_on_path.relative_to(ROOT))
    report.kv("calibrated_mandatory_count", native_differential["calibrated_mandatory_count"])
    before_state, before_report = capture_vpn_state(
        run_directory, "before", args.adb_serial, args.vpn_expected
    )

    run_summaries: list[dict[str, object]] = []
    role_signals: dict[str, dict[str, dict[str, set[str]]]] = {}
    for role, variant, group, process in roles:
        aggregates: dict[str, dict[str, set[str]]] = {}
        for index in range(1, args.repeat + 1):
            child_name = f"{role}-run-{index}"
            child_args = argparse.Namespace(
                adb_serial=args.adb_serial,
                variant=variant,
                vpn_expected=args.vpn_expected,
                module_expected="on",
                group=group,
            )
            child_path = run_directory / f"{child_name}.txt"
            with Report(run_directory, child_name) as child_report:
                run_probe(child_report, child_args)
                assert_module_state(adb, child_report, "on", process, "module_oracle")
            run_id = report_value(child_path, "run_id")
            verdict, detectors = load_detector_summary(run_id)
            validate_against_native_off(run_id, group, verdict, detectors, native_off)
            run_summaries.append(
                {
                    "role": role,
                    "group": group,
                    "index": index,
                    "run_id": run_id,
                    "verdict": verdict,
                }
            )
            for test_id, detector in detector_map(detectors, run_id).items():
                item = aggregates.setdefault(test_id, {"statuses": set(), "raw_hashes": set()})
                status = detector.get("status")
                if not isinstance(status, str):
                    raise CheckError(f"invalid detector status in {run_id}: {test_id}")
                item["statuses"].add(status)
                item["raw_hashes"].add(raw_hash(detector.get("raw_observations")))
            report.kv(f"{role}.{index}.id", run_id)
            report.kv(f"{role}.{index}.verdict", verdict)
        role_signals[role] = aggregates

    after_state, after_report = capture_vpn_state(
        run_directory, "after", args.adb_serial, args.vpn_expected
    )
    if after_state != before_state:
        raise CheckError(f"VPN state changed during the {baseline_group} module matrix")
    serialized_signals: dict[str, dict[str, object]] = {}
    for role, signals in role_signals.items():
        for test_id, values in signals.items():
            statuses = sorted(values["statuses"])
            if len(statuses) != 1:
                raise CheckError(f"module detector status is unstable: {role}::{test_id}")
            serialized_signals[f"{role}::{test_id}"] = {
                "status": statuses[0],
                "raw_hashes": sorted(values["raw_hashes"]),
            }
    expected_signal_count = sum(
        len(EXPECTED_TEST_IDS[group.removeprefix("secondary-")]) for _, _, group, _ in roles
    )
    if len(serialized_signals) != expected_signal_count:
        raise CheckError(
            f"module {baseline_group} signal count mismatch: "
            f"expected {expected_signal_count}, observed {len(serialized_signals)}"
        )
    native_oracle = {
        "off_id": native_off["baseline_id"],
        "on_id": native_on["baseline_id"],
        "calibrated_mandatory_count": native_differential["calibrated_mandatory_count"],
        "structural_differential_count": native_differential["structural_differential_count"],
    }
    covered_per_role = sum(
        1
        for test_id in EXPECTED_TEST_IDS.get(baseline_group, set())
        if baseline_group == "link" and test_id.startswith(LINK_COVERED_PREFIXES)
    )
    residual_per_role = sum(
        1
        for test_id in EXPECTED_TEST_IDS.get(baseline_group, set())
        if baseline_group == "link" and test_id.startswith(LINK_RESIDUAL_PREFIXES)
    )
    summary: dict[str, object] = {
        "schema_version": MODULE_SCHEMA_VERSION,
        "matrix_id": matrix_id,
        "group": baseline_group,
        "vpn_expected": args.vpn_expected,
        "module_expected": "on",
        "repeat": args.repeat,
        "artifacts": artifacts,
        "native_oracle": native_oracle,
        "roles": [role for role, _, _, _ in roles],
        "runs": run_summaries,
        "signals": serialized_signals,
        "covered_signal_count": covered_per_role * len(roles),
        "residual_signal_count": residual_per_role * len(roles),
        "state_before": before_state,
        "state_after": after_state,
        "vpn_reports": [
            str(before_report.relative_to(ROOT)),
            str(after_report.relative_to(ROOT)),
        ],
    }
    pairing = compatible_module_summary(summary, run_directory.parent, baseline_group)
    if pairing is None:
        opposite_state = "off" if args.vpn_expected == "on" else "on"
        summary["pairing"] = {
            "status": "WAITING_OPPOSITE_STATE",
            "required_vpn_expected": opposite_state,
        }
        report.kv("pairing_status", "waiting_opposite_state")
    else:
        opposite, opposite_path = pairing
        matrix_path = run_directory / "complete-matrix.json"
        complete = {
            "schema_version": MODULE_SCHEMA_VERSION,
            "group": baseline_group,
            "module_expected": "on",
            "artifacts": artifacts,
            "native_oracle": native_oracle,
            "vpn_off_matrix_id": (
                matrix_id if args.vpn_expected == "off" else opposite["matrix_id"]
            ),
            "vpn_on_matrix_id": (matrix_id if args.vpn_expected == "on" else opposite["matrix_id"]),
            "signal_count": len(serialized_signals),
            "covered_signal_count": summary["covered_signal_count"],
            "residual_signal_count": summary["residual_signal_count"],
            "status": "PASS",
        }
        atomic_json(matrix_path, complete)
        summary["pairing"] = {
            "status": "PAIRED",
            "opposite_summary": str(opposite_path.relative_to(ROOT)),
            "complete_matrix": str(matrix_path.relative_to(ROOT)),
        }
        report.kv("pairing_status", "paired")
        report.kv("complete_matrix", matrix_path.relative_to(ROOT))
    destination = run_directory / "summary.json"
    atomic_json(destination, summary)
    report.kv("signal_count", len(serialized_signals))
    report.kv("summary", destination.relative_to(ROOT))
    report.kv("device_mutation", "bounded force-stop/launch of exact independent probes only")


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


def orchestration_self_test() -> None:
    if len(expected_native_signal_ids(SYNC_DETECTOR_GROUPS)) != 28:
        raise CheckError("synchronous native signal catalog self-test failed")
    if len(expected_native_signal_ids(ASYNC_DETECTOR_GROUPS)) != 32:
        raise CheckError("asynchronous native signal catalog self-test failed")
    if len(expected_native_signal_ids(LINK_DETECTOR_GROUPS)) != 92:
        raise CheckError("LinkProperties native signal catalog self-test failed")
    role_counts = {
        "sync": sum(
            len(EXPECTED_TEST_IDS[group.removeprefix("secondary-")])
            for _, _, group, _ in SYNC_ROLES
        ),
        "async": sum(
            len(EXPECTED_TEST_IDS[group.removeprefix("secondary-")])
            for _, _, group, _ in ASYNC_ROLES
        ),
        "link": sum(
            len(EXPECTED_TEST_IDS[group.removeprefix("secondary-")])
            for _, _, group, _ in LINK_ROLES
        ),
    }
    if role_counts != {"sync": 84, "async": 48, "link": 138}:
        raise CheckError(f"module role catalog self-test failed: {role_counts}")

    link_raw = {"comparison": {"state": "off"}, "diagnostic": {"value": -34}}
    link_native_off: dict[str, object] = {
        "runs": [
            {"group": group, "verdict": "NO_PUBLIC_VPN_SIGNAL"} for group in LINK_DETECTOR_GROUPS
        ],
        "detector_groups": list(LINK_DETECTOR_GROUPS),
        "signals": {
            signal_id: {
                "statuses": ["NEGATIVE"],
                "mandatory": False,
                "raw_hashes": [raw_hash(link_raw)],
            }
            for signal_id in expected_native_signal_ids(LINK_DETECTOR_GROUPS)
        },
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
    validate_against_native_off(
        "self-test-link", "link", "NO_PUBLIC_VPN_SIGNAL", link_detectors, link_native_off
    )
    covered_mismatch = [dict(item) for item in link_detectors]
    mismatched = next(
        item
        for item in covered_mismatch
        if cast(str, item["test_id"]).startswith(LINK_COVERED_PREFIXES)
    )
    mismatched["raw_observations"] = {"comparison": {"state": "on"}}
    try:
        validate_against_native_off(
            "self-test-link-covered-mismatch",
            "link",
            "NO_PUBLIC_VPN_SIGNAL",
            covered_mismatch,
            link_native_off,
        )
    except CheckError:
        pass
    else:
        raise CheckError("covered LinkProperties structural mismatch was not rejected")

    native_signals = {
        signal_id: {"statuses": ["NEGATIVE"], "mandatory": False, "raw_hashes": ["hash"]}
        for signal_id in expected_native_signal_ids(ASYNC_DETECTOR_GROUPS)
    }
    native_off: dict[str, object] = {
        "runs": [{"group": group, "verdict": "INCONCLUSIVE"} for group in ASYNC_DETECTOR_GROUPS],
        "detector_groups": list(ASYNC_DETECTOR_GROUPS),
        "signals": native_signals,
    }
    for group in ASYNC_DETECTOR_GROUPS:
        detectors = [
            {"test_id": test_id, "status": "NEGATIVE", "mandatory": False}
            for test_id in EXPECTED_TEST_IDS[group.removeprefix("secondary-")]
        ]
        validate_against_native_off(
            f"self-test-{group}", group, "INCONCLUSIVE", detectors, native_off
        )
    try:
        validate_against_native_off(
            "self-test-wrong-verdict",
            "async",
            "NO_PUBLIC_VPN_SIGNAL",
            [
                {"test_id": test_id, "status": "NEGATIVE", "mandatory": False}
                for test_id in EXPECTED_TEST_IDS["async"]
            ],
            native_off,
        )
    except CheckError:
        pass
    else:
        raise CheckError("asynchronous group verdict mismatch was not rejected")

    sync_native_off: dict[str, object] = {
        "runs": [{"group": "sync", "verdict": "NO_PUBLIC_VPN_SIGNAL"}],
        "detector_groups": list(SYNC_DETECTOR_GROUPS),
        "signals": {
            test_id: {"statuses": ["NEGATIVE"], "mandatory": False, "raw_hashes": ["hash"]}
            for test_id in EXPECTED_TEST_IDS["sync"]
        },
    }
    sync_detectors = [
        {"test_id": test_id, "status": "NEGATIVE", "mandatory": False}
        for test_id in EXPECTED_TEST_IDS["sync"]
    ]
    validate_against_native_off(
        "self-test-secondary-sync",
        "secondary-sync",
        "NO_PUBLIC_VPN_SIGNAL",
        sync_detectors,
        sync_native_off,
    )
    missing_secondary = dict(native_off)
    missing_secondary["detector_groups"] = ["async", "active"]
    try:
        validate_against_native_off(
            "self-test-missing-secondary",
            "secondary-async",
            "INCONCLUSIVE",
            [
                {"test_id": test_id, "status": "NEGATIVE", "mandatory": False}
                for test_id in EXPECTED_TEST_IDS["async"]
            ],
            missing_secondary,
        )
    except CheckError:
        pass
    else:
        raise CheckError("missing asynchronous secondary oracle was not rejected")


def test_module(
    report: Report,
    args: argparse.Namespace,
    baseline_group: str,
    detector_groups: tuple[str, ...],
    roles: tuple[tuple[str, str, str, str], ...],
) -> None:
    if args.module_expected == "off":
        report.kv("phase", f"current-artifact native {baseline_group} reference")
        native_args = argparse.Namespace(
            report_dir=args.native_report_dir,
            adb_serial=args.adb_serial,
            vpn_expected=args.vpn_expected,
            repeat=args.repeat,
            baseline_id="",
        )
        run_native_baseline(report, native_args, baseline_group, detector_groups)
        return
    if args.module_expected != "on":
        raise CheckError("MODULE_EXPECTED must be on or off")
    report.kv("phase", f"post-hook {baseline_group} matrix")
    run_module_on(report, args, baseline_group, detector_groups, roles)


def test_module_sync(report: Report, args: argparse.Namespace) -> None:
    test_module(report, args, "sync", SYNC_DETECTOR_GROUPS, SYNC_ROLES)


def test_module_async(report: Report, args: argparse.Namespace) -> None:
    test_module(report, args, "async", ASYNC_DETECTOR_GROUPS, ASYNC_ROLES)


def test_module_link(report: Report, args: argparse.Namespace) -> None:
    test_module(report, args, "link", LINK_DETECTOR_GROUPS, LINK_ROLES)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--native-report-dir", required=True)
    parser.add_argument("--adb-serial", default="")
    parser.add_argument("--vpn-expected", required=True)
    parser.add_argument("--module-expected", required=True)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument(
        "command", choices=["test-module-sync", "test-module-async", "test-module-link"]
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    try:
        with Report(ROOT / args.report_dir, args.command) as report:
            if args.command == "test-module-sync":
                test_module_sync(report, args)
            elif args.command == "test-module-async":
                test_module_async(report, args)
            else:
                test_module_link(report, args)
    except CheckError:
        return 1
    except Exception:
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
