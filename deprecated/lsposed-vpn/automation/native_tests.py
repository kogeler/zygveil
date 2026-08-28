# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Make-wrapped native VPN-state differential test orchestration."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import traceback
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from adb import Adb
from module_runtime import assert_module_state, validate_installed_artifacts
from reporting import CheckError, Report

from probe import load_run_state, run_probe

ROOT = Path(__file__).resolve().parents[2]
BASELINE_AUTOMATION = ROOT / "tools/automation/baseline.py"
SAFE_BASELINE_ID = re.compile(r"native-(?:sync|async|link)-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}")
SAFE_SHA256 = re.compile(r"[0-9a-f]{64}")
SUMMARY_SCHEMA_VERSION = 3
PRIMARY_APK = ROOT / "dist/zygveil-probe-primary-debug.apk"
DETECTOR_SOURCE_HASH = ROOT / "dist/probe-detector-source.sha256"


def run_host(arguments: Sequence[str], timeout: int = 60) -> str:
    completed = subprocess.run(
        arguments,
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise CheckError(
            f"host command failed ({completed.returncode}): {' '.join(arguments)}: "
            f"{completed.stdout.strip()}"
        )
    return completed.stdout


def report_value(path: Path, key: str) -> str:
    prefix = key + "="
    values = [
        line.removeprefix(prefix)
        for line in path.read_text().splitlines()
        if line.startswith(prefix)
    ]
    if len(values) != 1:
        raise CheckError(f"expected one {key} in {path.relative_to(ROOT)}")
    return values[0]


def capture_vpn_state(
    directory: Path, name: str, adb_serial: str, expected: str
) -> tuple[str, Path]:
    relative_directory = directory.relative_to(ROOT)
    run_host(
        [
            sys.executable,
            str(BASELINE_AUTOMATION),
            "--report-dir",
            str(relative_directory),
            "--adb-serial",
            adb_serial,
            "vpn-status",
        ]
    )
    generated = directory / "vpn-status.txt"
    destination = directory / f"vpn-status-{name}.txt"
    generated.replace(destination)
    actual = report_value(destination, "active_vpn_state")
    expected_value = "yes" if expected == "on" else "no"
    if actual != expected_value:
        raise CheckError(
            f"VPN state mismatch at {name}: expected {expected_value}, observed {actual}"
        )
    return actual, destination


def load_detector_summary(run_id: str) -> tuple[str, list[dict[str, object]]]:
    metadata = load_run_state(run_id)
    path = ROOT / ".artifacts/reports/probe/runs" / f"{run_id}.jsonl"
    if not path.is_file():
        raise CheckError(f"probe JSONL is missing: {run_id}")
    records: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        decoded: object = json.loads(line)
        if not isinstance(decoded, dict):
            raise CheckError(f"probe JSONL record is not an object: {run_id}")
        records.append(cast(dict[str, object], decoded))
    summaries = [item for item in records if item.get("record_type") == "summary"]
    detectors = [item for item in records if item.get("record_type") == "detector"]
    if len(summaries) != 1:
        raise CheckError(f"probe JSONL summary count mismatch: {run_id}")
    if metadata.get("run_id") != run_id:
        raise CheckError(f"probe metadata run ID mismatch: {run_id}")
    return cast(str, summaries[0]["status"]), detectors


def raw_hash(value: object) -> str:
    if isinstance(value, dict) and "comparison" in value:
        value = value["comparison"]
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def comparison_hash_self_test() -> None:
    first = {
        "comparison": {"specified": True},
        "diagnostic": {"value": -34},
    }
    changed_diagnostic = {
        "comparison": {"specified": True},
        "diagnostic": {"value": -51},
    }
    changed_comparison = {
        "comparison": {"specified": False},
        "diagnostic": {"value": -(2**31)},
    }
    if raw_hash(first) != raw_hash(changed_diagnostic):
        raise CheckError("diagnostic value changed the structured comparison hash")
    if raw_hash(first) == raw_hash(changed_comparison):
        raise CheckError("structured comparison change did not change its hash")


def file_sha256(path: Path) -> str:
    if not path.is_file():
        raise CheckError(f"artifact is missing: {path.relative_to(ROOT)}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_identity() -> dict[str, str]:
    if not DETECTOR_SOURCE_HASH.is_file():
        raise CheckError("detector source hash is missing")
    fields = DETECTOR_SOURCE_HASH.read_text(encoding="utf-8").split()
    if (
        len(fields) != 2
        or SAFE_SHA256.fullmatch(fields[0]) is None
        or fields[1] != "probe-detector-source"
    ):
        raise CheckError("detector source hash file is invalid")
    return {
        "primary_apk_sha256": file_sha256(PRIMARY_APK),
        "detector_source_sha256": fields[0],
    }


def atomic_json(path: Path, value: object) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def read_summary(path: Path) -> dict[str, object] | None:
    try:
        decoded: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(decoded, dict):
        return None
    return cast(dict[str, object], decoded)


def compatible_opposite_summary(
    current: dict[str, object], baseline_directory: Path
) -> tuple[dict[str, object], Path] | None:
    expected_state = "off" if current["vpn_expected"] == "on" else "on"
    current_signals = current["signals"]
    if not isinstance(current_signals, dict):
        raise CheckError("current signal summary is invalid")
    candidates: list[tuple[dict[str, object], Path]] = []
    group = current.get("group")
    if group not in {"sync", "async", "link"}:
        raise CheckError("current baseline group is invalid")
    for path in sorted(baseline_directory.glob(f"native-{group}-*/summary.json")):
        candidate = read_summary(path)
        if candidate is None:
            continue
        if (
            candidate.get("schema_version") != SUMMARY_SCHEMA_VERSION
            or candidate.get("group") != current["group"]
            or candidate.get("variant") != current["variant"]
            or candidate.get("module_expected") != current["module_expected"]
            or candidate.get("vpn_expected") != expected_state
            or candidate.get("artifacts") != current["artifacts"]
            or candidate.get("detector_groups") != current.get("detector_groups")
        ):
            continue
        candidate_signals = candidate.get("signals")
        if not isinstance(candidate_signals, dict):
            continue
        if set(candidate_signals) != set(current_signals):
            continue
        baseline_id = candidate.get("baseline_id")
        if not isinstance(baseline_id, str) or SAFE_BASELINE_ID.fullmatch(baseline_id) is None:
            continue
        if path.parent.name != baseline_id:
            continue
        candidates.append((candidate, path))
    return candidates[-1] if candidates else None


def signal_status(signal: object, test_id: str) -> tuple[str, bool, list[str]]:
    if not isinstance(signal, dict):
        raise CheckError(f"invalid signal summary for {test_id}")
    statuses = signal.get("statuses")
    mandatory = signal.get("mandatory")
    raw_hashes = signal.get("raw_hashes")
    if (
        not isinstance(statuses, list)
        or len(statuses) != 1
        or not isinstance(statuses[0], str)
        or not isinstance(mandatory, bool)
        or not isinstance(raw_hashes, list)
        or not all(isinstance(item, str) for item in raw_hashes)
    ):
        raise CheckError(f"unstable or invalid signal summary for {test_id}")
    return statuses[0], mandatory, cast(list[str], raw_hashes)


def differential_summary(
    current: dict[str, object], opposite: dict[str, object]
) -> dict[str, object]:
    off = current if current["vpn_expected"] == "off" else opposite
    on = current if current["vpn_expected"] == "on" else opposite
    off_signals = cast(dict[str, object], off["signals"])
    on_signals = cast(dict[str, object], on["signals"])
    signals: dict[str, dict[str, object]] = {}
    calibrated_mandatory = 0
    structural_differential = 0
    for test_id in sorted(off_signals):
        off_status, off_mandatory, off_hashes = signal_status(off_signals[test_id], test_id)
        on_status, on_mandatory, on_hashes = signal_status(on_signals[test_id], test_id)
        if len(off_hashes) != 1 or len(on_hashes) != 1:
            raise CheckError(f"raw observations are unstable for {test_id}")
        if off_mandatory != on_mandatory:
            raise CheckError(f"mandatory flag changed between states for {test_id}")
        calibrated = off_status in {"NEGATIVE", "INCONCLUSIVE"} and on_status == "POSITIVE"
        if calibrated and off_mandatory:
            calibrated_mandatory += 1
        if calibrated:
            classification = "VPN_DISCRIMINATING"
        elif off_status == on_status and off_hashes != on_hashes:
            classification = "STRUCTURAL_DIFFERENTIAL"
            structural_differential += 1
        elif off_status == on_status:
            classification = "STATE_INVARIANT"
        else:
            classification = "DIFFERENTIAL_OTHER"
        signals[test_id] = {
            "mandatory": off_mandatory,
            "off_status": off_status,
            "on_status": on_status,
            "classification": classification,
            "calibrated_vpn_signal": calibrated,
            "off_raw_stable": len(off_hashes) == 1,
            "on_raw_stable": len(on_hashes) == 1,
            "raw_hash_sets_equal": off_hashes == on_hashes,
        }
    if calibrated_mandatory == 0 and current["group"] != "link":
        raise CheckError("same-artifact differential has no mandatory VPN-discriminating signal")
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "group": current["group"],
        "detector_groups": current.get("detector_groups"),
        "module_expected": "off",
        "artifacts": current["artifacts"],
        "off_baseline_id": off["baseline_id"],
        "on_baseline_id": on["baseline_id"],
        "signal_count": len(signals),
        "calibrated_mandatory_count": calibrated_mandatory,
        "structural_differential_count": structural_differential,
        "signals": signals,
    }


def validate_native_run(
    baseline_group: str,
    vpn_expected: str,
    run_id: str,
    verdict: str,
    detectors: list[dict[str, object]],
) -> None:
    errors = [item.get("test_id") for item in detectors if item.get("status") == "ERROR"]
    if errors:
        raise CheckError(f"native detector errors in {run_id}: {errors}")
    if baseline_group == "link":
        if verdict not in {"NO_PUBLIC_VPN_SIGNAL", "INCONCLUSIVE"}:
            raise CheckError(f"native link verdict mismatch for {run_id}: {verdict}")
        return
    mandatory_positive = [
        item.get("test_id")
        for item in detectors
        if item.get("mandatory") is True and item.get("status") == "POSITIVE"
    ]
    if vpn_expected == "on":
        if verdict != "VPN_DETECTED":
            raise CheckError(f"native {baseline_group} VPN-on verdict mismatch for {run_id}")
    elif mandatory_positive:
        raise CheckError(
            f"native VPN-off mandatory false positives in {run_id}: {mandatory_positive}"
        )
    elif baseline_group == "sync" and verdict != "NO_PUBLIC_VPN_SIGNAL":
        raise CheckError(f"native sync VPN-off verdict mismatch for {run_id}: {verdict}")
    elif baseline_group == "async" and verdict not in {
        "NO_PUBLIC_VPN_SIGNAL",
        "INCONCLUSIVE",
    }:
        raise CheckError(f"native async VPN-off verdict mismatch for {run_id}: {verdict}")


def run_native_baseline(
    report: Report,
    args: argparse.Namespace,
    baseline_group: str,
    detector_groups: tuple[str, ...],
) -> None:
    if args.vpn_expected not in {"on", "off"}:
        raise CheckError("VPN_EXPECTED must be on or off")
    if args.repeat < 2 or args.repeat > 10:
        raise CheckError("REPEAT must be between 2 and 10")
    baseline_id = args.baseline_id or (
        datetime.now(UTC).strftime(f"native-{baseline_group}-%Y%m%dT%H%M%SZ-")
        + uuid.uuid4().hex[:8]
    )
    if SAFE_BASELINE_ID.fullmatch(baseline_id) is None:
        raise CheckError("baseline ID has an invalid format")
    run_directory = ROOT / args.report_dir / baseline_group / baseline_id
    if run_directory.exists():
        raise CheckError(f"native baseline already exists: {baseline_id}")
    run_directory.mkdir(parents=True)

    report.kv("baseline_id", baseline_id)
    report.kv("vpn_expected", args.vpn_expected)
    report.kv("module_expected", "off")
    report.kv("repeat", args.repeat)
    report.kv("detector_groups", list(detector_groups))
    artifacts = artifact_identity()
    report.kv("primary_apk_sha256", artifacts["primary_apk_sha256"])
    report.kv("detector_source_sha256", artifacts["detector_source_sha256"])
    before_state, before_report = capture_vpn_state(
        run_directory, "before", args.adb_serial, args.vpn_expected
    )
    adb = Adb.select(args.adb_serial, report)
    validate_installed_artifacts(adb, report)
    report.kv("scope_mode", "exact two-probe scope retained; hook inactivity proven per run")

    run_summaries: list[dict[str, object]] = []
    aggregate: dict[str, dict[str, set[str]]] = {}
    mandatory_flags: dict[str, bool] = {}
    for detector_group in detector_groups:
        for index in range(1, args.repeat + 1):
            child_name = f"{detector_group}-run-{index}"
            child_args = argparse.Namespace(
                adb_serial=args.adb_serial,
                variant="primary",
                vpn_expected=args.vpn_expected,
                module_expected="off",
                group=detector_group,
            )
            child_path = run_directory / f"{child_name}.txt"
            with Report(run_directory, child_name) as child_report:
                run_probe(child_report, child_args)
                process = "dev.zygveil.probe.primary"
                if detector_group.startswith("secondary-"):
                    process += ":secondary"
                assert_module_state(
                    adb,
                    child_report,
                    "off",
                    process,
                    "module_oracle",
                )
            run_id = report_value(child_path, "run_id")
            verdict, detectors = load_detector_summary(run_id)
            validate_native_run(baseline_group, args.vpn_expected, run_id, verdict, detectors)
            run_summaries.append({"group": detector_group, "run_id": run_id, "verdict": verdict})
            for detector in detectors:
                test_id = detector.get("test_id")
                status = detector.get("status")
                mandatory = detector.get("mandatory")
                if (
                    not isinstance(test_id, str)
                    or not isinstance(status, str)
                    or not isinstance(mandatory, bool)
                ):
                    raise CheckError(f"invalid detector identity in {run_id}")
                signal_id = (
                    f"secondary::{test_id}" if detector_group.startswith("secondary-") else test_id
                )
                previous_mandatory = mandatory_flags.setdefault(signal_id, mandatory)
                if previous_mandatory != mandatory:
                    raise CheckError(f"mandatory flag changed between runs for {signal_id}")
                item = aggregate.setdefault(signal_id, {"statuses": set(), "raw_hashes": set()})
                item["statuses"].add(status)
                item["raw_hashes"].add(raw_hash(detector.get("raw_observations")))
            report.kv(f"{detector_group}.{index}.id", run_id)
            report.kv(f"{detector_group}.{index}.verdict", verdict)

    after_state, after_report = capture_vpn_state(
        run_directory, "after", args.adb_serial, args.vpn_expected
    )
    if after_state != before_state:
        raise CheckError(f"VPN state changed during native {baseline_group} baseline")
    serialized_signals = {
        test_id: {
            "mandatory": mandatory_flags[test_id],
            "statuses": sorted(values["statuses"]),
            "raw_hashes": sorted(values["raw_hashes"]),
        }
        for test_id, values in sorted(aggregate.items())
    }
    unstable = [
        test_id
        for test_id, values in serialized_signals.items()
        if len(cast(list[str], values["statuses"])) != 1
    ]
    if unstable:
        raise CheckError(f"detector status changed across repeated runs: {unstable}")
    summary = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "baseline_id": baseline_id,
        "group": baseline_group,
        "detector_groups": list(detector_groups),
        "variant": "primary",
        "vpn_expected": args.vpn_expected,
        "module_expected": "off",
        "repeat": args.repeat,
        "artifacts": artifacts,
        "runs": run_summaries,
        "signals": serialized_signals,
        "state_before": before_state,
        "state_after": after_state,
        "vpn_reports": [
            str(before_report.relative_to(ROOT)),
            str(after_report.relative_to(ROOT)),
        ],
    }
    pairing = compatible_opposite_summary(summary, run_directory.parent)
    differential: dict[str, object] | None = None
    differential_path: Path | None = None
    if pairing is None:
        opposite_state = "off" if args.vpn_expected == "on" else "on"
        summary["pairing"] = {
            "status": "WAITING_OPPOSITE_STATE",
            "required_vpn_expected": opposite_state,
        }
        report.kv("pairing_status", "waiting_opposite_state")
    else:
        opposite_summary, opposite_path = pairing
        differential = differential_summary(summary, opposite_summary)
        opposite_id = cast(str, opposite_summary["baseline_id"])
        differential_path = run_directory / f"differential-with-{opposite_id}.json"
        summary["pairing"] = {
            "status": "PAIRED",
            "opposite_baseline_id": opposite_id,
            "opposite_summary": str(opposite_path.relative_to(ROOT)),
            "differential": str(differential_path.relative_to(ROOT)),
        }
        report.kv("pairing_status", "paired")
        report.kv("opposite_baseline_id", opposite_id)
    destination = run_directory / "summary.json"
    atomic_json(destination, summary)
    if differential is not None and differential_path is not None:
        atomic_json(differential_path, differential)
        report.kv("differential", differential_path.relative_to(ROOT))
    report.kv("signal_count", len(serialized_signals))
    report.kv("summary", destination.relative_to(ROOT))
    report.kv("device_mutation", "bounded force-stop/launch of independent primary probe only")


def test_native_sync(report: Report, args: argparse.Namespace) -> None:
    run_native_baseline(report, args, "sync", ("sync",))


def test_native_async(report: Report, args: argparse.Namespace) -> None:
    run_native_baseline(
        report,
        args,
        "async",
        ("async", "active", "secondary-async", "secondary-active"),
    )


def test_native_link(report: Report, args: argparse.Namespace) -> None:
    run_native_baseline(report, args, "link", ("link", "secondary-link"))


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--adb-serial", default="")
    parser.add_argument("--vpn-expected", required=True)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--baseline-id", default="")
    parser.add_argument(
        "command", choices=["test-native-sync", "test-native-async", "test-native-link"]
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    try:
        with Report(ROOT / args.report_dir, args.command) as report:
            if args.command == "test-native-sync":
                test_native_sync(report, args)
            elif args.command == "test-native-async":
                test_native_async(report, args)
            else:
                test_native_link(report, args)
    except CheckError:
        return 1
    except Exception:
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
