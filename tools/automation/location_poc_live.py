# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Fast, non-attestable live-generation proof for one already-running canary process."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
import traceback
from pathlib import Path

from adb import Adb
from location_live_control import (
    parse_properties as parse_live_properties,
)
from location_live_control import (
    parse_status,
    read_private_file,
    validate_live_input,
)
from probe import (
    LOCATION_ORACLE_INPUT_KEYS,
    PACKAGES,
    read_poc_current_oracle_input,
    same_binary64_decimal,
)
from reporting import CheckError, Report, contains_private_decimal_values

ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = "/data/adb/modules/zygveil"
HELPER = f"{MODULE_DIR}/locationctl"
CANARY_PACKAGE = PACKAGES["canary"]
ACCEPTED_APPLY_STATES = {"applied", "saved_pending_upstream"}


def select_root_adbd(report: Report, args: argparse.Namespace) -> Adb:
    adb = Adb.select(args.adb_serial, report)
    identity = adb.shell("id", timeout=10, check=False)
    report.kv("root_escalation_attempted", "false")
    if identity.returncode != 0 or "uid=0" not in identity.stdout:
        raise CheckError("rooted adbd is required for the live POC")
    report.kv("adbd_state", "root")
    return adb


def single_canary_pid(adb: Adb) -> str:
    result = adb.shell("pidof", CANARY_PACKAGE, check=False)
    pids = [value for value in result.stdout.split() if value.isdigit()]
    if result.returncode != 0 or len(pids) != 1:
        raise CheckError("live POC requires exactly one already-running canary process")
    return pids[0]


def read_status(adb: Adb) -> dict[str, str]:
    result = adb.shell(HELPER, "status", timeout=15, check=False)
    if result.returncode != 0:
        raise CheckError("redacted live POC helper status is unavailable")
    return parse_status(result.stdout)


def render_live_input(values: dict[str, str]) -> str:
    return "".join(f"{key}={values[key]}\n" for key in LOCATION_ORACLE_INPUT_KEYS)


def points_match(left: dict[str, str], right: dict[str, str]) -> bool:
    return all(
        same_binary64_decimal(left[key], right[key]) for key in LOCATION_ORACLE_INPUT_KEYS[1:]
    )


def centers_differ(left: dict[str, str], right: dict[str, str]) -> bool:
    return any(
        not same_binary64_decimal(left[key], right[key])
        for key in ("center_latitude_deg", "center_longitude_deg")
    )


def apply_point(adb: Adb, input_text: str) -> tuple[str, str]:
    result = adb.shell_input(HELPER, "apply", input_text=input_text, timeout=15, check=False)
    response = parse_status(result.stdout)
    if result.returncode != 0 or response["control_state"] not in ACCEPTED_APPLY_STATES:
        raise CheckError("live POC helper did not accept the requested generation")
    return response["control_state"], response["persisted_generation"]


def wait_for_applied(adb: Adb, generation: str, timeout_seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        status = read_status(adb)
        if (
            status["control_state"] == "applied"
            and status["persisted_generation"] == generation
            and status["published_generation"] == generation
            and status["applied_generation"] == generation
        ):
            return True
        time.sleep(0.1)
    return False


def run_probe_phase(
    report: Report,
    args: argparse.Namespace,
    *,
    phase: str,
    reuse_process: bool,
    spatial_oracle: bool,
) -> int:
    phase_report = Path(args.report_dir) / "live-reuse" / phase
    command = [
        sys.executable,
        str(ROOT / "tools/automation/probe.py"),
        "--report-dir",
        str(phase_report),
        "--adb-serial",
        args.adb_serial,
        "--poc",
        "--variant",
        "canary",
        "--group",
        "location",
        "--raw-gnss-mode",
        args.raw_gnss_mode,
        "--observation-window-ms",
        str(args.observation_window_ms),
    ]
    if reuse_process:
        command.append("--reuse-process")
    if not spatial_oracle:
        command.append("--poc-no-oracle")
    command.append("probe-run")
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        timeout=90 + args.observation_window_ms // 1000,
    )
    report.kv(f"{phase}_probe_exit", result.returncode)
    return result.returncode


def ensure_applied(
    adb: Adb,
    report: Report,
    args: argparse.Namespace,
    *,
    state: str,
    generation: str,
    phase: str,
    reuse_process: bool,
) -> None:
    triggered = False
    if state == "saved_pending_upstream":
        triggered = True
        run_probe_phase(
            report,
            args,
            phase=f"{phase}-trigger",
            reuse_process=reuse_process,
            spatial_oracle=False,
        )
    report.kv(f"{phase}_upstream_trigger", str(triggered).lower())
    if not wait_for_applied(adb, generation):
        raise CheckError(f"{phase} generation did not become applied")


def live_reuse(report: Report, args: argparse.Namespace, private_decimals: list[str]) -> None:
    if not Path(args.input_file).is_file():
        raise CheckError("live POC private input file is missing")
    candidate_text = validate_live_input(read_private_file(args.input_file))
    candidate = parse_live_properties(candidate_text)
    private_decimals.extend(candidate[key] for key in LOCATION_ORACLE_INPUT_KEYS[1:])
    adb = select_root_adbd(report, args)
    original = read_poc_current_oracle_input(adb)
    private_decimals.extend(original[key] for key in LOCATION_ORACLE_INPUT_KEYS[1:])
    if not centers_differ(original, candidate):
        raise CheckError("live POC candidate must use a distinct horizontal center")
    before_status = read_status(adb)
    if before_status["control_state"] != "applied":
        raise CheckError("live POC requires an applied starting generation")
    before_pid = single_canary_pid(adb)
    report.kv("process_pid_before", before_pid)
    report.kv("candidate_center_distinct", "true")
    report.kv("artifact_class", "non_attestable_poc")
    report.kv("config_hash_comparison", "skipped")

    original_text = render_live_input(original)
    mutation_attempted = False
    primary_error: BaseException | None = None
    restore_error: BaseException | None = None
    try:
        mutation_attempted = True
        candidate_state, candidate_generation = apply_point(adb, candidate_text)
        report.kv("candidate_persisted_generation", candidate_generation)
        ensure_applied(
            adb,
            report,
            args,
            state=candidate_state,
            generation=candidate_generation,
            phase="candidate",
            reuse_process=True,
        )
        if single_canary_pid(adb) != before_pid:
            raise CheckError("canary process changed while applying the candidate generation")
        spatial_exit = run_probe_phase(
            report,
            args,
            phase="candidate-spatial",
            reuse_process=True,
            spatial_oracle=True,
        )
        if spatial_exit != 0 or single_canary_pid(adb) != before_pid:
            raise CheckError("same-process spatial canary did not pass")
        report.kv("candidate_spatial_verdict", "PASS")
        report.kv("process_reused", "true")
    except BaseException as error:
        primary_error = error
    finally:
        if mutation_attempted:
            try:
                restore_state, restore_generation = apply_point(adb, original_text)
                report.kv("restore_persisted_generation", restore_generation)
                current_pids = adb.shell("pidof", CANARY_PACKAGE, check=False).stdout.split()
                can_reuse = current_pids == [before_pid]
                ensure_applied(
                    adb,
                    report,
                    args,
                    state=restore_state,
                    generation=restore_generation,
                    phase="restore",
                    reuse_process=can_reuse,
                )
                restored = read_poc_current_oracle_input(adb)
                if not points_match(original, restored):
                    raise CheckError("live POC did not restore the original point")
                report.kv("original_point_restored", "true")
            except BaseException as error:
                restore_error = error

    report.kv("coordinates", "absent")
    report.kv("device_mutation", "temporary live update followed by original-point restoration")
    if restore_error is not None:
        raise CheckError("live POC original-point restoration failed") from restore_error
    if primary_error is not None:
        raise primary_error


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--adb-serial", default="")
    parser.add_argument("--input-file", required=True)
    parser.add_argument("--raw-gnss-mode", required=True, choices=("blocked", "passthrough"))
    parser.add_argument("--observation-window-ms", type=int, default=10_000)
    parser.add_argument("command", choices=("location-poc-live-reuse",))
    args = parser.parse_args()
    if args.observation_window_ms < 5_000 or args.observation_window_ms > 120_000:
        parser.error("--observation-window-ms must be between 5000 and 120000")
    return args


def main() -> int:
    args = parse_arguments()
    private_decimals: list[str] = []
    try:
        with Report(ROOT / args.report_dir, args.command) as report:
            try:
                live_reuse(report, args, private_decimals)
            finally:
                report.assert_redacted(
                    [
                        r"(?i)\b(?:center_latitude_deg|center_longitude_deg|"
                        r"altitude_ellipsoid_m|altitude_msl_m)\s*=",
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
