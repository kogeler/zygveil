# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Explicit Make-wrapped adbd identity transitions."""

from __future__ import annotations

import argparse
import traceback
from collections.abc import Callable
from pathlib import Path

from adb import Adb, ensure_device_ui_ready
from reporting import CheckError, Report

ROOT = Path(__file__).resolve().parents[2]


def restart_adbd(report: Report, args: argparse.Namespace, *, root: bool) -> None:
    adb = Adb.select(args.adb_serial, report)
    before = adb.shell("id", check=False)
    report.kv(
        "before_adbd_state",
        "root"
        if "uid=0" in before.stdout
        else "shell"
        if "uid=2000" in before.stdout
        else "unknown",
    )
    action = "root" if root else "unroot"
    result = adb.run(action, timeout=30, check=False)
    report.kv("adb_action", action)
    report.kv("adb_action_exit", result.returncode)
    if result.returncode != 0:
        raise CheckError(f"adb {action} failed")
    wait = adb.run("wait-for-device", timeout=60, check=False)
    report.kv("wait_for_device_exit", wait.returncode)
    if wait.returncode != 0:
        raise CheckError("device did not return after adbd restart")
    after = adb.shell("id", timeout=15, check=False)
    expected_uid = "uid=0" if root else "uid=2000"
    if after.returncode != 0 or expected_uid not in after.stdout:
        raise CheckError(f"adbd did not enter the requested {action} state")
    report.kv("after_adbd_state", "root" if root else "shell")
    report.kv("device_mutation", f"adb {action} restarted adbd")


def adb_root(report: Report, args: argparse.Namespace) -> None:
    restart_adbd(report, args, root=True)


def adb_unroot(report: Report, args: argparse.Namespace) -> None:
    restart_adbd(report, args, root=False)


def device_ui_ready(report: Report, args: argparse.Namespace) -> None:
    adb = Adb.select(args.adb_serial, report)
    ensure_device_ui_ready(adb, report)
    report.kv("device_mutation", "bounded display wake and noncredential keyguard dismissal")


COMMANDS: dict[str, Callable[[Report, argparse.Namespace], None]] = {
    "adb-root": adb_root,
    "adb-unroot": adb_unroot,
    "device-ui-ready": device_ui_ready,
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
