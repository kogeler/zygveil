# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Make-wrapped generated-state and signing-identity maintenance."""

from __future__ import annotations

import argparse
import shutil
import sys
import traceback
from pathlib import Path

from reporting import CheckError, Report

ROOT = Path(__file__).resolve().parents[2]
SIGNING_IDENTITY = ROOT / ".state/debug.keystore"
CONFIRMATION = "delete-stable-signing-identity"
CLEAN_PATHS = (
    ROOT / ".artifacts",
    ROOT / "dist",
    ROOT / ".gradle",
    ROOT / "components/location/controller/build",
    ROOT / "components/probe/build",
    ROOT / ".state/probe-runs",
    ROOT / ".state/data-plane-hmac.key",
)


def remove_path(path: Path) -> bool:
    try:
        path.relative_to(ROOT)
    except ValueError as error:
        raise CheckError(f"cleanup path escaped repository: {path}") from error
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
        return True
    if path.is_dir():
        shutil.rmtree(path)
        return True
    return False


def clean() -> list[str]:
    removed = [str(path.relative_to(ROOT)) for path in CLEAN_PATHS if remove_path(path)]
    removed.extend(
        str(path.relative_to(ROOT))
        for path in sorted(ROOT.rglob("__pycache__"))
        if remove_path(path)
    )
    if not SIGNING_IDENTITY.is_file():
        raise CheckError("ordinary clean did not preserve the stable signing identity")
    return removed


def clean_signing(confirm: str) -> list[str]:
    if confirm != CONFIRMATION:
        raise CheckError(f"refusing signing deletion; use CONFIRM={CONFIRMATION}")
    removed = [str(SIGNING_IDENTITY.relative_to(ROOT))] if remove_path(SIGNING_IDENTITY) else []
    return removed


def publish(report_dir: Path, command: str, removed: list[str]) -> None:
    with Report(report_dir, command) as report:
        report.kv("removed_count", len(removed))
        report.kv("removed", removed)
        report.kv("stable_signing_preserved", command == "clean")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--confirm", default="")
    parser.add_argument("command", choices=["clean", "clean-signing"])
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    try:
        removed = clean() if args.command == "clean" else clean_signing(args.confirm)
        publish(ROOT / args.report_dir, args.command, removed)
    except CheckError as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception:
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
