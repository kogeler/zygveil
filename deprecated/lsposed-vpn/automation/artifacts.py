# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Atomically publish and verify production artifacts without host Android tools."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import tempfile
import traceback
import zipfile
from pathlib import Path

from reporting import CheckError, Report

ROOT = Path(__file__).resolve().parents[2]
BUILD_APK = ROOT / ".artifacts/build/zygveil-legacy-vpn-debug.apk"
DIST_APK = ROOT / "dist/zygveil-legacy-vpn-debug.apk"
CHECKSUM = ROOT / "dist/zygveil-legacy-vpn-debug.apk.sha256"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with source.open("rb") as input_stream, os.fdopen(descriptor, "wb") as output_stream:
            shutil.copyfileobj(input_stream, output_stream)
            output_stream.flush()
            os.fsync(output_stream.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def export(report: Report) -> None:
    if not BUILD_APK.is_file():
        raise CheckError(f"built APK is missing: {BUILD_APK.relative_to(ROOT)}")
    try:
        with zipfile.ZipFile(BUILD_APK) as archive:
            required = {
                "META-INF/xposed/java_init.list",
                "META-INF/xposed/module.prop",
                "META-INF/xposed/scope.list",
            }
            missing = required - set(archive.namelist())
            if missing or archive.testzip() is not None:
                raise CheckError(f"built module APK validation failed: missing={sorted(missing)}")
            properties = archive.read("META-INF/xposed/module.prop").decode("utf-8")
            if "minApiVersion=102" not in properties or "targetApiVersion=102" not in properties:
                raise CheckError("built module API metadata mismatch")
    except zipfile.BadZipFile as error:
        raise CheckError("built artifact is not an APK ZIP") from error

    expected_hash = sha256(BUILD_APK)
    atomic_copy(BUILD_APK, DIST_APK)
    if sha256(DIST_APK) != expected_hash:
        raise CheckError("published APK checksum mismatch")
    atomic_text(CHECKSUM, f"{expected_hash}  {DIST_APK.name}\n")
    report.kv("source", BUILD_APK.relative_to(ROOT))
    report.kv("destination", DIST_APK.relative_to(ROOT))
    report.kv("checksum_file", CHECKSUM.relative_to(ROOT))
    report.kv("apk_sha256", expected_hash)
    report.kv("atomic_publish", "true")
    report.kv("host_android_tools", "not used")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("command", choices=["export"])
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    try:
        with Report(ROOT / args.report_dir, args.command) as report:
            export(report)
    except CheckError:
        return 1
    except Exception:
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
