# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Content-addressed source transport and strict container output extraction."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Iterable
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
DEPENDENCY_FILES = [
    "settings.gradle.kts",
    "build.gradle.kts",
    "gradle.properties",
    "gradle/wrapper/gradle-wrapper.properties",
    "gradlew",
    "components/location/controller/build.gradle.kts",
    "components/probe/build.gradle.kts",
    ".editorconfig",
    "mypy.ini",
    "ruff.toml",
    "tools/automation/dependency-cache.version",
]
IMAGE_FILES = [
    "containers/builder/Containerfile",
    "containers/builder/entrypoint.sh",
    *DEPENDENCY_FILES,
]
FORMATTABLE_NAMES = {
    ".containerignore",
    ".editorconfig",
    ".gitignore",
    "Makefile",
    "gradlew",
}
FORMATTABLE_SUFFIXES = {
    ".java",
    ".kt",
    ".kts",
    ".md",
    ".mk",
    ".properties",
    ".py",
    ".sh",
    ".xml",
}
SOURCE_MANIFEST = ".container-input/source-manifest.json"


class TransportError(RuntimeError):
    pass


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def content_key(paths: Iterable[str]) -> str:
    digest = hashlib.sha256()
    for relative in sorted(set(paths)):
        path = ROOT / relative
        if not path.is_file():
            raise TransportError(f"key input is missing: {relative}")
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()[:20]


def repository_paths() -> list[str]:
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    paths = []
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        relative = raw.decode("utf-8")
        path = ROOT / relative
        if not relative.startswith("deprecated/") and (path.exists() or path.is_symlink()):
            paths.append(relative)
    return sorted(paths)


def normalized_info(path: Path, name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    stat = path.lstat()
    info.mode = stat.st_mode & 0o777
    info.uid = 1000
    info.gid = 1000
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    if path.is_symlink():
        target = os.readlink(path)
        resolved = (path.parent / target).resolve()
        if not resolved.is_relative_to(ROOT.resolve()):
            raise TransportError(f"symlink leaves repository: {name}")
        info.type = tarfile.SYMTYPE
        info.linkname = target
        return info
    if not path.is_file():
        raise TransportError(f"unsupported source path: {name}")
    info.type = tarfile.REGTYPE
    info.size = stat.st_size
    return info


def add_path(archive: tarfile.TarFile, path: Path, name: str) -> None:
    info = normalized_info(path, name)
    if info.isreg():
        with path.open("rb") as stream:
            archive.addfile(info, stream)
    else:
        archive.addfile(info)


def add_bytes(archive: tarfile.TarFile, data: bytes, name: str) -> None:
    info = tarfile.TarInfo(name=name)
    info.mode = 0o600
    info.uid = 1000
    info.gid = 1000
    info.mtime = 0
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))


def validate_dependency_dir(directory: Path, expected_key: str) -> tuple[Path, Path]:
    cache = directory / "gradle-home.tar"
    manifest = directory / "manifest.json"
    if not cache.is_file() or not manifest.is_file():
        raise TransportError(f"dependency cache is incomplete: {directory}")
    data = json.loads(manifest.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or data.get("dependency_key") != expected_key:
        raise TransportError("dependency cache key/schema mismatch")
    actual = digest_file(cache)
    if data.get("archive_sha256") != actual:
        raise TransportError("dependency cache checksum mismatch")
    return cache, manifest


def source_archive(args: argparse.Namespace) -> None:
    source_paths = repository_paths()
    if SOURCE_MANIFEST in source_paths:
        raise TransportError(f"reserved source path is present: {SOURCE_MANIFEST}")
    with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as archive:
        for relative in source_paths:
            add_path(archive, ROOT / relative, relative)
        source_manifest = json.dumps(
            {"schema_version": 1, "paths": source_paths},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        add_bytes(archive, source_manifest, SOURCE_MANIFEST)
        if args.dependency_dir:
            cache, cache_manifest = validate_dependency_dir(
                Path(args.dependency_dir), args.dependency_key
            )
            add_path(archive, cache, ".container-input/gradle-home.tar")
            add_path(archive, cache_manifest, ".container-input/dependencies.json")
        if args.keystore:
            keystore = Path(args.keystore)
            if not keystore.is_file():
                raise TransportError(f"keystore is missing: {keystore}")
            add_path(archive, keystore, ".container-input/debug.keystore")


def safe_member_name(name: str) -> str:
    normalized = str(PurePosixPath(name))
    if normalized.startswith("/") or normalized == ".." or normalized.startswith("../"):
        raise TransportError(f"unsafe archive member: {name}")
    return normalized.removeprefix("./")


def parse_mappings(values: list[str]) -> dict[str, Path]:
    mappings: dict[str, Path] = {}
    root = ROOT.resolve()
    for value in values:
        source, separator, destination = value.partition("=")
        if not separator or not source or not destination:
            raise TransportError(f"invalid output mapping: {value}")
        target = (ROOT / destination).resolve()
        if not target.is_relative_to(root):
            raise TransportError(f"output leaves repository: {destination}")
        mappings[safe_member_name(source)] = target
    return mappings


def extract_outputs(args: argparse.Namespace) -> None:
    mappings = parse_mappings(args.map)
    seen: set[str] = set()
    temporary: dict[str, Path] = {}
    try:
        with tarfile.open(fileobj=sys.stdin.buffer, mode="r|*") as archive:
            for member in archive:
                name = safe_member_name(member.name)
                if name not in mappings:
                    raise TransportError(f"container returned non-allowlisted path: {name}")
                if name in seen or not member.isfile() or member.size > args.max_bytes:
                    raise TransportError(f"invalid output member: {name}")
                stream = archive.extractfile(member)
                if stream is None:
                    raise TransportError(f"could not read output member: {name}")
                destination = mappings[name]
                destination.parent.mkdir(parents=True, exist_ok=True)
                descriptor, candidate_name = tempfile.mkstemp(
                    prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
                )
                candidate_path = Path(candidate_name)
                with os.fdopen(descriptor, "wb") as output:
                    while block := stream.read(1024 * 1024):
                        output.write(block)
                    output.flush()
                    os.fsync(output.fileno())
                temporary[name] = candidate_path
                seen.add(name)
        missing = set(mappings) - seen
        if missing:
            raise TransportError(f"container omitted required outputs: {sorted(missing)}")
        for name, published_path in temporary.items():
            os.replace(published_path, mappings[name])
    finally:
        for temporary_path in temporary.values():
            temporary_path.unlink(missing_ok=True)


def dependency_status(args: argparse.Namespace) -> None:
    validate_dependency_dir(Path(args.directory), args.dependency_key)
    print(f"dependency cache verified: {args.directory}")


def apk_status(args: argparse.Namespace) -> None:
    import zipfile

    path = Path(args.path)
    if not path.is_file():
        raise TransportError(f"APK is missing: {path}")
    with zipfile.ZipFile(path) as archive:
        bad = archive.testzip()
        if bad:
            raise TransportError(f"APK has a corrupt member: {bad}")
    print(f"sha256={digest_file(path)}  {path}")


def is_formattable(relative: str) -> bool:
    path = PurePosixPath(relative)
    return relative in FORMATTABLE_NAMES or path.suffix in FORMATTABLE_SUFFIXES


def apply_formatted(args: argparse.Namespace) -> None:
    archive_path = Path(args.archive)
    if not archive_path.is_file():
        raise TransportError(f"formatted archive is missing: {archive_path}")
    allowed = {
        path
        for path in repository_paths()
        if is_formattable(path) and (ROOT / path).is_file() and not (ROOT / path).is_symlink()
    }
    contents: dict[str, bytes] = {}
    with tarfile.open(archive_path, "r:*") as archive:
        for member in archive:
            name = safe_member_name(member.name)
            if name not in allowed or name in contents or not member.isfile():
                raise TransportError(f"invalid formatted member: {name}")
            if member.size > 16 * 1024 * 1024:
                raise TransportError(f"formatted member is too large: {name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise TransportError(f"could not read formatted member: {name}")
            contents[name] = stream.read()
    if set(contents) != allowed:
        raise TransportError(
            f"formatted member set mismatch: missing={sorted(allowed - set(contents))} "
            f"extra={sorted(set(contents) - allowed)}"
        )

    temporary: dict[str, Path] = {}
    try:
        for relative, data in contents.items():
            destination = ROOT / relative
            descriptor, candidate_name = tempfile.mkstemp(
                prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
            )
            candidate_path = Path(candidate_name)
            with os.fdopen(descriptor, "wb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(candidate_path, destination.stat().st_mode & 0o777)
            temporary[relative] = candidate_path
        for relative, published_path in temporary.items():
            os.replace(published_path, ROOT / relative)
        print(f"formatted files applied: {len(contents)}")
    finally:
        for temporary_path in temporary.values():
            temporary_path.unlink(missing_ok=True)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    key = subparsers.add_parser("key")
    key.add_argument("kind", choices=["image", "dependencies"])

    digest = subparsers.add_parser("digest")
    digest.add_argument("path")

    source = subparsers.add_parser("source-archive")
    source.add_argument("--dependency-dir")
    source.add_argument("--dependency-key", default="")
    source.add_argument("--keystore")

    extract = subparsers.add_parser("extract")
    extract.add_argument("--map", action="append", required=True)
    extract.add_argument("--max-bytes", type=int, default=2 * 1024 * 1024 * 1024)

    status = subparsers.add_parser("dependency-status")
    status.add_argument("--directory", required=True)
    status.add_argument("--dependency-key", required=True)

    apk = subparsers.add_parser("apk-status")
    apk.add_argument("--path", required=True)
    formatted = subparsers.add_parser("apply-formatted")
    formatted.add_argument("--archive", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    try:
        if args.command == "key":
            print(content_key(IMAGE_FILES if args.kind == "image" else DEPENDENCY_FILES))
        elif args.command == "digest":
            print(digest_file(ROOT / args.path))
        elif args.command == "source-archive":
            source_archive(args)
        elif args.command == "extract":
            extract_outputs(args)
        elif args.command == "dependency-status":
            dependency_status(args)
        elif args.command == "apk-status":
            apk_status(args)
        elif args.command == "apply-formatted":
            apply_formatted(args)
    except (
        OSError,
        subprocess.SubprocessError,
        tarfile.TarError,
        json.JSONDecodeError,
        TransportError,
    ) as error:
        print(f"container transport: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
