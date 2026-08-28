# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Commands that run inside the confined Android builder."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import xml.etree.ElementTree as ET
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import cast

ROOT = Path.cwd()
OUTPUT = ROOT / ".container-output"
PROBE_ROOT = ROOT / "components/probe"
CONTROLLER_ROOT = ROOT / "components/location/controller"
SERVER_VPN_ROOT = ROOT / "components/server-vpn/runtime"
ZYGISK_HOST_ROOT = ROOT / "components/zygisk-host"
GRADLE_HOME = Path(os.environ.get("GRADLE_USER_HOME", "/tmp/home/.gradle"))
MAVEN_AAPT2 = "aapt2-9.2.1-15009934-linux.jar"
FORMATTABLE_NAMES = {".containerignore", ".editorconfig", ".gitignore", "Makefile", "gradlew"}
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
SOURCE_MANIFEST = ROOT / ".container-input/source-manifest.json"
ATTESTATION_SPOTLESS_TASKS = (
    "spotlessJavaCheck",
    "spotlessKotlinGradleCheck",
    "spotlessTechnicalTextCheck",
)


class JobError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def assert_private_identity_absent(data: bytes, *, member: str) -> None:
    markers = {
        "build_identity_field": b"build_" + b"fingerprint",
        "build_identity_api": b"Build." + b"FINGERPRINT",
        "persisted_adb_selector": b"selected_" + b"serial",
        "compatibility_base_digest": b"base_target_" + b"sha256",
        "compatibility_catalog_digest": b"connectivity_descriptor_" + b"sha256",
        "product_model_property": b"ro.product." + b"model",
        "product_manufacturer_property": b"ro.product." + b"manufacturer",
        "product_device_property": b"ro.product." + b"device",
        "product_name_property": b"ro.product." + b"name",
        "build_display_property": b"ro.build." + b"display.id",
        "build_property_identity": b"ro.build." + b"fingerprint",
        "vendor_fingerprint_property": b"ro.vendor.build." + b"fingerprint",
    }
    found = sorted(label for label, marker in markers.items() if marker in data)
    host_path = re.compile(
        rb"(?<![A-Za-z0-9_.-])(?:file://)?/(?:ho" + rb"me|med" + rb"ia)/[^\s'\"<>]+"
    )
    if host_path.search(data):
        found.append("host_private_path")
    if found:
        raise JobError(f"artifact privacy violation in {member}: {found}")


def assert_archive_privacy(path: Path) -> None:
    forbidden_members = (
        "target-" + "device.json",
        "server-vpn-" + "target.json",
        "target." + "properties",
        "target-artifacts." + "sha256",
        "target-artifacts." + "size",
    )
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            normalized = info.filename.lower()
            if any(normalized.endswith(name) for name in forbidden_members):
                raise JobError(f"artifact contains prohibited identity member: {info.filename}")
            if not info.is_dir():
                assert_private_identity_absent(
                    archive.read(info), member=f"{path.name}!{info.filename}"
                )


def run(arguments: list[str], *, timeout: int = 1800) -> str:
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
        print(completed.stdout, end="", file=sys.stderr)
        raise JobError(f"command failed with {completed.returncode}: {arguments[0]}")
    return completed.stdout


def write_report(name: str, values: list[tuple[str, object]]) -> Path:
    OUTPUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = OUTPUT / name
    with path.open("w", encoding="utf-8") as stream:
        stream.write(f"started_utc={utc_now()}\n")
        for key, value in values:
            stream.write(f"{key}={str(value).replace(chr(10), '\\n')}\n")
        stream.write("exit_status=0\n")
    return path


def safe_extract(archive_path: Path, destination: Path) -> None:
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    root = destination.resolve()
    with tarfile.open(archive_path, "r:*") as archive:
        for member in archive.getmembers():
            name = str(PurePosixPath(member.name))
            target = (destination / name).resolve()
            if name.startswith("/") or not target.is_relative_to(root):
                raise JobError(f"unsafe dependency member: {member.name}")
            if not (member.isfile() or member.isdir() or member.issym()):
                raise JobError(f"unsupported dependency member: {member.name}")
        archive.extractall(destination, filter="data")


def restore_dependencies() -> dict[str, object]:
    archive = ROOT / ".container-input/gradle-home.tar"
    manifest_path = ROOT / ".container-input/dependencies.json"
    if not archive.is_file() or not manifest_path.is_file():
        raise JobError("verified dependency input is missing")
    decoded: object = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(decoded, dict) or not all(isinstance(key, str) for key in decoded):
        raise JobError("dependency manifest is not a string-keyed object")
    manifest = cast(dict[str, object], decoded)
    if manifest.get("archive_sha256") != sha256(archive):
        raise JobError("dependency input checksum mismatch")
    safe_extract(archive, GRADLE_HOME)
    return manifest


def add_tree(archive: tarfile.TarFile, root: Path) -> None:
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.name.endswith(".lock") or path.name.endswith(".tmp") or "daemon" in path.parts:
            continue
        info = archive.gettarinfo(str(path), arcname=relative)
        info.uid = 1000
        info.gid = 1000
        info.uname = ""
        info.gname = ""
        info.mtime = 0
        if info.isfile():
            with path.open("rb") as stream:
                archive.addfile(info, stream)
        else:
            archive.addfile(info)


def dependencies(_args: argparse.Namespace) -> None:
    wrapper = ROOT / "gradle/wrapper/gradle-wrapper.jar"
    if sha256(wrapper) != "55243ef57851f12b070ad14f7f5bb8302daceeebc5bce5ece5fa6edb23e1145c":
        raise JobError("Gradle wrapper JAR checksum mismatch")
    GRADLE_HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    common = ["./gradlew", "--no-daemon", "--stacktrace"]
    resolution_tasks = [
        "resolveAllDependencies",
        "spotlessApply",
    ]
    run([*common, "--write-verification-metadata", "sha256", *resolution_tasks])
    verification = ROOT / "gradle/verification-metadata.xml"
    if not verification.is_file():
        raise JobError("Gradle did not create verification metadata")
    for relative in [
        ".gradle",
        "build",
        "components/location/controller/build",
        "components/probe/build",
    ]:
        shutil.rmtree(ROOT / relative, ignore_errors=True)
    run(
        [
            *common,
            "--offline",
            "--dependency-verification",
            "strict",
            *resolution_tasks,
        ]
    )

    aapt2_hashes = {sha256(path) for path in GRADLE_HOME.rglob(MAVEN_AAPT2) if path.is_file()}
    if len(aapt2_hashes) != 1:
        raise JobError(f"unexpected {MAVEN_AAPT2} hashes: {sorted(aapt2_hashes)}")

    OUTPUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    cache_archive = OUTPUT / "gradle-home.tar"
    with tarfile.open(cache_archive, "w") as archive:
        add_tree(archive, GRADLE_HOME)
    shutil.copy2(verification, OUTPUT / "verification-metadata.xml")
    manifest = {
        "schema_version": 1,
        "dependency_key": os.environ["DEPENDENCY_KEY"],
        "archive_sha256": sha256(cache_archive),
        "archive_bytes": cache_archive.stat().st_size,
        "gradle_version": "9.4.1",
        "agp_version": "9.2.1",
        "quality_dependencies": {
            "google_java_format": "1.29.0",
            "ktlint": "1.8.0",
            "spotless": "8.9.0",
        },
        "maven_aapt2": {"filename": MAVEN_AAPT2, "sha256": next(iter(aapt2_hashes))},
    }
    (OUTPUT / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def signing_init(_args: argparse.Namespace) -> None:
    OUTPUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    keystore = OUTPUT / "debug.keystore"
    run(
        [
            "keytool",
            "-genkeypair",
            "-keystore",
            str(keystore),
            "-storepass",
            "android",
            "-alias",
            "androiddebugkey",
            "-keypass",
            "android",
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "10000",
            "-dname",
            "CN=ZygVeil Debug,O=Development,C=FI",
        ]
    )
    keystore.chmod(0o600)
    write_report(
        "signing-init.txt",
        [("keystore_sha256", sha256(keystore)), ("secrets_printed", "false")],
    )


def signing_info(_args: argparse.Namespace) -> None:
    keystore = ROOT / ".container-input/debug.keystore"
    output = run(
        [
            "keytool",
            "-list",
            "-v",
            "-keystore",
            str(keystore),
            "-storepass",
            "android",
            "-alias",
            "androiddebugkey",
        ]
    )
    match = re.search(r"SHA256:\s*([0-9A-F:]+)", output)
    if not match:
        raise JobError("could not parse signing SHA-256 fingerprint")
    write_report(
        "signing-info.txt",
        [
            ("certificate_sha256", match.group(1)),
            ("keystore_sha256", sha256(keystore)),
            ("secrets_printed", "false"),
        ],
    )


def detector_source_hash() -> tuple[str, int]:
    source_root = PROBE_ROOT / "src/main/java/dev/zygveil/probe"
    shared_sources = [
        source_root / "BaseProbeService.java",
        source_root / "ProbeActivity.java",
        source_root / "ProbeCoordinator.java",
        source_root / "ProbePendingIntentReceiver.java",
        source_root / "ProbeService.java",
        source_root / "SecondaryProbePendingIntentReceiver.java",
        source_root / "SecondaryProbeService.java",
    ]
    paths = sorted(
        [
            PROBE_ROOT / "build.gradle.kts",
            PROBE_ROOT / "src/main/AndroidManifest.xml",
            *shared_sources,
            *(source_root / "detector").rglob("*.java"),
        ]
    )
    if any(not path.is_file() for path in paths):
        raise JobError("probe detector source inventory is incomplete")
    if not paths:
        raise JobError("probe detector source set is empty")
    digest = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(ROOT).as_posix()
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest(), len(paths)


def location_probe_source_hash() -> tuple[str, int]:
    explicit = [
        PROBE_ROOT / "build.gradle.kts",
        PROBE_ROOT / "src/main/AndroidManifest.xml",
        PROBE_ROOT / "src/main/java/dev/zygveil/probe/BaseLocationProbeService.java",
        PROBE_ROOT / "src/main/java/dev/zygveil/probe/LocationProbeService.java",
        PROBE_ROOT / "src/main/java/dev/zygveil/probe/SecondaryLocationProbeService.java",
        PROBE_ROOT / "src/main/java/dev/zygveil/probe/ProbeActivity.java",
        PROBE_ROOT / "src/main/java/dev/zygveil/probe/ProbeCoordinator.java",
        PROBE_ROOT / "src/main/java/dev/zygveil/probe/ProbePendingIntentReceiver.java",
        PROBE_ROOT / "src/main/java/dev/zygveil/probe/SecondaryProbePendingIntentReceiver.java",
        PROBE_ROOT / "src/main/java/dev/zygveil/probe/detector/RunConfig.java",
    ]
    paths = sorted(
        [
            *explicit,
            *(PROBE_ROOT / "src/main/java/dev/zygveil/probe/location").rglob("*.java"),
            *(PROBE_ROOT / "src/primary/java/dev/zygveil/probe/location").rglob("*.java"),
            *(PROBE_ROOT / "src/canary/java/dev/zygveil/probe/location").rglob("*.java"),
        ]
    )
    if any(not path.is_file() for path in paths):
        raise JobError("location probe source inventory is incomplete")
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(ROOT).as_posix().encode("utf-8") + b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest(), len(paths)


def apk_identity(path: Path, expected_sdk: dict[str, int] | None = None) -> tuple[str, set[str]]:
    aapt2 = "/opt/android-sdk/build-tools/37.0.0/aapt2"
    output = run([aapt2, "dump", "badging", str(path)])
    package = re.search(r"^package: name='([^']+)'", output, re.MULTILINE)
    if package is None:
        raise JobError(f"could not parse package ID from {path}")
    permissions = set(
        re.findall(r"^uses-permission(?:-sdk-\d+)?: name='([^']+)'", output, re.MULTILINE)
    )
    sdk_lines = [
        line
        for line in output.splitlines()
        if line.startswith(("package:", "sdkVersion:", "targetSdkVersion:"))
    ]
    manifest = run([aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", str(path)])
    min_sdk = re.search(
        r"android:minSdkVersion[^\n]*=(?:(?:\(type 0x10\))?0x([0-9a-fA-F]+)|([0-9]+))",
        manifest,
    )
    package_line = sdk_lines[0] if sdk_lines else ""
    compile_sdk = re.search(r"compileSdkVersion='([0-9]+)'", package_line)
    target_sdk = re.search(r"^targetSdkVersion:'([0-9]+)'$", output, re.MULTILINE)
    actual = {
        "min": (int(min_sdk.group(1), 16) if min_sdk.group(1) else int(min_sdk.group(2)))
        if min_sdk
        else None,
        "target": int(target_sdk.group(1)) if target_sdk else None,
        "compile": int(compile_sdk.group(1)) if compile_sdk else None,
    }
    expected = expected_sdk or {"min": 36, "target": 36, "compile": 36}
    if actual != expected:
        manifest_sdk_lines = [
            line.strip() for line in manifest.splitlines() if "SdkVersion" in line
        ]
        raise JobError(
            f"probe SDK boundary mismatch in {path}: actual={actual} "
            f"badging={sdk_lines[:8]} manifest={manifest_sdk_lines[:8]}"
        )
    return package.group(1), permissions


def intent_filter_signatures(xmltree: str) -> tuple[tuple[tuple[str, str], ...], ...]:
    """Return the direct action/category entries from each compiled intent filter."""
    lines = xmltree.splitlines()
    filters: list[tuple[tuple[str, str], ...]] = []
    for start, line in enumerate(lines):
        root = re.match(r"^(\s*)E: intent-filter\b", line)
        if root is None:
            continue
        root_indent = len(root.group(1))
        end = len(lines)
        descendants: list[tuple[int, int, str]] = []
        for index in range(start + 1, len(lines)):
            element = re.match(r"^(\s*)E: ([^\s]+)\b", lines[index])
            if element is None:
                continue
            indent = len(element.group(1))
            if indent <= root_indent:
                end = index
                break
            descendants.append((index, indent, element.group(2)))
        if not descendants:
            filters.append(())
            continue
        child_indent = min(indent for _, indent, _ in descendants)
        children = [entry for entry in descendants if entry[1] == child_indent]
        signature: list[tuple[str, str]] = []
        for child_position, (index, _, name) in enumerate(children):
            next_index = (
                children[child_position + 1][0] if child_position + 1 < len(children) else end
            )
            value = ""
            for attribute_line in lines[index + 1 : next_index]:
                attribute = re.match(
                    r'^\s+A: \S*:name\(0x[0-9a-fA-F]+\)="([^"]+)"',
                    attribute_line,
                )
                if attribute is not None:
                    value = attribute.group(1)
                    break
            signature.append((name, value))
        filters.append(tuple(signature))
    return tuple(filters)


def xmltree_attribute_values(xmltree: str, name: str) -> tuple[str, ...]:
    pattern = re.compile(
        rf'^\s+A: (?:\S*:)?{re.escape(name)}(?:\(0x[0-9a-fA-F]+\))?="([^"]*)"',
        re.MULTILINE,
    )
    return tuple(pattern.findall(xmltree))


def manifest_component_signatures(
    xmltree: str,
) -> tuple[tuple[str, str, bool | None], ...]:
    lines = xmltree.splitlines()
    signatures: list[tuple[str, str, bool | None]] = []
    for start, line in enumerate(lines):
        element = re.match(r"^(\s*)E: (activity|activity-alias|service|receiver|provider)\b", line)
        if element is None:
            continue
        indent = len(element.group(1))
        end = len(lines)
        for index in range(start + 1, len(lines)):
            nested = re.match(r"^(\s*)E: ", lines[index])
            if nested is not None and len(nested.group(1)) <= indent:
                end = index
                break
        block = "\n".join(lines[start + 1 : end])
        name = re.search(r'^\s+A: \S*:name\([^\n]*\)="([^"]+)"', block, re.MULTILINE)
        exported = re.search(
            r"^\s+A: \S*:exported\([^\n]*\)=(?:\(type 0x12\))?([^\s]+)",
            block,
            re.MULTILINE,
        )
        exported_value: bool | None = None
        if exported is not None:
            if exported.group(1) in {"true", "0xffffffff"}:
                exported_value = True
            elif exported.group(1) in {"false", "0x0"}:
                exported_value = False
        signatures.append(
            (element.group(2), name.group(1) if name is not None else "", exported_value)
        )
    return tuple(signatures)


def apk_presentation(path: Path) -> tuple[str, str]:
    aapt2 = "/opt/android-sdk/build-tools/37.0.0/aapt2"
    output = run([aapt2, "dump", "badging", str(path)])
    version = re.search(r"^package: .* versionName='([^']+)'", output, re.MULTILINE)
    label = re.search(r"^application-label:'([^']+)'", output, re.MULTILINE)
    if version is None or label is None:
        raise JobError("could not parse production version/label")
    return version.group(1), label.group(1)


def build_probe(_args: argparse.Namespace) -> None:
    manifest = restore_dependencies()
    keystore = ROOT / ".container-input/debug.keystore"
    if not keystore.is_file():
        raise JobError("stable signing input is missing")
    forbidden = ["libxposed", "io.github.libxposed", 'project(":app")', "META-INF/xposed"]
    probe_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "components/probe").rglob("*"))
        if path.is_file() and path.suffix in {".java", ".kts", ".xml"}
    )
    for token in forbidden:
        if token in probe_text:
            raise JobError(f"probe independence violation: {token}")
    probe_source_root = ROOT / "components/probe/src/main/java/dev/zygveil/probe"
    activity_source = (probe_source_root / "ProbeActivity.java").read_text(encoding="utf-8")
    base_service_source = (probe_source_root / "BaseProbeService.java").read_text(encoding="utf-8")
    service_sources = {
        name: (probe_source_root / f"{name}.java").read_text(encoding="utf-8")
        for name in ("ProbeService", "SecondaryProbeService")
    }
    if "ProbeCoordinator.execute" in activity_source or "ExecutorService" in activity_source:
        raise JobError("probe Activity owns non-location detector execution")
    for marker in ("abstract class BaseProbeService extends Service", "ProbeCoordinator.execute"):
        if marker not in base_service_source:
            raise JobError("probe non-location service lifecycle is incomplete")
    for name, service_source in service_sources.items():
        if f"class {name} extends BaseProbeService" not in service_source:
            raise JobError(f"probe service does not share the base lifecycle: {name}")
    environment = os.environ.copy()
    environment["ZYGVEIL_KEYSTORE"] = str(keystore)
    completed = subprocess.run(
        [
            "./gradlew",
            "--offline",
            "--no-daemon",
            "--stacktrace",
            "--dependency-verification",
            "strict",
            ":probe:assemblePrimaryDebug",
            ":probe:assembleCanaryDebug",
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=1800,
    )
    if completed.returncode != 0:
        print(completed.stdout, end="", file=sys.stderr)
        raise JobError(f"offline probe build failed with {completed.returncode}")

    source_paths = {
        "primary": ROOT
        / "components/probe/build/outputs/apk/primary/debug/probe-primary-debug.apk",
        "canary": ROOT / "components/probe/build/outputs/apk/canary/debug/probe-canary-debug.apk",
    }
    OUTPUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    exported: dict[str, Path] = {}
    identities: dict[str, str] = {}
    base_permissions = {
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.CHANGE_NETWORK_STATE",
        "android.permission.FOREGROUND_SERVICE",
        "android.permission.FOREGROUND_SERVICE_LOCATION",
        "android.permission.INTERNET",
    }
    for variant, source in source_paths.items():
        destination = OUTPUT / f"zygveil-probe-{variant}-debug.apk"
        shutil.copy2(source, destination)
        exported[variant] = destination
        package, permissions = apk_identity(destination)
        expected_package = f"dev.zygveil.probe.{variant}"
        expected_permissions = set(base_permissions)
        if variant == "canary":
            expected_permissions.add(
                "dev.zygveil.probe.canary.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
            )
        if package != expected_package or permissions != expected_permissions:
            raise JobError(
                f"probe manifest mismatch for {variant}: package={package} "
                f"permissions={sorted(permissions)}"
            )
        identities[variant] = package
        with zipfile.ZipFile(destination) as archive:
            if any(name.startswith("META-INF/xposed/") for name in archive.namelist()):
                raise JobError(f"Xposed metadata found in independent {variant} probe")
        assert_archive_privacy(destination)
        xmltree = run(
            [
                "/opt/android-sdk/build-tools/37.0.0/aapt2",
                "dump",
                "xmltree",
                "--file",
                "AndroidManifest.xml",
                str(destination),
            ]
        )
        component_namespace = "dev.zygveil.probe"
        base_components = (
            ("activity", f"{component_namespace}.ProbeActivity", True),
            ("service", f"{component_namespace}.ProbeService", False),
            ("service", f"{component_namespace}.SecondaryProbeService", False),
            ("service", f"{component_namespace}.LocationProbeService", False),
            ("service", f"{component_namespace}.SecondaryLocationProbeService", False),
            ("receiver", f"{component_namespace}.ProbePendingIntentReceiver", False),
            ("receiver", f"{component_namespace}.SecondaryProbePendingIntentReceiver", False),
        )
        dependency_components = (
            (("activity", "com.google.android.gms.common.api.GoogleApiActivity", False),)
            if variant == "canary"
            else ()
        )
        components = manifest_component_signatures(xmltree)
        expected_components = base_components + dependency_components
        if components != expected_components:
            raise JobError(f"probe component boundary mismatch for {variant}: {components}")
    if identities["primary"] == identities["canary"]:
        raise JobError("probe application IDs are not distinct")

    detector_hash, detector_files = detector_source_hash()
    location_hash, location_files = location_probe_source_hash()
    (OUTPUT / "probe-detector-source.sha256").write_text(
        f"{detector_hash}  probe-detector-source\n", encoding="utf-8"
    )
    write_report(
        "build-probe.txt",
        [
            ("dependency_key", manifest["dependency_key"]),
            ("network", "none"),
            ("compile_sdk", 36),
            ("target_sdk", 36),
            ("min_sdk", 36),
            ("detector_source_sha256", detector_hash),
            ("detector_source_files", detector_files),
            ("location_source_sha256", location_hash),
            ("location_source_files", location_files),
            ("location_record_schema", 4),
            ("location_processes", "main,secondary"),
            ("primary_application_id", identities["primary"]),
            ("canary_application_id", identities["canary"]),
            ("primary_apk_sha256", sha256(exported["primary"])),
            ("canary_apk_sha256", sha256(exported["canary"])),
            ("libxposed_dependency", "absent"),
            ("xposed_metadata", "absent"),
            ("production_hooks", "absent"),
            ("artifact_privacy", "pass"),
        ],
    )


def build_probe_canary_poc(_args: argparse.Namespace) -> None:
    restore_dependencies()
    keystore = ROOT / ".container-input/debug.keystore"
    if not keystore.is_file():
        raise JobError("stable signing input is missing")
    environment = os.environ.copy()
    environment["ZYGVEIL_KEYSTORE"] = str(keystore)
    completed = subprocess.run(
        [
            "./gradlew",
            "--offline",
            "--no-daemon",
            "--stacktrace",
            "--dependency-verification",
            "strict",
            ":probe:assembleCanaryDebug",
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=1800,
    )
    if completed.returncode != 0:
        print(completed.stdout, end="", file=sys.stderr)
        raise JobError(f"offline canary POC build failed with {completed.returncode}")

    source = ROOT / "components/probe/build/outputs/apk/canary/debug/probe-canary-debug.apk"
    OUTPUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = OUTPUT / "zygveil-probe-canary-poc.apk"
    shutil.copy2(source, destination)
    package, permissions = apk_identity(destination)
    expected_permissions = {
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.CHANGE_NETWORK_STATE",
        "android.permission.FOREGROUND_SERVICE",
        "android.permission.FOREGROUND_SERVICE_LOCATION",
        "android.permission.INTERNET",
        "dev.zygveil.probe.canary.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
    }
    if package != "dev.zygveil.probe.canary" or permissions != expected_permissions:
        raise JobError(
            f"canary POC identity mismatch: package={package} permissions={sorted(permissions)}"
        )
    with zipfile.ZipFile(destination) as archive:
        if any(name.startswith("META-INF/xposed/") for name in archive.namelist()):
            raise JobError("Xposed metadata found in independent canary POC")
    assert_archive_privacy(destination)
    write_report(
        "build-probe-canary-poc.txt",
        [
            ("network", "none"),
            ("variant", "canary"),
            ("application_id", package),
            ("artifact_class", "non_attestable_poc"),
            ("output_boundary", ".artifacts/poc"),
            ("primary_build", "skipped"),
            ("lint", "skipped"),
            ("hash_attestation", "skipped"),
            ("reproducibility", "skipped"),
            ("artifact_privacy", "pass"),
        ],
    )


def build_probe_server_vpn_poc(_args: argparse.Namespace) -> None:
    restore_dependencies()
    keystore = ROOT / ".container-input/debug.keystore"
    if not keystore.is_file():
        raise JobError("stable signing input is missing")
    environment = os.environ.copy()
    environment["ZYGVEIL_KEYSTORE"] = str(keystore)
    completed = subprocess.run(
        [
            "./gradlew",
            "--offline",
            "--no-daemon",
            "--stacktrace",
            "--dependency-verification",
            "strict",
            ":probe:assemblePrimaryDebug",
            ":probe:assembleCanaryDebug",
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=1800,
    )
    if completed.returncode != 0:
        print(completed.stdout, end="", file=sys.stderr)
        raise JobError(f"offline server-VPN probe POC build failed with {completed.returncode}")

    base_permissions = {
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.CHANGE_NETWORK_STATE",
        "android.permission.FOREGROUND_SERVICE",
        "android.permission.FOREGROUND_SERVICE_LOCATION",
        "android.permission.INTERNET",
    }
    OUTPUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    for variant in ("primary", "canary"):
        source = (
            ROOT / f"components/probe/build/outputs/apk/{variant}/debug/probe-{variant}-debug.apk"
        )
        destination = OUTPUT / f"zygveil-probe-{variant}-poc.apk"
        shutil.copy2(source, destination)
        package, permissions = apk_identity(destination)
        expected_permissions = set(base_permissions)
        if variant == "canary":
            expected_permissions.add(
                "dev.zygveil.probe.canary.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
            )
        if package != f"dev.zygveil.probe.{variant}" or permissions != expected_permissions:
            raise JobError(
                f"server-VPN {variant} probe POC identity mismatch: "
                f"package={package} permissions={sorted(permissions)}"
            )
        with zipfile.ZipFile(destination) as archive:
            if any(name.startswith("META-INF/xposed/") for name in archive.namelist()):
                raise JobError(f"Xposed metadata found in independent {variant} probe POC")
        assert_archive_privacy(destination)
    write_report(
        "build-probe-server-vpn-poc.txt",
        [
            ("network", "none"),
            ("variants", "primary,canary"),
            ("primary_application_id", "dev.zygveil.probe.primary"),
            ("canary_application_id", "dev.zygveil.probe.canary"),
            ("artifact_class", "non_attestable_poc"),
            ("output_boundary", ".artifacts/poc"),
            ("lint", "skipped"),
            ("hash_attestation", "skipped"),
            ("reproducibility", "skipped"),
            ("artifact_privacy", "pass"),
        ],
    )


def dex_class_descriptors(data: bytes, source: str) -> set[str]:
    if len(data) < 0x70 or data[:4] != b"dex\n" or data[7] != 0:
        raise JobError(f"unsupported DEX header: {source}")

    def u32(offset: int) -> int:
        if offset < 0 or offset + 4 > len(data):
            raise JobError(f"DEX table leaves bounds: {source}")
        return int(struct.unpack_from("<I", data, offset)[0])

    def string(index: int) -> str:
        string_count = u32(0x38)
        string_offset = u32(0x3C)
        if index < 0 or index >= string_count:
            raise JobError(f"DEX string index leaves bounds: {source}")
        cursor = u32(string_offset + index * 4)
        for _ in range(5):
            if cursor >= len(data):
                raise JobError(f"truncated DEX string length: {source}")
            value = data[cursor]
            cursor += 1
            if value & 0x80 == 0:
                break
        else:
            raise JobError(f"oversized DEX string length: {source}")
        terminator = data.find(b"\0", cursor)
        if terminator < 0:
            raise JobError(f"unterminated DEX string: {source}")
        return data[cursor:terminator].decode("utf-8", errors="strict")

    type_count = u32(0x40)
    type_offset = u32(0x44)
    class_count = u32(0x60)
    class_offset = u32(0x64)
    descriptors: set[str] = set()
    for class_number in range(class_count):
        class_index = u32(class_offset + class_number * 32)
        if class_index >= type_count:
            raise JobError(f"DEX class type leaves bounds: {source}")
        descriptors.add(string(u32(type_offset + class_index * 4)))
    return descriptors


def build_controller(_args: argparse.Namespace) -> None:
    manifest = restore_dependencies()
    keystore = ROOT / ".container-input/debug.keystore"
    if not keystore.is_file():
        raise JobError("stable signing input is missing")
    environment = os.environ.copy()
    environment["ZYGVEIL_KEYSTORE"] = str(keystore)
    completed = subprocess.run(
        [
            "./gradlew",
            "--offline",
            "--no-daemon",
            "--stacktrace",
            "--dependency-verification",
            "strict",
            ":location-controller:assembleDebug",
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=1800,
    )
    if completed.returncode != 0:
        print(completed.stdout, end="", file=sys.stderr)
        reports = sorted(
            (ROOT / "components/location/controller").glob("build/**/lint-results-debug.txt")
        )
        for report in reports:
            print(f"--- {report.relative_to(ROOT)} ---", file=sys.stderr)
            print(report.read_text(encoding="utf-8"), file=sys.stderr)
        raise JobError(f"offline controller build failed with {completed.returncode}")

    source = (
        ROOT
        / "components/location/controller/build/outputs/apk/debug/location-controller-debug.apk"
    )
    destination = OUTPUT / "zygveil-location-controller-debug.apk"
    OUTPUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    package, permissions = apk_identity(destination)
    if package != "dev.zygveil.location.controller" or permissions:
        raise JobError(
            f"controller manifest boundary mismatch: package={package} permissions={permissions}"
        )
    version_name, application_label = apk_presentation(destination)
    badging = run(
        ["/opt/android-sdk/build-tools/37.0.0/aapt2", "dump", "badging", str(destination)]
    )
    version_code = re.search(r"^package: .* versionCode='([0-9]+)'", badging, re.MULTILINE)
    launcher = re.search(r"^launchable-activity: name='([^']+)'", badging, re.MULTILINE)
    if (
        version_name != "0.1.0"
        or version_code is None
        or version_code.group(1) != "1"
        or application_label != "ZygVeil Location"
        or launcher is None
        or launcher.group(1) != "dev.zygveil.location.controller.ControllerActivity"
    ):
        raise JobError(
            "controller presentation mismatch: "
            f"version={version_name!r}/{version_code.group(1) if version_code else 'missing'} "
            f"label={application_label!r} launcher={launcher.group(1) if launcher else 'missing'}"
        )

    xmltree = run(
        [
            "/opt/android-sdk/build-tools/37.0.0/aapt2",
            "dump",
            "xmltree",
            "--file",
            "AndroidManifest.xml",
            str(destination),
        ]
    )
    components = re.findall(
        r"^\s+E: (activity|activity-alias|service|receiver|provider)\b",
        xmltree,
        re.MULTILINE,
    )
    expected_intent_filters = (
        (
            ("action", "android.intent.action.MAIN"),
            ("category", "android.intent.category.LAUNCHER"),
        ),
        (
            ("action", "dev.zygveil.location.controller.action.REQUEST_ROOT"),
            ("category", "android.intent.category.DEFAULT"),
        ),
    )
    intent_filters = intent_filter_signatures(xmltree)
    manifest_checks = {
        "components": components == ["activity"],
        "intent_filters": intent_filters == expected_intent_filters,
        "exported": re.search(r"^[^\n]*:exported\([^\n]*\)=true$", xmltree, re.MULTILINE)
        is not None,
        "single_top": re.search(r"^[^\n]*:launchMode\([^\n]*\)=1$", xmltree, re.MULTILINE)
        is not None,
        "backup_disabled": re.search(r"^[^\n]*:allowBackup\([^\n]*\)=false$", xmltree, re.MULTILINE)
        is not None,
        "extraction_rules": re.search(
            r"^[^\n]*:dataExtractionRules\([^\n]*\)=@0x[0-9a-fA-F]+$",
            xmltree,
            re.MULTILINE,
        )
        is not None,
    }
    failed_manifest_checks = sorted(name for name, passed in manifest_checks.items() if not passed)
    if failed_manifest_checks:
        diagnostic_tokens = (
            "intent-filter",
            "action",
            "category",
            "exported",
            "launchMode",
            "allowBackup",
            "dataExtractionRules",
        )
        diagnostic = [
            line.strip()
            for line in xmltree.splitlines()
            if any(token in line for token in diagnostic_tokens)
        ]
        raise JobError(
            "controller component boundary mismatch: "
            f"failed={failed_manifest_checks} components={components} "
            f"intent_filters={intent_filters} diagnostic={diagnostic}"
        )
    forbidden_manifest_patterns = {
        "queries": r"^\s+E: queries\b",
        "feature": r"^\s+E: uses-feature\b",
        "permission_element": (
            r"^\s+E: (?:uses-permission(?:-sdk-[0-9]+)?|permission|permission-group|"
            r"permission-tree)\b"
        ),
        "permission_attribute": r"^\s+A: \S*:permission(?:\(0x[0-9a-fA-F]+\))?=",
    }
    forbidden_manifest = sorted(
        name
        for name, pattern in forbidden_manifest_patterns.items()
        if re.search(pattern, xmltree, re.MULTILINE) is not None
    )
    if forbidden_manifest:
        raise JobError(f"controller manifest contains forbidden entries: {forbidden_manifest}")

    extraction_tree = run(
        [
            "/opt/android-sdk/build-tools/37.0.0/aapt2",
            "dump",
            "xmltree",
            "--file",
            "res/xml/data_extraction_rules.xml",
            str(destination),
        ]
    )
    extraction_elements = tuple(re.findall(r"^\s*E: ([^\s]+)\b", extraction_tree, re.MULTILINE))
    expected_extraction_elements = (
        "data-extraction-rules",
        "cloud-backup",
        "exclude",
        "exclude",
        "device-transfer",
        "exclude",
        "exclude",
    )
    if (
        extraction_elements != expected_extraction_elements
        or xmltree_attribute_values(extraction_tree, "domain")
        != ("root", "device_root", "root", "device_root")
        or xmltree_attribute_values(extraction_tree, "path") != (".", ".", ".", ".")
    ):
        raise JobError(
            f"controller extraction-rule boundary mismatch: elements={extraction_elements}"
        )

    signer_output = run(
        [
            "/opt/android-sdk/build-tools/37.0.0/apksigner",
            "verify",
            "--print-certs",
            str(destination),
        ]
    )
    signer = re.search(r"certificate SHA-256 digest:\s*([0-9a-fA-F]+)", signer_output)
    expected_signer = "2a2098191bdf2fdf1c4d3e4a2d2686c8b3f59f8225470331a44482ed073e0c0d"
    if signer is None or signer.group(1).lower() != expected_signer:
        raise JobError("controller signing identity mismatch")

    with zipfile.ZipFile(destination) as archive:
        names = set(archive.namelist())
        dex_names = sorted(name for name in names if re.fullmatch(r"classes[0-9]*\.dex", name))
        if not 1 <= len(dex_names) <= 4 or dex_names[0] != "classes.dex":
            raise JobError(f"controller DEX inventory mismatch: {dex_names}")
        if any(name.startswith("lib/") or name.startswith("META-INF/xposed/") for name in names):
            raise JobError("controller contains native or Xposed payload")
        dex_payloads = {name: archive.read(name) for name in dex_names}
        descriptors: set[str] = set()
        for name, data in dex_payloads.items():
            current = dex_class_descriptors(data, f"controller!{name}")
            duplicate = descriptors.intersection(current)
            if duplicate:
                raise JobError(f"controller duplicate DEX ownership: {sorted(duplicate)[:8]}")
            descriptors.update(current)
        expected_prefix = "Ldev/zygveil/location/controller/"
        foreign = sorted(value for value in descriptors if not value.startswith(expected_prefix))
        expected_desugar_support = [
            "Lcom/android/tools/r8/annotations/LambdaMethod;",
            "Ljava/lang/Record;",
            "Ljava/lang/invoke/MethodHandles$Lookup;",
            "Ljava/lang/invoke/VarHandle;",
        ]
        owned = descriptors.difference(expected_desugar_support)
        if foreign != expected_desugar_support or not 8 <= len(owned) <= 76:
            raise JobError(
                f"controller class ownership mismatch: owned={len(owned)} foreign={foreign[:8]}"
            )
        forbidden_dex = [
            b"Landroid/location/",
            b"Ljava/net/",
            b"Ldev/zygveil/module/",
            b"Ldev/zygveil/policy/",
            b"Ldev/zygveil/probe/",
            b"libxposed",
            b"Xposed",
            b"Zygisk",
            b"analytics",
            b"okhttp",
        ]
        found = [
            value.decode("ascii")
            for value in forbidden_dex
            if any(value in data for data in dex_payloads.values())
        ]
        if found:
            raise JobError(f"controller DEX boundary violation: {found}")
        helper_commands = [
            b"/data/adb/modules/zygveil/locationctl status",
            b"/data/adb/modules/zygveil/locationctl status-ui",
            b"/data/adb/modules/zygveil/locationctl apply",
        ]
        if not all(
            any(value in data for data in dex_payloads.values()) for value in helper_commands
        ):
            raise JobError("controller fixed helper command inventory mismatch")
    assert_archive_privacy(destination)

    write_report(
        "build-location-controller.txt",
        [
            ("dependency_key", manifest["dependency_key"]),
            ("network", "none"),
            ("application_id", package),
            ("application_label", application_label),
            ("version_code", 1),
            ("version_name", version_name),
            ("compile_sdk", 36),
            ("target_sdk", 36),
            ("min_sdk", 36),
            ("certificate_sha256", expected_signer),
            ("requested_permissions", "none"),
            ("exported_components", "ControllerActivity"),
            ("other_components", "none"),
            ("native_libraries", "none"),
            ("dex_files", len(dex_names)),
            ("dex_owned_classes", len(owned)),
            ("dex_desugar_support_classes", len(expected_desugar_support)),
            ("project_dependencies", "none"),
            ("fixed_helper_commands", 3),
            ("apk_sha256", sha256(destination)),
            ("apk_bytes", destination.stat().st_size),
            ("artifact_privacy", "pass"),
        ],
    )


def quality_gradle(arguments: list[str]) -> str:
    return run(
        [
            "./gradlew",
            "--offline",
            "--no-daemon",
            "--stacktrace",
            "--dependency-verification",
            "strict",
            *arguments,
        ]
    )


def test_server_vpn_model(_args: argparse.Namespace) -> None:
    output_directory = Path("/tmp/server-vpn-model-unit-classes")
    shutil.rmtree(output_directory, ignore_errors=True)
    output_directory.mkdir(mode=0o700, parents=True)
    policy_root = SERVER_VPN_ROOT / "src/main/java/dev/zygveil/servervpn/policy"
    policy_sources = sorted(policy_root.glob("*.java"))
    harness = (
        SERVER_VPN_ROOT
        / "src/testHarness/java/dev/zygveil/servervpn/policy/ServerVpnModelUnitMain.java"
    )
    if len(policy_sources) < 7:
        raise JobError("server-VPN model source inventory is incomplete")
    for source in [*policy_sources, harness]:
        if not source.is_file():
            raise JobError(f"server-VPN model test source is missing: {source.relative_to(ROOT)}")
    run(
        [
            "javac",
            "--release",
            "21",
            "-Xlint:all",
            "-Werror",
            "-d",
            str(output_directory),
            *[str(source) for source in policy_sources],
            str(harness),
        ]
    )
    output = run(
        [
            "java",
            "-ea",
            "-cp",
            str(output_directory),
            "dev.zygveil.servervpn.policy.ServerVpnModelUnitMain",
        ]
    )
    fields = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    if fields.get("schema_version") != "1" or fields.get("status") != "PASS":
        raise JobError(f"server-VPN model result mismatch: {fields}")
    count = fields.get("tests", "")
    if not count.isdigit() or int(count) < 1_200:
        raise JobError(f"server-VPN model coverage count is too small: {count!r}")
    write_report(
        "test-server-vpn-model.txt",
        [
            ("network", "none"),
            ("artifact_class", "non_attestable_model_gate"),
            ("javac_xlint_werror", "pass"),
            ("status", fields["status"]),
            ("tests", count),
            ("categories", fields.get("categories", "missing")),
            ("model_sources", len(policy_sources)),
            ("android_internal_dependencies", "absent"),
            ("jni_dependencies", "absent"),
            ("production_hooks", "absent"),
            ("hash_attestation", "skipped"),
        ],
    )


def test_server_vpn_config(_args: argparse.Namespace) -> None:
    build_directory = Path("/tmp/server-vpn-config-test")
    shutil.rmtree(build_directory, ignore_errors=True)
    run(
        [
            location_cmake(),
            "-S",
            "components/server-vpn/runtime/native",
            "-B",
            str(build_directory),
            "-G",
            "Ninja",
            f"-DCMAKE_MAKE_PROGRAM={location_ninja()}",
            "-DCMAKE_BUILD_TYPE=Release",
        ]
    )
    run(
        [
            location_cmake(),
            "--build",
            str(build_directory),
            "--target",
            "server_vpn_config_test",
            "server_vpn_status_test",
        ]
    )
    config_output = run(
        [
            str(build_directory / "server_vpn_config_test"),
            "components/server-vpn/runtime/policy.properties",
        ]
    )
    status_output = run([str(build_directory / "server_vpn_status_test")])
    config_fields = dict(line.split("=", 1) for line in config_output.splitlines() if "=" in line)
    status_fields = dict(line.split("=", 1) for line in status_output.splitlines() if "=" in line)
    config_count = config_fields.get("tests", "")
    status_count = status_fields.get("tests", "")
    if (
        config_fields.get("schema_version") != "1"
        or config_fields.get("status") != "PASS"
        or status_fields.get("schema_version") != "1"
        or status_fields.get("status") != "PASS"
        or not config_count.isdigit()
        or int(config_count) < 60
        or not status_count.isdigit()
        or int(status_count) < 30
    ):
        raise JobError(
            "server-VPN config/status result mismatch: "
            f"config={config_fields}, status={status_fields}"
        )
    count = int(config_count) + int(status_count)
    write_report(
        "test-server-vpn-config.txt",
        [
            ("network", "none"),
            ("artifact_class", "non_attestable_config_gate"),
            ("cxx_standard", 23),
            ("warnings_as_errors", "true"),
            ("status", config_fields["status"]),
            ("tests", count),
            (
                "categories",
                f"{config_fields.get('categories', 'missing')},"
                f"{status_fields.get('categories', 'missing')}",
            ),
            ("feature_enabled_key", "absent"),
            ("runtime_mode_key", "absent"),
            ("target_mode", "eligible_user0_apps"),
            ("hash_attestation", "skipped"),
        ],
    )


def test_controller_unit(_args: argparse.Namespace) -> None:
    output_directory = Path("/tmp/location-controller-unit-classes")
    shutil.rmtree(output_directory, ignore_errors=True)
    output_directory.mkdir(mode=0o700, parents=True)
    source_root = CONTROLLER_ROOT / "src/main/java/dev/zygveil/location/controller"
    source_names = [
        "ControllerState.java",
        "CoordinateInput.java",
        "HelperStatus.java",
        "OperationGuard.java",
        "PresetCodec.java",
        "RootHelper.java",
        "RootStatusStore.java",
    ]
    sources = [source_root / name for name in source_names]
    harness = ROOT / (
        "components/location/controller/src/testHarness/java/dev/zygveil/location/controller/"
        "ControllerUnitMain.java"
    )
    for source in [*sources, harness]:
        if not source.is_file():
            raise JobError(f"controller unit source is missing: {source.relative_to(ROOT)}")
    run(
        [
            "javac",
            "--release",
            "21",
            "-Xlint:all",
            "-Werror",
            "-d",
            str(output_directory),
            *[str(source) for source in sources],
            str(harness),
        ]
    )
    output = run(
        [
            "java",
            "-ea",
            "-cp",
            str(output_directory),
            "dev.zygveil.location.controller.ControllerUnitMain",
        ]
    )
    fields = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    count = fields.get("tests", "")
    if (
        fields.get("schema_version") != "1"
        or fields.get("status") != "PASS"
        or not count.isdigit()
        or int(count) < 100
    ):
        raise JobError(f"controller unit harness result mismatch: {fields}")
    write_report(
        "test-location-controller-unit.txt",
        [
            ("network", "none"),
            ("javac_xlint_werror", "pass"),
            ("status", fields["status"]),
            ("tests", count),
            ("categories", fields.get("categories", "missing")),
            ("android_dependencies", "absent"),
        ],
    )


def location_cmake() -> str:
    return "/opt/android-sdk/cmake/3.31.6/bin/cmake"


def location_ninja() -> str:
    return "/opt/android-sdk/cmake/3.31.6/bin/ninja"


def test_location_unit(_args: argparse.Namespace) -> None:
    build_directory = Path("/tmp/location-model-build")
    shutil.rmtree(build_directory, ignore_errors=True)
    run(
        [
            location_cmake(),
            "-S",
            "components/zygisk-host/native",
            "-B",
            str(build_directory),
            "-G",
            "Ninja",
            f"-DCMAKE_MAKE_PROGRAM={location_ninja()}",
            "-DCMAKE_BUILD_TYPE=Release",
        ]
    )
    run(
        [
            location_cmake(),
            "--build",
            str(build_directory),
            "--target",
            "location_model_test",
            "location_control_test",
            "locationctl_test",
            "location_process_liveness_test",
            "location_application_delivery_test",
        ]
    )
    model_output = run(
        [
            str(build_directory / "location_model_test"),
            "components/zygisk-host/config.example.properties",
        ]
    )
    control_output = run([str(build_directory / "location_control_test")])
    control_repeat_output = run([str(build_directory / "location_control_test")])
    helper_output = run([str(build_directory / "locationctl_test")])
    liveness_output = run([str(build_directory / "location_process_liveness_test")])
    delivery_output = run([str(build_directory / "location_application_delivery_test")])
    model_fields = dict(line.split("=", 1) for line in model_output.splitlines() if "=" in line)
    control_fields = dict(line.split("=", 1) for line in control_output.splitlines() if "=" in line)
    helper_fields = dict(line.split("=", 1) for line in helper_output.splitlines() if "=" in line)
    liveness_fields = dict(
        line.split("=", 1) for line in liveness_output.splitlines() if "=" in line
    )
    delivery_fields = dict(
        line.split("=", 1) for line in delivery_output.splitlines() if "=" in line
    )
    model_count = model_fields.get("tests", "")
    control_count = control_fields.get("tests", "")
    helper_count = helper_fields.get("tests", "")
    liveness_count = liveness_fields.get("tests", "")
    delivery_count = delivery_fields.get("tests", "")
    if (
        model_fields.get("schema_version") != "1"
        or model_fields.get("status") != "PASS"
        or control_fields.get("schema_version") != "1"
        or control_fields.get("status") != "PASS"
        or control_repeat_output != control_output
        or helper_fields.get("schema_version") != "1"
        or helper_fields.get("status") != "PASS"
        or liveness_fields.get("schema_version") != "1"
        or liveness_fields.get("status") != "PASS"
        or delivery_fields.get("schema_version") != "1"
        or delivery_fields.get("status") != "PASS"
        or not model_count.isdigit()
        or not control_count.isdigit()
        or not helper_count.isdigit()
        or not liveness_count.isdigit()
        or not delivery_count.isdigit()
        or int(model_count) < 500
        or int(control_count) < 30
        or int(helper_count) < 20
        or int(liveness_count) < 10
        or int(delivery_count) < 15
    ):
        raise JobError(
            "location unit result mismatch: "
            f"model={model_fields}, control={control_fields}, helper={helper_fields}, "
            f"liveness={liveness_fields}, delivery={delivery_fields}"
        )
    count = (
        int(model_count)
        + int(control_count)
        + int(helper_count)
        + int(liveness_count)
        + int(delivery_count)
    )
    write_report(
        "test-location-unit.txt",
        [
            ("network", "none"),
            ("cxx_standard", 23),
            ("warnings_as_errors", "true"),
            ("deterministic_repeat", "pass"),
            ("status", model_fields["status"]),
            ("tests", count),
            (
                "categories",
                f"{model_fields.get('categories', 'missing')},"
                f"{control_fields.get('categories', 'missing')},"
                f"{helper_fields.get('categories', 'missing')},"
                f"{liveness_fields.get('categories', 'missing')},"
                f"{delivery_fields.get('categories', 'missing')}",
            ),
        ],
    )


def deterministic_zip(path: Path, entries: dict[str, tuple[bytes, int]]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(entries):
            data, mode = entries[name]
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (mode & 0xFFFF) << 16
            archive.writestr(info, data)


def validate_global_location_application_source() -> None:
    source = (ROOT / "components/zygisk-host/native/module.cpp").read_text(encoding="utf-8")
    pre_signature = "void preAppSpecialize(zygisk::AppSpecializeArgs*) override {"
    post_signature = "void postAppSpecialize(const zygisk::AppSpecializeArgs*) override {"
    start = source.find(pre_signature)
    post = source.find(post_signature, start + len(pre_signature))
    end = source.find("void preServerSpecialize", post + len(post_signature))
    if start < 0 or post < 0 or end < 0:
        raise JobError("global location application lifecycle signature is missing")
    lifecycle = source[start:end]
    forbidden_selection = {
        "nice_name",
        "app_data_dir",
        "package_name",
        "process_name",
        "signing",
        "foreground",
        "target_list",
        "getuid(",
        "geteuid(",
        "getgid(",
        "getegid(",
        "/proc/",
        "dev.zygveil.probe",
        "com.google.android.apps.maps",
    }
    found = sorted(token for token in forbidden_selection if token in lifecycle)
    if found:
        raise JobError(f"global location application lifecycle contains selection data: {found}")
    bridge = (
        ROOT / "components/zygisk-host/bridge/dev/zygveil/location/bridge/HookBridge.java"
    ).read_text(encoding="utf-8")
    for marker in (
        "synchronized (this)",
        "dispatch(hookId, localBackup, args)",
        "localBackup.invoke(receiver, parameters)",
    ):
        if marker not in bridge:
            raise JobError(f"location acquisition pass-through is missing: {marker}")
    hook_host = (ROOT / "components/zygisk-host/native/hook_host.cpp").read_text(encoding="utf-8")
    monitor = hook_host.find("MonitorEnter(bridge_object)")
    hook = hook_host.find("lsplant::Hook(env, target, bridge_object, callback)")
    backup = hook_host.find("CallVoidMethod(bridge_object, bridge.set_backup, backup)")
    if min(monitor, hook, backup) < 0 or monitor > hook or hook > backup:
        raise JobError("shared hook host does not assign backups under its bridge monitor")
    runtime = (ROOT / "components/zygisk-host/native/runtime.cpp").read_text(encoding="utf-8")
    owner_filter = "OwnerAt(index) != hook_host::FeatureOwner::kLocation"
    if runtime.count(owner_filter) < 2 or "DeactivateInstalledBridges(env)" not in runtime:
        raise JobError("deferred location activation is not isolated to location-owned hooks")
    monitor_start = source.find("void MonitorApplicationControlPage")
    waiting_start = source.find("if (state == ControlRuntimeState::kWaiting)", monitor_start)
    active_start = source.find("if (state == ControlRuntimeState::kActive)", waiting_start)
    monitor_end = source.find(
        "StoreControlRuntimeState(delivery, ControlRuntimeState::kInactive)", active_start
    )
    if min(monitor_start, waiting_start, active_start, monitor_end) < 0:
        raise JobError("application delivery monitor lifecycle is incomplete")
    waiting_branch = source[waiting_start:active_start]
    active_branch = source[active_start:monitor_end]
    active_publish = "PublishControlAck(delivery, candidate.config_generation,"
    active_gate = "StoreControlRuntimeState(delivery, ControlRuntimeState::kActive)"
    if active_gate in waiting_branch or active_publish in waiting_branch:
        raise JobError("pending location generation prematurely activates application delivery")
    if active_publish not in active_branch or active_gate not in active_branch:
        raise JobError("authoritative location activation is not mirrored to applications")


def validate_server_vpn_application_isolation_source() -> None:
    source = (ROOT / "components/zygisk-host/native/module.cpp").read_text(encoding="utf-8")
    pre_signature = "void preAppSpecialize(zygisk::AppSpecializeArgs*) override {"
    post_signature = "void postAppSpecialize(const zygisk::AppSpecializeArgs*) override {"
    start = source.find(pre_signature)
    post = source.find(post_signature, start + len(pre_signature))
    end = source.find("void preServerSpecialize", post + len(post_signature))
    if start < 0 or post < 0 or end < 0:
        raise JobError("server-VPN application isolation lifecycle signature is missing")
    lifecycle = source[start:end]
    forbidden = {
        "server_vpn",
        "server-vpn",
        "ServerVpn",
        "ServerVPN",
        "kServerVpn",
        "connectCompanion",
        "pthread_create",
    }
    found = sorted(token for token in forbidden if token in lifecycle)
    if found:
        raise JobError(f"application lifecycle contains server-VPN state: {found}")


def validate_server_vpn_activation_source() -> None:
    bridge = (
        ROOT
        / "components/server-vpn/runtime/bridge/dev/zygveil/servervpn/bridge/ServerVpnBridge.java"
    ).read_text(encoding="utf-8")
    runtime = (
        ROOT
        / "components/server-vpn/runtime/bridge/dev/zygveil/servervpn/bridge/ServerVpnRuntime.java"
    ).read_text(encoding="utf-8")
    native = (ROOT / "components/server-vpn/runtime/native/runtime.cpp").read_text(encoding="utf-8")
    hook_host = (ROOT / "components/zygisk-host/native/hook_host.cpp").read_text(encoding="utf-8")
    module = (ROOT / "components/zygisk-host/native/module.cpp").read_text(encoding="utf-8")
    for marker in (
        "private static volatile boolean activationActive;",
        "static void activate()",
        "static void deactivate()",
        "if (!activationActive",
    ):
        if marker not in runtime:
            raise JobError(f"server-VPN global activation gate is missing: {marker}")
    activate_start = runtime.find("static void activate()")
    activate_end = runtime.find("\n  static void deactivate()", activate_start)
    if (
        activate_start < 0
        or activate_end < 0
        or "readyForActivation()" in runtime[activate_start:activate_end]
    ):
        raise JobError("server-VPN committed activation repeats external readiness work")
    if "private volatile boolean active;" in bridge:
        raise JobError("server-VPN bridge retains a per-instance activation gate")
    for marker in (
        "synchronized (this)",
        "ServerVpnRuntime.isActive()",
        "ServerVpnRuntime.invokeBackup(localBackup, args, staticTarget)",
    ):
        if marker not in bridge:
            raise JobError(f"server-VPN acquisition pass-through is missing: {marker}")

    claim = native.find("__atomic_compare_exchange_n(")
    activation = native.find("CallVoidMethod(activation_bridge, bridge_activate_)")
    if claim < 0 or activation < 0 or claim > activation:
        raise JobError("server-VPN terminal claim does not precede the global activation flip")
    if native.count("CallVoidMethod(activation_bridge, bridge_activate_)") != 1 or (
        "CallVoidMethod(bridge, bridge_activate_)" in native
    ):
        raise JobError("server-VPN activation is not a single global flip")

    monitor = hook_host.find("MonitorEnter(bridge_object)")
    hook = hook_host.find("lsplant::Hook(env, target, bridge_object, callback)")
    backup = hook_host.find("CallVoidMethod(bridge_object, bridge.set_backup, backup)")
    release = hook_host.find("if (!release_monitor())", backup)
    globals_before_hook = hook_host.find("jobject target_global")
    if (
        min(monitor, hook, backup, release, globals_before_hook) < 0
        or globals_before_hook > monitor
        or monitor > hook
        or hook > backup
        or backup > release
    ):
        raise JobError("shared hook host does not publish bridge backup under its monitor")

    status_start = module.find("void HandleServerVpnStatusChannel(int socket, int descriptor)")
    status_end = module.find("\n}\n#endif", status_start)
    if status_start < 0 or status_end < 0:
        raise JobError("server-VPN status companion implementation is missing")
    status_handler = module[status_start:status_end]
    for marker in (
        "expected_claim == kRuntimeActivationCommitted",
        "kStatusCommitWaitAttempts",
        'committed ? "arming" : "inactive"',
        'committed ? "post_server_commit_delayed" : "post_server_timeout"',
    ):
        if marker not in status_handler:
            raise JobError(f"server-VPN committed status grace is missing: {marker}")


def compile_location_bridge() -> Path:
    bridge_classes = Path("/tmp/location-bridge-classes")
    bridge_output = Path("/tmp/location-bridge-dex")
    shutil.rmtree(bridge_classes, ignore_errors=True)
    shutil.rmtree(bridge_output, ignore_errors=True)
    bridge_classes.mkdir(mode=0o700, parents=True)
    bridge_output.mkdir(mode=0o700, parents=True)
    bridge_source = (
        ROOT / "components/zygisk-host/bridge/dev/zygveil/location/bridge/HookBridge.java"
    )
    run(
        [
            "javac",
            "--release",
            "17",
            "-Xlint:all",
            "-Werror",
            "-d",
            str(bridge_classes),
            str(bridge_source),
        ]
    )
    bridge_class = bridge_classes / "dev/zygveil/location/bridge/HookBridge.class"
    run(
        [
            "/opt/android-sdk/build-tools/37.0.0/d8",
            "--min-api",
            "36",
            "--output",
            str(bridge_output),
            str(bridge_class),
        ]
    )
    bridge_dex = bridge_output / "classes.dex"
    bridge_bytes = bridge_dex.read_bytes()
    if not bridge_bytes.startswith(b"dex\n"):
        raise JobError("location bridge output is not DEX")
    for bridge_method in [b"dispatch", b"activateFailClosed", b"deactivateFailClosed"]:
        if bridge_method not in bridge_bytes:
            raise JobError(f"location bridge lifecycle method is missing: {bridge_method!r}")
    return bridge_dex


def build_location(_args: argparse.Namespace) -> None:
    validate_global_location_application_source()
    validate_server_vpn_application_isolation_source()
    validate_server_vpn_activation_source()
    source_root = ROOT / "components/zygisk-host"
    location_hook_count = 5
    server_catalog = ROOT / "components/server-vpn/runtime/hook_catalog.json"
    server_decoded: object = json.loads(server_catalog.read_text(encoding="utf-8"))
    if not isinstance(server_decoded, dict) or server_decoded.get("schema_version") != 1:
        raise JobError("server-VPN hook catalog schema mismatch")
    server_hooks = server_decoded.get("hook_catalog")
    if not isinstance(server_hooks, list) or len(server_hooks) != 14:
        raise JobError("server-VPN hook catalog inventory mismatch")

    bridge_dex = compile_location_bridge()
    bridge_bytes = bridge_dex.read_bytes()
    server_bridge_dex = compile_server_vpn_bridge()
    server_bridge_bytes = server_bridge_dex.read_bytes()

    native_build = Path("/tmp/location-native-build")
    shutil.rmtree(native_build, ignore_errors=True)
    ndk = Path("/opt/android-sdk/ndk/29.0.14206865")
    run(
        [
            location_cmake(),
            "-S",
            "components/zygisk-host/native",
            "-B",
            str(native_build),
            "-G",
            "Ninja",
            f"-DCMAKE_MAKE_PROGRAM={location_ninja()}",
            f"-DCMAKE_TOOLCHAIN_FILE={ndk / 'build/cmake/android.toolchain.cmake'}",
            "-DANDROID_ABI=arm64-v8a",
            "-DANDROID_PLATFORM=android-35",
            "-DANDROID_STL=c++_static",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DVENDOR_SOURCE_ROOT=/opt/vendor-src",
            "-DZYGVEIL_SERVER_VPN_FEATURE=ON",
        ],
        timeout=1800,
    )
    run(
        [
            location_cmake(),
            "--build",
            str(native_build),
            "--target",
            "zygveil",
            "locationctl",
        ],
        timeout=1800,
    )
    native_library = native_build / "libzygveil.so"
    location_helper = native_build / "locationctl"
    shadowhook_helper = native_build / "libshadowhook_nothing.so"
    if (
        not native_library.is_file()
        or not location_helper.is_file()
        or not shadowhook_helper.is_file()
    ):
        raise JobError("location native output is incomplete")
    readelf = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf"
    dynamic = run([str(readelf), "--dynamic", str(native_library)])
    needed = sorted(set(re.findall(r"Shared library: \[([^]]+)]", dynamic)))
    forbidden_needed = {
        "libandroid.so",
        "libc++_shared.so",
        "liblsplant.so",
        "libshadowhook.so",
    }
    if forbidden_needed.intersection(needed):
        raise JobError(f"location ELF has forbidden dependencies: {needed}")
    symbols = run([str(readelf), "--dyn-syms", str(native_library)])
    for entry in ["zygisk_module_entry", "zygisk_companion_entry"]:
        if entry not in symbols:
            raise JobError(f"location ELF entry is missing: {entry}")
    if "AArch64" not in run([str(readelf), "--file-header", str(native_library)]):
        raise JobError("location ELF architecture is not AArch64")
    program_headers = run([str(readelf), "--program-headers", "--wide", str(native_library)])
    tls_alignments = re.findall(
        r"^\s*TLS\s+.*\s+(0x[0-9a-fA-F]+)\s*$", program_headers, re.MULTILINE
    )
    if len(tls_alignments) != 1 or int(tls_alignments[0], 16) < 64:
        raise JobError("location ELF TLS alignment is incompatible with ARM64 Bionic")
    native_tls_alignment = int(tls_alignments[0], 16)
    native_strings = run(["strings", str(native_library)])
    for status_marker in [
        ".runtime-status.lock",
        ".runtime-status.tmp",
        "zygveil-location-status",
        "hook_rollback_retained",
        "runtime_status_process_mismatch",
        "event=pre_app_delivery_ready scope=global delivery=shared_applied",
        "event=post_app_delivery_result active=%s reason=%s hook_count=%zu",
        "application_delivery_active",
        "application_fail_closed_activation_failed",
        ".app-control",
        "pidfd_process_identity_invalid",
        "pidfd_process_handle_invalid",
        "event=server_vpn_inputs state=%s reason=%s",
        "config_target_mode_invalid",
    ]:
        if status_marker not in native_strings:
            raise JobError(f"location atomic status boundary is missing: {status_marker}")
    for poc_marker in ["event=pre_app_poc_ready", "event=post_app_poc_result"]:
        if poc_marker in native_strings:
            raise JobError(f"ordinary location ELF contains POC behavior: {poc_marker}")
    location_helper_dynamic = run([str(readelf), "--dynamic", str(location_helper)])
    location_helper_needed = sorted(
        set(re.findall(r"Shared library: \[([^]]+)]", location_helper_dynamic))
    )
    if forbidden_needed.intersection(location_helper_needed):
        raise JobError(f"locationctl has forbidden dependencies: {location_helper_needed}")
    if "AArch64" not in run([str(readelf), "--file-header", str(location_helper)]):
        raise JobError("locationctl architecture is not AArch64")
    helper_symbols = run([str(readelf), "--symbols", str(location_helper)])
    if re.search(r"\bmain$", helper_symbols, re.MULTILINE) is None:
        raise JobError("locationctl main symbol is missing")
    helper_strings = run(["strings", str(location_helper)])
    for command in [
        "protocol-self-test",
        "status-ui",
        "apply",
        "recovery_required",
        ".config.properties.tmp",
        "runtime-status.properties",
    ]:
        if command not in helper_strings:
            raise JobError(f"locationctl fixed command is missing: {command}")
    helper_dynamic = run([str(readelf), "--dynamic", str(shadowhook_helper)])
    helper_needed = sorted(set(re.findall(r"Shared library: \[([^]]+)]", helper_dynamic)))
    if helper_needed:
        raise JobError(f"ShadowHook linker helper has unexpected dependencies: {helper_needed}")
    if "AArch64" not in run([str(readelf), "--file-header", str(shadowhook_helper)]):
        raise JobError("ShadowHook linker helper architecture is not AArch64")

    module_files = source_root / "module"
    control_metadata = (
        "schema_version=1\n"
        "page_bytes=4096\n"
        "page_name=zygveil-location-control\n"
        "page_storage=sealed_memfd\n"
        "page_mode=0777\n"
        "page_seals=grow,shrink,seal\n"
        "helper_name=locationctl\n"
        "input_transport=stdin\n"
    ).encode("ascii")
    entries: dict[str, tuple[bytes, int]] = {
        "THIRD_PARTY.md": ((source_root / "THIRD_PARTY.md").read_bytes(), 0o644),
        "bridge.dex": (bridge_bytes, 0o644),
        "config.properties": ((source_root / "config.example.properties").read_bytes(), 0o600),
        "customize.sh": ((module_files / "customize.sh").read_bytes(), 0o755),
        "guard.sh": ((module_files / "guard.sh").read_bytes(), 0o755),
        "licenses/Component-LSPlant-LGPL-3.0.txt": (
            Path("/opt/vendor-src/lsplant/LICENSE").read_bytes(),
            0o644,
        ),
        "licenses/DexBuilder-LGPL-3.0.txt": (
            Path(
                "/opt/vendor-src/lsplant/lsplant/src/main/jni/external/dex_builder/LICENSE"
            ).read_bytes(),
            0o644,
        ),
        "licenses/Android-NDK-NOTICE.txt": (
            Path("/opt/android-sdk/ndk/29.0.14206865/NOTICE").read_bytes(),
            0o644,
        ),
        "licenses/parallel-hashmap-Apache-2.0.txt": (
            Path(
                "/opt/vendor-src/lsplant/lsplant/src/main/jni/external/"
                "dex_builder/external/parallel_hashmap/LICENSE"
            ).read_bytes(),
            0o644,
        ),
        "licenses/ShadowHook-MIT.txt": (
            Path("/opt/vendor-src/shadowhook/LICENSE").read_bytes(),
            0o644,
        ),
        "licenses/Zygisk-0BSD.txt": (
            (source_root / "licenses/Zygisk-0BSD.txt").read_bytes(),
            0o644,
        ),
        "libshadowhook_nothing.so": (shadowhook_helper.read_bytes(), 0o644),
        "locationctl": (location_helper.read_bytes(), 0o755),
        "live-control.properties": (control_metadata, 0o644),
        "module.prop": ((module_files / "module.prop").read_bytes(), 0o644),
        "post-fs-data.sh": ((module_files / "post-fs-data.sh").read_bytes(), 0o755),
        "zygisk/arm64-v8a.so": (native_library.read_bytes(), 0o755),
        "server-vpn-bridge.dex": (server_bridge_bytes, 0o644),
        "server-vpn-config.properties": (
            (ROOT / "components/server-vpn/runtime/policy.properties").read_bytes(),
            0o644,
        ),
    }
    if b"dev/zygveil/servervpn" in bridge_bytes or b"dev/zygveil/location" in server_bridge_bytes:
        raise JobError("location and server-VPN bridge identities are mixed")
    OUTPUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = OUTPUT / "zygveil.zip"
    comparison = OUTPUT / "zygveil-repeat.zip"
    deterministic_zip(destination, entries)
    deterministic_zip(comparison, entries)
    if sha256(destination) != sha256(comparison):
        raise JobError("location module ZIP is not deterministic")
    comparison.unlink()
    with zipfile.ZipFile(destination) as archive:
        if archive.testzip() is not None or set(archive.namelist()) != set(entries):
            raise JobError("location module ZIP inspection failed")
        observed_modes = {
            info.filename: (info.external_attr >> 16) & 0o7777 for info in archive.infolist()
        }
        expected_modes = {name: mode for name, (_, mode) in entries.items()}
        if observed_modes != expected_modes:
            raise JobError("location module ZIP mode inventory mismatch")
        if archive.read("config.properties").find(b"enabled=false") < 0:
            raise JobError("location module lacks the first-coordinate waiting config")
        if archive.read("config.properties").find(b"raw_gnss_mode=blocked") < 0:
            raise JobError("location module default Raw GNSS mode mismatch")
        installer = archive.read("customize.sh")
        if b'rm -f "$MODPATH/disable"' not in installer or b'touch "$MODPATH/disable"' in installer:
            raise JobError("combined module installer does not guarantee production enablement")
        if (
            b"LIVE_MODULE=/data/adb/modules/zygveil" not in installer
            or b'cp -p "$LIVE_CONFIG" "$MODPATH/config.properties"' not in installer
            or b"Existing location configuration is unavailable or unsafe" not in installer
        ):
            raise JobError(
                "combined module installer does not preserve one-way location activation"
            )
        if any(name.endswith(".apk") for name in archive.namelist()):
            raise JobError("APK found in combined module ZIP")
        config_lines = {
            line.split(b"=", 1)[0]
            for line in archive.read("config.properties").splitlines()
            if line and not line.startswith(b"#") and b"=" in line
        }
        expected_config_keys = {
            b"schema_version",
            b"enabled",
            b"raw_gnss_mode",
            b"center_latitude_deg",
            b"center_longitude_deg",
            b"altitude_ellipsoid_m",
            b"altitude_msl_m",
            b"horizontal_jitter_sigma_m",
            b"horizontal_jitter_radius_m",
            b"horizontal_correlation_time_s",
            b"vertical_jitter_sigma_m",
            b"accuracy_correlation_time_s",
            b"speed_deadband_mps",
            b"speed_max_mps",
            b"bearing_min_speed_mps",
            b"random_seed",
            b"config_generation",
        }
        if (
            config_lines != expected_config_keys
            or archive.read("live-control.properties") != control_metadata
        ):
            raise JobError("location module config/control metadata mismatch")
    assert_archive_privacy(destination)
    write_report(
        "build-location.txt",
        [
            ("network", "none"),
            ("abi", "arm64-v8a"),
            ("android_platform", 36),
            ("ndk", "29.0.14206865"),
            ("zygisk_api", 5),
            ("hook_count", location_hook_count),
            ("server_vpn_hook_count", len(server_hooks)),
            ("engine_owner", "shared"),
            ("application_hook_count", 1),
            ("application_scope", "global_unfiltered"),
            ("application_selection_source_scan", "pass"),
            ("application_failure_semantics", "fail_closed_after_activation"),
            ("application_delivery_liveness", "companion_pidfd"),
            ("bridge_dex_sha256", sha256(bridge_dex)),
            ("server_vpn_bridge_dex_sha256", sha256(server_bridge_dex)),
            ("native_sha256", sha256(native_library)),
            ("native_needed", needed),
            ("native_tls_alignment", native_tls_alignment),
            ("locationctl_sha256", sha256(location_helper)),
            ("locationctl_needed", location_helper_needed),
            ("control_page_schema", 1),
            ("control_page_bytes", 4096),
            ("control_page_name", "zygveil-location-control"),
            ("control_page_storage", "sealed_memfd"),
            ("control_page_mode", "0777"),
            ("control_page_seals", "grow,shrink,seal"),
            ("status_channel_storage", "sealed_memfd"),
            ("zip_entries", len(entries)),
            ("config_mode", "0600"),
            ("locationctl_mode", "0755"),
            ("shadowhook_helper_sha256", sha256(shadowhook_helper)),
            ("shadowhook_helper_needed", helper_needed),
            ("compatibility_guard", "absent"),
            ("server_vpn_hook_catalog_sha256", sha256(server_catalog)),
            ("server_vpn_packaged_policy", "present"),
            ("zip_sha256", sha256(destination)),
            ("zip_bytes", destination.stat().st_size),
            ("deterministic_repeat", "pass"),
            ("default_enabled", "false"),
            ("default_raw_gnss_mode", "blocked"),
            ("artifact_privacy", "pass"),
        ],
    )


def build_location_development(
    *,
    poc_semantics: bool,
    server_vpn_feature: bool = False,
) -> None:
    validate_global_location_application_source()
    artifact_label = (
        "server-VPN full-catalog POC"
        if server_vpn_feature
        else "POC"
        if poc_semantics
        else "production candidate"
    )
    bridge_dex = compile_location_bridge()
    server_vpn_bridge_dex = compile_server_vpn_bridge() if server_vpn_feature else None

    native_build = Path(
        "/tmp/server-vpn-full-catalog-native-build"
        if server_vpn_feature
        else "/tmp/location-app-poc-native-build"
        if poc_semantics
        else "/tmp/location-production-candidate-native-build"
    )
    shutil.rmtree(native_build, ignore_errors=True)
    ndk = Path("/opt/android-sdk/ndk/29.0.14206865")
    cmake_arguments = [
        location_cmake(),
        "-S",
        "components/zygisk-host/native",
        "-B",
        str(native_build),
        "-G",
        "Ninja",
        f"-DCMAKE_MAKE_PROGRAM={location_ninja()}",
        f"-DCMAKE_TOOLCHAIN_FILE={ndk / 'build/cmake/android.toolchain.cmake'}",
        "-DANDROID_ABI=arm64-v8a",
        "-DANDROID_PLATFORM=android-35",
        "-DANDROID_STL=c++_static",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DVENDOR_SOURCE_ROOT=/opt/vendor-src",
    ]
    if poc_semantics:
        cmake_arguments.append("-DZYGVEIL_LOCATION_APP_POC=ON")
    if server_vpn_feature:
        cmake_arguments.append("-DZYGVEIL_SERVER_VPN_FEATURE=ON")
    run(cmake_arguments, timeout=1800)
    run(
        [
            location_cmake(),
            "--build",
            str(native_build),
            "--target",
            "zygveil",
            "locationctl",
        ],
        timeout=1800,
    )
    native_library = native_build / "libzygveil.so"
    location_helper = native_build / "locationctl"
    shadowhook_helper = native_build / "libshadowhook_nothing.so"
    if (
        not native_library.is_file()
        or not location_helper.is_file()
        or not shadowhook_helper.is_file()
    ):
        raise JobError(f"location {artifact_label} runtime output is incomplete")
    readelf = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf"
    if "AArch64" not in run([str(readelf), "--file-header", str(native_library)]):
        raise JobError(f"location {artifact_label} ELF architecture is not AArch64")
    dynamic = run([str(readelf), "--dynamic", str(native_library)])
    needed = sorted(set(re.findall(r"Shared library: \[([^]]+)]", dynamic)))
    forbidden_needed = {
        "libandroid.so",
        "libc++_shared.so",
        "liblsplant.so",
        "libshadowhook.so",
    }
    if forbidden_needed.intersection(needed):
        raise JobError(f"location {artifact_label} ELF has forbidden dependencies: {needed}")
    symbols = run([str(readelf), "--dyn-syms", str(native_library)])
    for entry in ["zygisk_module_entry", "zygisk_companion_entry"]:
        if entry not in symbols:
            raise JobError(f"location {artifact_label} ELF entry is missing: {entry}")
    defined_exports = re.findall(
        r"^\s*\d+:\s+\S+\s+\d+\s+\S+\s+GLOBAL\s+DEFAULT\s+\d+\s+(\S+)$",
        symbols,
        re.MULTILINE,
    )
    if sorted(defined_exports) != ["zygisk_companion_entry", "zygisk_module_entry"]:
        raise JobError(
            f"location {artifact_label} exported symbol inventory mismatch: {defined_exports}"
        )
    program_headers = run([str(readelf), "--program-headers", "--wide", str(native_library)])
    tls_alignments = re.findall(
        r"^\s*TLS\s+.*\s+(0x[0-9a-fA-F]+)\s*$", program_headers, re.MULTILINE
    )
    if len(tls_alignments) != 1 or int(tls_alignments[0], 16) < 64:
        raise JobError(f"location {artifact_label} TLS alignment is incompatible")
    native_strings = run(["strings", str(native_library)])
    lifecycle_markers = (
        [
            "event=pre_app_poc_ready scope=global delivery=shared_applied",
            "event=post_app_poc_result active=%s reason=%s hook_count=%zu",
        ]
        if poc_semantics
        else [
            "event=pre_app_delivery_ready scope=global delivery=shared_applied",
            "event=post_app_delivery_result active=%s reason=%s hook_count=%zu",
            "application_fail_closed_activation_failed",
        ]
    )
    for marker in [
        *lifecycle_markers,
        "zygveil-location-control",
        "android.location.Location$1",
        "createFromParcel",
        "android.os.Parcel",
        "application_delivery_active",
        "pidfd_process_identity_invalid",
        "pidfd_process_handle_invalid",
    ]:
        if marker not in native_strings:
            raise JobError(f"location {artifact_label} marker is missing: {marker}")
    if not poc_semantics and any(
        marker in native_strings
        for marker in ("event=pre_app_poc_ready", "event=post_app_poc_result")
    ):
        raise JobError("location production candidate contains POC lifecycle behavior")
    gate_markers = ("event=server_vpn_shared_host_gate", "shared_owner_pass")
    if any(marker in native_strings for marker in gate_markers):
        raise JobError("ordinary location artifact contains server-VPN diagnostic code")
    feature_markers = (
        "event=server_vpn_inputs state=%s reason=%s",
        "config_target_mode_invalid",
    )
    if server_vpn_feature:
        validate_server_vpn_application_isolation_source()
        validate_server_vpn_activation_source()
        for marker in feature_markers:
            if marker not in native_strings:
                raise JobError(f"server-VPN runtime marker is missing: {marker}")
        module_source = (ROOT / "components/zygisk-host/native/module.cpp").read_text(
            encoding="utf-8"
        )
        for marker in (
            "O_NOFOLLOW",
            "status.st_uid == 0",
            "status.st_gid == 0",
            "status.st_nlink == 1",
            'ReadRootTextAt(directory, "server-vpn-config.properties"',
        ):
            if marker not in module_source:
                raise JobError(f"server-VPN packaged-policy boundary is missing: {marker}")
    elif any(marker in native_strings for marker in feature_markers):
        raise JobError("ordinary location artifact contains server-VPN feature code")
    if not server_vpn_feature:
        for forbidden_identity in [
            "dev.zygveil.probe.canary",
            "com.google.android.apps.maps",
        ]:
            if forbidden_identity in native_strings:
                raise JobError(f"location {artifact_label} contains application selection data")

    OUTPUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    native_output = (
        "libzygveil_server_vpn_poc.so"
        if server_vpn_feature
        else "libzygveil_app_poc.so"
        if poc_semantics
        else "libzygveil_candidate.so"
    )
    helper_output = (
        "locationctl-server-vpn-poc"
        if server_vpn_feature
        else "locationctl-app-poc"
        if poc_semantics
        else "locationctl-candidate"
    )
    bridge_output = (
        "bridge-server-vpn-poc.dex"
        if server_vpn_feature
        else "bridge-app-poc.dex"
        if poc_semantics
        else "bridge-candidate.dex"
    )
    linker_helper_output = (
        "libshadowhook_nothing-server-vpn-poc.so"
        if server_vpn_feature
        else "libshadowhook_nothing-app-poc.so"
        if poc_semantics
        else "libshadowhook_nothing-candidate.so"
    )
    report_output = (
        "build-server-vpn-poc.txt"
        if server_vpn_feature
        else "build-location-app-poc.txt"
        if poc_semantics
        else "build-location-candidate.txt"
    )
    shutil.copy2(native_library, OUTPUT / native_output)
    shutil.copy2(location_helper, OUTPUT / helper_output)
    shutil.copy2(bridge_dex, OUTPUT / bridge_output)
    if server_vpn_bridge_dex is not None:
        shutil.copy2(
            server_vpn_bridge_dex,
            OUTPUT / "server-vpn-bridge-poc.dex",
        )
    shutil.copy2(shadowhook_helper, OUTPUT / linker_helper_output)
    for output_name in (
        native_output,
        helper_output,
        bridge_output,
        linker_helper_output,
    ):
        assert_private_identity_absent((OUTPUT / output_name).read_bytes(), member=output_name)
    if server_vpn_bridge_dex is not None:
        assert_private_identity_absent(
            (OUTPUT / "server-vpn-bridge-poc.dex").read_bytes(),
            member="server-vpn-bridge-poc.dex",
        )
    write_report(
        report_output,
        [
            ("network", "none"),
            ("abi", "arm64-v8a"),
            (
                "artifact_class",
                "non_attestable_server_vpn_full_catalog_poc"
                if server_vpn_feature
                else "non_attestable_poc"
                if poc_semantics
                else "non_attestable_production_candidate",
            ),
            ("output_boundary", ".artifacts/poc"),
            ("application_scope", "global_unfiltered"),
            ("application_selection_source_scan", "pass"),
            ("configuration_delivery", "shared_applied_generation"),
            ("authoritative_control_memfd", "zygveil-location-control"),
            ("authoritative_control_mode", "0777"),
            ("application_delivery_file", ".app-control"),
            ("application_control_bytes", 4096),
            ("application_control_mode", "0600"),
            ("application_mapping", "read_only"),
            ("application_control_access", "fixed_module_dir_read_only_mapping"),
            ("application_companion_request", "absent"),
            ("delivery_monitor", "single_companion_registration_handler"),
            ("delivery_liveness", "companion_pidfd"),
            ("runtime_status_schema", 4),
            ("control_descriptor_owner", "zygisk_companion"),
            ("parcel_hook_count", 1),
            (
                "engine_owner",
                "shared" if server_vpn_feature else "location_only",
            ),
            ("connectivity_hook_count", 14 if server_vpn_feature else 0),
            ("server_vpn_diagnostic_hook_retained", "false"),
            (
                "application_failure_semantics",
                "fail_open" if poc_semantics else "fail_closed_after_activation",
            ),
            ("bridge_compiled", "true"),
            ("server_vpn_bridge_delivery", "system_server_only"),
            ("linker_helper_compiled", "true"),
            ("native_needed", needed),
            ("unit_tests", "skipped"),
            ("hash_attestation", "skipped"),
            ("reproducibility", "skipped"),
            ("module_zip", "skipped"),
            ("artifact_privacy", "pass"),
        ],
    )


def build_location_app_poc(_args: argparse.Namespace) -> None:
    build_location_development(poc_semantics=True)


def build_location_candidate(_args: argparse.Namespace) -> None:
    build_location_development(poc_semantics=False)


def build_server_vpn_poc(_args: argparse.Namespace) -> None:
    build_location_development(poc_semantics=False, server_vpn_feature=True)
    runtime_files = {
        "zygisk/arm64-v8a.so": OUTPUT / "libzygveil_server_vpn_poc.so",
        "locationctl": OUTPUT / "locationctl-server-vpn-poc",
        "bridge.dex": OUTPUT / "bridge-server-vpn-poc.dex",
        "server-vpn-bridge.dex": OUTPUT / "server-vpn-bridge-poc.dex",
        "libshadowhook_nothing.so": OUTPUT / "libshadowhook_nothing-server-vpn-poc.so",
    }
    if any(not path.is_file() for path in runtime_files.values()):
        raise JobError("server-VPN POC runtime set is incomplete")

    source_root = ROOT / "components/zygisk-host"
    module_files = source_root / "module"
    control_metadata = (
        "schema_version=1\n"
        "page_bytes=4096\n"
        "page_name=zygveil-location-control\n"
        "page_storage=sealed_memfd\n"
        "page_mode=0777\n"
        "page_seals=grow,shrink,seal\n"
        "helper_name=locationctl\n"
        "input_transport=stdin\n"
    ).encode("ascii")
    entries: dict[str, tuple[bytes, int]] = {
        "THIRD_PARTY.md": ((source_root / "THIRD_PARTY.md").read_bytes(), 0o644),
        "config.properties": ((source_root / "config.example.properties").read_bytes(), 0o600),
        "customize.sh": ((module_files / "customize.sh").read_bytes(), 0o755),
        "guard.sh": ((module_files / "guard.sh").read_bytes(), 0o755),
        "licenses/Component-LSPlant-LGPL-3.0.txt": (
            Path("/opt/vendor-src/lsplant/LICENSE").read_bytes(),
            0o644,
        ),
        "licenses/DexBuilder-LGPL-3.0.txt": (
            Path(
                "/opt/vendor-src/lsplant/lsplant/src/main/jni/external/dex_builder/LICENSE"
            ).read_bytes(),
            0o644,
        ),
        "licenses/Android-NDK-NOTICE.txt": (
            Path("/opt/android-sdk/ndk/29.0.14206865/NOTICE").read_bytes(),
            0o644,
        ),
        "licenses/parallel-hashmap-Apache-2.0.txt": (
            Path(
                "/opt/vendor-src/lsplant/lsplant/src/main/jni/external/"
                "dex_builder/external/parallel_hashmap/LICENSE"
            ).read_bytes(),
            0o644,
        ),
        "licenses/ShadowHook-MIT.txt": (
            Path("/opt/vendor-src/shadowhook/LICENSE").read_bytes(),
            0o644,
        ),
        "licenses/Zygisk-0BSD.txt": (
            (source_root / "licenses/Zygisk-0BSD.txt").read_bytes(),
            0o644,
        ),
        "live-control.properties": (control_metadata, 0o644),
        "post-fs-data.sh": ((module_files / "post-fs-data.sh").read_bytes(), 0o755),
    }
    for name, path in runtime_files.items():
        entries[name] = (
            path.read_bytes(),
            0o755 if name in {"zygisk/arm64-v8a.so", "locationctl"} else 0o644,
        )

    catalog = ROOT / "components/server-vpn/runtime/hook_catalog.json"
    decoded: object = json.loads(catalog.read_text(encoding="utf-8"))
    if not isinstance(decoded, dict) or decoded.get("schema_version") != 1:
        raise JobError("server-VPN hook catalog schema mismatch")
    hooks = decoded.get("hook_catalog")
    if not isinstance(hooks, list) or len(hooks) != 14:
        raise JobError("server-VPN hook catalog inventory mismatch")
    entries["server-vpn-config.properties"] = (
        (ROOT / "components/server-vpn/runtime/policy.properties").read_bytes(),
        0o644,
    )
    entries["module.prop"] = (
        b"id=zygveil\n"
        b"name=ZygVeil POC\n"
        b"version=0.2.0-poc\n"
        b"versionCode=2\n"
        b"author=kogeler\n"
        b"description=Non-attestable combined Zygisk full-catalog POC\n",
        0o644,
    )

    if any(name.endswith(".apk") for name in entries):
        raise JobError("server-VPN POC ZIP contains an APK")
    location_bridge_has_server_vpn = b"dev/zygveil/servervpn" in entries["bridge.dex"][0]
    server_vpn_bridge_has_location = b"dev/zygveil/location" in entries["server-vpn-bridge.dex"][0]
    if location_bridge_has_server_vpn or server_vpn_bridge_has_location:
        raise JobError("server-VPN and application-delivered bridge identities are mixed")
    if b"CoexistenceBridge" in entries["server-vpn-bridge.dex"][0]:
        raise JobError("server-VPN POC contains disposable coexistence code")
    destination = OUTPUT / "zygveil-poc.zip"
    deterministic_zip(destination, entries)
    with zipfile.ZipFile(destination) as archive:
        observed_modes = {
            info.filename: (info.external_attr >> 16) & 0o7777 for info in archive.infolist()
        }
        if archive.testzip() is not None or observed_modes != {
            name: mode for name, (_, mode) in entries.items()
        }:
            raise JobError("server-VPN POC ZIP integrity or mode inventory mismatch")
        if archive.read("module.prop").find(b"id=zygveil\n") < 0:
            raise JobError("server-VPN POC generic host identity mismatch")
        installer = archive.read("customize.sh")
        if (
            b'rm -f "$MODPATH/disable"' not in installer
            or b'touch "$MODPATH/disable"' in installer
            or b'cp -p "$LIVE_CONFIG" "$MODPATH/config.properties"' not in installer
        ):
            raise JobError("server-VPN POC installer violates production lifecycle semantics")
    assert_archive_privacy(destination)
    write_report(
        "build-server-vpn-poc.txt",
        [
            ("network", "none"),
            ("artifact_class", "non_attestable_server_vpn_full_catalog_poc"),
            ("output_boundary", ".artifacts/poc/server-vpn"),
            ("engine_owner", "shared"),
            ("module_id", "zygveil"),
            ("installed_default", "magisk_enabled"),
            ("connectivity_hook_count", len(hooks)),
            ("runtime_activation", "next_boot_all_or_none"),
            ("production_catalog_size", len(hooks)),
            ("target_mode", "eligible_user0_apps"),
            ("feature_enabled_key", "absent"),
            ("controller_or_apk", "absent"),
            ("packaged_policy", "present"),
            ("server_bridge_delivery", "system_server_only"),
            ("application_bridge", "location_only"),
            ("abi", "arm64-v8a"),
            ("zip_entries", len(entries)),
            ("hash_attestation", "skipped"),
            ("reproducibility", "skipped"),
            ("artifact_privacy", "pass"),
        ],
    )


def parse_java_method_descriptor(signature: str) -> tuple[list[str], str]:
    primitive_types = {
        "B": "byte",
        "C": "char",
        "D": "double",
        "F": "float",
        "I": "int",
        "J": "long",
        "S": "short",
        "V": "void",
        "Z": "boolean",
    }

    def parse_type(offset: int) -> tuple[str, int]:
        if offset >= len(signature):
            raise JobError(f"truncated Java descriptor: {signature}")
        marker = signature[offset]
        if marker in primitive_types:
            return primitive_types[marker], offset + 1
        if marker == "L":
            end = signature.find(";", offset)
            if end < 0:
                raise JobError(f"unterminated Java object descriptor: {signature}")
            return signature[offset + 1 : end].replace("/", "."), end + 1
        if marker == "[":
            end = offset
            while end < len(signature) and signature[end] == "[":
                end += 1
            _, next_offset = parse_type(end)
            return signature[offset:next_offset].replace("/", "."), next_offset
        raise JobError(f"unsupported Java descriptor type: {signature}")

    if not signature.startswith("("):
        raise JobError(f"invalid Java method descriptor: {signature}")
    parameters: list[str] = []
    offset = 1
    while offset < len(signature) and signature[offset] != ")":
        parameter, offset = parse_type(offset)
        if parameter == "void":
            raise JobError(f"void Java parameter descriptor: {signature}")
        parameters.append(parameter)
    if offset >= len(signature) or signature[offset] != ")":
        raise JobError(f"invalid Java method descriptor terminator: {signature}")
    return_type, offset = parse_type(offset + 1)
    if offset != len(signature):
        raise JobError(f"trailing Java method descriptor data: {signature}")
    return parameters, return_type


def compile_server_vpn_bridge() -> Path:
    classes = Path("/tmp/server-vpn-bridge-classes")
    dex_output = Path("/tmp/server-vpn-bridge-dex")
    generated_root = Path("/tmp/server-vpn-bridge-generated")
    for path in (classes, dex_output, generated_root):
        shutil.rmtree(path, ignore_errors=True)
        path.mkdir(mode=0o700, parents=True)
    policy_root = ROOT / "components/server-vpn/runtime/src/main/java/dev/zygveil/servervpn/policy"
    policy_sources = sorted(policy_root.glob("*.java"))
    bridge_root = ROOT / "components/server-vpn/runtime/bridge/dev/zygveil/servervpn/bridge"
    bridge_sources = sorted(bridge_root.glob("*.java"))
    catalog_value: object = json.loads(
        (ROOT / "components/server-vpn/runtime/hook_catalog.json").read_text(encoding="utf-8")
    )
    if not isinstance(catalog_value, dict) or catalog_value.get("schema_version") != 1:
        raise JobError("server-VPN production hook catalog schema mismatch")
    catalog = cast(dict[str, object], catalog_value)
    boundary = catalog.get("service_boundary")
    hooks = catalog.get("hook_catalog")
    support_methods = catalog.get("support_methods")
    platform_methods = catalog.get("platform_support_methods")
    copy_mechanisms = catalog.get("copy_mechanisms")
    support_fields = catalog.get("support_fields")
    platform_fields = catalog.get("platform_support_fields")
    constants = catalog.get("authorization_constants")
    if (
        not isinstance(boundary, dict)
        or not isinstance(hooks, list)
        or len(hooks) != 14
        or not isinstance(support_methods, list)
        or len(support_methods) != 4
        or not isinstance(platform_methods, list)
        or len(platform_methods) != 1
        or not isinstance(copy_mechanisms, list)
        or len(copy_mechanisms) != 2
        or not isinstance(support_fields, list)
        or len(support_fields) != 5
        or not isinstance(platform_fields, list)
        or len(platform_fields) != 1
        or not isinstance(constants, dict)
        or constants.get("private_flag_privileged") != 8
    ):
        raise JobError("server-VPN production catalog shape mismatch")
    service_class = boundary.get("service_class")
    owner_class = boundary.get("registration_owner_class")
    owner_fields = boundary.get("registration_owner_fields")
    if (
        not isinstance(service_class, str)
        or not isinstance(owner_class, str)
        or not isinstance(owner_fields, list)
        or len(owner_fields) != 6
    ):
        raise JobError("server-VPN production service boundary mismatch")

    def method_row(raw: object, key_name: str) -> list[str]:
        if not isinstance(raw, dict):
            raise JobError("server-VPN production method entry is invalid")
        key = raw.get(key_name)
        class_name = raw.get("class")
        method_name = raw.get("method")
        signature = raw.get("signature")
        if not all(isinstance(value, str) for value in (key, class_name, method_name, signature)):
            raise JobError("server-VPN production method identity is invalid")
        parameters, return_type = parse_java_method_descriptor(cast(str, signature))
        return [
            cast(str, key),
            cast(str, class_name),
            cast(str, method_name),
            return_type,
            *parameters,
        ]

    def field_row(raw: object, *, default_class: str | None = None) -> list[str]:
        if not isinstance(raw, dict):
            raise JobError("server-VPN production field entry is invalid")
        role = raw.get("role", raw.get("name"))
        class_name = raw.get("class", default_class)
        name = raw.get("name")
        type_descriptor = raw.get("type")
        access_flags = raw.get("access_flags")
        if (
            not isinstance(role, str)
            or not isinstance(class_name, str)
            or not isinstance(name, str)
            or not isinstance(type_descriptor, str)
            or not isinstance(access_flags, int)
            or isinstance(access_flags, bool)
        ):
            raise JobError("server-VPN production field identity is invalid")
        parameters, field_type = parse_java_method_descriptor(f"(){type_descriptor}")
        if parameters or field_type == "void":
            raise JobError("server-VPN production field descriptor is invalid")
        return [role, class_name, name, field_type, str(access_flags & 0xDF)]

    hook_rows = [method_row(raw, "id") for raw in hooks]
    expected_ids = [
        "sync.network_capabilities",
        "sync.link_properties",
        "sync.legacy_active",
        "sync.legacy_type",
        "sync.legacy_network",
        "sync.legacy_all",
        "sync.default_proxy",
        "ingress.listen",
        "ingress.pending_listen",
        "ingress.pending_request",
        "ingress.request",
        "ingress.connectivity_diagnostics",
        "egress.callback",
        "egress.pending_intent",
    ]
    if [row[0] for row in hook_rows] != expected_ids:
        raise JobError("server-VPN production hook order mismatch")
    ingress_payload_indexes = [-1] * len(hooks)
    ingress_claim_indexes = [-1] * len(hooks)
    ingress_payload_kinds = [0] * len(hooks)
    ingress_nullable_payloads = [False] * len(hooks)
    egress_owner_indexes = [-1] * len(hooks)
    egress_source_indexes = [-1] * len(hooks)
    for index, (raw, row) in enumerate(zip(hooks, hook_rows, strict=True)):
        if not isinstance(raw, dict):
            raise JobError("server-VPN production hook entry is invalid")
        roles = raw.get("argument_roles")
        if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
            raise JobError("server-VPN production hook argument roles are invalid")
        if len(roles) != len(row) - 4:
            raise JobError("server-VPN production hook argument role count mismatch")
        if index < 7 or index > 11:
            if index < 12:
                continue
            owners = [
                position + 1
                for position, role in enumerate(roles)
                if role.startswith("registration=")
            ]
            sources = [
                position + 1
                for position, role in enumerate(roles)
                if role.startswith("network_agent=")
            ]
            if len(owners) != 1 or len(sources) != 1:
                raise JobError("server-VPN egress ownership role mismatch")
            egress_owner_indexes[index] = owners[0]
            egress_source_indexes[index] = sources[0]
            continue
        payloads = [
            (position + 1, role)
            for position, role in enumerate(roles)
            if role.startswith("capabilities=") or role.startswith("request=")
        ]
        claims = [
            position + 1
            for position, role in enumerate(roles)
            if role.startswith("calling_package=")
        ]
        if len(payloads) != 1 or len(claims) != 1:
            raise JobError("server-VPN ingress ownership role mismatch")
        payload_index, payload_role = payloads[0]
        ingress_payload_indexes[index] = payload_index
        ingress_claim_indexes[index] = claims[0]
        ingress_payload_kinds[index] = 1 if payload_role.startswith("capabilities=") else 2
        ingress_nullable_payloads[index] = "nullable_" in payload_role
    support_method_rows = [method_row(raw, "role") for raw in support_methods]
    platform_method_rows = [method_row(raw, "role") for raw in platform_methods]
    owner_field_rows = [field_row(raw, default_class=owner_class) for raw in owner_fields]
    support_field_rows = [field_row(raw) for raw in support_fields]
    platform_field_rows = [field_row(raw) for raw in platform_fields]
    for label, rows in (
        ("support method", support_method_rows),
        ("platform method", platform_method_rows),
        ("owner field", owner_field_rows),
        ("support field", support_field_rows),
        ("platform field", platform_field_rows),
    ):
        keys = [row[0] for row in rows]
        if len(keys) != len(set(keys)):
            raise JobError(f"server-VPN duplicate {label} role")

    def java_row(values: list[str]) -> str:
        return "    {" + ", ".join(json.dumps(value) for value in values) + "},"

    def java_int_array(values: list[int]) -> str:
        return "{" + ", ".join(str(value) for value in values) + "}"

    def java_boolean_array(values: list[bool]) -> str:
        return "{" + ", ".join("true" if value else "false" for value in values) + "}"

    generated = "\n".join(
        [
            "// Generated from components/server-vpn/runtime/hook_catalog.json "
            "by the confined builder.",
            "package dev.zygveil.servervpn.bridge;",
            "",
            "final class ExactCatalog {",
            f"  static final String SERVICE_CLASS = {json.dumps(service_class)};",
            "  static final int FIELD_MODIFIER_MASK = 0xDF;",
            "  static final int PRIVATE_FLAG_PRIVILEGED = 8;",
            "  static final String[][] HOOKS = {",
            *[java_row(row) for row in hook_rows],
            "  };",
            "  static final int[] INGRESS_PAYLOAD_INDEXES = "
            + java_int_array(ingress_payload_indexes)
            + ";",
            "  static final int[] INGRESS_CLAIM_INDEXES = "
            + java_int_array(ingress_claim_indexes)
            + ";",
            "  static final int[] INGRESS_PAYLOAD_KINDS = "
            + java_int_array(ingress_payload_kinds)
            + ";",
            "  static final boolean[] INGRESS_NULLABLE_PAYLOADS = "
            + java_boolean_array(ingress_nullable_payloads)
            + ";",
            "  static final int[] EGRESS_OWNER_INDEXES = "
            + java_int_array(egress_owner_indexes)
            + ";",
            "  static final int[] EGRESS_SOURCE_INDEXES = "
            + java_int_array(egress_source_indexes)
            + ";",
            "  static final String[][] SUPPORT_METHODS = {",
            *[java_row(row) for row in support_method_rows],
            "  };",
            "  static final String[][] PLATFORM_METHODS = {",
            *[java_row(row) for row in platform_method_rows],
            "  };",
            "  static final String[][] OWNER_FIELDS = {",
            *[java_row(row) for row in owner_field_rows],
            "  };",
            "  static final String[][] SUPPORT_FIELDS = {",
            *[java_row(row) for row in support_field_rows],
            "  };",
            "  static final String[][] PLATFORM_FIELDS = {",
            *[java_row(row) for row in platform_field_rows],
            "  };",
            "",
            "  private ExactCatalog() {}",
            "}",
            "",
        ]
    )
    generated_source = generated_root / "dev/zygveil/servervpn/bridge/ExactCatalog.java"
    generated_source.parent.mkdir(mode=0o700, parents=True)
    generated_source.write_text(generated, encoding="utf-8")
    if len(policy_sources) < 7 or len(bridge_sources) != 2:
        raise JobError("server-VPN production bridge source inventory is incomplete")
    android_jar = Path("/opt/android-sdk/platforms/android-36/android.jar")
    if not android_jar.is_file():
        raise JobError("Android 36 public SDK is unavailable for the server-VPN bridge")
    run(
        [
            "javac",
            "--release",
            "17",
            "-classpath",
            str(android_jar),
            "-Xlint:all",
            "-Werror",
            "-d",
            str(classes),
            *[str(source) for source in policy_sources],
            *[str(source) for source in bridge_sources],
            str(generated_source),
        ]
    )
    class_files = sorted(str(path) for path in classes.rglob("*.class"))
    if len(class_files) < len(policy_sources) + len(bridge_sources) + 1:
        raise JobError("server-VPN production bridge class output is incomplete")
    run(
        [
            "/opt/android-sdk/build-tools/37.0.0/d8",
            "--min-api",
            "36",
            "--output",
            str(dex_output),
            *class_files,
        ]
    )
    bridge_dex = dex_output / "classes.dex"
    bridge_bytes = bridge_dex.read_bytes()
    for marker in (
        b"dev/zygveil/servervpn/bridge/ServerVpnBridge",
        b"dev/zygveil/servervpn/bridge/ServerVpnRuntime",
        b"dev/zygveil/servervpn/policy/TargetAuthorization",
        b"dev/zygveil/servervpn/policy/DonorSelection",
        b"dev/zygveil/servervpn/policy/RequestNormalization",
        b"dev/zygveil/servervpn/policy/IngressArguments",
        b"dev/zygveil/servervpn/policy/EgressArguments",
        b"dev/zygveil/servervpn/policy/SnapshotProjection",
        b"dev/zygveil/servervpn/policy/EgressDecision",
        b"sync.default_proxy",
        b"ingress.connectivity_diagnostics",
        b"egress.pending_intent",
        b"prepareRuntime",
        b"authorizedPackage",
        b"EXCLUDED_PACKAGES",
        b"INGRESS_PAYLOAD_INDEXES",
        b"INGRESS_CLAIM_INDEXES",
        b"EGRESS_OWNER_INDEXES",
        b"EGRESS_SOURCE_INDEXES",
        b"package_manager_authorization_context",
        b"connected_network_state",
        b"preferred_donor_handles",
        b"reject_privileged_application",
    ):
        if marker not in bridge_bytes:
            raise JobError(f"server-VPN production bridge marker is missing: {marker!r}")
    for forbidden in (
        b"CoexistenceBridge",
        b"ZygVeilServerVpnGate",
        b"dev/zygveil/location/bridge",
        b"com/google/android/apps/maps",
    ):
        if forbidden in bridge_bytes:
            raise JobError(f"server-VPN production bridge contains forbidden marker: {forbidden!r}")
    return bridge_dex


def shell_sources() -> list[str]:
    module_scripts = sorted(
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "components/zygisk-host/module").glob("*.sh")
    )
    paths = ["containers/builder/entrypoint.sh", "gradlew", *module_scripts]
    return [path for path in paths if (ROOT / path).is_file()]


def formattable_paths() -> list[Path]:
    if not SOURCE_MANIFEST.is_file():
        raise JobError("source manifest is missing")
    manifest = json.loads(SOURCE_MANIFEST.read_text(encoding="utf-8"))
    raw_paths = manifest.get("paths")
    if manifest.get("schema_version") != 1 or not isinstance(raw_paths, list):
        raise JobError("source manifest schema mismatch")
    paths: list[Path] = []
    seen: set[str] = set()
    for relative in raw_paths:
        if not isinstance(relative, str) or relative in seen:
            raise JobError("source manifest contains an invalid or duplicate path")
        seen.add(relative)
        normalized = str(PurePosixPath(relative))
        path = (ROOT / normalized).resolve()
        if (
            normalized != relative
            or normalized.startswith("/")
            or normalized == ".."
            or normalized.startswith("../")
            or not path.is_relative_to(ROOT.resolve())
        ):
            raise JobError(f"unsafe source manifest path: {relative!r}")
        source = ROOT / relative
        if (
            not relative.startswith("deprecated/")
            and (relative in FORMATTABLE_NAMES or source.suffix in FORMATTABLE_SUFFIXES)
            and (source.is_file() and not source.is_symlink())
        ):
            paths.append(source)
    return paths


def format_check(_args: argparse.Namespace) -> None:
    restore_dependencies()
    quality_gradle(["spotlessCheck"])
    run(["ruff", "format", "--check", "tools/automation"])
    run(["shfmt", "-i", "4", "-ci", "-sr", "-d", *shell_sources()])
    write_report(
        "format-check.txt",
        [("spotless", "pass"), ("ruff_format", "pass"), ("shfmt", "pass")],
    )


def attestation_format_check(_args: argparse.Namespace) -> None:
    restore_dependencies()
    quality_gradle(list(ATTESTATION_SPOTLESS_TASKS))
    run(["ruff", "format", "--check", "tools/automation"])
    run(["shfmt", "-i", "4", "-ci", "-sr", "-d", *shell_sources()])
    write_report(
        "attestation-format-check.txt",
        [
            ("spotless_code", "pass"),
            ("ruff_format", "pass"),
            ("shfmt", "pass"),
            ("documentation", "excluded"),
        ],
    )


def lint(_args: argparse.Namespace) -> None:
    restore_dependencies()
    try:
        quality_gradle(
            [
                "--continue",
                ":location-controller:lintDebug",
                ":probe:lintPrimaryDebug",
                ":probe:lintCanaryDebug",
            ]
        )
    except JobError:
        reports = sorted(ROOT.glob("*/build/**/lint-results-debug.txt"))
        for report in reports:
            print(f"--- {report.relative_to(ROOT)} ---", file=sys.stderr)
            print(report.read_text(encoding="utf-8"), file=sys.stderr)
        raise
    run(["ruff", "check", "tools/automation"])
    run(["shellcheck", *shell_sources()])
    run(
        [
            "hadolint",
            "--failure-threshold",
            "warning",
            "--ignore",
            "DL3008",
            "--ignore",
            "DL4006",
            "containers/builder/Containerfile",
        ]
    )
    write_report(
        "lint.txt",
        [
            ("android_lint", "pass"),
            ("ruff", "pass"),
            ("shellcheck", "pass"),
            ("hadolint", "pass"),
        ],
    )


def static_analysis(_args: argparse.Namespace) -> None:
    restore_dependencies()
    quality_gradle(
        [
            ":location-controller:compileDebugJavaWithJavac",
            ":probe:compilePrimaryDebugJavaWithJavac",
            ":probe:compileCanaryDebugJavaWithJavac",
        ]
    )
    run(["mypy", "--config-file", "mypy.ini", "tools/automation"])
    write_report(
        "static-analysis.txt",
        [("javac_xlint_werror", "pass"), ("mypy", "pass")],
    )


def format_source(_args: argparse.Namespace) -> None:
    restore_dependencies()
    quality_gradle(["spotlessApply"])
    run(["ruff", "check", "--fix", "tools/automation"])
    run(["ruff", "format", "tools/automation"])
    run(["shfmt", "-i", "4", "-ci", "-sr", "-w", *shell_sources()])
    OUTPUT.mkdir(mode=0o700, parents=True, exist_ok=True)
    formatted = formattable_paths()
    with tarfile.open(OUTPUT / "formatted-source.tar", "w") as archive:
        for path in formatted:
            info = archive.gettarinfo(str(path), arcname=path.relative_to(ROOT).as_posix())
            info.uid = 1001
            info.gid = 1001
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            with path.open("rb") as stream:
                archive.addfile(info, stream)
    write_report(
        "format.txt",
        [("formatted_files", len(formatted)), ("transport", "allowlisted-tar")],
    )


def package_revision(directory: Path) -> str:
    xml_path = directory / "package.xml"
    if xml_path.is_file():
        root = ET.parse(xml_path).getroot()
        for element in root.iter():
            if element.tag.rsplit("}", 1)[-1] == "revision":
                parts: dict[str, str] = {}
                for child in element:
                    parts[child.tag.rsplit("}", 1)[-1]] = child.text or "0"
                return ".".join(
                    [
                        parts.get("major", "0"),
                        parts.get("minor", "0"),
                        parts.get("micro", "0"),
                    ]
                )
    properties = directory / "source.properties"
    if properties.is_file():
        match = re.search(
            r"^Pkg\.Revision\s*=\s*([^\s]+)",
            properties.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        if match:
            return match.group(1)
    children = sorted(path.name for path in directory.iterdir()) if directory.is_dir() else []
    raise JobError(f"package revision is missing: {directory}; entries={children}")


def toolchain_info(_args: argparse.Namespace) -> None:
    sdk = Path("/opt/android-sdk")
    package_files = {
        "platform_36_revision": sdk / "platforms/android-36",
        "platform_37_revision": sdk / "platforms/android-37.0",
        "build_tools_37_revision": sdk / "build-tools/37.0.0",
        "platform_tools_revision": sdk / "platform-tools",
        "cmake_revision": sdk / "cmake/3.31.6",
        "ndk_revision": sdk / "ndk/29.0.14206865",
    }
    expected_revisions = {
        "platform_36_revision": "2.0.0",
        "platform_37_revision": "2.0.0",
        "build_tools_37_revision": "37.0.0",
        "platform_tools_revision": "36.0.2",
        "cmake_revision": "3.31.6",
        "ndk_revision": "29.0.14206865",
    }
    platform_36_jar = sdk / "platforms/android-36/android.jar"
    platform_37_jar = sdk / "platforms/android-37.0/android.jar"
    aapt2 = sdk / "build-tools/37.0.0/aapt2"
    cmake = sdk / "cmake/3.31.6/bin/cmake"
    ninja = sdk / "cmake/3.31.6/bin/ninja"
    ndk_build = sdk / "ndk/29.0.14206865/ndk-build"
    for path in [platform_36_jar, platform_37_jar, aapt2, cmake, ninja, ndk_build]:
        if not path.is_file():
            raise JobError(f"SDK build input is missing: {path}")
    expected_environment = {
        "ANDROID_USER_HOME": "/tmp/home/.android",
        "GRADLE_USER_HOME": "/tmp/home/.gradle",
        "HOME": "/tmp/home",
    }
    for name, expected in expected_environment.items():
        if os.environ.get(name) != expected:
            raise JobError(f"environment mismatch for {name}: {os.environ.get(name)!r}")
    passwd_home = pwd.getpwuid(os.getuid()).pw_dir
    if passwd_home != "/tmp/home":
        raise JobError(f"passwd home mismatch: {passwd_home!r}")
    quality_versions = {
        "ruff": run(["ruff", "--version"]).strip(),
        "mypy": run(["mypy", "--version"]).strip(),
        "librt": run(
            [
                "python3",
                "-c",
                "import importlib.metadata; print(importlib.metadata.version('librt'))",
            ]
        ).strip(),
        "pathspec": run(
            [
                "python3",
                "-c",
                "import importlib.metadata; print(importlib.metadata.version('pathspec'))",
            ]
        ).strip(),
        "mypy_extensions": run(
            [
                "python3",
                "-c",
                "import importlib.metadata; print(importlib.metadata.version('mypy-extensions'))",
            ]
        ).strip(),
        "typing_extensions": run(
            [
                "python3",
                "-c",
                "import importlib.metadata; print(importlib.metadata.version('typing-extensions'))",
            ]
        ).strip(),
        "shellcheck": run(["shellcheck", "--version"]).splitlines()[1],
        "shfmt": run(["shfmt", "--version"]).strip(),
        "hadolint": run(["hadolint", "--version"]).strip(),
    }
    expected_quality_versions = {
        "ruff": r"ruff 0\.16\.4",
        "mypy": r"mypy 2\.3\.1(?: \(compiled: (?:yes|no)\))?",
        "librt": r"0\.15\.0",
        "pathspec": r"1\.1\.1",
        "mypy_extensions": r"1\.1\.0",
        "typing_extensions": r"4\.16\.0",
        "shellcheck": r"version: 0\.11\.0",
        "shfmt": r"v3\.13\.1",
        "hadolint": r"Haskell Dockerfile Linter 2\.14\.0",
    }
    for name, expected_pattern in expected_quality_versions.items():
        if re.fullmatch(expected_pattern, quality_versions[name]) is None:
            raise JobError(f"quality tool version mismatch for {name}: {quality_versions[name]!r}")
    values: list[tuple[str, object]] = [
        ("java", run(["java", "-version"]).splitlines()[0]),
        *[(name.lower(), value) for name, value in expected_environment.items()],
        ("passwd_home", passwd_home),
        *quality_versions.items(),
        ("gradle_wrapper_jar_sha256", sha256(Path("/opt/gradle-wrapper/gradle-wrapper.jar"))),
        ("android_36_jar_sha256", sha256(platform_36_jar)),
        ("android_37_jar_sha256", sha256(platform_37_jar)),
        ("aapt2_sha256", sha256(aapt2)),
        ("cmake", run([str(cmake), "--version"]).splitlines()[0]),
        ("ninja", run([str(ninja), "--version"]).strip()),
        ("ndk_build", str(ndk_build)),
        ("zygisk_api_header", "/opt/vendor-src/zygisk-api/module/jni/zygisk.hpp"),
        ("ndk_static_libcxx", "/opt/android-sdk/ndk/29.0.14206865/NOTICE"),
        ("lsplant_source", "/opt/vendor-src/lsplant"),
        ("shadowhook_source", "/opt/vendor-src/shadowhook"),
    ]
    for key, path in package_files.items():
        if not path.is_dir():
            raise JobError(f"SDK package metadata is missing: {path}")
        actual_revision = package_revision(path)
        if actual_revision != expected_revisions[key]:
            raise JobError(
                f"SDK package revision mismatch for {path}: "
                f"expected {expected_revisions[key]}, got {actual_revision}"
            )
        values.append((key, actual_revision))
    write_report("image.txt", values)


def status_field(name: str) -> str:
    for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{name}:"):
            return line.split(":", 1)[1].strip()
    return "missing"


def network_block(_args: argparse.Namespace) -> None:
    blocked = False
    error_name = "none"
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=2):
            pass
    except OSError as error:
        blocked = True
        error_name = type(error).__name__
    if not blocked:
        raise JobError("outbound connection unexpectedly succeeded")
    write_report(
        "network-block.txt",
        [("outbound_blocked", "true"), ("failure_type", error_name)],
    )


def confinement(_args: argparse.Namespace) -> None:
    checks: list[tuple[str, object]] = [
        ("uid", os.getuid()),
        ("cap_eff", status_field("CapEff")),
        ("no_new_privs", status_field("NoNewPrivs")),
        ("seccomp", status_field("Seccomp")),
        ("git_absent", str(not (ROOT / ".git").exists()).lower()),
        ("workspace_absent", str(not Path("/workspace").exists()).lower()),
        ("podman_socket_absent", str(not Path("/run/podman/podman.sock").exists()).lower()),
        ("ssh_auth_sock_absent", str("SSH_AUTH_SOCK" not in os.environ).lower()),
    ]
    if os.getuid() == 0 or status_field("CapEff") != "0000000000000000":
        raise JobError("uid/capability confinement mismatch")
    if status_field("NoNewPrivs") != "1" or status_field("Seccomp") != "2":
        raise JobError("NoNewPrivs/seccomp confinement mismatch")
    try:
        Path("/confinement-write").write_text("forbidden", encoding="utf-8")
    except OSError:
        checks.append(("root_read_only", "true"))
    else:
        raise JobError("container root is writable")
    for directory in [Path("/tmp"), Path("/work")]:
        marker = directory / f"write-test-{os.getpid()}"
        marker.write_text("ok", encoding="utf-8")
        marker.unlink()
    checks.append(("tmp_work_writable", "true"))
    makefile = ROOT / "Makefile"
    before = sha256(makefile)
    with makefile.open("a", encoding="utf-8") as stream:
        stream.write("\n# private container mutation\n")
    checks.extend(
        [
            ("private_source_before", before),
            ("private_source_after", sha256(makefile)),
            ("private_source_mutated", "true"),
        ]
    )
    write_report("confinement.txt", checks)


COMMANDS = {
    "build-controller": build_controller,
    "build-location": build_location,
    "build-location-app-poc": build_location_app_poc,
    "build-location-candidate": build_location_candidate,
    "build-server-vpn-poc": build_server_vpn_poc,
    "dependencies": dependencies,
    "signing-init": signing_init,
    "signing-info": signing_info,
    "build-probe": build_probe,
    "build-probe-canary-poc": build_probe_canary_poc,
    "build-probe-server-vpn-poc": build_probe_server_vpn_poc,
    "toolchain-info": toolchain_info,
    "network-block": network_block,
    "confinement": confinement,
    "attestation-format-check": attestation_format_check,
    "format-check": format_check,
    "format-source": format_source,
    "lint": lint,
    "static-analysis": static_analysis,
    "test-location-unit": test_location_unit,
    "test-location-controller-unit": test_controller_unit,
    "test-server-vpn-config": test_server_vpn_config,
    "test-server-vpn-model": test_server_vpn_model,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=sorted(COMMANDS))
    args = parser.parse_args()
    try:
        COMMANDS[args.command](args)
    except (OSError, KeyError, json.JSONDecodeError, subprocess.SubprocessError, JobError) as error:
        print(f"container job: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
