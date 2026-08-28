# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Repository, host, device, and VPN baseline automation."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import shutil
import stat
import subprocess
import sys
import traceback
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import cast

from adb import Adb, device_selection_self_test, device_ui_state_self_test, shell_argument_self_test
from reporting import CheckError, Report

ROOT = Path(__file__).resolve().parents[2]
REQUIRED_DOCUMENTS = [
    Path("README.md"),
    Path("AGENTS.md"),
    Path("components/README.md"),
    Path("components/zygisk-host/THIRD_PARTY.md"),
    Path("docs/contracts/README.md"),
    Path("docs/contracts/ARCHITECTURE.md"),
    Path("docs/contracts/PUBLIC_API.md"),
    Path("docs/contracts/PROBE.md"),
    Path("docs/contracts/AUTOMATION.md"),
    Path("docs/contracts/VALIDATION.md"),
    Path("docs/contracts/SECURITY.md"),
    Path("docs/maintenance/DEVELOPMENT.md"),
    Path("docs/maintenance/DEVICE_OPERATIONS.md"),
]
CONTRACT_DOCUMENTS = [
    path
    for path in REQUIRED_DOCUMENTS
    if path.parent == Path("docs/contracts") and path.name != "README.md"
]
SERVER_VPN_HOOK_CATALOG = ROOT / "components/server-vpn/runtime/hook_catalog.json"


def validate_server_vpn_hook_catalog(report: Report) -> None:
    if not SERVER_VPN_HOOK_CATALOG.is_file():
        raise CheckError("server-VPN hook catalog is missing")
    decoded: object = json.loads(SERVER_VPN_HOOK_CATALOG.read_text(encoding="utf-8"))
    if not isinstance(decoded, dict) or decoded.get("schema_version") != 1:
        raise CheckError("server-VPN hook catalog schema mismatch")
    catalog = cast(dict[str, object], decoded)
    forbidden_keys = {
        "artifacts",
        "base_target_descriptor",
        "connectivity_apex",
        "dependencies",
        "hook_engine_artifacts",
    }
    if forbidden_keys & catalog.keys():
        raise CheckError("server-VPN hook catalog contains device-bound inventory")

    boundary = catalog.get("service_boundary")
    if not isinstance(boundary, dict):
        raise CheckError("server-VPN service boundary is invalid")
    service_class = boundary.get("service_class")
    if service_class != "android.net.connectivity.com.android.server.ConnectivityService":
        raise CheckError("server-VPN service declaring class mismatch")
    fields = boundary.get("registration_owner_fields")
    expected_owner_fields = {
        "mAsUid",
        "mMessenger",
        "mNetworkRequestForCallback",
        "mPendingIntent",
        "mPid",
        "mUid",
    }
    if (
        not isinstance(fields, list)
        or {value.get("name") for value in fields if isinstance(value, dict)}
        != expected_owner_fields
    ):
        raise CheckError("server-VPN registration owner field catalog mismatch")

    methods = catalog.get("candidate_methods")
    if not isinstance(methods, list) or not methods:
        raise CheckError("server-VPN candidate method catalog is empty")
    identities: set[tuple[str, str, str]] = set()
    for value in methods:
        if not isinstance(value, dict):
            raise CheckError("server-VPN candidate method entry is invalid")
        identity = (value.get("class"), value.get("method"), value.get("signature"))
        if (
            not all(isinstance(item, str) and item for item in identity)
            or identity in identities
            or identity[0] != service_class
            or "code_offset" in value
        ):
            raise CheckError("server-VPN candidate method identity is invalid")
        typed_identity = cast(tuple[str, str, str], identity)
        identities.add(typed_identity)

    hooks = catalog.get("hook_catalog")
    expected_hook_ids = {
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
    }
    if (
        not isinstance(hooks, list)
        or {value.get("id") for value in hooks if isinstance(value, dict)} != expected_hook_ids
    ):
        raise CheckError("server-VPN fixed hook ID catalog mismatch")
    hook_identities: set[tuple[str, str, str]] = set()
    for value in hooks:
        if not isinstance(value, dict):
            raise CheckError("server-VPN hook catalog entry is invalid")
        identity = (value.get("class"), value.get("method"), value.get("signature"))
        typed_identity = cast(tuple[str, str, str], identity)
        if (
            not all(isinstance(item, str) and item for item in identity)
            or typed_identity in hook_identities
            or typed_identity not in identities
            or "code_offset" in value
            or value.get("phase") not in {"before", "after"}
            or not isinstance(value.get("argument_roles"), list)
            or not isinstance(value.get("return_role"), str)
            or not isinstance(value.get("target_authority"), str)
            or not isinstance(value.get("copy_strategy"), str)
            or not isinstance(value.get("failure_behavior"), str)
        ):
            raise CheckError("server-VPN fixed hook catalog identity is invalid")
        hook_identities.add(typed_identity)

    excluded = catalog.get("excluded_candidates")
    if not isinstance(excluded, list):
        raise CheckError("server-VPN excluded candidate catalog is invalid")
    excluded_identities: set[tuple[str, str, str]] = set()
    for value in excluded:
        if not isinstance(value, dict):
            raise CheckError("server-VPN excluded candidate entry is invalid")
        identity = (service_class, value.get("method"), value.get("signature"))
        typed_identity = cast(tuple[str, str, str], identity)
        if (
            not all(isinstance(item, str) and item for item in identity)
            or typed_identity in excluded_identities
            or typed_identity not in identities
            or not isinstance(value.get("reason"), str)
        ):
            raise CheckError("server-VPN excluded candidate identity is invalid")
        excluded_identities.add(typed_identity)
    if hook_identities & excluded_identities or hook_identities | excluded_identities != identities:
        raise CheckError("server-VPN candidate selection is not a fixed partition")

    support_methods = catalog.get("support_methods")
    platform_support_methods = catalog.get("platform_support_methods")
    copy_mechanisms = catalog.get("copy_mechanisms")
    support_fields = catalog.get("support_fields")
    platform_support_fields = catalog.get("platform_support_fields")
    authorization_constants = catalog.get("authorization_constants")
    if not isinstance(support_methods, list) or len(support_methods) != 4:
        raise CheckError("server-VPN support method catalog mismatch")
    if not isinstance(platform_support_methods, list) or len(platform_support_methods) != 1:
        raise CheckError("server-VPN platform support method catalog mismatch")
    if not isinstance(copy_mechanisms, list) or len(copy_mechanisms) != 2:
        raise CheckError("server-VPN detached copy mechanism catalog mismatch")
    if not isinstance(support_fields, list) or len(support_fields) != 5:
        raise CheckError("server-VPN support field catalog mismatch")
    if not isinstance(platform_support_fields, list) or len(platform_support_fields) != 1:
        raise CheckError("server-VPN platform support field catalog mismatch")
    if authorization_constants != {"private_flag_privileged": 8}:
        raise CheckError("server-VPN authorization constants mismatch")
    for entries in (support_methods, platform_support_methods, copy_mechanisms):
        for value in entries:
            if not isinstance(value, dict) or not all(
                isinstance(value.get(key), str) and value.get(key)
                for key in ("class", "method", "signature", "role")
            ):
                raise CheckError("server-VPN support method identity is invalid")
            if "code_offset" in value:
                raise CheckError("server-VPN support method contains a build-derived offset")
    for entries in (support_fields, platform_support_fields):
        for value in entries:
            if not isinstance(value, dict) or not all(
                isinstance(value.get(key), str) and value.get(key)
                for key in ("class", "name", "type", "role")
            ):
                raise CheckError("server-VPN support field identity is invalid")
            flags = value.get("access_flags")
            if not isinstance(flags, int) or isinstance(flags, bool) or flags < 0:
                raise CheckError("server-VPN support field flags are invalid")
    report.kv(
        "server_vpn_hook_catalog_sha256",
        hashlib.sha256(SERVER_VPN_HOOK_CATALOG.read_bytes()).hexdigest(),
    )
    report.kv("server_vpn_candidate_method_count", len(methods))
    report.kv("server_vpn_hook_count", len(hooks))
    report.kv("server_vpn_copy_mechanism_count", len(copy_mechanisms))


def run_host(arguments: Sequence[str], timeout: int = 30) -> str:
    try:
        completed = subprocess.run(
            arguments,
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise CheckError(f"host command timed out: {arguments[0]}") from error
    if completed.returncode != 0:
        raise CheckError(
            f"host command failed ({completed.returncode}): {' '.join(arguments)}: "
            f"{completed.stdout.strip()}"
        )
    return completed.stdout


def first_line(value: str) -> str:
    return value.splitlines()[0] if value.splitlines() else ""


def doctor(report: Report, _args: argparse.Namespace) -> None:
    report.section("required-tools")
    tools = [
        "bash",
        "make",
        "git",
        "podman",
        "adb",
        "tar",
        "sha256sum",
        "python3",
    ]
    for tool in tools:
        path = shutil.which(tool)
        if not path:
            raise CheckError(f"required command not found: {tool}")
        report.kv(f"tool.{tool}", path)

    report.section("versions")
    report.kv("python", sys.version.replace("\n", " "))
    report.kv("python_executable", sys.executable)
    report.kv("make", first_line(run_host(["make", "--version"])))
    report.kv("git", run_host(["git", "--version"]).strip())
    report.kv("podman", run_host(["podman", "version", "--format", "{{.Client.Version}}"]).strip())
    report.kv("adb", first_line(run_host(["adb", "version"])))

    report.section("podman")
    run_host(["podman", "info"], timeout=45)
    rootless = run_host(["podman", "info", "--format", "{{.Host.Security.Rootless}}"]).strip()
    report.kv("rootless", rootless)
    report.kv(
        "cgroup_version",
        run_host(["podman", "info", "--format", "{{.Host.CgroupsVersion}}"]).strip(),
    )
    report.kv(
        "graph_root",
        run_host(["podman", "info", "--format", "{{.Store.GraphRoot}}"]).strip(),
    )
    if rootless != "true":
        raise CheckError(f"rootless Podman is required, got {rootless}")

    report.section("host-toolchain-inventory")
    for tool in ["java", "javac", "gradle", "sdkmanager", "avdmanager"]:
        report.kv(f"host.{tool}", shutil.which(tool) or "absent")
    report.kv(
        "policy",
        "host Java/Gradle/Android tools are inventory-only; build recipes use containers",
    )
    if shutil.which("dpkg-query"):
        packages = run_host(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"])
        for line in packages.splitlines():
            if re.search(r"openjdk|gradle|android-sdk|sdkmanager", line, re.IGNORECASE):
                report.line(line)

    report.section("repository")
    report.kv("root", ROOT)
    report.kv("git_work_tree", run_host(["git", "rev-parse", "--is-inside-work-tree"]).strip())
    for line in run_host(["git", "status", "--short", "--branch"]).splitlines():
        report.line(line)
    report.kv("network_access", "none")
    report.kv("package_install", "none")


def docs_check(report: Report, _args: argparse.Namespace) -> None:
    files = [ROOT / path for path in REQUIRED_DOCUMENTS]
    contents = {path: path.read_text(encoding="utf-8") for path in files}

    report.section("required-files")
    for path in files:
        if not path.is_file() or path.stat().st_size == 0:
            raise CheckError(f"missing or empty file: {path.relative_to(ROOT)}")
        report.kv(f"{path.relative_to(ROOT)}.bytes", path.stat().st_size)
    report.section("server-vpn-hook-catalog")
    validate_server_vpn_hook_catalog(report)
    deprecated_readme = (ROOT / "deprecated/README.md").read_text(encoding="utf-8")
    for required in ("unsupported", "untested", "excluded"):
        if required not in deprecated_readme:
            raise CheckError(f"deprecated boundary omits required label: {required}")
    report.kv("deprecated_boundary_labels", "PASS")

    report.section("product-identity")
    stale_tokens = (
        "dev.vpnmask",
        "dev/vpnmask",
        "zygisk-location",
        "lsposed_ghost_vpn",
        "lsposed-ghost-vpn",
        "ghost-fixed-location",
        "Ghost Fixed Location",
        "Ghost Location Controller",
        "VpnApiMask",
        "VpnMaskModule",
        "VPN_MASK_KEYSTORE",
        "ghost::",
        "GHOST_",
        "ghost_shadowhook",
        "ghost_fixed_location",
        "libghost",
    )
    repository_files = {
        Path(value)
        for value in run_host(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"]
        ).splitlines()
        if value
    }
    stale_matches: list[str] = []
    scanned_files = 0
    for relative in sorted(repository_files):
        if relative.parts[:1] == ("deprecated",):
            continue
        path = ROOT / relative
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        scanned_files += 1
        if relative == Path("tools/automation/baseline.py"):
            continue
        stale_matches.extend(f"{relative}:{token}" for token in stale_tokens if token in content)
    if stale_matches:
        report.kv("stale_identity_matches", stale_matches)
        raise CheckError("repository contains stale product identities")
    report.kv("canonical_product", "ZygVeil")
    report.kv("canonical_namespace", "dev.zygveil")
    report.kv("canonical_module_id", "zygveil")
    report.kv("scanned_file_count", scanned_files)

    report.section("markdown")
    for path in files:
        text = contents[path]
        fences = sum(line.startswith("```") for line in text.splitlines())
        report.kv(f"{path.relative_to(ROOT)}.fences", fences)
        if fences % 2:
            raise CheckError(f"unpaired Markdown fence: {path.relative_to(ROOT)}")
        if any(re.search(r"[ \t]+$", line) for line in text.splitlines()):
            raise CheckError(f"trailing whitespace: {path.relative_to(ROOT)}")
        if re.search(r"\b(?:TODO|TBD|FIXME)\b", text):
            raise CheckError(f"documentation contains a placeholder: {path.relative_to(ROOT)}")

    report.section("internal-links")
    internal_link_count = 0
    link_pattern = re.compile(r"\[[^]]+]\(([^)]+)\)")
    for path, content in contents.items():
        for destination in link_pattern.findall(content):
            if destination.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target_name = destination.split("#", 1)[0].strip("<>")
            target = (path.parent / target_name).resolve()
            if not target.is_relative_to(ROOT) or not target.is_file():
                raise CheckError(f"broken internal link in {path.relative_to(ROOT)}: {destination}")
            internal_link_count += 1
    report.kv("validated_link_count", internal_link_count)

    automation_text = (ROOT / "docs/contracts/AUTOMATION.md").read_text(encoding="utf-8")
    documented_target_rows = re.findall(r"^\| `([^`]+)` \|", automation_text, re.MULTILINE)
    documented_targets = set(documented_target_rows)
    implemented_targets: set[str] = set()
    make_files = [ROOT / "Makefile", *sorted((ROOT / "mk").glob("*.mk"))]
    for make_file in make_files:
        for line in make_file.read_text(encoding="utf-8").splitlines():
            match = re.match(r"^([a-z][a-z0-9-]*):(?:\s|$)", line)
            if match:
                implemented_targets.add(match.group(1))
    report.section("make-target-contract")
    report.kv("documented_target_count", len(documented_targets))
    report.kv("implemented_target_count", len(implemented_targets))
    if not documented_targets or len(documented_target_rows) != len(documented_targets):
        raise CheckError("documented Make targets are empty or duplicated")
    undocumented = implemented_targets - documented_targets
    unimplemented = documented_targets - implemented_targets
    if undocumented or unimplemented:
        report.kv("undocumented_implemented_targets", sorted(undocumented))
        report.kv("documented_unimplemented_targets", sorted(unimplemented))
        raise CheckError("Make target inventory differs from docs/contracts/AUTOMATION.md")

    help_text = (ROOT / "mk/common.mk").read_text(encoding="utf-8")
    help_rows = re.findall(r"^\s*'make ([a-z][a-z0-9-]*)\s", help_text, re.MULTILINE)
    help_targets = set(help_rows)
    report.kv("help_target_count", len(help_targets))
    if len(help_rows) != len(help_targets) or help_targets != implemented_targets:
        report.kv("implemented_missing_from_help", sorted(implemented_targets - help_targets))
        report.kv("unknown_or_duplicate_help_targets", sorted(help_targets - implemented_targets))
        raise CheckError("make help inventory differs from implemented targets")

    report.section("contract-assertions")
    all_identifiers: list[str] = []
    assertion_pattern = re.compile(r"^### `([A-Z]{3}-[0-9]{3})` - .+$", re.MULTILINE)
    for relative in CONTRACT_DOCUMENTS:
        content = (ROOT / relative).read_text(encoding="utf-8")
        matches = list(assertion_pattern.finditer(content))
        if not matches:
            raise CheckError(f"contract has no assertions: {relative}")
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(content)
            body = content[match.end() : end]
            identifier = match.group(1)
            all_identifiers.append(identifier)
            if "**Contract:**" not in body or "**Evidence:**" not in body:
                raise CheckError(f"malformed contract assertion: {identifier}")
            contract_text = body.split("**Evidence:**", 1)[0]
            if not re.search(r"\b(?:MUST|MAY)\b", contract_text):
                raise CheckError(f"contract assertion lacks normative language: {identifier}")
        report.kv(f"{relative.name}.assertions", len(matches))
    duplicates = sorted(
        identifier for identifier in set(all_identifiers) if all_identifiers.count(identifier) > 1
    )
    if duplicates:
        report.kv("duplicate_contract_ids", duplicates)
        raise CheckError("contract assertion identifiers are duplicated")
    report.kv("assertion_count", len(all_identifiers))

    known_identifiers = set(all_identifiers)
    reference_pattern = re.compile(r"`((?:ARC|API|PRB|AUT|VAL|SEC)-[0-9]{3})`")
    referenced_identifiers = {
        identifier
        for content in contents.values()
        for identifier in reference_pattern.findall(content)
    }
    unknown_identifiers = referenced_identifiers - known_identifiers
    if unknown_identifiers:
        report.kv("unknown_contract_ids", sorted(unknown_identifiers))
        raise CheckError("documentation references undefined contract assertions")
    report.kv("referenced_assertion_count", len(referenced_identifiers))

    report.section("probe-detector-contract")
    from probe import EXPECTED_TEST_IDS

    expected_groups: object = EXPECTED_TEST_IDS
    if not isinstance(expected_groups, dict) or not all(
        isinstance(group, str)
        and isinstance(identifiers, set)
        and all(isinstance(identifier, str) for identifier in identifiers)
        for group, identifiers in expected_groups.items()
    ):
        raise CheckError("could not parse EXPECTED_TEST_IDS from probe automation")
    typed_groups = cast(dict[str, set[str]], expected_groups)
    expected_detectors = {
        identifier for identifiers in typed_groups.values() for identifier in identifiers
    }
    documented_detector_rows = re.findall(
        r"^(?:sync|matcher|legacy|callback|pending|request|reserve|schema|link|"
        r"scalar|structure|diagnostics|data_plane)\.[a-z0-9_.]+$",
        contents[ROOT / "docs/contracts/PROBE.md"],
        re.MULTILINE,
    )
    documented_detectors = set(documented_detector_rows)
    report.kv("implementation_detector_count", len(expected_detectors))
    report.kv("documented_detector_count", len(documented_detectors))
    if (
        len(documented_detector_rows) != len(documented_detectors)
        or documented_detectors != expected_detectors
    ):
        report.kv("undocumented_detectors", sorted(expected_detectors - documented_detectors))
        report.kv(
            "unknown_or_duplicate_documented_detectors",
            sorted(documented_detectors - expected_detectors),
        )
        raise CheckError("probe detector catalog differs from docs/contracts/PROBE.md")

    report.section("content-keys")
    for kind in ["image", "dependencies"]:
        key = run_host([sys.executable, "tools/automation/container.py", "key", kind]).strip()
        report.kv(kind, key)

    report.section("documented-toolchain")
    source_versions = [
        (
            "gradle",
            ROOT / "gradle/wrapper/gradle-wrapper.properties",
            r"gradle-([0-9.]+)-bin\.zip",
        ),
        (
            "android_gradle_plugin",
            ROOT / "build.gradle.kts",
            r'id\("com\.android\.application"\) version "([0-9.]+)"',
        ),
        (
            "spotless",
            ROOT / "build.gradle.kts",
            r'id\("com\.diffplug\.spotless"\) version "([0-9.]+)"',
        ),
        (
            "google_java_format",
            ROOT / "build.gradle.kts",
            r'googleJavaFormat\("([0-9.]+)"\)',
        ),
        ("ktlint", ROOT / "build.gradle.kts", r'ktlint\("([0-9.]+)"\)'),
        (
            "android_build_tools",
            ROOT / "components/probe/build.gradle.kts",
            r'buildToolsVersion = "([0-9.]+)"',
        ),
        (
            "java_language",
            ROOT / "components/probe/build.gradle.kts",
            r"sourceCompatibility = JavaVersion\.VERSION_([0-9]+)",
        ),
        (
            "ruff",
            ROOT / "containers/builder/Containerfile",
            r"^ARG RUFF_VERSION=([^\s]+)$",
        ),
        (
            "mypy",
            ROOT / "containers/builder/Containerfile",
            r"^ARG MYPY_VERSION=([^\s]+)$",
        ),
        (
            "shellcheck",
            ROOT / "containers/builder/Containerfile",
            r"^ARG SHELLCHECK_VERSION=([^\s]+)$",
        ),
        (
            "shfmt",
            ROOT / "containers/builder/Containerfile",
            r"^ARG SHFMT_VERSION=([^\s]+)$",
        ),
        (
            "hadolint",
            ROOT / "containers/builder/Containerfile",
            r"^ARG HADOLINT_VERSION=([^\s]+)$",
        ),
    ]
    for label, source, pattern in source_versions:
        matches = re.findall(pattern, source.read_text(encoding="utf-8"), re.MULTILINE)
        if len(matches) != 1:
            raise CheckError(f"could not resolve exact source version: {label}")
        version = matches[0]
        if f"`{version}`" not in automation_text:
            raise CheckError(f"automation contract omits current source version: {label}")
        report.kv(label, version)

    report.section("agent-entrypoint")
    agent_text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    linked_documents = [path for path in REQUIRED_DOCUMENTS if path.parts[:1] == ("docs",)]
    for relative in linked_documents:
        if relative.as_posix() not in agent_text:
            raise CheckError(f"AGENTS.md does not link required document: {relative}")
    report.kv("linked_document_count", len(linked_documents))

    report.section("documentation-inventory")
    expected_markdown = set(REQUIRED_DOCUMENTS)
    actual_markdown = (
        {path.relative_to(ROOT) for path in ROOT.glob("*.md") if path.is_file()}
        | {path.relative_to(ROOT) for path in (ROOT / "components").rglob("*.md")}
        | {path.relative_to(ROOT) for path in (ROOT / "docs").rglob("*.md")}
    )
    if actual_markdown != expected_markdown:
        report.kv("unexpected_markdown", sorted(actual_markdown - expected_markdown))
        report.kv("missing_markdown", sorted(expected_markdown - actual_markdown))
        raise CheckError("repository Markdown inventory differs from the documentation contract")
    report.kv("markdown_file_count", len(actual_markdown))

    report.section("sha256")
    for path in files:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        report.line(f"{digest}  {path.relative_to(ROOT)}")


def privacy_check(report: Report, _args: argparse.Namespace) -> None:
    repository_files = {
        Path(value)
        for value in run_host(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"]
        ).splitlines()
        if value
    }
    forbidden_paths = {
        Path("docs") / ("target-" + "device.json"),
        Path("docs") / ("server-vpn-" + "target.json"),
        Path("components/zygisk-host/module") / ("target." + "properties"),
        Path("components/zygisk-host/module") / ("target-artifacts." + "sha256"),
        Path("components/zygisk-host/module") / ("target-artifacts." + "size"),
    }
    byte_markers = {
        "build_identity_field": b"build_" + b"fingerprint",
        "build_identity_api": b"Build." + b"FINGERPRINT",
        "persisted_adb_selector": b"selected_" + b"serial",
        "extended_adb_inventory": b"adb devices " + b"-l",
        "compatibility_base_digest": b"base_target_" + b"sha256",
        "compatibility_catalog_digest": b"connectivity_descriptor_" + b"sha256",
        "product_model_property": b"ro.product." + b"model",
        "product_manufacturer_property": b"ro.product." + b"manufacturer",
        "product_device_property": b"ro.product." + b"device",
        "product_name_property": b"ro.product." + b"name",
        "build_display_property": b"ro.build." + b"display.id",
        "build_fingerprint_property": b"ro.build." + b"fingerprint",
        "vendor_fingerprint_property": b"ro.vendor.build." + b"fingerprint",
    }
    implementation_identifier = re.compile(
        r"(?i)\b(?:getimei|getmeid|telephony_imei|telephony_meid|subscriber_id|"
        r"sim_serial|iccid|android_id)\b"
    )
    host_path = re.compile(
        r"(?<![A-Za-z0-9_.-])(?:file://)?/(?:ho" + r"me|med" + r"ia)/[^\s'\"<>]+"
    )
    violations: dict[str, set[str]] = {}
    scanned_bytes = 0
    for relative in sorted(repository_files):
        path = ROOT / relative
        if not path.is_file():
            continue
        raw = path.read_bytes()
        scanned_bytes += len(raw)
        categories = violations.setdefault(relative.as_posix(), set())
        if relative in forbidden_paths:
            categories.add("forbidden_device_inventory_path")
        if relative != Path("tools/automation/baseline.py"):
            categories.update(label for label, marker in byte_markers.items() if marker in raw)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        if text and relative != Path("tools/automation/baseline.py"):
            if host_path.search(text):
                categories.add("host_private_path")
            if (
                relative.parts[:2] == ("tools", "automation")
                or relative.parts[:1] == ("components",)
            ) and implementation_identifier.search(text):
                categories.add("persistent_device_identifier_api")
        if not categories:
            del violations[relative.as_posix()]
    report.section("repository-privacy")
    report.kv("scanned_file_count", len(repository_files))
    report.kv("scanned_bytes", scanned_bytes)
    report.kv("forbidden_match_file_count", len(violations))
    if violations:
        report.kv(
            "forbidden_match_categories",
            {path: sorted(categories) for path, categories in sorted(violations.items())},
        )
        raise CheckError("repository contains device identity or host-private path material")
    report.kv("device_identity", "absent")
    report.kv("host_private_paths", "absent")


def package_summary(adb: Adb, report: Report, package: str) -> None:
    path_result = adb.shell("pm", "path", package, check=False)
    installed = path_result.returncode == 0 and path_result.stdout.startswith("package:")
    report.kv(f"package.{package}.installed", str(installed).lower())
    if not installed:
        return
    details = adb.shell("dumpsys", "package", package).stdout
    for key, pattern in [
        ("version_code", r"versionCode=([^\s]+)"),
        ("version_name", r"versionName=([^\s]+)"),
        ("target_sdk", r"targetSdk=([^\s]+)"),
    ]:
        match = re.search(pattern, details)
        report.kv(f"package.{package}.{key}", match.group(1) if match else "unknown")


def parse_vpn_agents(connectivity: str) -> list[dict[str, str]]:
    agents = []
    pattern = re.compile(
        r"NetworkAgentInfo\{.*?network\{(?P<network>\d+)\}.*?"
        r"nc\{\[ Transports: (?P<transports>[A-Z_|]+) "
        r"Capabilities: (?P<capabilities>[A-Z0-9_&]+)"
    )
    for line in connectivity.splitlines():
        match = pattern.search(line)
        if not match or "VPN" not in match.group("transports").split("|"):
            continue
        owner = re.search(r"OwnerUid: (\d+)", line)
        agents.append(
            {
                "network": match.group("network"),
                "transports": match.group("transports"),
                "capabilities": match.group("capabilities"),
                "owner_uid": owner.group(1) if owner else "unknown",
            }
        )
    return agents


def count_vpn_requests(connectivity: str) -> int:
    requests = set()
    for line in connectivity.splitlines():
        if "NetworkRequest [" not in line:
            continue
        transport = re.search(r"Transports: ([A-Z_|]+)", line)
        if not transport or "VPN" not in transport.group(1).split("|"):
            continue
        request_id = re.search(r"\bid=(\d+)", line)
        request_type = re.search(r"NetworkRequest \[ ([A-Z_]+)", line)
        package = re.search(r"RequestorPkg: ([A-Za-z0-9_.]+)", line)
        requests.add(
            (
                request_id.group(1) if request_id else "unknown",
                request_type.group(1) if request_type else "unknown",
                package.group(1) if package else "unknown",
            )
        )
    return len(requests)


def vpn_status(report: Report, args: argparse.Namespace) -> None:
    adb = Adb.select(args.adb_serial, report)
    report.section("secure-settings")
    for key in ["always_on_vpn_app", "always_on_vpn_lockdown"]:
        result = adb.shell("settings", "get", "secure", key, check=False)
        report.kv(key, result.stdout.strip() if result.returncode == 0 else "unavailable")

    report.section("provider-candidates")
    packages = adb.shell("pm", "list", "packages").stdout
    candidates = sorted(
        line.removeprefix("package:")
        for line in packages.splitlines()
        if re.search(
            r"wireguard|openvpn|strongswan|tailscale|zerotier|(?:^|[.])vpn(?:[.]|$)",
            line,
            re.IGNORECASE,
        )
    )
    report.kv("candidate_count", len(candidates))
    for index, package in enumerate(candidates):
        report.kv(f"candidate.{index}.package", package)
    package_summary(adb, report, "com.wireguard.android")

    connectivity_result = adb.shell("dumpsys", "connectivity", timeout=30, check=False)
    vpn_result = adb.shell("dumpsys", "vpn", timeout=30, check=False)
    agents = parse_vpn_agents(connectivity_result.stdout)
    request_count = count_vpn_requests(connectivity_result.stdout)

    report.section("sanitized-vpn-state")
    report.kv("dumpsys_connectivity_exit", connectivity_result.returncode)
    report.kv("dumpsys_vpn_exit", vpn_result.returncode)
    report.kv("active_vpn_agent_count", len(agents))
    for index, agent in enumerate(agents):
        for key, value in agent.items():
            report.kv(f"active_agent.{index}.{key}", value)
    report.kv("registered_vpn_request_count", request_count)
    if connectivity_result.returncode != 0:
        report.kv("active_vpn_state", "inconclusive")
    else:
        report.kv("active_vpn_state", "yes" if agents else "no")
    report.kv("raw_dumps_persisted", "false")
    report.kv("device_mutation", "none")
    report.assert_redacted(
        [
            r"LinkAddresses",
            r"DnsAddresses",
            r"Routes:",
            r"InterfaceName:",
            r"\bSSID[:=]",
            r"\bBSSID[:=]",
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        ]
    )


def topology_check(report: Report, _args: argparse.Namespace) -> None:
    report.section("supported-component-roots")
    supported_roots = [
        Path("components/zygisk-host"),
        Path("components/location/controller"),
        Path("components/server-vpn/runtime"),
        Path("components/probe"),
    ]
    for relative in supported_roots:
        if not (ROOT / relative).is_dir():
            raise CheckError(f"supported component root is missing: {relative}")
        report.kv(str(relative), "present")

    report.section("retired-root-paths")
    retired_roots = [
        Path("app"),
        Path("policy"),
        Path("probe"),
        Path("location-controller"),
        Path("server-vpn"),
        Path("server-vpn-probe"),
        Path("zygisk-location"),
        Path("zygveil"),
    ]
    present = [str(relative) for relative in retired_roots if (ROOT / relative).exists()]
    if present:
        raise CheckError(f"retired root component paths are present: {present}")
    report.kv("present_count", 0)

    settings = (ROOT / "settings.gradle.kts").read_text(encoding="utf-8")
    expected_project_dirs = {
        'project(":location-controller").projectDir = file("components/location/controller")',
        'project(":probe").projectDir = file("components/probe")',
    }
    if not expected_project_dirs.issubset(set(settings.splitlines())):
        raise CheckError("supported Gradle projectDir mapping is incomplete")
    for forbidden in ['include(":app"', 'include(":policy"', "deprecated/"]:
        if forbidden in settings:
            raise CheckError(f"deprecated Gradle graph reference is present: {forbidden}")

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    if "deprecated/" in makefile:
        raise CheckError("root Make graph references deprecated source")
    from container import repository_paths

    transported_paths = repository_paths()
    if any(path.startswith("deprecated/") for path in transported_paths):
        raise CheckError("deprecated source entered the supported source transport")
    probe_build = (ROOT / "components/probe/build.gradle.kts").read_text(encoding="utf-8")
    for required in [
        'create("primary")',
        'create("canary")',
        'applicationId = "dev.zygveil.probe"',
    ]:
        if required not in probe_build:
            raise CheckError(f"universal probe identity is incomplete: {required}")
    report.section("deprecated-boundary")
    report.kv("root_gradle_reference", "absent")
    report.kv("root_make_reference", "absent")
    report.kv("source_transport", "excluded")
    report.kv("transported_path_count", len(transported_paths))
    report.kv("probe_projects", 1)


def syntax(report: Report, _args: argparse.Namespace) -> None:
    report.section("python")
    python_files = sorted((ROOT / "tools/automation").glob("*.py"))
    for path in python_files:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        report.kv(f"parsed.{path.relative_to(ROOT)}", "pass")
    report.section("make")
    output = run_host(["make", "--no-print-directory", "--dry-run", "help"])
    report.kv("make_dry_run", "pass")
    report.kv("make_dry_run_lines", len(output.splitlines()))
    post_fs_data = (ROOT / "components/zygisk-host/module/post-fs-data.sh").read_text(
        encoding="utf-8"
    )
    for marker in (
        "schema_version=4",
        "control_fd=0",
        "control_owner_pid=0",
        "control_owner_start_ticks=0",
        'rm -f "$MODDIR/server-vpn-runtime-status.properties"',
        '"$MODDIR/.server-vpn-runtime-status.tmp"',
    ):
        if marker not in post_fs_data:
            raise CheckError(f"guard-failure lifecycle omits required marker: {marker}")
    if "schema_version=3" in post_fs_data:
        raise CheckError("guard-failure runtime status retains obsolete schema 3")
    report.kv("guard_failure_runtime_status_schema", 4)
    report.kv("guard_failure_server_vpn_stale_status_cleanup", "pass")
    report.section("adb-shell-quoting-self-test")
    shell_argument_self_test()
    report.kv("posix_argument_round_trip", "pass")
    device_selection_self_test()
    report.kv("device_selection", "pass")
    device_ui_state_self_test()
    report.kv("device_ui_state_parser", "pass")
    report.section("vpn-parser-self-test")
    physical_with_vpn_request = "\n".join(
        [
            "NetworkAgentInfo{network{100} nc{[ Transports: WIFI "
            "Capabilities: INTERNET&NOT_VPN ]}}",
            "NetworkRequest [ LISTEN id=61, [ Transports: VPN "
            "RequestorPkg: com.android.systemui ] ]",
        ]
    )
    if parse_vpn_agents(physical_with_vpn_request):
        raise CheckError("VPN request was incorrectly parsed as an active VPN agent")
    if count_vpn_requests(physical_with_vpn_request) != 1:
        raise CheckError("VPN request self-test count mismatch")
    active_vpn = (
        "NetworkAgentInfo{network{101} nc{[ Transports: VPN "
        "Capabilities: INTERNET&TRUSTED OwnerUid: 10234 ]}}"
    )
    parsed = parse_vpn_agents(active_vpn)
    if len(parsed) != 1 or parsed[0]["network"] != "101":
        raise CheckError("active VPN agent self-test mismatch")
    report.kv("request_is_not_active_agent", "pass")
    report.kv("active_agent_detection", "pass")
    report.section("probe-jsonl-self-test")
    from probe import parser_self_test

    parser_self_test()
    report.kv("valid_schema", "pass")
    report.kv("cleanup_failure_rejected", "pass")
    from server_vpn_oracle import self_test as server_vpn_oracle_self_test

    server_vpn_oracle_self_test()
    report.kv("server_vpn_differential_oracle", "pass")
    from server_vpn_device import state_machine_self_test

    state_machine_self_test()
    report.kv("server_vpn_state_machine", "pass")
    from server_vpn_final import state_machine_self_test as server_vpn_final_self_test

    server_vpn_final_self_test()
    report.kv("server_vpn_final_state_machine", "pass")
    from final_preflight import state_machine_self_test as final_preflight_self_test

    final_preflight_self_test()
    report.kv("final_preflight_state_machine", "pass")
    from location_device import configuration_self_test

    configuration_self_test()
    report.kv("location_config_and_redaction", "pass")
    from location_acceptance import oracle_self_test

    oracle_self_test()
    report.kv("location_acceptance_oracle", "pass")
    from location_final_inputs import self_test as location_final_inputs_self_test

    location_final_inputs_self_test()
    report.kv("location_final_input_relationships", "pass")
    from reboot_intent import self_test as reboot_intent_self_test

    reboot_intent_self_test()
    report.kv("durable_reboot_intent", "pass")
    from reporting import deferred_private_text_self_test, local_path_redaction_self_test

    deferred_private_text_self_test()
    report.kv("deferred_private_phase_publication", "pass")
    local_path_redaction_self_test()
    report.kv("local_path_redaction", "pass")
    from location_live_control import privacy_self_test as live_control_privacy_self_test

    live_control_privacy_self_test()
    report.kv("location_live_control_privacy", "pass")
    from location_controller_device import parser_self_test as controller_status_self_test

    controller_status_self_test()
    report.kv("location_controller_status_protocol", "pass")
    report.section("supported-orchestration-self-tests")
    report.kv("location", "pass")
    report.kv("universal_probe", "pass")
    report.kv("server_vpn_recon", "pass")


def attestation_keys(report: Report, _args: argparse.Namespace) -> None:
    from container import DEPENDENCY_FILES, IMAGE_FILES, content_key

    image_key = content_key(IMAGE_FILES)
    dependency_key = content_key(DEPENDENCY_FILES)
    if (
        re.fullmatch(r"[0-9a-f]{20}", image_key) is None
        or re.fullmatch(r"[0-9a-f]{20}", dependency_key) is None
    ):
        raise CheckError("current builder or dependency content key is invalid")
    builder_tag = f"localhost/zygveil-builder:{image_key}"
    run_host(["podman", "image", "exists", builder_tag])
    run_host(
        [
            sys.executable,
            "tools/automation/container.py",
            "dependency-status",
            "--directory",
            f".artifacts/dependencies/{dependency_key}",
            "--dependency-key",
            dependency_key,
        ]
    )
    keystore = ROOT / ".state/debug.keystore"
    if not keystore.is_file() or stat.S_IMODE(keystore.stat().st_mode) != 0o600:
        raise CheckError("stable signing input is missing or not mode 0600; run make bootstrap")
    report.section("content-keys")
    report.kv("image", image_key)
    report.kv("dependencies", dependency_key)
    report.kv("builder_tag", builder_tag)
    report.kv("dependency_cache", "verified")
    report.kv("signing_input_mode", "0600")


COMMANDS: dict[str, Callable[[Report, argparse.Namespace], None]] = {
    "attestation-keys": attestation_keys,
    "doctor": doctor,
    "docs-check": docs_check,
    "privacy-check": privacy_check,
    "vpn-status": vpn_status,
    "syntax": syntax,
    "topology-check": topology_check,
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
