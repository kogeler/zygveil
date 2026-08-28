# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Documentation-independent host preflight for the formal ZygVeil final flow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
import traceback
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import cast

from container import DEPENDENCY_FILES, IMAGE_FILES, content_key, repository_paths
from reporting import CheckError, DeferredPrivateText, Report

ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT_RECEIPT = ROOT / ".artifacts/state/final-preflight.json"
PREFLIGHT_SESSION = ROOT / ".artifacts/state/final-preflight-session.json"
PREFLIGHT_WRITE = DeferredPrivateText()
SIGNING_REPORT = ROOT / ".artifacts/reports/container/signing-info.txt"
SIGNING_KEYSTORE = ROOT / ".state/debug.keystore"
EXPECTED_CERTIFICATE_SHA256 = "2a2098191bdf2fdf1c4d3e4a2d2686c8b3f59f8225470331a44482ed073e0c0d"
DOCUMENTATION_PATHS = {"LICENSE", "REUSE.toml"}
DOCUMENTATION_PREFIXES = ("components/zygisk-host/licenses/",)
REQUIRED_GATE_REPORTS: tuple[tuple[str, Path], ...] = (
    ("privacy-check", ROOT / ".artifacts/reports/baseline/privacy-check.txt"),
    ("topology-check", ROOT / ".artifacts/reports/baseline/topology-check.txt"),
    ("attestation-keys", ROOT / ".artifacts/reports/baseline/attestation-keys.txt"),
    (
        "attestation-format-check",
        ROOT / ".artifacts/reports/quality/attestation-format-check.txt",
    ),
    ("lint", ROOT / ".artifacts/reports/quality/lint.txt"),
    ("static-analysis", ROOT / ".artifacts/reports/quality/static-analysis.txt"),
    ("syntax", ROOT / ".artifacts/reports/baseline/syntax.txt"),
    ("test-location-unit", ROOT / ".artifacts/reports/location/test-location-unit.txt"),
    (
        "test-location-controller-unit",
        ROOT / ".artifacts/reports/location/test-location-controller-unit.txt",
    ),
    ("test-server-vpn-model", ROOT / ".artifacts/reports/server-vpn/test-server-vpn-model.txt"),
    ("test-server-vpn-config", ROOT / ".artifacts/reports/server-vpn/test-server-vpn-config.txt"),
    ("signing-info", SIGNING_REPORT),
    ("test-network-block", ROOT / ".artifacts/reports/container/network-block.txt"),
    ("confinement-test", ROOT / ".artifacts/reports/container/confinement.txt"),
)
PREFLIGHT_INPUT_KEYS = {
    "builder_tag",
    "builder_key",
    "builder_image_id",
    "builder_image_digest",
    "dependency_key",
    "dependency_manifest_sha256",
    "dependency_archive_sha256",
    "dependency_archive_bytes",
    "certificate_sha256",
    "keystore_sha256",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def is_documentation_path(relative: str) -> bool:
    return (
        relative.lower().endswith(".md")
        or relative in DOCUMENTATION_PATHS
        or relative.startswith(DOCUMENTATION_PREFIXES)
        or relative.startswith("docs/")
    )


def supported_source_paths() -> tuple[str, ...]:
    return tuple(
        relative
        for relative in repository_paths()
        if not is_documentation_path(relative) and not relative.startswith(("dist/", "tmp/"))
    )


def supported_source_digest() -> str:
    digest = hashlib.sha256()
    for relative in supported_source_paths():
        path = ROOT / relative
        if not path.is_file() and not path.is_symlink():
            continue
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(f"{stat.S_IMODE(path.lstat().st_mode):04o}".encode("ascii") + b"\0")
        if path.is_symlink():
            digest.update(os.readlink(path).encode("utf-8"))
        else:
            digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def write_private_object(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def load_private_object(path: Path, label: str) -> dict[str, object]:
    if not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise CheckError(f"{label} is missing or not mode 0600")
    try:
        decoded: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CheckError(f"{label} is unreadable") from error
    if not isinstance(decoded, dict):
        raise CheckError(f"{label} is not an object")
    return cast(dict[str, object], decoded)


def parse_report(path: Path, name: str) -> dict[str, str]:
    if not path.is_file() or path.stat().st_size == 0:
        raise CheckError(f"required preflight report is missing: {name}")
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise CheckError(f"required preflight report is unreadable: {name}") from error
    for line in lines:
        if not line or line.startswith("[") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    if values.get("exit_status") != "0":
        raise CheckError(f"required preflight report did not pass: {name}")
    declared_name = values.get("report")
    if declared_name is not None and declared_name != name:
        raise CheckError(f"required preflight report identity mismatch: {name}")
    return values


def gate_records(*, fresh_after_ns: int | None) -> dict[str, object]:
    records: dict[str, object] = {}
    for name, path in REQUIRED_GATE_REPORTS:
        if fresh_after_ns is not None and (
            not path.is_file() or path.stat().st_mtime_ns < fresh_after_ns
        ):
            raise CheckError(f"preflight gate report is stale for this run: {name}")
        parse_report(path, name)
        records[name] = {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": sha256_file(path),
        }
    return records


def builder_image_identity(builder_tag: str) -> tuple[str, str]:
    try:
        completed = subprocess.run(
            [
                "podman",
                "image",
                "inspect",
                builder_tag,
                "--format",
                "{{.Id}} {{.Digest}}",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CheckError("preflight builder image identity is unavailable") from error
    fields = completed.stdout.strip().split()
    if completed.returncode != 0 or len(fields) != 2:
        raise CheckError("preflight builder image is missing or ambiguous")
    image_id = fields[0].removeprefix("sha256:")
    digest = fields[1]
    if (
        re.fullmatch(r"[0-9a-f]{64}", image_id) is None
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
    ):
        raise CheckError("preflight builder image identity is malformed")
    return image_id, digest


def materialized_dependency_identity(dependency_key: str) -> dict[str, object]:
    directory = ROOT / ".artifacts/dependencies" / dependency_key
    manifest = directory / "manifest.json"
    archive = directory / "gradle-home.tar"
    try:
        manifest_identity = manifest.lstat()
        archive_identity = archive.lstat()
        decoded: object = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CheckError("preflight dependency cache identity is unavailable") from error
    if (
        not stat.S_ISREG(manifest_identity.st_mode)
        or not stat.S_ISREG(archive_identity.st_mode)
        or manifest_identity.st_uid != os.getuid()
        or archive_identity.st_uid != os.getuid()
        or manifest_identity.st_nlink != 1
        or archive_identity.st_nlink != 1
        or not isinstance(decoded, dict)
        or decoded.get("schema_version") != 1
        or decoded.get("dependency_key") != dependency_key
        or decoded.get("archive_bytes") != archive_identity.st_size
        or re.fullmatch(r"[0-9a-f]{64}", str(decoded.get("archive_sha256"))) is None
    ):
        raise CheckError("preflight dependency cache identity is invalid")
    return {
        "dependency_manifest_sha256": sha256_file(manifest),
        "dependency_archive_sha256": decoded["archive_sha256"],
        "dependency_archive_bytes": archive_identity.st_size,
    }


def materialized_keystore_sha256() -> str:
    try:
        identity = SIGNING_KEYSTORE.lstat()
    except OSError as error:
        raise CheckError("preflight signing keystore is unavailable") from error
    if (
        not stat.S_ISREG(identity.st_mode)
        or stat.S_IMODE(identity.st_mode) != 0o600
        or identity.st_uid != os.getuid()
        or identity.st_nlink != 1
        or identity.st_size <= 0
    ):
        raise CheckError("preflight signing keystore identity is invalid")
    return sha256_file(SIGNING_KEYSTORE)


def materialized_inputs(*, builder_tag: str, dependency_key: str) -> dict[str, object]:
    builder_key = content_key(IMAGE_FILES)
    expected_dependency_key = content_key(DEPENDENCY_FILES)
    expected_builder_tag = f"localhost/zygveil-builder:{builder_key}"
    if builder_tag != expected_builder_tag or dependency_key != expected_dependency_key:
        raise CheckError("preflight builder or dependency content key changed")
    current_keystore = materialized_keystore_sha256()
    image_id, image_digest = builder_image_identity(builder_tag)
    dependency = materialized_dependency_identity(dependency_key)
    return {
        "builder_tag": builder_tag,
        "builder_key": builder_key,
        "builder_image_id": image_id,
        "builder_image_digest": image_digest,
        "dependency_key": dependency_key,
        **dependency,
        "keystore_sha256": current_keystore,
    }


def current_inputs(*, builder_tag: str, dependency_key: str) -> dict[str, object]:
    inputs = materialized_inputs(builder_tag=builder_tag, dependency_key=dependency_key)
    signing = parse_report(SIGNING_REPORT, "signing-info")
    certificate = signing.get("certificate_sha256", "").replace(":", "").lower()
    keystore = signing.get("keystore_sha256", "").lower()
    if (
        certificate != EXPECTED_CERTIFICATE_SHA256
        or re.fullmatch(r"[0-9a-f]{64}", keystore) is None
        or keystore != inputs["keystore_sha256"]
    ):
        raise CheckError("preflight signing identity mismatch")
    return {
        **inputs,
        "certificate_sha256": certificate,
    }


def verification_inputs(*, builder_tag: str, dependency_key: str) -> dict[str, object]:
    return {
        **materialized_inputs(builder_tag=builder_tag, dependency_key=dependency_key),
        "certificate_sha256": EXPECTED_CERTIFICATE_SHA256,
    }


def frozen_receipt_inputs(
    receipt: dict[str, object], *, builder_tag: str, dependency_key: str
) -> dict[str, object]:
    builder_key = content_key(IMAGE_FILES)
    expected_dependency_key = content_key(DEPENDENCY_FILES)
    expected_builder_tag = f"localhost/zygveil-builder:{builder_key}"
    inputs = {key: receipt.get(key) for key in PREFLIGHT_INPUT_KEYS}
    if (
        builder_tag != expected_builder_tag
        or dependency_key != expected_dependency_key
        or inputs["builder_tag"] != builder_tag
        or inputs["builder_key"] != builder_key
        or inputs["dependency_key"] != dependency_key
        or inputs["certificate_sha256"] != EXPECTED_CERTIFICATE_SHA256
        or re.fullmatch(r"[0-9a-f]{64}", str(inputs["builder_image_id"])) is None
        or re.fullmatch(r"sha256:[0-9a-f]{64}", str(inputs["builder_image_digest"])) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(inputs["dependency_manifest_sha256"])) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(inputs["dependency_archive_sha256"])) is None
        or type(inputs["dependency_archive_bytes"]) is not int
        or inputs["dependency_archive_bytes"] <= 0
        or re.fullmatch(r"[0-9a-f]{64}", str(inputs["keystore_sha256"])) is None
    ):
        raise CheckError("frozen preflight build-input receipt is invalid")
    return inputs


def object_digest(value: dict[str, object]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def with_preflight_id(value: dict[str, object]) -> dict[str, object]:
    result = dict(value)
    result["preflight_id"] = object_digest(value)
    return result


def validate_preflight_id(value: dict[str, object]) -> None:
    preflight_id = value.get("preflight_id")
    body = {key: item for key, item in value.items() if key != "preflight_id"}
    if not isinstance(preflight_id, str) or preflight_id != object_digest(body):
        raise CheckError("final preflight receipt identity mismatch")


def validate_receipt_binding(
    receipt: dict[str, object],
    *,
    source_sha256: str,
    inputs: dict[str, object],
    gate_set: list[str],
) -> None:
    validate_preflight_id(receipt)
    if set(inputs) != PREFLIGHT_INPUT_KEYS:
        raise CheckError("final preflight input inventory mismatch")
    expected_keys = {
        "schema_version",
        "artifact_class",
        "session_id",
        "source_sha256",
        "gate_set",
        "gate_reports",
        "preflight_id",
        *inputs,
    }
    session_id = receipt.get("session_id")
    gate_reports = receipt.get("gate_reports")
    if (
        set(receipt) != expected_keys
        or receipt.get("schema_version") != 2
        or receipt.get("artifact_class") != "final_preflight"
        or not isinstance(session_id, str)
        or re.fullmatch(r"[0-9a-f]{32}", session_id) is None
        or receipt.get("source_sha256") != source_sha256
        or receipt.get("gate_set") != gate_set
        or not isinstance(gate_reports, dict)
        or set(gate_reports) != set(gate_set)
        or any(receipt.get(key) != value for key, value in inputs.items())
    ):
        raise CheckError("final preflight receipt no longer matches its required binding")
    expected_paths = {
        name: path.relative_to(ROOT).as_posix() for name, path in REQUIRED_GATE_REPORTS
    }
    for name in gate_set:
        record = gate_reports.get(name)
        if (
            name not in expected_paths
            or not isinstance(record, dict)
            or set(record) != {"path", "sha256"}
            or record.get("path") != expected_paths[name]
            or re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256"))) is None
        ):
            raise CheckError("final preflight recorded gate evidence is invalid")


def prepare(report: Report, args: argparse.Namespace) -> None:
    PREFLIGHT_RECEIPT.unlink(missing_ok=True)
    inputs = materialized_inputs(
        builder_tag=args.builder_tag,
        dependency_key=args.dependency_key,
    )
    session: dict[str, object] = {
        "schema_version": 2,
        "session_id": uuid.uuid4().hex,
        "source_sha256": supported_source_digest(),
        "materialized_inputs_sha256": object_digest(inputs),
        "started_ns": time.time_ns(),
    }
    write_private_object(PREFLIGHT_SESSION, session)
    report.kv("session_id", session["session_id"])
    report.kv("source_sha256", session["source_sha256"])
    report.kv("materialized_inputs_sha256", session["materialized_inputs_sha256"])
    report.kv("materialized_input_precheck", "PASS")
    report.kv("receipt_invalidated", "true")
    report.kv("device_mutation", "none")


def load_session() -> dict[str, object]:
    session = load_private_object(PREFLIGHT_SESSION, "final preflight session")
    if (
        set(session)
        != {
            "schema_version",
            "session_id",
            "source_sha256",
            "materialized_inputs_sha256",
            "started_ns",
        }
        or session.get("schema_version") != 2
        or not isinstance(session.get("session_id"), str)
        or re.fullmatch(r"[0-9a-f]{32}", cast(str, session["session_id"])) is None
        or not isinstance(session.get("source_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", cast(str, session["source_sha256"])) is None
        or not isinstance(session.get("materialized_inputs_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", cast(str, session["materialized_inputs_sha256"])) is None
        or not isinstance(session.get("started_ns"), int)
        or isinstance(session.get("started_ns"), bool)
        or cast(int, session["started_ns"]) <= 0
    ):
        raise CheckError("final preflight session schema mismatch")
    return session


def attestation_check_summary(report: Report, _args: argparse.Namespace) -> None:
    records = gate_records(fresh_after_ns=None)
    report.kv("documentation_gate", "excluded")
    report.kv("required_gate_count", len(REQUIRED_GATE_REPORTS))
    report.kv("required_gate_set", ",".join(name for name, _path in REQUIRED_GATE_REPORTS))
    report.kv("gate_report_set_sha256", object_digest(records))
    report.kv("repository_check", "PASS")
    report.kv("device_mutation", "none")


def record(report: Report, args: argparse.Namespace) -> None:
    PREFLIGHT_RECEIPT.unlink(missing_ok=True)
    session = load_session()
    source_sha256 = supported_source_digest()
    if source_sha256 != session["source_sha256"]:
        raise CheckError("attestable input changed while final preflight was running")
    inputs = current_inputs(builder_tag=args.builder_tag, dependency_key=args.dependency_key)
    materialized = {key: value for key, value in inputs.items() if key != "certificate_sha256"}
    if object_digest(materialized) != session["materialized_inputs_sha256"]:
        raise CheckError("materialized build inputs changed while final preflight was running")
    started_ns = cast(int, session["started_ns"])
    gates = gate_records(fresh_after_ns=started_ns)
    values: dict[str, object] = {
        "schema_version": 2,
        "artifact_class": "final_preflight",
        "session_id": session["session_id"],
        "source_sha256": source_sha256,
        **inputs,
        "gate_set": [name for name, _path in REQUIRED_GATE_REPORTS],
        "gate_reports": gates,
    }
    receipt = with_preflight_id(values)
    PREFLIGHT_WRITE.stage(
        PREFLIGHT_RECEIPT,
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
    )
    report.kv("preflight_id", receipt["preflight_id"])
    report.kv("source_sha256", source_sha256)
    report.kv("required_gate_count", len(REQUIRED_GATE_REPORTS))
    report.kv("receipt", PREFLIGHT_RECEIPT.relative_to(ROOT))
    report.kv("receipt_mode", "0600")
    report.kv("device_mutation", "none")


def load_preflight_receipt(
    *,
    builder_tag: str,
    dependency_key: str,
    report: Report | None,
    require_materialized_inputs: bool = True,
) -> dict[str, object]:
    receipt = load_private_object(PREFLIGHT_RECEIPT, "final preflight receipt")
    expected_gate_set = [name for name, _path in REQUIRED_GATE_REPORTS]
    inputs = (
        verification_inputs(builder_tag=builder_tag, dependency_key=dependency_key)
        if require_materialized_inputs
        else frozen_receipt_inputs(
            receipt,
            builder_tag=builder_tag,
            dependency_key=dependency_key,
        )
    )
    validate_receipt_binding(
        receipt,
        source_sha256=supported_source_digest(),
        inputs=inputs,
        gate_set=expected_gate_set,
    )
    if report is not None:
        report.kv("preflight_id", receipt["preflight_id"])
        report.kv("preflight_source_sha256", receipt["source_sha256"])
        report.kv("preflight_gate_count", len(expected_gate_set))
    return receipt


def verify(report: Report, args: argparse.Namespace) -> None:
    load_preflight_receipt(
        builder_tag=args.builder_tag,
        dependency_key=args.dependency_key,
        report=report,
    )
    report.kv("preflight_verification", "PASS")
    report.kv("device_mutation", "none")


def state_machine_self_test() -> None:
    gate_names = [name for name, _path in REQUIRED_GATE_REPORTS]
    if not gate_names or len(gate_names) != len(set(gate_names)):
        raise CheckError("final preflight gate inventory is empty or duplicated")
    if (
        "current_inputs" in load_preflight_receipt.__code__.co_names
        or "parse_report" in verification_inputs.__code__.co_names
    ):
        raise CheckError("final preflight verifier can re-read mutable gate reports")
    paths = supported_source_paths()
    if (
        any(is_documentation_path(path) for path in paths)
        or any(path.startswith(("dist/", "tmp/", "deprecated/")) for path in paths)
        or "tools/automation/final_preflight.py" not in paths
        or not all(
            is_documentation_path(path)
            for path in (
                "README.MD",
                "docs/new-runbook.txt",
                "components/zygisk-host/licenses/new-notice.txt",
                "LICENSE",
                "REUSE.toml",
            )
        )
    ):
        raise CheckError("final preflight source selector self-test failed")
    from container_job import (
        ATTESTATION_SPOTLESS_TASKS,
        attestation_format_check,
        build_controller,
        build_location,
        build_probe,
    )

    if (
        ATTESTATION_SPOTLESS_TASKS
        != (
            "spotlessJavaCheck",
            "spotlessKotlinGradleCheck",
            "spotlessTechnicalTextCheck",
        )
        or "ATTESTATION_SPOTLESS_TASKS" not in attestation_format_check.__code__.co_names
    ):
        raise CheckError("attestation formatter can consume textual documentation")

    if "test_location_unit" in build_location.__code__.co_names or "test_controller_unit" in (
        build_controller.__code__.co_names
    ):
        raise CheckError("final artifact build invokes a preflight unit gate")
    artifact_build_constants = {
        value
        for function in (build_controller, build_probe)
        for value in function.__code__.co_consts
        if isinstance(value, str)
    }
    if artifact_build_constants.intersection(
        {
            ":location-controller:lintDebug",
            ":probe:lintPrimaryDebug",
            ":probe:lintCanaryDebug",
        }
    ):
        raise CheckError("final artifact build invokes a preflight lint gate")
    location_make = (ROOT / "mk/location.mk").read_text(encoding="utf-8")
    for target in ("location-build", "location-controller-build"):
        recipe = location_make.split(f"\n{target}:", 1)[1].split("\n\n", 1)[0]
        if "test-location-unit.txt" in recipe or "test-location-controller-unit.txt" in recipe:
            raise CheckError("final artifact build overwrites a preflight unit report")
    server_make = (ROOT / "mk/server-vpn.mk").read_text(encoding="utf-8")
    acceptance_make = (ROOT / "mk/acceptance.mk").read_text(encoding="utf-8")
    quality_make = (ROOT / "mk/quality.mk").read_text(encoding="utf-8")
    root_make = (ROOT / "Makefile").read_text(encoding="utf-8")

    def target_block(source: str, target: str) -> str:
        match = re.search(
            rf"(?m)^{re.escape(target)}:(?P<header>[^\n]*)\n(?P<recipe>(?:\t[^\n]*(?:\n|$))+)",
            source,
        )
        if match is None or match.group("header").strip():
            raise CheckError(f"final Make target has prerequisites or no recipe: {target}")
        return match.group("recipe")

    def require_order(recipe: str, target: str, markers: tuple[str, ...]) -> None:
        positions = [recipe.find(marker) for marker in markers]
        if any(position < 0 for position in positions) or positions != sorted(positions):
            raise CheckError(f"final Make target order is invalid: {target}")

    require_order(
        target_block(acceptance_make, "final-preflight"),
        "final-preflight",
        ("location-input-check", " prepare", " attestation-check", " record"),
    )
    attestation_block = acceptance_make.split("\nattestation-check:", 1)[1].split("\n\n", 1)[0]
    if (
        "docs-check" in attestation_block
        or " quality" in attestation_block
        or re.search(r"(?<!attestation-)format-check", attestation_block) is not None
        or "attestation-check" not in attestation_block.splitlines()[-1]
    ):
        raise CheckError("attestation check depends on repository documentation quality")
    attestation_recipe = target_block(quality_make, "attestation-format-check")
    if "attestation-format-check" not in attestation_recipe or "format-check" in (
        attestation_recipe.replace("attestation-format-check", "")
    ):
        raise CheckError("attestation formatting target is not documentation-independent")
    require_order(
        target_block(location_make, "location-final-build"),
        "location-final-build",
        (
            "final-preflight-verify",
            "FINAL_ARTIFACT_BUILD=1",
            "location-controller-build build-probe location-build",
        ),
    )
    require_order(
        target_block(server_make, "server-vpn-final-build"),
        "server-vpn-final-build",
        ("location-final-build", "final-freeze"),
    )
    require_order(
        target_block(location_make, "location-final-attest"),
        "location-final-attest",
        ("server-vpn-final-verify", "test-location-acceptance"),
    )
    require_order(
        target_block(server_make, "server-vpn-final-attest"),
        "server-vpn-final-attest",
        ("server-vpn-final-verify", "server-vpn-final-acceptance", "location-final-attest"),
    )
    if ".NOTPARALLEL:" not in root_make:
        raise CheckError("root Make graph does not serialize stateful final recipes")
    probe_make = (ROOT / "mk/probe.mk").read_text(encoding="utf-8")
    for source, declaration in (
        (
            location_make,
            "location-build: $(if $(filter 1,$(FINAL_ARTIFACT_BUILD)),,image)",
        ),
        (
            location_make,
            "location-controller-build: "
            "$(if $(filter 1,$(FINAL_ARTIFACT_BUILD)),,image deps signing-init)",
        ),
        (
            probe_make,
            "build-probe: $(if $(filter 1,$(FINAL_ARTIFACT_BUILD)),,image deps signing-init)",
        ),
    ):
        if declaration not in source:
            raise CheckError("formal artifact recipe can enter bootstrap prerequisites")
    for target in (
        "test-location-final-baseline",
        "test-location-final-disabled",
        "test-location-final-passthrough",
        "test-location-final-blocked",
        "test-location-final-live",
        "test-location-final-live-edge",
        "test-location-final-isolation",
        "test-location-final-stability",
        "test-location-final-failures",
        "test-location-final-stress",
        "test-location-final-persistence",
        "test-location-final-restored",
    ):
        if "LOCATION_FINAL_ACCEPTANCE_RUN" not in target_block(location_make, target):
            raise CheckError(f"formal location phase is not freeze-bound: {target}")
    sample: dict[str, object] = {"schema_version": 1, "value": "safe"}
    identified = with_preflight_id(sample)
    validate_preflight_id(identified)
    identified["value"] = "changed"
    try:
        validate_preflight_id(identified)
    except CheckError:
        pass
    else:
        raise CheckError("final preflight identity self-test accepted a mutation")
    binding_inputs: dict[str, object] = {
        "builder_tag": f"localhost/zygveil-builder:{'a' * 20}",
        "builder_key": "a" * 20,
        "builder_image_id": "b" * 64,
        "builder_image_digest": f"sha256:{'c' * 64}",
        "dependency_key": "d" * 20,
        "dependency_manifest_sha256": "e" * 64,
        "dependency_archive_sha256": "f" * 64,
        "dependency_archive_bytes": 1,
        "certificate_sha256": EXPECTED_CERTIFICATE_SHA256,
        "keystore_sha256": "3" * 64,
    }
    lint_report = dict(REQUIRED_GATE_REPORTS)["lint"].relative_to(ROOT).as_posix()
    binding_gates: dict[str, object] = {"lint": {"path": lint_report, "sha256": "b" * 64}}
    binding_body: dict[str, object] = {
        "schema_version": 2,
        "artifact_class": "final_preflight",
        "session_id": "d" * 32,
        "source_sha256": "e" * 64,
        **binding_inputs,
        "gate_set": ["lint"],
        "gate_reports": binding_gates,
    }
    binding_receipt = with_preflight_id(binding_body)
    validate_receipt_binding(
        binding_receipt,
        source_sha256="e" * 64,
        inputs=binding_inputs,
        gate_set=["lint"],
    )
    mismatch_cases = (
        {"source_sha256": "f" * 64},
        {"inputs": {"builder_key": "f" * 20}},
        {"gate_set": ["topology-check"]},
    )
    for mismatch in mismatch_cases:
        try:
            validate_receipt_binding(
                binding_receipt,
                source_sha256=cast(str, mismatch.get("source_sha256", "e" * 64)),
                inputs=cast(dict[str, object], mismatch.get("inputs", binding_inputs)),
                gate_set=cast(list[str], mismatch.get("gate_set", ["lint"])),
            )
        except CheckError:
            pass
        else:
            raise CheckError("final preflight binding self-test accepted a mismatch")
    malformed_body = dict(binding_body)
    malformed_body["gate_reports"] = {"lint": {"path": "wrong-report.txt", "sha256": "b" * 64}}
    try:
        validate_receipt_binding(
            with_preflight_id(malformed_body),
            source_sha256="e" * 64,
            inputs=binding_inputs,
            gate_set=["lint"],
        )
    except CheckError:
        pass
    else:
        raise CheckError("final preflight binding self-test accepted malformed gate evidence")
    with tempfile.TemporaryDirectory(prefix="zygveil-preflight-self-test-") as temporary:
        private_path = Path(temporary) / "receipt.json"
        write_private_object(private_path, sample)
        if stat.S_IMODE(private_path.stat().st_mode) != 0o600:
            raise CheckError("final preflight private-write self-test failed")
        load_private_object(private_path, "self-test receipt")
        private_path.chmod(0o644)
        try:
            load_private_object(private_path, "self-test receipt")
        except CheckError:
            pass
        else:
            raise CheckError("final preflight mode self-test accepted a public receipt")


COMMANDS: dict[str, Callable[[Report, argparse.Namespace], None]] = {
    "attestation-check": attestation_check_summary,
    "prepare": prepare,
    "record": record,
    "verify": verify,
}
REPORT_NAMES = {
    "attestation-check": "attestation-check",
    "prepare": "final-preflight-prepare",
    "record": "final-preflight",
    "verify": "final-preflight-verify",
}


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--builder-tag", required=True)
    parser.add_argument("--dependency-key", required=True)
    parser.add_argument("command", choices=sorted(COMMANDS))
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    try:
        with Report(ROOT / args.report_dir, REPORT_NAMES[args.command]) as report:
            COMMANDS[args.command](report, args)
        PREFLIGHT_WRITE.commit()
    except CheckError:
        PREFLIGHT_WRITE.discard()
        if args.command == "record":
            PREFLIGHT_RECEIPT.unlink(missing_ok=True)
        return 1
    except Exception:
        PREFLIGHT_WRITE.discard()
        if args.command == "record":
            PREFLIGHT_RECEIPT.unlink(missing_ok=True)
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
