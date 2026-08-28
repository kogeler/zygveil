# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Freeze-bound, privacy-safe validation of formal location input fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
import traceback
from decimal import Decimal
from pathlib import Path

from location_device import BOOT_INPUT_KEYS, read_private_config
from probe import (
    LOCATION_ORACLE_INPUT_KEYS,
    read_private_oracle_input,
    same_binary64_decimal,
)
from reporting import CheckError, DeferredPrivateText, Report, contains_private_decimal_values
from server_vpn_final import load_generation

ROOT = Path(__file__).resolve().parents[2]
FINAL_INPUT_RECEIPT = ROOT / ".artifacts/state/location-final-inputs.json"
LOCATION_FIELDS = LOCATION_ORACLE_INPUT_KEYS[1:]
HORIZONTAL_FIELDS = ("center_latitude_deg", "center_longitude_deg")
FIXTURE_ROLES = (
    "boot_blocked",
    "boot_passthrough",
    "oracle_blocked",
    "oracle_passthrough",
    "live",
    "edge",
)
INPUT_RECEIPT_WRITE = DeferredPrivateText()


def same_location(left: dict[str, str], right: dict[str, str]) -> bool:
    return all(same_binary64_decimal(left[key], right[key]) for key in LOCATION_FIELDS)


def horizontally_distinct(left: dict[str, str], right: dict[str, str]) -> bool:
    return any(not same_binary64_decimal(left[key], right[key]) for key in HORIZONTAL_FIELDS)


def edge_relation(reference: dict[str, str], edge: dict[str, str]) -> tuple[bool, bool]:
    reference_latitude = Decimal(reference["center_latitude_deg"])
    reference_longitude = Decimal(reference["center_longitude_deg"])
    edge_latitude = Decimal(edge["center_latitude_deg"])
    edge_longitude = Decimal(edge["center_longitude_deg"])
    opposite_hemisphere = (
        reference_latitude * edge_latitude < 0 or reference_longitude * edge_longitude < 0
    )
    bounded_geographic_edge = abs(edge_latitude) >= 80 or abs(edge_longitude) >= 170
    return opposite_hemisphere, bounded_geographic_edge


def validate_fixture_relationships(
    blocked_boot: dict[str, str],
    passthrough_boot: dict[str, str],
    blocked_oracle: dict[str, str],
    passthrough_oracle: dict[str, str],
    live: dict[str, str],
    edge: dict[str, str],
) -> tuple[bool, bool]:
    if blocked_boot["raw_gnss_mode"] != "blocked":
        raise CheckError("blocked boot fixture has the wrong Raw GNSS mode")
    if passthrough_boot["raw_gnss_mode"] != "passthrough":
        raise CheckError("passthrough boot fixture has the wrong Raw GNSS mode")
    if any(
        blocked_boot[key] != passthrough_boot[key]
        for key in BOOT_INPUT_KEYS
        if key != "raw_gnss_mode"
    ):
        raise CheckError("boot fixtures drift beyond their Raw GNSS mode")
    if not same_location(blocked_oracle, passthrough_oracle):
        raise CheckError("blocked and passthrough boot oracles disagree")
    if not same_location(blocked_boot, blocked_oracle):
        raise CheckError("blocked boot fixture and oracle disagree")
    if not same_location(passthrough_boot, passthrough_oracle):
        raise CheckError("passthrough boot fixture and oracle disagree")
    if not horizontally_distinct(blocked_oracle, live):
        raise CheckError("first live fixture is not horizontally distinct from boot")
    if not horizontally_distinct(live, edge):
        raise CheckError("edge fixture is not horizontally distinct from the first live fixture")
    opposite_hemisphere, bounded_geographic_edge = edge_relation(live, edge)
    if not (opposite_hemisphere or bounded_geographic_edge):
        raise CheckError("edge fixture exercises neither a hemisphere nor dateline/pole boundary")
    return opposite_hemisphere, bounded_geographic_edge


def semantic_digest(values: dict[str, str]) -> str:
    body = json.dumps(values, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(body).hexdigest()


def read_fixtures(args: argparse.Namespace) -> dict[str, dict[str, str]]:
    return {
        "boot_blocked": read_private_config(args.boot_blocked),
        "boot_passthrough": read_private_config(args.boot_passthrough),
        "oracle_blocked": read_private_oracle_input(args.oracle_blocked),
        "oracle_passthrough": read_private_oracle_input(args.oracle_passthrough),
        "live": read_private_oracle_input(args.live),
        "edge": read_private_oracle_input(args.edge),
    }


def canonical_receipt(
    fixtures: dict[str, dict[str, str]],
    *,
    generation_id: str,
    opposite_hemisphere: bool,
    bounded_geographic_edge: bool,
) -> dict[str, object]:
    if re.fullmatch(r"[0-9a-f]{64}", generation_id) is None:
        raise CheckError("formal location input receipt has an invalid frozen generation")
    body: dict[str, object] = {
        "schema_version": 1,
        "artifact_class": "location_final_inputs",
        "generation_id": generation_id,
        "fixture_digests": {role: semantic_digest(fixtures[role]) for role in FIXTURE_ROLES},
        "relations": {
            "boot_mode_only_difference": True,
            "boot_oracle_match": True,
            "live_points_horizontally_distinct": True,
            "edge_opposite_hemisphere": opposite_hemisphere,
            "edge_bounded_dateline_or_pole": bounded_geographic_edge,
        },
    }
    identity_body = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
    body["receipt_id"] = hashlib.sha256(identity_body).hexdigest()
    return body


def validate_inputs(
    args: argparse.Namespace, *, generation_id: str | None
) -> tuple[dict[str, dict[str, str]], dict[str, object] | None, bool, bool]:
    fixtures = read_fixtures(args)
    opposite_hemisphere, bounded_geographic_edge = validate_fixture_relationships(
        fixtures["boot_blocked"],
        fixtures["boot_passthrough"],
        fixtures["oracle_blocked"],
        fixtures["oracle_passthrough"],
        fixtures["live"],
        fixtures["edge"],
    )
    receipt = (
        canonical_receipt(
            fixtures,
            generation_id=generation_id,
            opposite_hemisphere=opposite_hemisphere,
            bounded_geographic_edge=bounded_geographic_edge,
        )
        if generation_id is not None
        else None
    )
    return fixtures, receipt, opposite_hemisphere, bounded_geographic_edge


def report_inputs(
    report: Report,
    fixtures: dict[str, dict[str, str]],
    *,
    generation_id: str,
    opposite_hemisphere: bool,
    bounded_geographic_edge: bool,
) -> None:
    report.kv(
        "generation_id",
        generation_id,
    )
    report.kv("fixture_count", len(fixtures))
    for role, values in fixtures.items():
        report.kv(f"fixture.{role}.sha256", semantic_digest(values))
    report.kv("boot_mode_only_difference", "true")
    report.kv("boot_oracle_match", "true")
    report.kv("live_points_horizontally_distinct", "true")
    report.kv("edge_opposite_hemisphere", str(opposite_hemisphere).lower())
    report.kv("edge_bounded_dateline_or_pole", str(bounded_geographic_edge).lower())
    report.kv("input_precheck", "PASS")
    report.kv("device_mutation", "none")


def private_decimal_values(fixtures: dict[str, dict[str, str]]) -> tuple[str, ...]:
    return tuple(
        value
        for values in fixtures.values()
        for key, value in values.items()
        if key in LOCATION_FIELDS
    )


def check_inputs(report: Report, args: argparse.Namespace) -> tuple[str, ...]:
    generation = load_generation(report, args) if args.final_context else None
    generation_id = str(generation["generation_id"]) if generation is not None else None
    fixtures, receipt, opposite_hemisphere, bounded_geographic_edge = validate_inputs(
        args, generation_id=generation_id
    )
    report_inputs(
        report,
        fixtures,
        generation_id=generation_id or "preflight-unbound",
        opposite_hemisphere=opposite_hemisphere,
        bounded_geographic_edge=bounded_geographic_edge,
    )
    if receipt is not None:
        try:
            FINAL_INPUT_RECEIPT.lstat()
        except FileNotFoundError:
            existing = None
        except OSError as error:
            raise CheckError("formal location input receipt identity is unavailable") from error
        else:
            existing = load_private_receipt(FINAL_INPUT_RECEIPT)
        if existing == receipt:
            report.kv("input_receipt_write", "semantic_noop")
        else:
            if existing is not None and existing.get("generation_id") == generation_id:
                raise CheckError(
                    "formal location inputs cannot be rebound within one frozen generation"
                )
            INPUT_RECEIPT_WRITE.stage(
                FINAL_INPUT_RECEIPT,
                json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
            )
            report.kv("input_receipt_write", "new_generation")
        report.kv("input_receipt_id", receipt["receipt_id"])
        report.kv("input_receipt_mode", "0600")
    return private_decimal_values(fixtures)


def load_private_receipt(path: Path) -> dict[str, object]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        raise CheckError("formal location input receipt is missing") from None
    except OSError as error:
        raise CheckError("formal location input receipt could not be opened safely") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or not 0 < before.st_size <= 4096
        ):
            raise CheckError("formal location input receipt identity is invalid")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 1024))
            if not block:
                raise CheckError("formal location input receipt changed while being read")
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise CheckError("formal location input receipt changed while being read")
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
        )
        if tuple(getattr(before, field) for field in stable_fields) != tuple(
            getattr(after, field) for field in stable_fields
        ):
            raise CheckError("formal location input receipt changed while being read")
    finally:
        os.close(descriptor)
    try:
        raw = b"".join(chunks).decode("utf-8")
        decoded: object = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CheckError("formal location input receipt is unreadable") from error
    if not isinstance(decoded, dict):
        raise CheckError("formal location input receipt is not an object")
    values = dict(decoded)
    if raw != json.dumps(values, sort_keys=True, separators=(",", ":")) + "\n":
        raise CheckError("formal location input receipt is not canonical")
    return values


def verify_final_input_receipt(
    report: Report, args: argparse.Namespace, generation: dict[str, object]
) -> tuple[str, ...]:
    generation_id = str(generation["generation_id"])
    fixtures, expected, opposite_hemisphere, bounded_geographic_edge = validate_inputs(
        args, generation_id=generation_id
    )
    if expected is None or load_private_receipt(FINAL_INPUT_RECEIPT) != expected:
        raise CheckError("formal location inputs changed after their frozen receipt")
    report.kv("input_receipt_id", expected["receipt_id"])
    report.kv("input_receipt_generation_id", generation_id)
    report.kv("input_receipt_verification", "PASS")
    report_inputs(
        report,
        fixtures,
        generation_id=generation_id,
        opposite_hemisphere=opposite_hemisphere,
        bounded_geographic_edge=bounded_geographic_edge,
    )
    return private_decimal_values(fixtures)


def self_test() -> None:
    boot = {
        "schema_version": "1",
        "raw_gnss_mode": "blocked",
        "center_latitude_deg": "60.0",
        "center_longitude_deg": "24.0",
        "altitude_ellipsoid_m": "35.0",
        "altitude_msl_m": "5.0",
        "horizontal_jitter_sigma_m": "1.2",
        "horizontal_jitter_radius_m": "4.0",
        "horizontal_correlation_time_s": "40.0",
        "vertical_jitter_sigma_m": "1.5",
        "accuracy_correlation_time_s": "30.0",
        "speed_deadband_mps": "0.04",
        "speed_max_mps": "0.35",
        "bearing_min_speed_mps": "0.20",
        "random_seed": "1",
    }
    boot_oracle = {key: boot[key] for key in LOCATION_ORACLE_INPUT_KEYS}
    live = dict(
        boot_oracle,
        center_latitude_deg="61.0",
        center_longitude_deg="25.0",
    )
    edge = dict(
        boot_oracle,
        center_latitude_deg="-33.0",
        center_longitude_deg="151.0",
    )
    validate_fixture_relationships(
        boot,
        dict(boot, raw_gnss_mode="passthrough"),
        boot_oracle,
        boot_oracle,
        live,
        edge,
    )
    fixtures = {
        "boot_blocked": boot,
        "boot_passthrough": dict(boot, raw_gnss_mode="passthrough"),
        "oracle_blocked": boot_oracle,
        "oracle_passthrough": boot_oracle,
        "live": live,
        "edge": edge,
    }
    receipt = canonical_receipt(
        fixtures,
        generation_id="a" * 64,
        opposite_hemisphere=True,
        bounded_geographic_edge=False,
    )
    fixture_digests = receipt.get("fixture_digests")
    if (
        receipt.get("generation_id") != "a" * 64
        or not isinstance(fixture_digests, dict)
        or set(fixture_digests) != set(FIXTURE_ROLES)
        or re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("receipt_id"))) is None
    ):
        raise CheckError("formal location input receipt self-test failed")
    changed = dict(fixtures)
    changed["live"] = dict(live, center_latitude_deg="62.0")
    if (
        canonical_receipt(
            changed,
            generation_id="a" * 64,
            opposite_hemisphere=True,
            bounded_geographic_edge=False,
        )
        == receipt
    ):
        raise CheckError("formal location input receipt accepted changed fixture content")
    with tempfile.TemporaryDirectory(prefix="zygveil-input-receipt-self-test-") as directory:
        path = Path(directory) / "receipt.json"
        path.write_text(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)
        if load_private_receipt(path) != receipt:
            raise CheckError("formal location input receipt round-trip self-test failed")
        path.chmod(0o644)
        try:
            load_private_receipt(path)
        except CheckError:
            pass
        else:
            raise CheckError("formal location input receipt mode self-test failed")
    for invalid in (
        dict(boot, random_seed="2"),
        dict(boot, center_latitude_deg="61.0"),
    ):
        try:
            validate_fixture_relationships(
                boot,
                dict(invalid, raw_gnss_mode="passthrough"),
                boot_oracle,
                boot_oracle,
                live,
                edge,
            )
        except CheckError:
            pass
        else:
            raise CheckError("formal location fixture relationship self-test accepted drift")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--builder-tag", default="")
    parser.add_argument("--dependency-key", default="")
    parser.add_argument("--final-context", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--boot-blocked", required=True)
    parser.add_argument("--boot-passthrough", required=True)
    parser.add_argument("--oracle-blocked", required=True)
    parser.add_argument("--oracle-passthrough", required=True)
    parser.add_argument("--live", required=True)
    parser.add_argument("--edge", required=True)
    args = parser.parse_args()
    if args.verify and not args.final_context:
        parser.error("--verify requires --final-context")
    return args


def main() -> int:
    args = parse_arguments()
    try:
        report_name = (
            "location-final-input-verify"
            if args.verify
            else "location-final-input-check"
            if args.final_context
            else "location-input-check"
        )
        with Report(ROOT / args.report_dir, report_name) as report:
            private_decimals: tuple[str, ...] = ()
            try:
                if args.verify:
                    generation = load_generation(report, args)
                    private_decimals = verify_final_input_receipt(report, args, generation)
                else:
                    private_decimals = check_inputs(report, args)
            finally:
                report.assert_redacted(
                    [r"\.state/", r"(?i)(?:latitude|longitude|altitude)="],
                    [lambda content: contains_private_decimal_values(content, private_decimals)],
                )
        INPUT_RECEIPT_WRITE.commit()
    except CheckError:
        INPUT_RECEIPT_WRITE.discard()
        return 1
    except Exception:
        INPUT_RECEIPT_WRITE.discard()
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
