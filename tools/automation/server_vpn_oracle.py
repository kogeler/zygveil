# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Pure differential oracle for universal-probe server-VPN records."""

from __future__ import annotations

import json
from datetime import datetime
from typing import cast

from reporting import CheckError

CALLBACK_GROUPS = {
    "server-vpn-active",
    "server-vpn-async",
    "server-vpn-link",
}
VOLATILE_SCALAR_TEST_IDS = {
    "sync.active.getter.down_kbps",
    "sync.active.getter.up_kbps",
    "sync.active.getter.signal_strength",
}
VOLATILE_NETWORK_INVENTORY_TEST_IDS = {
    f"link.{source}.{field}"
    for source in ("active", "all", "callback.default", "callback.broad")
    for field in ("addresses", "routes", "dns", "proxy", "nat64", "dhcp")
}
PROJECTION_OUTCOMES = {
    "absent",
    "present_sanitized",
    "present_stock",
    "unavailable",
    "inconclusive",
    "error",
}
DIAGNOSTICS_GROUP = "server-vpn-diagnostics"
DIAGNOSTICS_MANDATORY = {
    "diagnostics.lifecycle": True,
    "diagnostics.connectivity_report": True,
    "diagnostics.data_stall_report": False,
    "diagnostics.connectivity_result": False,
}
DIAGNOSTICS_RESIDUAL_PROJECTION = {
    "diagnostics.lifecycle": {
        "status": "NEGATIVE",
        "observation": {"registered": True, "delivery_observed": False},
    },
    "diagnostics.connectivity_report": {
        "status": "INCONCLUSIVE",
        "observation": {
            "delivery_count": 0,
            "network_present_count": 0,
            "capabilities_present_count": 0,
            "link_properties_present_count": 0,
            "vpn_transport_count": 0,
            "not_vpn_capability_count": 0,
        },
    },
    "diagnostics.data_stall_report": {
        "status": "INCONCLUSIVE",
        "observation": {
            "delivery_count": 0,
            "network_present_count": 0,
            "capabilities_present_count": 0,
            "link_properties_present_count": 0,
            "vpn_transport_count": 0,
            "not_vpn_capability_count": 0,
        },
    },
    "diagnostics.connectivity_result": {
        "status": "INCONCLUSIVE",
        "observation": {"delivery_count": 0, "reported_connected_count": 0},
    },
}


def detector_records(records: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    detectors = {
        cast(str, record["test_id"]): record
        for record in records
        if record.get("record_type") == "detector"
    }
    if not detectors:
        raise CheckError("server-VPN run has no detector records")
    return detectors


def run_interval(records: list[dict[str, object]]) -> tuple[float, float]:
    summary = next(
        (record for record in records if record.get("record_type") == "summary"),
        None,
    )
    if summary is None:
        raise CheckError("server-VPN run has no summary")
    started_at = records[0].get("started_at")
    elapsed_ms = summary.get("elapsed_ms")
    if (
        not isinstance(started_at, str)
        or not isinstance(elapsed_ms, int)
        or isinstance(elapsed_ms, bool)
        or elapsed_ms < 0
    ):
        raise CheckError("server-VPN run interval is invalid")
    try:
        started = datetime.fromisoformat(started_at.replace("Z", "+00:00")).timestamp()
    except ValueError as error:
        raise CheckError("server-VPN start timestamp is invalid") from error
    return started, started + elapsed_ms / 1000


def stable_observation(record: dict[str, object]) -> object:
    raw = record.get("raw_observations")
    if not isinstance(raw, dict):
        raise CheckError(f"server-VPN raw observation is invalid: {record.get('test_id')}")
    comparison = raw.get("comparison")
    if record.get("test_id") in VOLATILE_NETWORK_INVENTORY_TEST_IDS:
        if not isinstance(comparison, dict):
            raise CheckError(
                f"server-VPN volatile network inventory is invalid: {record.get('test_id')}"
            )
        network_count = comparison.get("network_count")
        link_count = comparison.get("link_count")
        values = comparison.get("values")
        if (
            not isinstance(network_count, int)
            or isinstance(network_count, bool)
            or network_count < 0
            or not isinstance(link_count, int)
            or isinstance(link_count, bool)
            or link_count < 0
            or not isinstance(values, list)
            or len(values) != link_count
            or any(not isinstance(value, dict) for value in values)
        ):
            raise CheckError(
                f"server-VPN volatile network inventory shape is invalid: {record.get('test_id')}"
            )
        outcome = record.get("projection_outcome")
        if outcome not in PROJECTION_OUTCOMES:
            raise CheckError(
                f"server-VPN volatile network projection outcome is invalid: "
                f"{record.get('test_id')}"
            )
        return {
            "inventory": "runtime-volatile-ip-derived",
            "projection_outcome": outcome,
            "shape": "valid",
        }
    if isinstance(comparison, dict):
        return comparison
    normalized = {
        key: normalize_value(value)
        for key, value in raw.items()
        if key not in {"diagnostic", "events"}
    }
    if record.get("test_id") in VOLATILE_SCALAR_TEST_IDS:
        value = raw.get("value")
        if not isinstance(value, int) or isinstance(value, bool):
            raise CheckError(
                f"server-VPN volatile scalar is not an integer: {record.get('test_id')}"
            )
        normalized["value"] = "runtime-volatile-integer"
    return normalized


def normalize_value(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: normalize_value(nested)
            for key, nested in sorted(value.items())
            if key not in {"diagnostic", "events"}
        }
    if isinstance(value, list):
        normalized = [normalize_value(item) for item in value]
        return sorted(
            normalized,
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
        )
    return value


def stable_run_projection(records: list[dict[str, object]]) -> dict[str, object]:
    return {
        test_id: {
            "status": record["status"],
            "observation": stable_observation(record),
        }
        for test_id, record in sorted(detector_records(records).items())
    }


def differing_test_ids(left: dict[str, object], right: dict[str, object]) -> list[str]:
    return sorted(test_id for test_id in left if left[test_id] != right[test_id])


def require_identity(
    records: list[dict[str, object]],
    *,
    variant: str,
    module_expected: bool,
) -> tuple[str, str]:
    first = records[0]
    if (
        first.get("schema_version") != 2
        or first.get("variant") != variant
        or first.get("vpn_expected") is not True
        or first.get("module_expected") is not module_expected
    ):
        raise CheckError("server-VPN differential role metadata mismatch")
    group = first.get("group")
    process = first.get("process")
    if not isinstance(group, str) or not group.startswith("server-vpn-"):
        raise CheckError("server-VPN differential group is invalid")
    if not isinstance(process, str) or not process:
        raise CheckError("server-VPN differential process is invalid")
    expected_secondary = process.endswith(":secondary")
    if any(
        record.get("group") != group
        or record.get("variant") != variant
        or record.get("process") != process
        or record.get("vpn_expected") is not True
        or record.get("module_expected") is not module_expected
        for record in records
    ):
        raise CheckError("server-VPN differential run identity is inconsistent")
    return group, "secondary" if expected_secondary else "main"


def require_phase(records: list[dict[str, object]], *, target_active: bool) -> None:
    detectors = detector_records(records)
    mandatory = [record for record in detectors.values() if record.get("mandatory") is True]
    if any(record.get("status") in {"ERROR", "UNAVAILABLE"} for record in detectors.values()):
        raise CheckError("server-VPN phase contains an error or unavailable detector")
    group = cast(str, records[0]["group"])
    if group == "server-vpn-link":
        if any(record.get("status") == "ERROR" for record in detectors.values()):
            raise CheckError("server-VPN link phase contains an error")
        return
    if not mandatory:
        raise CheckError("server-VPN phase has no mandatory source records")
    if target_active:
        if any(record.get("status") != "NEGATIVE" for record in mandatory):
            raise CheckError("active target retains a mandatory public VPN signal")
        if any(record.get("projection_outcome") != "present_sanitized" for record in mandatory):
            raise CheckError("active target projection outcome is incomplete")
    else:
        if any(
            record.get("status") in {"INCONCLUSIVE", "ERROR", "UNAVAILABLE"} for record in mandatory
        ):
            raise CheckError("stock phase lacks a complete mandatory source record")
        if not any(record.get("status") == "POSITIVE" for record in mandatory):
            raise CheckError("stock phase did not observe a calibrated public VPN signal")


def evaluate_differential(
    baseline: list[dict[str, object]],
    active_target: list[dict[str, object]],
    active_canary: list[dict[str, object]],
    rollback: list[dict[str, object]],
) -> dict[str, object]:
    baseline_group, baseline_role = require_identity(
        baseline, variant="primary", module_expected=False
    )
    target_group, target_role = require_identity(
        active_target, variant="primary", module_expected=True
    )
    canary_group, canary_role = require_identity(
        active_canary, variant="canary", module_expected=True
    )
    rollback_group, rollback_role = require_identity(
        rollback, variant="primary", module_expected=False
    )
    if len({baseline_group, target_group, canary_group, rollback_group}) != 1:
        raise CheckError("server-VPN differential groups differ")
    if len({baseline_role, target_role, canary_role, rollback_role}) != 1:
        raise CheckError("server-VPN differential process roles differ")

    baseline_ids = set(detector_records(baseline))
    for records in (active_target, active_canary, rollback):
        if set(detector_records(records)) != baseline_ids:
            raise CheckError("server-VPN differential catalogs differ")

    require_phase(baseline, target_active=False)
    require_phase(active_target, target_active=True)
    require_phase(active_canary, target_active=False)
    require_phase(rollback, target_active=False)

    baseline_projection = stable_run_projection(baseline)
    target_projection = stable_run_projection(active_target)
    canary_projection = stable_run_projection(active_canary)
    rollback_projection = stable_run_projection(rollback)
    if baseline_projection != canary_projection:
        differing = ",".join(differing_test_ids(baseline_projection, canary_projection))
        raise CheckError(f"active canary differs from the stock public projection: {differing}")
    if baseline_projection != rollback_projection:
        differing = ",".join(differing_test_ids(baseline_projection, rollback_projection))
        raise CheckError(f"post-disable projection did not return to stock: {differing}")
    if baseline_projection == target_projection:
        raise CheckError("active target did not change any source-specific projection")

    target_start, target_end = run_interval(active_target)
    canary_start, canary_end = run_interval(active_canary)
    overlap_ms = int(max(0.0, min(target_end, canary_end) - max(target_start, canary_start)) * 1000)
    overlap_required = baseline_group in CALLBACK_GROUPS
    if overlap_required and overlap_ms <= 0:
        raise CheckError("active callback target/canary sessions did not overlap")
    return {
        "differential": "PASS",
        "group": baseline_group,
        "process_role": baseline_role,
        "detector_count": len(baseline_ids),
        "overlap_ms": overlap_ms,
        "overlap_required": overlap_required,
        "stock_restored": True,
        "target_projection_changed": True,
    }


def require_diagnostics_residual(records: list[dict[str, object]]) -> None:
    detectors = detector_records(records)
    if set(detectors) != set(DIAGNOSTICS_MANDATORY):
        raise CheckError("server-VPN diagnostics residual catalog differs")
    if any(
        record.get("mandatory") is not DIAGNOSTICS_MANDATORY[test_id]
        for test_id, record in detectors.items()
    ):
        raise CheckError("server-VPN diagnostics residual mandatory metadata differs")
    if stable_run_projection(records) != DIAGNOSTICS_RESIDUAL_PROJECTION:
        raise CheckError("server-VPN diagnostics residual projection differs")
    summary = next(
        (record for record in records if record.get("record_type") == "summary"),
        None,
    )
    if summary is None or summary.get("status") != "INCONCLUSIVE":
        raise CheckError("server-VPN diagnostics residual summary differs")


def evaluate_diagnostics_residual(
    baseline: list[dict[str, object]],
    active_target: list[dict[str, object]],
    active_canary: list[dict[str, object]],
    rollback: list[dict[str, object]],
) -> dict[str, object]:
    baseline_group, baseline_role = require_identity(
        baseline, variant="primary", module_expected=False
    )
    target_group, target_role = require_identity(
        active_target, variant="primary", module_expected=True
    )
    canary_group, canary_role = require_identity(
        active_canary, variant="canary", module_expected=True
    )
    rollback_group, rollback_role = require_identity(
        rollback, variant="primary", module_expected=False
    )
    if {baseline_group, target_group, canary_group, rollback_group} != {DIAGNOSTICS_GROUP}:
        raise CheckError("server-VPN diagnostics residual group differs")
    if len({baseline_role, target_role, canary_role, rollback_role}) != 1:
        raise CheckError("server-VPN diagnostics residual process roles differ")
    for records in (baseline, active_target, active_canary, rollback):
        require_diagnostics_residual(records)
    return {
        "residual": "PASS",
        "group": DIAGNOSTICS_GROUP,
        "process_role": baseline_role,
        "detector_count": len(DIAGNOSTICS_MANDATORY),
        "permission_boundary": "ordinary_application_not_network_owner",
        "stock_restored": True,
    }


def self_test() -> None:
    def run(
        *,
        variant: str,
        module_expected: bool,
        status: str,
        outcome: str,
        started_at: str,
        elapsed_ms: int,
        group: str = "server-vpn-async",
    ) -> list[dict[str, object]]:
        package = f"dev.zygveil.probe.{variant}"
        detector = {
            "schema_version": 2,
            "record_type": "detector",
            "run_id": f"probe-{variant}-{module_expected}",
            "variant": variant,
            "application_id": package,
            "process": package,
            "vpn_expected": True,
            "module_expected": module_expected,
            "group": group,
            "test_id": "sync.active.transport.vpn",
            "mandatory": True,
            "status": status,
            "projection_outcome": outcome,
            "raw_observations": {"vpn_transport": status == "POSITIVE"},
            "exception": None,
            "started_at": started_at,
            "elapsed_ms": 10,
            "cleanup_status": "complete",
        }
        summary = {
            **detector,
            "record_type": "summary",
            "test_id": "summary",
            "status": "VPN_DETECTED" if status == "POSITIVE" else "NO_PUBLIC_VPN_SIGNAL",
            "raw_observations": {},
            "elapsed_ms": elapsed_ms,
            "detector_count": 1,
        }
        summary.pop("projection_outcome")
        return [detector, summary]

    baseline = run(
        variant="primary",
        module_expected=False,
        status="POSITIVE",
        outcome="present_stock",
        started_at="2026-08-26T00:00:00Z",
        elapsed_ms=2_000,
    )
    target = run(
        variant="primary",
        module_expected=True,
        status="NEGATIVE",
        outcome="present_sanitized",
        started_at="2026-08-26T00:00:01Z",
        elapsed_ms=2_000,
    )
    canary = run(
        variant="canary",
        module_expected=True,
        status="POSITIVE",
        outcome="present_stock",
        started_at="2026-08-26T00:00:01.500000Z",
        elapsed_ms=2_000,
    )
    rollback = run(
        variant="primary",
        module_expected=False,
        status="POSITIVE",
        outcome="present_stock",
        started_at="2026-08-26T00:00:04Z",
        elapsed_ms=2_000,
    )
    result = evaluate_differential(baseline, target, canary, rollback)
    if (
        result["differential"] != "PASS"
        or result["overlap_required"] is not True
        or result["overlap_ms"] != 1_500
    ):
        raise CheckError("server-VPN differential overlap self-test failed")

    sync_baseline = run(
        variant="primary",
        module_expected=False,
        status="POSITIVE",
        outcome="present_stock",
        started_at="2026-08-26T00:00:00Z",
        elapsed_ms=100,
        group="server-vpn-sync",
    )
    sync_target = run(
        variant="primary",
        module_expected=True,
        status="NEGATIVE",
        outcome="present_sanitized",
        started_at="2026-08-26T00:00:01Z",
        elapsed_ms=100,
        group="server-vpn-sync",
    )
    sync_canary = run(
        variant="canary",
        module_expected=True,
        status="POSITIVE",
        outcome="present_stock",
        started_at="2026-08-26T00:00:02Z",
        elapsed_ms=100,
        group="server-vpn-sync",
    )
    sync_rollback = run(
        variant="primary",
        module_expected=False,
        status="POSITIVE",
        outcome="present_stock",
        started_at="2026-08-26T00:00:03Z",
        elapsed_ms=100,
        group="server-vpn-sync",
    )

    def add_scalar(records: list[dict[str, object]], test_id: str, value: int) -> None:
        detector = dict(records[0])
        detector.update(
            {
                "test_id": test_id,
                "mandatory": False,
                "status": "NEGATIVE",
                "raw_observations": {"value": value},
            }
        )
        records.insert(-1, detector)
        records[-1]["detector_count"] = cast(int, records[-1]["detector_count"]) + 1

    for records, value in (
        (sync_baseline, 12_000),
        (sync_target, 1_248),
        (sync_canary, 1_248),
        (sync_rollback, 12_000),
    ):
        add_scalar(records, "sync.active.getter.up_kbps", value)
    sync_result = evaluate_differential(
        sync_baseline,
        sync_target,
        sync_canary,
        sync_rollback,
    )
    if (
        sync_result["differential"] != "PASS"
        or sync_result["overlap_required"] is not False
        or sync_result["overlap_ms"] != 0
    ):
        raise CheckError("server-VPN synchronous differential self-test failed")

    for test_id in VOLATILE_SCALAR_TEST_IDS:
        left: dict[str, object] = {
            "test_id": test_id,
            "raw_observations": {"value": -2_147_483_648},
        }
        right: dict[str, object] = {
            "test_id": test_id,
            "raw_observations": {"value": 97_256},
        }
        if stable_observation(left) != stable_observation(right):
            raise CheckError("server-VPN volatile scalar normalization self-test failed")
    owner_left: dict[str, object] = {
        "test_id": "sync.active.getter.owner_uid",
        "raw_observations": {"value": -1},
    }
    owner_right: dict[str, object] = {
        "test_id": "sync.active.getter.owner_uid",
        "raw_observations": {"value": 10_123},
    }
    if stable_observation(owner_left) == stable_observation(owner_right):
        raise CheckError("server-VPN structural getter normalization self-test failed")

    def inventory_run(
        *,
        variant: str,
        module_expected: bool,
        outcome: str,
        count: int,
        started_at: str,
    ) -> list[dict[str, object]]:
        records = run(
            variant=variant,
            module_expected=module_expected,
            status="NEGATIVE",
            outcome=outcome,
            started_at=started_at,
            elapsed_ms=2_000,
            group="server-vpn-link",
        )
        records[0].update(
            {
                "test_id": "link.all.addresses",
                "mandatory": False,
                "raw_observations": {
                    "comparison": {
                        "network_count": count,
                        "link_count": count,
                        "values": [
                            {
                                "link_present": True,
                                "count": index + 1,
                                "values": [{"family": "ipv6", "scope": "global"}],
                            }
                            for index in range(count)
                        ],
                    }
                },
            }
        )
        return records

    inventory_result = evaluate_differential(
        inventory_run(
            variant="primary",
            module_expected=False,
            outcome="present_stock",
            count=1,
            started_at="2026-08-26T00:00:00Z",
        ),
        inventory_run(
            variant="primary",
            module_expected=True,
            outcome="present_sanitized",
            count=2,
            started_at="2026-08-26T00:00:01Z",
        ),
        inventory_run(
            variant="canary",
            module_expected=True,
            outcome="present_stock",
            count=3,
            started_at="2026-08-26T00:00:01.500000Z",
        ),
        inventory_run(
            variant="primary",
            module_expected=False,
            outcome="present_stock",
            count=4,
            started_at="2026-08-26T00:00:04Z",
        ),
    )
    if inventory_result["differential"] != "PASS":
        raise CheckError("server-VPN volatile network inventory self-test failed")
    malformed_inventory = inventory_run(
        variant="primary",
        module_expected=False,
        outcome="present_stock",
        count=1,
        started_at="2026-08-26T00:00:00Z",
    )[0]
    cast(dict[str, object], malformed_inventory["raw_observations"])["comparison"] = {
        "network_count": "one",
        "link_count": 0,
        "values": [],
    }
    try:
        stable_observation(malformed_inventory)
    except CheckError:
        pass
    else:
        raise CheckError("server-VPN volatile network inventory accepted an invalid shape")

    nonoverlapping_canary = run(
        variant="canary",
        module_expected=True,
        status="POSITIVE",
        outcome="present_stock",
        started_at="2026-08-26T00:00:04Z",
        elapsed_ms=100,
    )
    try:
        evaluate_differential(baseline, target, nonoverlapping_canary, rollback)
    except CheckError:
        pass
    else:
        raise CheckError("server-VPN differential accepted non-overlapping callbacks")

    def diagnostics_run(*, variant: str, module_expected: bool) -> list[dict[str, object]]:
        package = f"dev.zygveil.probe.{variant}"
        records: list[dict[str, object]] = []
        for test_id, projection in DIAGNOSTICS_RESIDUAL_PROJECTION.items():
            records.append(
                {
                    "schema_version": 2,
                    "record_type": "detector",
                    "variant": variant,
                    "process": package,
                    "vpn_expected": True,
                    "module_expected": module_expected,
                    "group": DIAGNOSTICS_GROUP,
                    "test_id": test_id,
                    "mandatory": DIAGNOSTICS_MANDATORY[test_id],
                    "status": projection["status"],
                    "raw_observations": projection["observation"],
                    "started_at": "2026-08-26T00:00:00Z",
                }
            )
        records.append(
            {
                "schema_version": 2,
                "record_type": "summary",
                "variant": variant,
                "process": package,
                "vpn_expected": True,
                "module_expected": module_expected,
                "group": DIAGNOSTICS_GROUP,
                "test_id": "summary",
                "status": "INCONCLUSIVE",
                "raw_observations": {},
                "started_at": "2026-08-26T00:00:00Z",
                "elapsed_ms": 3_000,
            }
        )
        return records

    diagnostics = [
        diagnostics_run(variant="primary", module_expected=False),
        diagnostics_run(variant="primary", module_expected=True),
        diagnostics_run(variant="canary", module_expected=True),
        diagnostics_run(variant="primary", module_expected=False),
    ]
    diagnostics_result = evaluate_diagnostics_residual(*diagnostics)
    if diagnostics_result["residual"] != "PASS":
        raise CheckError("server-VPN diagnostics residual self-test failed")
    diagnostics[1][0]["raw_observations"] = {
        "registered": True,
        "delivery_observed": True,
    }
    try:
        evaluate_diagnostics_residual(*diagnostics)
    except CheckError:
        pass
    else:
        raise CheckError("server-VPN diagnostics residual accepted a changed projection")

    canary[0]["raw_observations"] = {"vpn_transport": False}
    try:
        evaluate_differential(baseline, target, canary, rollback)
    except CheckError:
        pass
    else:
        raise CheckError("server-VPN differential accepted a changed canary projection")
