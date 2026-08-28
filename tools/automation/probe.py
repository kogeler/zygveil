# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Make-wrapped lifecycle and schema validation for the independent public probe."""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import math
import os
import re
import stat
import tempfile
import time
import traceback
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import ROUND_CEILING, Decimal, InvalidOperation
from pathlib import Path
from typing import cast

from adb import Adb, CommandResult, ensure_device_ui_ready, system_server_process_identity
from location_live_control import STATUS_KEYS as LIVE_STATUS_KEYS
from location_live_control import parse_status as parse_live_status
from reporting import CheckError, Report, contains_private_decimal_values
from server_vpn_oracle import detector_records, require_phase, run_interval

ROOT = Path(__file__).resolve().parents[2]
PACKAGES = {
    "primary": "dev.zygveil.probe.primary",
    "canary": "dev.zygveil.probe.canary",
}
APKS = {
    "primary": ROOT / "dist/zygveil-probe-primary-debug.apk",
    "canary": ROOT / "dist/zygveil-probe-canary-debug.apk",
}
POC_PRIMARY_APK = ROOT / ".artifacts/poc/probe/zygveil-probe-primary-poc.apk"
POC_CANARY_APK = ROOT / ".artifacts/poc/probe/zygveil-probe-canary-poc.apk"
RUN_STATE = ROOT / ".state/probe-runs"
POC_RUN_STATE = ROOT / ".artifacts/poc/state/probe-runs"
SAFE_RUN_ID = re.compile(r"probe-[0-9TZ-]+-[0-9a-f]{8}")
DETECTOR_STATUSES = {"POSITIVE", "NEGATIVE", "INCONCLUSIVE", "UNAVAILABLE", "ERROR"}
VERDICTS = {"VPN_DETECTED", "NO_PUBLIC_VPN_SIGNAL", "INCONCLUSIVE"}
LOCATION_STATUSES = {"SUCCESS", "ERROR", "UNAVAILABLE", "REGISTERED", "TIMEOUT"}
LOCATION_VERDICTS = {"PASS", "FAIL", "ERROR"}
LOCATION_STARTUP_TIMEOUT_SECONDS = 15
LOCATION_OBSERVATION_TYPES = {
    "provider_inventory",
    "last_known",
    "current",
    "location_update",
    "location_batch",
    "gnss_capabilities",
    "gnss_status",
    "nmea",
    "raw_measurement_status",
    "raw_measurement_event",
    "navigation_status",
    "navigation_event",
    "gms_last_known",
    "gms_current",
    "gms_location_update",
    "gms_location_batch",
    "gms_location_availability",
    "gms_pending_intent",
    "process_isolation",
}
LOCATION_PLATFORM_SPATIAL_TYPES = {
    "last_known",
    "current",
    "location_update",
    "location_batch",
}
LOCATION_GMS_SPATIAL_TYPES = {
    "gms_last_known",
    "gms_current",
    "gms_location_update",
    "gms_location_batch",
    "gms_pending_intent",
}
LOCATION_GMS_REQUIRED_OBJECT_SOURCES = {
    "gms_fused.last.default",
    "gms_fused.last.request",
    "gms_fused.current.priority",
    "gms_fused.current.request",
    "gms_fused.update.callback",
    "gms_fused.update.listener",
    "gms_fused.update.pending_intent",
}
LOCATION_SPATIAL_TYPES = LOCATION_PLATFORM_SPATIAL_TYPES | LOCATION_GMS_SPATIAL_TYPES
LOCATION_SYNTHETIC_REQUIRED_FLAGS = {
    "complete",
    "coordinates_finite",
    "latitude_in_range",
    "longitude_in_range",
    "within_expected_radius",
    "has_accuracy",
    "has_altitude",
    "has_vertical_accuracy",
    "has_msl_altitude",
    "has_msl_altitude_accuracy",
    "has_speed",
    "has_speed_accuracy",
    "numeric_fields_finite",
    "accuracy_non_negative",
    "vertical_accuracy_non_negative",
    "speed_non_negative",
    "bearing_in_range",
    "bearing_presence_consistent",
    "speed_within_expected_bound",
    "stationary_bearing_absent",
    "altitude_pair_consistent",
}
LOCATION_REQUIRED_FIELDS = {
    "schema_version",
    "record_type",
    "session_id",
    "variant",
    "application_id",
    "process",
    "observation_type",
    "monotonic_ns",
    "wall_time_ms",
    "source",
    "status",
    "payload",
}
LOCATION_SUMMARY_KEYS = {
    "configured_raw_gnss_mode",
    "oracle_required",
    "oracle_status",
    "oracle_unlinked",
    "expected_config_generation",
    "expected_config_sha256",
    "reported_measurement_capability",
    "reported_navigation_capability",
    "measurement_registration_result",
    "navigation_registration_result",
    "measurement_callback_status",
    "navigation_callback_status",
    "measurement_event_count",
    "navigation_event_count",
    "first_measurement_event_latency_ms",
    "first_navigation_event_latency_ms",
    "observation_window_ms",
    "unexpected_event_detected",
    "ordinary_location_event_count",
    "location_batch_event_count",
    "gnss_status_event_count",
    "nmea_event_count",
    "gms_client_required",
    "gms_client_status",
    "gms_required_surface_complete",
    "gms_last_known_location_count",
    "gms_current_location_count",
    "gms_callback_location_count",
    "gms_listener_location_count",
    "gms_pending_intent_location_count",
    "gms_total_location_count",
    "platform_location_sample_count",
    "platform_gms_comparison_count",
    "platform_gms_max_distance_m",
    "platform_gms_consistency_threshold_m",
    "platform_gms_consistent",
    "platform_gms_object_comparison_count",
    "platform_gms_max_object_distance_m",
    "platform_gms_object_consistent",
    "cleanup_status",
    "cleanup_failures",
    "session_verdict",
}
LOCATION_PRIVATE_KEYS = {
    "center_latitude_deg",
    "center_longitude_deg",
    "latitude_deg",
    "longitude_deg",
    "accuracy_m",
    "altitude_ellipsoid_m",
    "vertical_accuracy_m",
    "altitude_msl_m",
    "msl_altitude_accuracy_m",
    "speed_mps",
    "speed_accuracy_mps",
    "bearing_deg",
    "bearing_accuracy_deg",
    "packed_latitude",
    "packed_longitude",
    "latitude_hemisphere",
    "longitude_hemisphere",
    "geoid_separation_m",
    "speed_knots",
    "course_deg",
    "pdop",
    "hdop",
    "vdop",
    "raw_sentence",
    "error_message",
}
RAW_GNSS_PRIVATE_KEYS = {
    "data",
    "raw_data",
    "pseudorange_rate_mps",
    "received_sv_time_ns",
    "time_offset_ns",
}
LOCATION_ORACLE_INPUT_KEYS = (
    "schema_version",
    "center_latitude_deg",
    "center_longitude_deg",
    "altitude_ellipsoid_m",
    "altitude_msl_m",
)
LOCATION_ORACLE_KEYS = (
    "schema_version",
    "config_generation",
    "config_sha256",
    "center_latitude_deg",
    "center_longitude_deg",
    "altitude_ellipsoid_m",
    "altitude_msl_m",
    "horizontal_jitter_radius_m",
    "speed_max_mps",
    "bearing_min_speed_mps",
)
POC_UNATTESTED_CONFIG_DIGEST = "0" * 64
LOCATION_CONFIG_KEYS = {
    "schema_version",
    "enabled",
    "raw_gnss_mode",
    "center_latitude_deg",
    "center_longitude_deg",
    "altitude_ellipsoid_m",
    "altitude_msl_m",
    "horizontal_jitter_sigma_m",
    "horizontal_jitter_radius_m",
    "horizontal_correlation_time_s",
    "vertical_jitter_sigma_m",
    "accuracy_correlation_time_s",
    "speed_deadband_mps",
    "speed_max_mps",
    "bearing_min_speed_mps",
    "random_seed",
    "config_generation",
}
LOCATION_MODULE_DIR = "/data/adb/modules/zygveil"
LOCATION_ORACLE_DEVICE_PATH = "no_backup/location-oracle.properties"
LOCATION_ORACLE_PATH_CHECKS = (
    ("-e", LOCATION_ORACLE_DEVICE_PATH),
    ("-L", LOCATION_ORACLE_DEVICE_PATH),
)
LINK_RAW_KEYS = {
    "comparison",
    "diagnostic",
    "network_count",
    "link_count",
    "values",
    "link_present",
    "interface_present",
    "count",
    "family",
    "scope",
    "prefix_length",
    "flags",
    "destination_family",
    "default",
    "has_gateway",
    "gateway_family",
    "gateway_scope",
    "type",
    "interface_relation",
    "domains_present",
    "configured",
    "value",
    "active",
    "server_name_present",
    "present",
    "nat64_present",
    "nat64_family",
    "nat64_prefix_length",
    "supported",
    "capabilities_present",
    "specified",
    "event_types",
    "events",
}
LINK_RAW_STRINGS = {
    "ipv4",
    "ipv6",
    "other",
    "none",
    "any_local",
    "loopback",
    "link_local",
    "site_local",
    "multicast",
    "global",
    "same",
    "different",
    "missing",
    "onAvailable",
    "onCapabilitiesChanged",
    "onLinkPropertiesChanged",
    "onLost",
    "onUnavailable",
}
EXPECTED_TEST_IDS = {
    "active": {
        "request.callback.default",
        "request.callback.timeout",
        "request.callback.handler",
        "request.callback.handler_timeout",
        "request.pending.vpn_exclusive",
        "reserve.signature",
    },
    "async": {
        "callback.default",
        "callback.default_handler",
        "callback.broad",
        "callback.broad_handler",
        "callback.vpn_inclusive",
        "callback.vpn_exclusive",
        "callback.vpn_mixed",
        "callback.vpn_exclusive_other_uid",
        "callback.best_matching",
        "pending.listen.vpn_exclusive",
    },
    "schema": {"schema.self_test"},
    "link": {
        "link.active.interface",
        "link.active.addresses",
        "link.active.routes",
        "link.active.dns",
        "link.active.mtu",
        "link.active.private_dns",
        "link.active.proxy",
        "link.active.nat64",
        "link.active.dhcp",
        "link.active.wake_on_lan",
        "link.active.signal_strength",
        "link.all.interface",
        "link.all.addresses",
        "link.all.routes",
        "link.all.dns",
        "link.all.mtu",
        "link.all.private_dns",
        "link.all.proxy",
        "link.all.nat64",
        "link.all.dhcp",
        "link.all.wake_on_lan",
        "link.all.signal_strength",
        "link.callback.default.interface",
        "link.callback.default.addresses",
        "link.callback.default.routes",
        "link.callback.default.dns",
        "link.callback.default.mtu",
        "link.callback.default.private_dns",
        "link.callback.default.proxy",
        "link.callback.default.nat64",
        "link.callback.default.dhcp",
        "link.callback.default.wake_on_lan",
        "link.callback.default.signal_strength",
        "link.callback.default.lifecycle",
        "link.callback.broad.interface",
        "link.callback.broad.addresses",
        "link.callback.broad.routes",
        "link.callback.broad.dns",
        "link.callback.broad.mtu",
        "link.callback.broad.private_dns",
        "link.callback.broad.proxy",
        "link.callback.broad.nat64",
        "link.callback.broad.dhcp",
        "link.callback.broad.wake_on_lan",
        "link.callback.broad.signal_strength",
        "link.callback.broad.lifecycle",
    },
    "sync": {
        "sync.active.transport.vpn",
        "sync.active.capability.not_vpn",
        "sync.active.capabilities.not_vpn",
        "sync.active.transport_info.vpn_token",
        "sync.active.caps_string.vpn_token",
        "sync.active.getter.down_kbps",
        "sync.active.getter.up_kbps",
        "sync.active.getter.signal_strength",
        "sync.active.getter.owner_uid",
        "sync.active.getter.enterprise_ids",
        "sync.active.getter.network_specifier",
        "sync.active.getter.subscription_ids",
        "sync.active.copy.consistency",
        "sync.active.parcel.consistency",
        "sync.all.transport.vpn",
        "sync.all.capability.not_vpn",
        "sync.all.capabilities.not_vpn",
        "sync.all.transport_info.vpn_token",
        "sync.all.caps_string.vpn_token",
        "sync.all.copy.consistency",
        "sync.all.parcel.consistency",
        "matcher.default",
        "matcher.vpn_inclusive",
        "matcher.vpn_exclusive",
        "matcher.mixed",
        "legacy.active",
        "legacy.network",
        "legacy.all",
    },
}
SERVER_VPN_GROUPS = {
    "server-vpn-sync",
    "server-vpn-async",
    "server-vpn-active",
    "server-vpn-link",
    "server-vpn-diagnostics",
}
SERVER_VPN_CONCURRENT_VARIANTS = ("primary", "canary")
SERVER_VPN_CANARY_READY_TIMEOUT_SECONDS = 5
SERVER_VPN_PRIMARY_DISPATCH_MAX_DELAY_MS = 1_000
SERVER_VPN_COORDINATED_START_LEAD_MS = 3_000
DATA_PLANE_TEST_IDS = {
    "data_plane.dns",
    "data_plane.tls_https",
    "data_plane.lifecycle",
}
SERVER_VPN_SYNC_EXTRA_IDS = {
    "sync.default_proxy",
    "scalar.active_metered",
    "scalar.active_multipath",
    "scalar.all_multipath",
    "structure.link.active.parcel",
    "structure.request.default.copy",
    "structure.request.default.parcel",
}
EXPECTED_TEST_IDS.update(
    {
        "server-vpn-sync": EXPECTED_TEST_IDS["sync"] | SERVER_VPN_SYNC_EXTRA_IDS,
        "server-vpn-async": EXPECTED_TEST_IDS["async"],
        "server-vpn-active": EXPECTED_TEST_IDS["active"],
        "server-vpn-link": EXPECTED_TEST_IDS["link"],
        "server-vpn-diagnostics": {
            "diagnostics.lifecycle",
            "diagnostics.connectivity_report",
            "diagnostics.data_stall_report",
            "diagnostics.connectivity_result",
        },
        "data-plane": DATA_PLANE_TEST_IDS,
    }
)
SERVER_VPN_PROJECTION_OUTCOMES = {
    "absent",
    "present_sanitized",
    "present_stock",
    "unavailable",
    "inconclusive",
    "error",
}
REQUIRED_FIELDS = {
    "schema_version",
    "record_type",
    "run_id",
    "variant",
    "application_id",
    "process",
    "vpn_expected",
    "module_expected",
    "group",
    "test_id",
    "mandatory",
    "status",
    "raw_observations",
    "exception",
    "started_at",
    "elapsed_ms",
    "cleanup_status",
}


def utc_compact() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def variant_package(variant: str) -> str:
    try:
        return PACKAGES[variant]
    except KeyError as error:
        raise CheckError(f"unsupported probe variant: {variant}") from error


def parse_expected(value: str, name: str) -> bool:
    if value not in {"on", "off"}:
        raise CheckError(f"{name} must be on or off")
    return value == "on"


def parse_properties(text: str, *, expected: set[str], label: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "=" not in line:
            raise CheckError(f"{label} has an invalid line")
        key, value = (part.strip() for part in line.split("=", 1))
        if not key or not value or key in values:
            raise CheckError(f"{label} has an invalid or duplicate field")
        values[key] = value
    if set(values) != expected:
        raise CheckError(f"{label} schema/key set mismatch")
    return values


def validate_decimal(
    value: str, *, fraction_digits: int, minimum: str, maximum: str, label: str
) -> Decimal:
    if re.fullmatch(r"-?[0-9]+(?:\.[0-9]+)?", value) is None:
        raise CheckError(f"{label} contains a non-canonical decimal")
    if len(value.partition(".")[2]) > fraction_digits:
        raise CheckError(f"{label} decimal precision is too large")
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        raise CheckError(f"{label} contains an invalid decimal") from None
    if parsed < Decimal(minimum) or parsed > Decimal(maximum):
        raise CheckError(f"{label} decimal is outside its supported range")
    return parsed


def validate_oracle_input_values(values: dict[str, str], *, label: str) -> None:
    if set(values) != set(LOCATION_ORACLE_INPUT_KEYS) or values["schema_version"] != "1":
        raise CheckError(f"{label} schema/key set mismatch")
    validate_decimal(
        values["center_latitude_deg"],
        fraction_digits=8,
        minimum="-90",
        maximum="90",
        label=label,
    )
    validate_decimal(
        values["center_longitude_deg"],
        fraction_digits=8,
        minimum="-180",
        maximum="180",
        label=label,
    )
    for key in ("altitude_ellipsoid_m", "altitude_msl_m"):
        validate_decimal(
            values[key],
            fraction_digits=3,
            minimum="-12000",
            maximum="100000",
            label=label,
        )


def read_private_oracle_input(path_text: str) -> dict[str, str]:
    path = Path(path_text)
    if not path.is_absolute():
        path = ROOT / path
    state_root = (ROOT / ".state").resolve()
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise CheckError("location oracle file is unavailable") from None
    if not resolved.is_relative_to(state_root) or path.is_symlink():
        raise CheckError("location oracle must be a regular file below ignored .state")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        raise CheckError("location oracle file could not be opened safely") from None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > 1024
        ):
            raise CheckError("location oracle owner/mode/type/size is invalid")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(remaining, 512))
            if not block:
                raise CheckError("location oracle changed while being read")
            chunks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise CheckError("location oracle changed while being read")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise CheckError("location oracle changed while being read")
    finally:
        os.close(descriptor)
    try:
        text = b"".join(chunks).decode("ascii")
    except UnicodeDecodeError:
        raise CheckError("location oracle must contain only ASCII") from None
    values = parse_properties(
        text, expected=set(LOCATION_ORACLE_INPUT_KEYS), label="location oracle"
    )
    validate_oracle_input_values(values, label="location oracle")
    return values


def parse_poc_current_oracle_input(text: str) -> dict[str, str]:
    coordinate_keys = set(LOCATION_ORACLE_INPUT_KEYS[1:])
    values = parse_properties(
        text,
        expected=LIVE_STATUS_KEYS | coordinate_keys,
        label="current POC location status",
    )
    status_text = "".join(f"{key}={values[key]}\n" for key in sorted(LIVE_STATUS_KEYS))
    status = parse_live_status(status_text)
    if (
        status["module_state"] != "active"
        or status["runtime_state"] != "active"
        or status["control_state"] != "applied"
    ):
        raise CheckError("current POC point is not an applied active generation")
    oracle_input = {key: values[key] for key in LOCATION_ORACLE_INPUT_KEYS}
    validate_oracle_input_values(oracle_input, label="current POC location status")
    return oracle_input


def read_poc_current_oracle_input(adb: Adb) -> dict[str, str]:
    helper = f"{LOCATION_MODULE_DIR}/locationctl"
    result = adb.shell(helper, "status-ui", timeout=15, check=False)
    if result.returncode != 0:
        raise CheckError("current POC location status is unavailable")
    return parse_poc_current_oracle_input(result.stdout)


def parse_location_helper_status(text: str) -> dict[str, str]:
    return parse_live_status(text)


def same_binary64_decimal(left: str, right: str) -> bool:
    try:
        left_value = float(Decimal(left))
        right_value = float(Decimal(right))
    except (InvalidOperation, OverflowError, ValueError):
        return False
    return math.isfinite(left_value) and math.isfinite(right_value) and left_value == right_value


def location_oracle_runtime_identity_matches(
    config: dict[str, str],
    status: dict[str, str],
    raw_gnss_mode: str,
    current_pid: str,
    current_start_ticks: str,
    current_boot_id: str,
    generation: int,
) -> bool:
    active_identity = (
        config["enabled"] == "true"
        and status["module_state"] == "active"
        and status["runtime_state"] == "active"
        and status["control_state"] == "applied"
        and config["raw_gnss_mode"] == raw_gnss_mode
        and status["raw_gnss_mode"] == raw_gnss_mode
        and status["system_server_pid"] == current_pid
        and status["system_server_start_ticks"] == current_start_ticks
        and status["boot_id"] == current_boot_id
        and int(status["persisted_generation"]) == generation
        and int(status["published_generation"]) == generation
        and int(status["applied_generation"]) == generation
    )
    inactive_identity = (
        config["enabled"] in {"true", "false"}
        and status["module_state"] == "inactive"
        and status["runtime_state"] == "unavailable"
        and status["control_state"] == "unavailable"
        and status["reason"] == "runtime_inactive"
        and status["boot_id"] == "unavailable"
        and status["boot_config_generation"] == "0"
        and int(status["persisted_generation"]) == generation
        and status["published_generation"] == "0"
        and status["applied_generation"] == "0"
        and status["system_server_pid"] == "0"
        and status["system_server_start_ticks"] == "0"
    )
    return active_identity or inactive_identity


def build_location_oracle(
    adb: Adb, input_values: dict[str, str], raw_gnss_mode: str, *, poc: bool
) -> tuple[str, int, str]:
    identity = adb.shell("id", timeout=10, check=False)
    if identity.returncode != 0 or "uid=0" not in identity.stdout:
        raise CheckError("a private location oracle requires rooted adbd")
    helper = f"{LOCATION_MODULE_DIR}/locationctl"
    status_result = adb.shell(helper, "status", timeout=15, check=False)
    if status_result.returncode != 0:
        raise CheckError("redacted location helper status is unavailable")
    status = parse_location_helper_status(status_result.stdout)
    current_pid, current_start_ticks = system_server_process_identity(adb)
    current_boot_id = adb.shell("cat", "/proc/sys/kernel/random/boot_id").stdout.strip()
    config_result = adb.shell("cat", f"{LOCATION_MODULE_DIR}/config.properties", check=False)
    if config_result.returncode != 0 or len(config_result.stdout.encode("ascii", "ignore")) > 4096:
        raise CheckError("current location configuration is unavailable")
    try:
        config_result.stdout.encode("ascii")
    except UnicodeEncodeError:
        raise CheckError("current location configuration is invalid") from None
    config = parse_properties(
        config_result.stdout, expected=LOCATION_CONFIG_KEYS, label="current location configuration"
    )
    if config["schema_version"] != "1" or config["enabled"] not in {"true", "false"}:
        raise CheckError("current location configuration is not valid schema 1")
    for key in LOCATION_ORACLE_INPUT_KEYS[1:]:
        if not same_binary64_decimal(config[key], input_values[key]):
            raise CheckError("private location oracle does not match the persisted live point")
    generation_text = config["config_generation"]
    if not generation_text.isdigit() or int(generation_text) <= 0:
        raise CheckError("current location configuration generation is invalid")
    generation = int(generation_text)
    if not location_oracle_runtime_identity_matches(
        config,
        status,
        raw_gnss_mode,
        current_pid,
        current_start_ticks,
        current_boot_id,
        generation,
    ):
        raise CheckError("private location oracle is not bound to the current runtime state")
    digest = POC_UNATTESTED_CONFIG_DIGEST
    if not poc:
        digest = hashlib.sha256(config_result.stdout.encode("ascii")).hexdigest()
        device_digest = adb.shell(
            "sha256sum", f"{LOCATION_MODULE_DIR}/config.properties", check=False
        )
        digest_fields = device_digest.stdout.split()
        if device_digest.returncode != 0 or len(digest_fields) != 2 or digest_fields[0] != digest:
            raise CheckError("current location configuration digest is not stable")
    oracle = {
        "schema_version": "1",
        "config_generation": str(generation),
        "config_sha256": digest,
        "center_latitude_deg": input_values["center_latitude_deg"],
        "center_longitude_deg": input_values["center_longitude_deg"],
        "altitude_ellipsoid_m": input_values["altitude_ellipsoid_m"],
        "altitude_msl_m": input_values["altitude_msl_m"],
        "horizontal_jitter_radius_m": config["horizontal_jitter_radius_m"],
        "speed_max_mps": config["speed_max_mps"],
        "bearing_min_speed_mps": config["bearing_min_speed_mps"],
    }
    content = "".join(f"{key}={oracle[key]}\n" for key in LOCATION_ORACLE_KEYS)
    if len(content.encode("ascii")) > 2048:
        raise CheckError("constructed location oracle is oversized")
    return content, generation, digest


def write_location_oracle(adb: Adb, package: str, content: str) -> None:
    script = (
        "set -eu; umask 077; /system/bin/mkdir -p no_backup; "
        f"/system/bin/rm -f {LOCATION_ORACLE_DEVICE_PATH}; "
        f"/system/bin/cat > {LOCATION_ORACLE_DEVICE_PATH}; "
        f"/system/bin/chmod 600 {LOCATION_ORACLE_DEVICE_PATH}"
    )
    result = adb.shell_input(
        "run-as",
        package,
        "/system/bin/sh",
        "-c",
        script,
        input_text=content,
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        output = result.stdout.lower()
        category = (
            "permission_denied"
            if "permission denied" in output or "not allowed" in output
            else "capability_rejected"
            if "capabil" in output
            else "package_not_debuggable"
            if "not debuggable" in output
            else "unknown_package"
            if "unknown package" in output
            else "data_directory_rejected"
            if "data directory" in output
            else "selinux_context_rejected"
            if "selinux" in output or "context" in output
            else "path_unavailable"
            if "no such file" in output or "not found" in output
            else "run_as_rejected"
            if "run-as" in output
            else "shell_failed"
        )
        raise CheckError(
            "could not deliver the private location oracle through stdin "
            f"(exit={result.returncode}, category={category})"
        )
    uid_result = adb.shell("run-as", package, "/system/bin/id", "-u", check=False)
    file_result = adb.shell(
        "run-as",
        package,
        "/system/bin/stat",
        "-c",
        "%F:%a:%u:%h:%s",
        LOCATION_ORACLE_DEVICE_PATH,
        check=False,
    )
    expected = f"regular file:600:{uid_result.stdout.strip()}:1:{len(content.encode('ascii'))}"
    if (
        uid_result.returncode != 0
        or not uid_result.stdout.strip().isdigit()
        or file_result.returncode != 0
        or file_result.stdout.strip() != expected
    ):
        raise CheckError("delivered location oracle identity is invalid")


def remove_location_oracle(adb: Adb, package: str) -> None:
    result = adb.shell(
        "run-as", package, "/system/bin/rm", "-f", LOCATION_ORACLE_DEVICE_PATH, check=False
    )
    if result.returncode != 0:
        raise CheckError("could not remove the probe location oracle")


def location_oracle_absent(adb: Adb, package: str) -> bool:
    return_codes = tuple(
        adb.shell(
            "run-as",
            package,
            "/system/bin/test",
            predicate,
            path,
            check=False,
        ).returncode
        for predicate, path in LOCATION_ORACLE_PATH_CHECKS
    )
    return location_oracle_absent_from_return_codes(return_codes)


def location_oracle_absent_from_return_codes(return_codes: tuple[int, ...]) -> bool:
    if len(return_codes) != len(LOCATION_ORACLE_PATH_CHECKS) or any(
        return_code not in {0, 1} for return_code in return_codes
    ):
        raise CheckError("could not inspect the probe location oracle path")
    return all(return_code == 1 for return_code in return_codes)


def install_apk(adb: Adb, report: Report, variant: str, path: Path | None = None) -> None:
    path = APKS[variant] if path is None else path
    if not path.is_file():
        raise CheckError(f"probe APK is missing: {path.relative_to(ROOT)}")
    result = adb.run("install", "-r", "-g", str(path), timeout=120, check=False)
    report.kv("install_exit", result.returncode)
    report.kv("install_result", result.stdout.strip())
    if result.returncode != 0 or "Success" not in result.stdout:
        raise CheckError(f"could not install {variant} probe")
    package = variant_package(variant)
    package_path = adb.shell("pm", "path", package, check=False)
    if package_path.returncode != 0 or not package_path.stdout.startswith("package:"):
        raise CheckError(f"installed package is not visible: {package}")
    report.kv("variant", variant)
    report.kv("application_id", package)
    report.kv("device_mutation", "adb install -r independent probe APK")


def install_primary(report: Report, args: argparse.Namespace) -> None:
    install_apk(Adb.select(args.adb_serial, report), report, "primary")


def install_canary(report: Report, args: argparse.Namespace) -> None:
    install_apk(Adb.select(args.adb_serial, report), report, "canary")


def install_canary_poc(report: Report, args: argparse.Namespace) -> None:
    install_apk(Adb.select(args.adb_serial, report), report, "canary", POC_CANARY_APK)
    report.kv("artifact_class", "non_attestable_poc")


def install_primary_poc(report: Report, args: argparse.Namespace) -> None:
    install_apk(Adb.select(args.adb_serial, report), report, "primary", POC_PRIMARY_APK)
    report.kv("artifact_class", "non_attestable_poc")


def state_path(run_id: str, poc: bool = False) -> Path:
    if SAFE_RUN_ID.fullmatch(run_id) is None:
        raise CheckError("run ID has an invalid format")
    root = POC_RUN_STATE if poc else RUN_STATE
    return root / f"{run_id}.json"


def write_private_text(destination: Path, content: str) -> None:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination.parent.chmod(0o700)
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex[:8]}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def write_run_state(run_id: str, values: dict[str, object], poc: bool = False) -> None:
    destination = state_path(run_id, poc)
    write_private_text(destination, json.dumps(values, sort_keys=True) + "\n")


def load_run_state(run_id: str, poc: bool = False) -> dict[str, object]:
    path = state_path(run_id, poc)
    if not path.is_file():
        raise CheckError(f"run metadata is missing: {run_id}")
    decoded: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(decoded, dict) or not all(isinstance(key, str) for key in decoded):
        raise CheckError("run metadata is not a string-keyed object")
    return cast(dict[str, object], decoded)


def read_device_jsonl(adb: Adb, package: str, run_id: str) -> str:
    result = adb.shell(
        "run-as",
        package,
        "/system/bin/cat",
        f"files/runs/{run_id}.jsonl",
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        raise CheckError(f"probe result is unavailable for {run_id}")
    return result.stdout


def result_file_ready(returncode: int, output: str) -> bool:
    if returncode == 0 and not output.strip():
        return True
    if returncode == 1 and not output.strip():
        return False
    raise CheckError("probe run-result readiness check failed")


def parse_device_elapsed_realtime_ms(content: str) -> int:
    fields = content.split()
    if len(fields) != 2:
        raise CheckError("device uptime has an invalid field count")
    if any(re.fullmatch(r"[0-9]+\.[0-9]+", field) is None for field in fields):
        raise CheckError("device uptime has an invalid decimal format")
    try:
        uptime_seconds = Decimal(fields[0])
        idle_seconds = Decimal(fields[1])
    except InvalidOperation as error:
        raise CheckError("device uptime is not decimal") from error
    if (
        not uptime_seconds.is_finite()
        or not idle_seconds.is_finite()
        or uptime_seconds < 0
        or idle_seconds < 0
    ):
        raise CheckError("device uptime is outside the valid range")
    milliseconds = (uptime_seconds * 1_000).to_integral_value(rounding=ROUND_CEILING)
    return int(milliseconds)


def coordinated_start_target(adb: Adb) -> int:
    result = adb.shell("cat", "/proc/uptime", check=False)
    if result.returncode != 0:
        raise CheckError("device uptime is unavailable for coordinated launch")
    return parse_device_elapsed_realtime_ms(result.stdout) + SERVER_VPN_COORDINATED_START_LEAD_MS


def wait_for_run_result_ready(adb: Adb, package: str, run_id: str, started_ns: int) -> int:
    deadline_ns = started_ns + SERVER_VPN_CANARY_READY_TIMEOUT_SECONDS * 1_000_000_000
    while time.monotonic_ns() < deadline_ns:
        result = adb.shell(
            "run-as",
            package,
            "test",
            "-f",
            f"files/runs/{run_id}.jsonl",
            check=False,
        )
        if result_file_ready(result.returncode, result.stdout):
            elapsed_ns = time.monotonic_ns() - started_ns
            return (elapsed_ns + 999_999) // 1_000_000
        time.sleep(0.02)
    raise CheckError("canary probe did not publish its run-result readiness file in time")


def expected_server_vpn_outcome(
    metadata: dict[str, object], mandatory: object, status: object
) -> str:
    if status == "ERROR":
        return "error"
    if status == "UNAVAILABLE":
        return "unavailable"
    if status == "INCONCLUSIVE":
        return "inconclusive"
    if status == "POSITIVE":
        return "present_stock"
    if status != "NEGATIVE":
        raise CheckError(f"unsupported server-VPN detector status: {status}")
    target_active = (
        metadata.get("variant") == "primary"
        and metadata.get("vpn_expected") is True
        and metadata.get("module_expected") is True
    )
    if target_active:
        return "present_sanitized"
    return "absent" if mandatory is True else "present_stock"


def validate_server_vpn_privacy(raw: object, exception: object, line: int) -> None:
    forbidden_keys = {
        "address",
        "dns_server",
        "endpoint",
        "gateway",
        "host",
        "interface_name",
        "installed_packages",
        "object_dump",
        "package_inventory",
        "path",
        "port",
        "process_mapping",
        "raw_object",
        "route",
    }
    ipv4 = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")

    def inspect(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if key in forbidden_keys:
                    raise CheckError(
                        f"server-VPN record contains private key at line {line}: {key}"
                    )
                inspect(nested)
        elif isinstance(value, list):
            for nested in value:
                inspect(nested)
        elif isinstance(value, str):
            if value.startswith("/") or "/data/" in value or "/proc/" in value:
                raise CheckError(f"server-VPN record contains a private path at line {line}")
            if ipv4.search(value):
                raise CheckError(f"server-VPN record contains an IP address at line {line}")
        elif value is not None and not isinstance(value, (int, float, bool)):
            raise CheckError(f"server-VPN record contains an invalid value at line {line}")

    inspect(raw)
    if exception is not None:
        if not isinstance(exception, dict) or set(exception) != {"class", "message"}:
            raise CheckError(f"server-VPN exception shape is invalid at line {line}")
        if not isinstance(exception.get("class"), str) or exception.get("message") is not None:
            raise CheckError(f"server-VPN exception message is not redacted at line {line}")


def validate_jsonl(
    content: str,
    metadata: dict[str, object],
    private_decimal_values: tuple[str, ...] = (),
) -> tuple[list[dict[str, object]], str]:
    if metadata.get("detector_group") == "location":
        return validate_location_jsonl(content, metadata, private_decimal_values)
    records: list[dict[str, object]] = []
    for index, line in enumerate(content.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            decoded: object = json.loads(line)
        except json.JSONDecodeError as error:
            raise CheckError(f"invalid JSONL at line {index}") from error
        if not isinstance(decoded, dict) or not all(isinstance(key, str) for key in decoded):
            raise CheckError(f"JSONL line {index} is not a string-keyed object")
        record = cast(dict[str, object], decoded)
        record_type = record.get("record_type")
        detector_group = metadata.get("detector_group")
        server_vpn = detector_group in SERVER_VPN_GROUPS
        required = set(REQUIRED_FIELDS)
        if server_vpn and record_type == "detector":
            required.add("projection_outcome")
        missing = required - set(record)
        if missing:
            raise CheckError(f"JSONL line {index} misses fields: {sorted(missing)}")
        expected_schema = 2 if server_vpn else 1
        if record["schema_version"] != expected_schema:
            raise CheckError(f"unsupported schema version at line {index}")
        for key in ["run_id", "variant", "application_id"]:
            if record[key] != metadata[key]:
                raise CheckError(f"JSONL {key} mismatch at line {index}")
        if record["vpn_expected"] != metadata["vpn_expected"]:
            raise CheckError(f"JSONL vpn_expected mismatch at line {index}")
        if record["module_expected"] != metadata["module_expected"]:
            raise CheckError(f"JSONL module_expected mismatch at line {index}")
        if record["group"] != metadata["detector_group"]:
            raise CheckError(f"JSONL detector group mismatch at line {index}")
        status = record["status"]
        if record_type == "detector" and status not in DETECTOR_STATUSES:
            raise CheckError(f"invalid detector status at line {index}: {status}")
        if record_type == "summary" and status not in VERDICTS:
            raise CheckError(f"invalid summary verdict at line {index}: {status}")
        if record_type not in {"detector", "summary"}:
            raise CheckError(f"invalid record type at line {index}: {record_type}")
        if server_vpn and record_type == "detector":
            outcome = record["projection_outcome"]
            if outcome not in SERVER_VPN_PROJECTION_OUTCOMES:
                raise CheckError(f"invalid server-VPN projection outcome at line {index}")
            if outcome != expected_server_vpn_outcome(metadata, record["mandatory"], status):
                raise CheckError(f"server-VPN projection outcome mismatch at line {index}")
            validate_server_vpn_privacy(record["raw_observations"], record["exception"], index)
        elif server_vpn and "projection_outcome" in record:
            raise CheckError(f"server-VPN summary has a projection outcome at line {index}")
        if detector_group in {"link", "server-vpn-link"} and record_type == "detector":
            validate_link_raw(record["test_id"], record["raw_observations"], index)
        if record["cleanup_status"] != "complete":
            raise CheckError(f"cleanup failed at line {index}: {record['cleanup_status']}")
        records.append(record)
    summaries = [record for record in records if record["record_type"] == "summary"]
    detectors = [record for record in records if record["record_type"] == "detector"]
    if len(summaries) != 1 or records[-1] is not summaries[0]:
        raise CheckError("probe JSONL must end with exactly one summary")
    if summaries[0].get("detector_count") != len(detectors):
        raise CheckError("summary detector count mismatch")
    if any(not isinstance(record["test_id"], str) for record in detectors):
        raise CheckError("detector test IDs must be strings")
    test_ids = [cast(str, record["test_id"]) for record in detectors]
    if len(test_ids) != len(set(test_ids)):
        raise CheckError("detector test IDs are duplicated")
    detector_group_value = metadata.get("detector_group")
    if isinstance(detector_group_value, str) and detector_group_value in EXPECTED_TEST_IDS:
        expected_ids = EXPECTED_TEST_IDS[detector_group_value]
        actual_ids = set(test_ids)
        if actual_ids != expected_ids:
            missing_ids = sorted(expected_ids - actual_ids)
            unexpected_ids = sorted(actual_ids - expected_ids)
            raise CheckError(
                f"detector ID set mismatch: missing={missing_ids}, unexpected={unexpected_ids}"
            )
    for record in detectors:
        if record["mandatory"] and record["status"] in {"ERROR", "UNAVAILABLE"}:
            raise CheckError(f"mandatory detector failed: {record['test_id']}")
    return records, cast(str, summaries[0]["status"])


def oracle_location_payloads(
    records: list[dict[str, object]],
) -> list[tuple[str, str, dict[str, object]]]:
    values: list[tuple[str, str, dict[str, object]]] = []
    for record in records:
        observation_type = cast(str, record["observation_type"])
        source = cast(str, record["source"])
        if (
            record["record_type"] != "observation"
            or record["status"] != "SUCCESS"
            or observation_type not in LOCATION_SPATIAL_TYPES
        ):
            continue
        payload = cast(dict[str, object], record["payload"])
        scalar = "coordinates_finite" in payload
        batched = "locations" in payload
        if scalar and batched:
            raise CheckError(f"location payload has two object shapes: {observation_type}")
        if scalar:
            values.append((observation_type, source, payload))
        if batched:
            locations = payload["locations"]
            batch_size = payload.get("batch_size")
            if (
                not isinstance(locations, list)
                or not isinstance(batch_size, int)
                or isinstance(batch_size, bool)
                or batch_size != len(locations)
                or not all(isinstance(location, dict) for location in locations)
            ):
                raise CheckError(f"location batch payload is invalid: {observation_type}")
            values.extend(
                (observation_type, source, cast(dict[str, object], location))
                for location in locations
            )
    return values


def validate_oracle_location_payload(payload: dict[str, object]) -> bool:
    failed_flags = sorted(
        flag for flag in LOCATION_SYNTHETIC_REQUIRED_FLAGS if payload.get(flag) is not True
    )
    if failed_flags:
        return False
    if payload.get("outside_expected_center_exclusion") is not False:
        return False
    if not isinstance(payload.get("mock"), bool):
        return False
    for key in (
        "expected_center_distance_m",
        "displacement_from_first_sample_m",
        "time_ms",
        "elapsed_realtime_ns",
    ):
        value = payload.get(key)
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            or float(value) < 0.0
            or (key in {"time_ms", "elapsed_realtime_ns"} and float(value) == 0.0)
        ):
            return False
    if "cross_channel_distance_m" in payload:
        distance = payload["cross_channel_distance_m"]
        if (
            not isinstance(distance, (int, float))
            or isinstance(distance, bool)
            or not math.isfinite(float(distance))
            or float(distance) < 0.0
            or payload.get("cross_channel_consistent") is not True
        ):
            return False
    return True


def validate_location_jsonl(
    content: str,
    metadata: dict[str, object],
    private_decimal_values: tuple[str, ...] = (),
) -> tuple[list[dict[str, object]], str]:
    if contains_private_decimal_values(content, private_decimal_values):
        raise CheckError("location JSONL exposes a private decimal input value")
    records: list[dict[str, object]] = []
    last_monotonic_ns = -1
    for index, line in enumerate(content.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            decoded: object = json.loads(line)
        except json.JSONDecodeError as error:
            raise CheckError(f"invalid location JSONL at line {index}") from error
        if not isinstance(decoded, dict) or not all(isinstance(key, str) for key in decoded):
            raise CheckError(f"location JSONL line {index} is not a string-keyed object")
        record = cast(dict[str, object], decoded)
        missing = LOCATION_REQUIRED_FIELDS - set(record)
        if missing:
            raise CheckError(f"location JSONL line {index} misses fields: {sorted(missing)}")
        if set(record) != LOCATION_REQUIRED_FIELDS:
            raise CheckError(f"location JSONL line {index} has unexpected fields")
        if record["schema_version"] != 4:
            raise CheckError(f"unsupported location schema at line {index}")
        for record_key, metadata_key in [
            ("session_id", "run_id"),
            ("variant", "variant"),
            ("application_id", "application_id"),
        ]:
            if record[record_key] != metadata[metadata_key]:
                raise CheckError(f"location JSONL {record_key} mismatch at line {index}")
        expected_process = cast(str, metadata["application_id"])
        if metadata.get("secondary"):
            expected_process += ":secondary"
        if record["process"] != expected_process:
            raise CheckError(f"location process is invalid at line {index}")
        if not isinstance(record["source"], str) or not record["source"]:
            raise CheckError(f"location source is invalid at line {index}")
        monotonic_ns = record["monotonic_ns"]
        if not isinstance(monotonic_ns, int) or monotonic_ns < last_monotonic_ns:
            raise CheckError(f"location monotonic timestamp regressed at line {index}")
        last_monotonic_ns = monotonic_ns
        if not isinstance(record["wall_time_ms"], int) or record["wall_time_ms"] <= 0:
            raise CheckError(f"location wall timestamp is invalid at line {index}")
        if not isinstance(record["payload"], dict):
            raise CheckError(f"location payload is not an object at line {index}")
        validate_location_privacy(record["payload"], index)
        observation_type = record["observation_type"]
        record_type = record["record_type"]
        status = record["status"]
        if record_type == "observation":
            if observation_type not in LOCATION_OBSERVATION_TYPES:
                raise CheckError(
                    f"invalid location observation type at line {index}: {observation_type}"
                )
            if status not in LOCATION_STATUSES:
                raise CheckError(f"invalid location status at line {index}: {status}")
        elif record_type == "summary":
            if observation_type != "location_summary" or status not in LOCATION_VERDICTS:
                raise CheckError(f"invalid location summary at line {index}")
        else:
            raise CheckError(f"invalid location record type at line {index}: {record_type}")
        if observation_type in {"raw_measurement_event", "navigation_event"}:
            validate_raw_gnss_summary(record["payload"], index)
        if observation_type == "nmea" and "raw_sentence" in record["payload"]:
            raise CheckError(f"NMEA record contains a raw sentence at line {index}")
        records.append(record)

    if not records:
        raise CheckError("location JSONL is empty")
    summaries = [record for record in records if record["record_type"] == "summary"]
    if len(summaries) != 1 or records[-1] is not summaries[0]:
        raise CheckError("location JSONL must end with exactly one summary")
    observations = [record for record in records if record["record_type"] == "observation"]
    actual_types = {cast(str, record["observation_type"]) for record in observations}
    if actual_types != LOCATION_OBSERVATION_TYPES:
        raise CheckError(
            "location observation set mismatch: "
            f"missing={sorted(LOCATION_OBSERVATION_TYPES - actual_types)}, "
            f"unexpected={sorted(actual_types - LOCATION_OBSERVATION_TYPES)}"
        )
    if metadata.get("variant") == "primary":
        for record in observations:
            if record["observation_type"] not in LOCATION_GMS_SPATIAL_TYPES | {
                "gms_location_availability"
            }:
                continue
            record_payload = cast(dict[str, object], record["payload"])
            if (
                record["status"] != "UNAVAILABLE"
                or record_payload.get("reason") != "variant_not_enabled"
            ):
                raise CheckError("primary probe emitted an enabled GMS observation")
    summary = summaries[0]
    payload = cast(dict[str, object], summary["payload"])
    missing_summary = LOCATION_SUMMARY_KEYS - set(payload)
    if missing_summary:
        raise CheckError(f"location summary misses fields: {sorted(missing_summary)}")
    if payload["configured_raw_gnss_mode"] != metadata.get("raw_gnss_mode"):
        raise CheckError("location summary Raw GNSS mode mismatch")
    if payload["observation_window_ms"] != metadata.get("observation_window_ms"):
        raise CheckError("location summary observation window mismatch")
    oracle_required = metadata.get("location_oracle_required") is True
    if payload["oracle_required"] is not oracle_required or payload["oracle_unlinked"] is not True:
        raise CheckError("location summary oracle lifecycle mismatch")
    if oracle_required:
        if (
            payload["oracle_status"] != "loaded"
            or payload["expected_config_generation"] != metadata.get("expected_config_generation")
            or payload["expected_config_sha256"] != metadata.get("expected_config_sha256")
        ):
            raise CheckError("location summary oracle identity mismatch")
        if (
            not isinstance(payload["expected_config_generation"], int)
            or payload["expected_config_generation"] <= 0
            or not isinstance(payload["expected_config_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", payload["expected_config_sha256"]) is None
        ):
            raise CheckError("location summary oracle identity is invalid")
        expected_digest = payload["expected_config_sha256"]
        if (metadata.get("poc") is True) != (expected_digest == POC_UNATTESTED_CONFIG_DIGEST):
            raise CheckError("location summary oracle attestation mode mismatch")
        spatial_payloads = oracle_location_payloads(observations)
        spatial_failure = any(
            not validate_oracle_location_payload(spatial_payload)
            for _observation_type, _source, spatial_payload in spatial_payloads
        )
        platform_payloads = [
            item for item in spatial_payloads if item[0] in LOCATION_PLATFORM_SPATIAL_TYPES
        ]
        gms_payloads = [item for item in spatial_payloads if item[0] in LOCATION_GMS_SPATIAL_TYPES]
        spatial_failure |= not platform_payloads
        spatial_failure |= metadata.get("variant") == "canary" and not gms_payloads
        if metadata.get("variant") == "canary":
            gms_sources = {source for _type, source, _payload in gms_payloads}
            spatial_failure |= gms_sources != LOCATION_GMS_REQUIRED_OBJECT_SOURCES
        if summary["status"] == "PASS" and spatial_failure:
            raise CheckError("location session passed with invalid private-oracle object delivery")
        if spatial_failure and summary["status"] not in {"FAIL", "ERROR"}:
            raise CheckError("private-oracle object failure did not fail the location session")
    elif (
        payload["oracle_status"] != "not_requested"
        or payload["expected_config_generation"] is not None
        or payload["expected_config_sha256"] is not None
    ):
        raise CheckError("location summary unexpectedly contains an oracle identity")
    if payload["cleanup_status"] != "complete":
        raise CheckError("location callback cleanup failed")
    if payload["session_verdict"] != summary["status"]:
        raise CheckError("location session verdict mismatch")
    for key in [
        "measurement_event_count",
        "navigation_event_count",
        "ordinary_location_event_count",
        "location_batch_event_count",
        "gnss_status_event_count",
        "nmea_event_count",
        "gms_last_known_location_count",
        "gms_current_location_count",
        "gms_callback_location_count",
        "gms_listener_location_count",
        "gms_pending_intent_location_count",
        "gms_total_location_count",
        "platform_location_sample_count",
        "platform_gms_comparison_count",
        "platform_gms_object_comparison_count",
    ]:
        if not isinstance(payload[key], int) or cast(int, payload[key]) < 0:
            raise CheckError(f"location summary count is invalid: {key}")
    gms_component_count = sum(
        cast(int, payload[key])
        for key in [
            "gms_last_known_location_count",
            "gms_current_location_count",
            "gms_callback_location_count",
            "gms_listener_location_count",
            "gms_pending_intent_location_count",
        ]
    )
    if gms_component_count != payload["gms_total_location_count"]:
        raise CheckError("GMS location summary count mismatch")
    comparison_count = cast(int, payload["platform_gms_comparison_count"])
    maximum_distance = payload["platform_gms_max_distance_m"]
    threshold = payload["platform_gms_consistency_threshold_m"]
    consistent = payload["platform_gms_consistent"]
    if (
        not isinstance(threshold, (int, float))
        or isinstance(threshold, bool)
        or not math.isfinite(float(threshold))
        or float(threshold) <= 0.0
    ):
        raise CheckError("platform/GMS consistency threshold is invalid")
    if comparison_count == 0:
        if maximum_distance is not None or consistent is not None:
            raise CheckError("platform/GMS empty comparison state is invalid")
    elif (
        not isinstance(maximum_distance, (int, float))
        or isinstance(maximum_distance, bool)
        or not math.isfinite(float(maximum_distance))
        or float(maximum_distance) < 0.0
        or not isinstance(consistent, bool)
        or consistent != (float(maximum_distance) <= float(threshold))
    ):
        raise CheckError("platform/GMS comparison state is invalid")
    object_comparison_count = cast(int, payload["platform_gms_object_comparison_count"])
    maximum_object_distance = payload["platform_gms_max_object_distance_m"]
    object_consistent = payload["platform_gms_object_consistent"]
    if object_comparison_count == 0:
        if maximum_object_distance is not None or object_consistent is not None:
            raise CheckError("platform/GMS empty object comparison state is invalid")
    elif (
        not isinstance(maximum_object_distance, (int, float))
        or isinstance(maximum_object_distance, bool)
        or not math.isfinite(float(maximum_object_distance))
        or float(maximum_object_distance) < 0.0
        or not isinstance(object_consistent, bool)
        or object_consistent != (float(maximum_object_distance) <= float(threshold))
    ):
        raise CheckError("platform/GMS object comparison state is invalid")
    surface_complete = payload["gms_required_surface_complete"]
    if not isinstance(surface_complete, bool):
        raise CheckError("GMS required-surface state is invalid")
    if metadata.get("variant") == "primary":
        if (
            payload["gms_client_required"] is not False
            or payload["gms_client_status"] != "not_enabled"
            or surface_complete is not True
            or payload["gms_total_location_count"] != 0
            or comparison_count != 0
        ):
            raise CheckError("primary probe unexpectedly enabled the GMS client")
    else:
        if payload["gms_client_required"] is not True or payload["gms_client_status"] not in {
            "created",
            "started",
            "complete",
            "failed",
        }:
            raise CheckError("canary GMS client state is invalid")
        gms_failure = (
            not surface_complete
            or any(
                payload[key] == 0
                for key in (
                    "gms_last_known_location_count",
                    "gms_current_location_count",
                    "gms_callback_location_count",
                    "gms_listener_location_count",
                    "gms_pending_intent_location_count",
                )
            )
            or comparison_count == 0
            or consistent is not True
            or object_comparison_count == 0
            or object_consistent is not True
        )
        if summary["status"] == "PASS" and gms_failure:
            raise CheckError("canary passed with incomplete or inconsistent GMS coverage")
        if gms_failure and summary["status"] not in {"FAIL", "ERROR"}:
            raise CheckError("canary GMS failure did not fail the session")
    if metadata.get("raw_gnss_mode") == "blocked":
        if payload["measurement_event_count"] != 0 or payload["navigation_event_count"] != 0:
            raise CheckError("blocked Raw GNSS mode delivered an event")
        if payload["unexpected_event_detected"] is not False:
            raise CheckError("blocked Raw GNSS mode reported an unexpected event")
    return records, cast(str, summary["status"])


def validate_location_privacy(payload: object, line: int) -> None:
    def inspect(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if not isinstance(key, str):
                    raise CheckError(f"location payload key is invalid at line {line}")
                if key in LOCATION_PRIVATE_KEYS or key in RAW_GNSS_PRIVATE_KEYS:
                    raise CheckError(f"location payload exposes a private field at line {line}")
                inspect(nested)
        elif isinstance(value, list):
            for nested in value:
                inspect(nested)
        elif isinstance(value, str):
            if re.search(r"\$[A-Z]", value):
                raise CheckError(f"location payload exposes a raw NMEA sentence at line {line}")
        elif isinstance(value, float):
            if not math.isfinite(value):
                raise CheckError(f"location payload contains a non-finite number at line {line}")
        elif value is not None and not isinstance(value, (int, bool)):
            raise CheckError(f"location payload value is invalid at line {line}")

    inspect(payload)


def validate_raw_gnss_summary(payload: object, line: int) -> None:
    def inspect(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if not isinstance(key, str):
                    raise CheckError(f"Raw GNSS payload key is invalid at line {line}")
                if key in RAW_GNSS_PRIVATE_KEYS:
                    raise CheckError(f"Raw GNSS payload exposes {key} at line {line}")
                inspect(nested)
        elif isinstance(value, list):
            for nested in value:
                inspect(nested)
        elif value is not None and not isinstance(value, (str, int, float, bool)):
            raise CheckError(f"Raw GNSS payload value is invalid at line {line}")

    inspect(payload)


def serialize_location_records(records: list[dict[str, object]]) -> str:
    for line, record in enumerate(records, start=1):
        validate_location_privacy(record.get("payload"), line)
    return "".join(json.dumps(record, sort_keys=True) + "\n" for record in records)


def validate_link_raw(test_id: object, raw: object, line: int) -> None:
    if not isinstance(test_id, str) or not test_id.startswith("link."):
        raise CheckError(f"invalid link detector identity at line {line}")
    if not isinstance(raw, dict) or not isinstance(raw.get("comparison"), dict):
        raise CheckError(f"link detector lacks a comparison object at line {line}")
    if set(raw) - {"comparison", "diagnostic"}:
        raise CheckError(f"link detector has unexpected top-level observations at line {line}")
    if "diagnostic" in raw and not test_id.endswith(("signal_strength", "lifecycle")):
        raise CheckError(f"link detector has an unsupported diagnostic at line {line}")

    def inspect(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if not isinstance(key, str) or key not in LINK_RAW_KEYS:
                    raise CheckError(f"link detector has a non-private key at line {line}: {key}")
                inspect(nested)
        elif isinstance(value, list):
            for nested in value:
                inspect(nested)
        elif isinstance(value, str) and value not in LINK_RAW_STRINGS:
            raise CheckError(f"link detector has a non-private string at line {line}")
        elif value is not None and not isinstance(value, (str, int, bool)):
            raise CheckError(f"link detector has an invalid JSON value at line {line}")

    inspect(raw)


def parser_self_test() -> None:
    coordinated_launch_self_test()
    concurrent_source = inspect.getsource(run_concurrent_server_vpn)
    required_coordination = {"coordinated_start_target", "wait_for_run_result_ready"}
    if not required_coordination.issubset(run_concurrent_server_vpn.__code__.co_names):
        raise CheckError("concurrent probe does not use the tested readiness handshake")
    if '"-W"' in concurrent_source:
        raise CheckError("concurrent probe uses a blocking Activity launch")
    if (
        "ThreadPoolExecutor" in concurrent_source
        or "execute_concurrent_launch_pair" in concurrent_source
    ):
        raise CheckError("concurrent probe races Activity launch requests")
    for operation in (run_probe, run_concurrent_server_vpn):
        if "ensure_device_ui_ready" not in operation.__code__.co_names:
            raise CheckError(f"{operation.__name__} has no device UI readiness gate")
    metadata: dict[str, object] = {
        "run_id": "probe-20260821T000000Z-01234567",
        "variant": "primary",
        "application_id": PACKAGES["primary"],
        "vpn_expected": False,
        "module_expected": False,
        "detector_group": "schema",
    }
    base: dict[str, object] = {
        "schema_version": 1,
        "run_id": metadata["run_id"],
        "variant": metadata["variant"],
        "application_id": metadata["application_id"],
        "process": PACKAGES["primary"],
        "vpn_expected": False,
        "module_expected": False,
        "group": "schema",
        "mandatory": True,
        "raw_observations": {},
        "exception": None,
        "started_at": "2026-08-21T00:00:00Z",
        "elapsed_ms": 0,
        "cleanup_status": "complete",
    }
    detector = {
        **base,
        "record_type": "detector",
        "test_id": "schema.self_test",
        "status": "NEGATIVE",
    }
    summary = {
        **base,
        "record_type": "summary",
        "test_id": "summary",
        "status": "NO_PUBLIC_VPN_SIGNAL",
        "detector_count": 1,
    }
    content = json.dumps(detector) + "\n" + json.dumps(summary) + "\n"
    records, verdict = validate_jsonl(content, metadata)
    if len(records) != 2 or verdict != "NO_PUBLIC_VPN_SIGNAL":
        raise CheckError("probe JSONL self-test did not accept a valid run")
    detector["cleanup_status"] = "failed"
    invalid = json.dumps(detector) + "\n" + json.dumps(summary) + "\n"
    try:
        validate_jsonl(invalid, metadata)
    except CheckError:
        pass
    else:
        raise CheckError("probe JSONL self-test accepted cleanup failure")
    server_metadata: dict[str, object] = {
        "run_id": "probe-20260821T000001Z-01234567",
        "variant": "primary",
        "application_id": PACKAGES["primary"],
        "vpn_expected": True,
        "module_expected": True,
        "detector_group": "server-vpn-diagnostics",
    }
    server_base: dict[str, object] = {
        "schema_version": 2,
        "run_id": server_metadata["run_id"],
        "variant": server_metadata["variant"],
        "application_id": server_metadata["application_id"],
        "process": PACKAGES["primary"],
        "vpn_expected": True,
        "module_expected": True,
        "group": "server-vpn-diagnostics",
        "exception": None,
        "started_at": "2026-08-21T00:00:01Z",
        "elapsed_ms": 0,
        "cleanup_status": "complete",
    }
    server_detectors: list[dict[str, object]] = []
    for test_id in sorted(EXPECTED_TEST_IDS["server-vpn-diagnostics"]):
        lifecycle = test_id == "diagnostics.lifecycle"
        mandatory = lifecycle or test_id == "diagnostics.connectivity_report"
        server_detectors.append(
            {
                **server_base,
                "record_type": "detector",
                "test_id": test_id,
                "mandatory": mandatory,
                "status": "NEGATIVE" if lifecycle else "INCONCLUSIVE",
                "projection_outcome": ("present_sanitized" if lifecycle else "inconclusive"),
                "raw_observations": {},
            }
        )
    server_summary = {
        **server_base,
        "record_type": "summary",
        "test_id": "summary",
        "mandatory": True,
        "status": "INCONCLUSIVE",
        "raw_observations": {},
        "detector_count": len(server_detectors),
    }
    server_content = "".join(
        json.dumps(item) + "\n" for item in [*server_detectors, server_summary]
    )
    validate_jsonl(server_content, server_metadata)

    invalid_server = json.loads(server_content.splitlines()[0])
    invalid_server["projection_outcome"] = "present_stock"
    invalid_content = "\n".join(
        [
            json.dumps(invalid_server),
            *server_content.splitlines()[1:],
        ]
    )
    try:
        validate_jsonl(invalid_content + "\n", server_metadata)
    except CheckError:
        pass
    else:
        raise CheckError("server-VPN self-test accepted a mismatched projection outcome")

    invalid_server = json.loads(server_content.splitlines()[0])
    invalid_server["raw_observations"] = {"endpoint": "192.0.2.1"}
    invalid_content = "\n".join(
        [
            json.dumps(invalid_server),
            *server_content.splitlines()[1:],
        ]
    )
    try:
        validate_jsonl(invalid_content + "\n", server_metadata)
    except CheckError:
        pass
    else:
        raise CheckError("server-VPN self-test accepted a private network endpoint")
    validate_link_raw(
        "link.active.signal_strength",
        {
            "comparison": {"values": [{"capabilities_present": True, "specified": True}]},
            "diagnostic": [{"value": -34}],
        },
        1,
    )
    try:
        validate_link_raw(
            "link.active.interface",
            {"comparison": {"interface_name": "tun0"}},
            1,
        )
    except CheckError:
        pass
    else:
        raise CheckError("probe JSONL self-test accepted a raw network identifier")
    private_oracle_self_test()
    location_parser_self_test()


def coordinated_launch_self_test() -> None:
    if not result_file_ready(0, "") or result_file_ready(1, ""):
        raise CheckError("probe readiness predicate self-test failed")
    for returncode, output in ((0, "unexpected"), (1, "run-as failed"), (2, "")):
        try:
            result_file_ready(returncode, output)
        except CheckError:
            pass
        else:
            raise CheckError("probe readiness predicate accepted an ambiguous result")
    if parse_device_elapsed_realtime_ms("123.4567 789.0000\n") != 123_457:
        raise CheckError("device uptime parser self-test failed")
    for invalid_uptime in ("", "1.0", "-1.0 0.0", "1e3 0.0", "nan 0.0"):
        try:
            parse_device_elapsed_realtime_ms(invalid_uptime)
        except CheckError:
            pass
        else:
            raise CheckError("device uptime parser accepted an invalid value")
    result_store_source = (
        ROOT / "components/probe/src/main/java/dev/zygveil/probe/detector/ResultStore.java"
    ).read_text(encoding="utf-8")
    for marker in ("new FileOutputStream(destination, false)", "stream.getFD().sync()"):
        if marker not in result_store_source:
            raise CheckError("probe readiness-file initialization marker is missing")
    run_config_source = (
        ROOT / "components/probe/src/main/java/dev/zygveil/probe/detector/RunConfig.java"
    ).read_text(encoding="utf-8")
    for marker in ("awaitCoordinatedStart", "SystemClock.elapsedRealtime()"):
        if marker not in run_config_source:
            raise CheckError("probe coordinated-start marker is missing")
    copy_to_start = run_config_source.find("public void copyTo(Intent intent)")
    copy_to_end = run_config_source.find("public boolean isServerVpnGroup()", copy_to_start)
    if copy_to_start < 0 or copy_to_end < 0:
        raise CheckError("probe callback-copy boundary is missing")
    if (
        "EXTRA_COORDINATED_START_ELAPSED_REALTIME_MS"
        in run_config_source[copy_to_start:copy_to_end]
    ):
        raise CheckError("probe callback copy propagates the initial rendezvous target")


def private_oracle_self_test() -> None:
    if LOCATION_ORACLE_PATH_CHECKS != (
        ("-e", LOCATION_ORACLE_DEVICE_PATH),
        ("-L", LOCATION_ORACLE_DEVICE_PATH),
    ):
        raise CheckError("private location oracle path checks changed")
    if not location_oracle_absent_from_return_codes((1, 1)):
        raise CheckError("private location oracle absence self-test failed")
    if location_oracle_absent_from_return_codes((0, 1)):
        raise CheckError("private location oracle regular-file self-test failed")
    if location_oracle_absent_from_return_codes((1, 0)):
        raise CheckError("private location oracle symlink self-test failed")
    try:
        location_oracle_absent_from_return_codes((127, 1))
    except CheckError:
        pass
    else:
        raise CheckError("private location oracle inspection-error self-test failed")
    if not same_binary64_decimal("12.3456789", "12.345678899999999"):
        raise CheckError("private location oracle round-trip self-test failed")
    if same_binary64_decimal("12.3456789", "12.3456788"):
        raise CheckError("private location oracle distinct-value self-test failed")
    if same_binary64_decimal("nan", "nan"):
        raise CheckError("private location oracle non-finite self-test failed")
    identity_config = {"enabled": "true", "raw_gnss_mode": "blocked"}
    identity_status = {
        "module_state": "active",
        "runtime_state": "active",
        "control_state": "applied",
        "reason": "none",
        "raw_gnss_mode": "blocked",
        "boot_config_generation": "6",
        "system_server_pid": "1234",
        "system_server_start_ticks": "424242",
        "boot_id": "12345678-1234-1234-1234-123456789abc",
        "persisted_generation": "8",
        "published_generation": "8",
        "applied_generation": "8",
    }
    identity_args = (
        "blocked",
        "1234",
        "424242",
        "12345678-1234-1234-1234-123456789abc",
        8,
    )
    if not location_oracle_runtime_identity_matches(
        identity_config, identity_status, *identity_args
    ):
        raise CheckError("active private oracle identity self-test failed")
    disabled_status = dict(
        identity_status,
        module_state="inactive",
        runtime_state="unavailable",
        control_state="unavailable",
        reason="runtime_inactive",
        boot_config_generation="0",
        persisted_generation="8",
        published_generation="0",
        applied_generation="0",
        system_server_pid="0",
        system_server_start_ticks="0",
        boot_id="unavailable",
    )
    disabled_identity_args = ("passthrough", *identity_args[1:])
    if not location_oracle_runtime_identity_matches(
        identity_config, disabled_status, *disabled_identity_args
    ):
        raise CheckError("retained activation private oracle identity self-test failed")
    if not location_oracle_runtime_identity_matches(
        dict(identity_config, enabled="false"), disabled_status, *disabled_identity_args
    ):
        raise CheckError("waiting config private oracle identity self-test failed")
    if location_oracle_runtime_identity_matches(
        identity_config,
        dict(disabled_status, control_state="applied"),
        *disabled_identity_args,
    ):
        raise CheckError("invalid disabled private oracle identity self-test failed")

    content = (
        "schema_version=1\n"
        "center_latitude_deg=66.12345678\n"
        "center_longitude_deg=-11.87654321\n"
        "altitude_ellipsoid_m=123.125\n"
        "altitude_msl_m=99.875\n"
    )
    poc_status = (
        "schema_version=1\nmodule_state=active\nruntime_state=active\n"
        "control_state=applied\nreason=none\nraw_gnss_mode=blocked\n"
        "boot_config_generation=6\npersisted_generation=8\npublished_generation=8\n"
        "applied_generation=8\nsystem_server_pid=1234\n"
        "system_server_start_ticks=424242\n"
        "boot_id=12345678-1234-1234-1234-123456789abc\n"
        + "\n".join(content.splitlines()[1:])
        + "\n"
    )
    if parse_poc_current_oracle_input(poc_status) != parse_properties(
        content, expected=set(LOCATION_ORACLE_INPUT_KEYS), label="location oracle self-test"
    ):
        raise CheckError("current POC oracle self-test changed the live point")
    pending_status = (
        poc_status.replace("control_state=applied", "control_state=saved_pending_upstream")
        .replace("persisted_generation=8", "persisted_generation=9")
        .replace("published_generation=8", "published_generation=9")
    )
    try:
        parse_poc_current_oracle_input(pending_status)
    except CheckError:
        pass
    else:
        raise CheckError("current POC oracle self-test accepted a pending generation")

    state_root = ROOT / ".state"
    state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".oracle-self-test-", dir=state_root)
    path = Path(name)
    link = path.with_name(path.name + ".link")
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, content.encode("ascii"))
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        values = read_private_oracle_input(str(path))
        if set(values) != set(LOCATION_ORACLE_INPUT_KEYS):
            raise CheckError("private location oracle self-test changed the schema")
        os.chmod(path, 0o640)
        try:
            read_private_oracle_input(str(path))
        except CheckError:
            pass
        else:
            raise CheckError("private location oracle mode self-test failed")
        os.chmod(path, 0o600)
        link.symlink_to(path)
        try:
            read_private_oracle_input(str(link))
        except CheckError:
            pass
        else:
            raise CheckError("private location oracle symlink self-test failed")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        link.unlink(missing_ok=True)
        path.unlink(missing_ok=True)


def enforce_location_verdict(
    metadata: dict[str, object], verdict: str, records: list[dict[str, object]]
) -> None:
    if metadata.get("detector_group") != "location" or verdict == "PASS":
        return
    if metadata.get("expected_spatial_mismatch") is not True:
        raise CheckError(f"location probe verdict is {verdict}")
    summaries = [record for record in records if record["record_type"] == "summary"]
    summary_payload = cast(dict[str, object], summaries[0]["payload"])
    spatial_payloads = oracle_location_payloads(
        [record for record in records if record["record_type"] == "observation"]
    )
    outside = sum(
        payload.get("outside_expected_center_exclusion") is True
        for _observation_type, _source, payload in spatial_payloads
    )
    observation_errors = sum(
        record["status"] == "ERROR" for record in records if record["record_type"] == "observation"
    )
    if (
        verdict != "FAIL"
        or not spatial_payloads
        or outside == 0
        or observation_errors != 0
        or summary_payload.get("cleanup_status") != "complete"
        or summary_payload.get("unexpected_event_detected") is not False
    ):
        raise CheckError("expected stock spatial mismatch is not cleanly isolated")


def location_parser_self_test() -> None:
    def synthetic_payload() -> dict[str, object]:
        return {
            "provider": "fused",
            "time_ms": 1_777_000_000_001,
            "elapsed_realtime_ns": 100,
            "mock": False,
            "complete": True,
            "coordinates_finite": True,
            "latitude_in_range": True,
            "longitude_in_range": True,
            "expected_center_distance_m": 0.4,
            "within_expected_radius": True,
            "outside_expected_center_exclusion": False,
            "displacement_from_first_sample_m": 0.0,
            "has_accuracy": True,
            "has_altitude": True,
            "has_vertical_accuracy": True,
            "has_msl_altitude": True,
            "has_msl_altitude_accuracy": True,
            "has_speed": True,
            "has_speed_accuracy": True,
            "has_bearing": False,
            "has_bearing_accuracy": False,
            "numeric_fields_finite": True,
            "accuracy_non_negative": True,
            "vertical_accuracy_non_negative": True,
            "speed_non_negative": True,
            "bearing_in_range": True,
            "bearing_presence_consistent": True,
            "speed_within_expected_bound": True,
            "stationary_bearing_absent": True,
            "altitude_pair_consistent": True,
        }

    metadata: dict[str, object] = {
        "run_id": "probe-20260821T000000Z-89abcdef",
        "variant": "primary",
        "application_id": PACKAGES["primary"],
        "detector_group": "location",
        "secondary": False,
        "raw_gnss_mode": "blocked",
        "observation_window_ms": 5_000,
        "location_oracle_required": True,
        "expected_config_generation": 42,
        "expected_config_sha256": "a" * 64,
    }
    records: list[dict[str, object]] = []
    for index, observation_type in enumerate(sorted(LOCATION_OBSERVATION_TYPES), start=1):
        payload: dict[str, object] = {}
        status = "SUCCESS"
        if observation_type == "last_known":
            payload = synthetic_payload()
        elif observation_type == "location_batch":
            payload = {"batch_size": 1, "locations": [synthetic_payload()]}
        elif observation_type in LOCATION_GMS_SPATIAL_TYPES | {"gms_location_availability"}:
            status = "UNAVAILABLE"
            payload = {"reason": "variant_not_enabled"}
        records.append(
            {
                "schema_version": 4,
                "record_type": "observation",
                "session_id": metadata["run_id"],
                "variant": metadata["variant"],
                "application_id": metadata["application_id"],
                "process": PACKAGES["primary"],
                "observation_type": observation_type,
                "monotonic_ns": index,
                "wall_time_ms": 1_777_000_000_000 + index,
                "source": "self-test",
                "status": status,
                "payload": payload,
            }
        )
    summary_payload: dict[str, object] = {
        "configured_raw_gnss_mode": "blocked",
        "oracle_required": True,
        "oracle_status": "loaded",
        "oracle_unlinked": True,
        "expected_config_generation": 42,
        "expected_config_sha256": "a" * 64,
        "reported_measurement_capability": True,
        "reported_navigation_capability": True,
        "measurement_registration_result": "REGISTERED",
        "navigation_registration_result": "REGISTERED",
        "measurement_callback_status": "READY",
        "navigation_callback_status": "READY",
        "measurement_event_count": 0,
        "navigation_event_count": 0,
        "first_measurement_event_latency_ms": None,
        "first_navigation_event_latency_ms": None,
        "observation_window_ms": 5_000,
        "unexpected_event_detected": False,
        "ordinary_location_event_count": 1,
        "location_batch_event_count": 1,
        "gnss_status_event_count": 1,
        "nmea_event_count": 1,
        "gms_client_required": False,
        "gms_client_status": "not_enabled",
        "gms_required_surface_complete": True,
        "gms_last_known_location_count": 0,
        "gms_current_location_count": 0,
        "gms_callback_location_count": 0,
        "gms_listener_location_count": 0,
        "gms_pending_intent_location_count": 0,
        "gms_total_location_count": 0,
        "platform_location_sample_count": 1,
        "platform_gms_comparison_count": 0,
        "platform_gms_max_distance_m": None,
        "platform_gms_consistency_threshold_m": 25.0,
        "platform_gms_consistent": None,
        "platform_gms_object_comparison_count": 0,
        "platform_gms_max_object_distance_m": None,
        "platform_gms_object_consistent": None,
        "cleanup_status": "complete",
        "cleanup_failures": [],
        "session_verdict": "PASS",
    }
    records.append(
        {
            "schema_version": 4,
            "record_type": "summary",
            "session_id": metadata["run_id"],
            "variant": metadata["variant"],
            "application_id": metadata["application_id"],
            "process": PACKAGES["primary"],
            "observation_type": "location_summary",
            "monotonic_ns": len(records) + 1,
            "wall_time_ms": 1_777_000_000_999,
            "source": "session",
            "status": "PASS",
            "payload": summary_payload,
        }
    )
    content = "".join(json.dumps(record) + "\n" for record in records)
    accepted, verdict = validate_location_jsonl(content, metadata)
    if verdict != "PASS" or len(accepted) != len(records):
        raise CheckError("location JSONL self-test did not accept a valid run")

    canary_records = cast(list[dict[str, object]], json.loads(json.dumps(records)))
    for record in canary_records:
        record["variant"] = "canary"
        record["application_id"] = PACKAGES["canary"]
        record["process"] = PACKAGES["canary"]
        observation_type = cast(str, record["observation_type"])
        if observation_type in {
            "gms_last_known",
            "gms_current",
            "gms_location_update",
        }:
            record["status"] = "SUCCESS"
            record["payload"] = synthetic_payload()
            record["source"] = {
                "gms_last_known": "gms_fused.last.default",
                "gms_current": "gms_fused.current.priority",
                "gms_location_update": "gms_fused.update.listener",
            }[observation_type]
        elif observation_type in {"gms_location_batch", "gms_pending_intent"}:
            record["status"] = "SUCCESS"
            record["payload"] = {"batch_size": 1, "locations": [synthetic_payload()]}
            record["source"] = (
                "gms_fused.update.callback"
                if observation_type == "gms_location_batch"
                else "gms_fused.update.pending_intent"
            )
        elif observation_type == "gms_location_availability":
            record["status"] = "SUCCESS"
            record["payload"] = {"location_available": True}
    expanded_canary_records: list[dict[str, object]] = []
    for record in canary_records:
        expanded_canary_records.append(record)
        alternate_source = {
            "gms_last_known": "gms_fused.last.request",
            "gms_current": "gms_fused.current.request",
        }.get(cast(str, record["observation_type"]))
        if alternate_source is not None:
            alternate = cast(dict[str, object], json.loads(json.dumps(record)))
            alternate["source"] = alternate_source
            expanded_canary_records.append(alternate)
    canary_records = expanded_canary_records
    canary_summary = cast(dict[str, object], canary_records[-1]["payload"])
    canary_summary.update(
        {
            "gms_client_required": True,
            "gms_client_status": "complete",
            "gms_required_surface_complete": True,
            "gms_last_known_location_count": 2,
            "gms_current_location_count": 2,
            "gms_callback_location_count": 1,
            "gms_listener_location_count": 1,
            "gms_pending_intent_location_count": 1,
            "gms_total_location_count": 7,
            "platform_gms_comparison_count": 1,
            "platform_gms_max_distance_m": 0.1,
            "platform_gms_consistent": True,
            "platform_gms_object_comparison_count": 1,
            "platform_gms_max_object_distance_m": 0.1,
            "platform_gms_object_consistent": True,
        }
    )
    canary_metadata = {
        **metadata,
        "variant": "canary",
        "application_id": PACKAGES["canary"],
    }
    canary_content = "".join(json.dumps(record) + "\n" for record in canary_records)
    validate_location_jsonl(canary_content, canary_metadata)

    invalid_canary = cast(list[dict[str, object]], json.loads(json.dumps(canary_records)))
    invalid_canary_summary = cast(dict[str, object], invalid_canary[-1]["payload"])
    invalid_canary_summary["gms_listener_location_count"] = 0
    invalid_canary_summary["gms_total_location_count"] = 6
    try:
        validate_location_jsonl(
            "".join(json.dumps(record) + "\n" for record in invalid_canary),
            canary_metadata,
        )
    except CheckError:
        pass
    else:
        raise CheckError("location JSONL self-test accepted a missing GMS delivery surface")

    invalid_canary = cast(list[dict[str, object]], json.loads(json.dumps(canary_records)))
    listener_record = next(
        record for record in invalid_canary if record["observation_type"] == "gms_location_update"
    )
    listener_record["source"] = "gms_fused.update.callback"
    try:
        validate_location_jsonl(
            "".join(json.dumps(record) + "\n" for record in invalid_canary),
            canary_metadata,
        )
    except CheckError:
        pass
    else:
        raise CheckError("location JSONL self-test accepted an unbound GMS listener count")

    invalid_canary = cast(list[dict[str, object]], json.loads(json.dumps(canary_records)))
    invalid_canary_summary = cast(dict[str, object], invalid_canary[-1]["payload"])
    invalid_canary_summary["platform_gms_max_object_distance_m"] = 30.0
    invalid_canary_summary["platform_gms_object_consistent"] = False
    try:
        validate_location_jsonl(
            "".join(json.dumps(record) + "\n" for record in invalid_canary),
            canary_metadata,
        )
    except CheckError:
        pass
    else:
        raise CheckError("location JSONL self-test accepted inconsistent GMS object state")

    invalid_canary = cast(list[dict[str, object]], json.loads(json.dumps(canary_records)))
    outside_record = next(
        record for record in invalid_canary if record["observation_type"] == "gms_last_known"
    )
    cast(dict[str, object], outside_record["payload"])["within_expected_radius"] = False
    try:
        validate_location_jsonl(
            "".join(json.dumps(record) + "\n" for record in invalid_canary),
            canary_metadata,
        )
    except CheckError:
        pass
    else:
        raise CheckError("location JSONL self-test accepted a physical GMS coordinate")

    failed_canary = cast(list[dict[str, object]], json.loads(json.dumps(invalid_canary)))
    failed_canary[-1]["status"] = "FAIL"
    failed_canary_summary = cast(dict[str, object], failed_canary[-1]["payload"])
    failed_canary_summary["session_verdict"] = "FAIL"
    _failed_records, failed_verdict = validate_location_jsonl(
        "".join(json.dumps(record) + "\n" for record in failed_canary),
        canary_metadata,
    )
    if failed_verdict != "FAIL":
        raise CheckError("location JSONL self-test did not preserve a spatial FAIL verdict")

    poc_records = cast(list[dict[str, object]], json.loads(json.dumps(records)))
    poc_payload = cast(dict[str, object], poc_records[-1]["payload"])
    poc_payload["expected_config_sha256"] = POC_UNATTESTED_CONFIG_DIGEST
    poc_metadata = {
        **metadata,
        "poc": True,
        "expected_config_sha256": POC_UNATTESTED_CONFIG_DIGEST,
    }
    validate_location_jsonl(
        "".join(json.dumps(record) + "\n" for record in poc_records), poc_metadata
    )
    try:
        validate_location_jsonl(content, poc_metadata)
    except CheckError:
        pass
    else:
        raise CheckError("location JSONL self-test accepted an attested digest in POC mode")
    enforce_location_verdict(metadata, verdict, records)
    try:
        enforce_location_verdict(metadata, "FAIL", records)
    except CheckError:
        pass
    else:
        raise CheckError("location verdict self-test accepted a failed session")
    restored_spatial = cast(
        dict[str, object],
        json.loads(
            json.dumps(
                next(
                    record
                    for record in records
                    if record.get("observation_type") in LOCATION_PLATFORM_SPATIAL_TYPES
                    and record.get("status") == "SUCCESS"
                    and (
                        "coordinates_finite" in cast(dict[str, object], record["payload"])
                        or "locations" in cast(dict[str, object], record["payload"])
                    )
                )
            )
        ),
    )
    restored_spatial_payload = cast(dict[str, object], restored_spatial["payload"])
    if "locations" in restored_spatial_payload:
        cast(list[dict[str, object]], restored_spatial_payload["locations"])[0][
            "outside_expected_center_exclusion"
        ] = True
    else:
        restored_spatial_payload["outside_expected_center_exclusion"] = True
    restored_summary = cast(dict[str, object], json.loads(json.dumps(records[-1])))
    restored_summary["status"] = "FAIL"
    cast(dict[str, object], restored_summary["payload"])["session_verdict"] = "FAIL"
    restored_records = [restored_spatial, restored_summary]
    enforce_location_verdict(
        {**metadata, "expected_spatial_mismatch": True}, "FAIL", restored_records
    )
    serialized = serialize_location_records(accepted)
    if "latitude_deg" in serialized or "longitude_deg" in serialized:
        raise CheckError("location report serialization retained a private coordinate")

    invalid_records = cast(list[dict[str, object]], json.loads(json.dumps(records)))
    coordinate_record = next(
        record for record in invalid_records if record["observation_type"] == "last_known"
    )
    cast(dict[str, object], coordinate_record["payload"])["latitude_deg"] = 60.1
    try:
        validate_location_jsonl(
            "".join(json.dumps(record) + "\n" for record in invalid_records), metadata
        )
    except CheckError:
        pass
    else:
        raise CheckError("location JSONL self-test accepted an exact coordinate")

    invalid_records = cast(list[dict[str, object]], json.loads(json.dumps(records)))
    decimal_record = next(
        record for record in invalid_records if record["observation_type"] == "last_known"
    )
    cast(dict[str, object], decimal_record["payload"])["unexpected_metric"] = 66.12345678
    try:
        validate_location_jsonl(
            "".join(json.dumps(record) + "\n" for record in invalid_records),
            metadata,
            ("66.12345678",),
        )
    except CheckError:
        pass
    else:
        raise CheckError("location JSONL self-test accepted a private decimal value")

    invalid_records = cast(list[dict[str, object]], json.loads(json.dumps(records)))
    nmea_record = next(record for record in invalid_records if record["observation_type"] == "nmea")
    cast(dict[str, object], nmea_record["payload"])["unexpected_metric"] = "$GLGGA,raw*00"
    try:
        validate_location_jsonl(
            "".join(json.dumps(record) + "\n" for record in invalid_records), metadata
        )
    except CheckError:
        pass
    else:
        raise CheckError("location JSONL self-test accepted a raw NMEA talker sentence")

    invalid_records = cast(list[dict[str, object]], json.loads(json.dumps(records)))
    invalid_summary = cast(dict[str, object], invalid_records[-1]["payload"])
    invalid_summary["measurement_event_count"] = 1
    try:
        validate_location_jsonl(
            "".join(json.dumps(record) + "\n" for record in invalid_records), metadata
        )
    except CheckError:
        pass
    else:
        raise CheckError("location JSONL self-test accepted a blocked measurement event")

    invalid_records = cast(list[dict[str, object]], json.loads(json.dumps(records)))
    raw_record = next(
        record
        for record in invalid_records
        if record["observation_type"] == "raw_measurement_event"
    )
    cast(dict[str, object], raw_record["payload"])["received_sv_time_ns"] = 123
    try:
        validate_location_jsonl(
            "".join(json.dumps(record) + "\n" for record in invalid_records), metadata
        )
    except CheckError:
        pass
    else:
        raise CheckError("location JSONL self-test accepted private Raw GNSS fields")

    without_oracle = cast(list[dict[str, object]], json.loads(json.dumps(records)))
    without_oracle_payload = cast(dict[str, object], without_oracle[-1]["payload"])
    without_oracle_payload.update(
        {
            "oracle_required": False,
            "oracle_status": "not_requested",
            "expected_config_generation": None,
            "expected_config_sha256": None,
        }
    )
    metadata_without_oracle = {**metadata, "location_oracle_required": False}
    metadata_without_oracle.pop("expected_config_generation")
    metadata_without_oracle.pop("expected_config_sha256")
    validate_location_jsonl(
        "".join(json.dumps(record) + "\n" for record in without_oracle),
        metadata_without_oracle,
    )


def collect_and_validate(
    adb: Adb,
    report: Report,
    run_id: str,
    metadata: dict[str, object],
    private_decimal_values: tuple[str, ...] = (),
) -> None:
    package = cast(str, metadata["application_id"])
    content = read_device_jsonl(adb, package, run_id)
    records, verdict = validate_jsonl(content, metadata, private_decimal_values)
    run_root = (
        ROOT / ".artifacts/poc/reports/probe/runs"
        if metadata.get("poc") is True
        else ROOT / ".artifacts/reports/probe/runs"
    )
    destination = run_root / f"{run_id}.jsonl"
    report_content = (
        serialize_location_records(records)
        if metadata.get("detector_group") == "location"
        else content
    )
    write_private_text(destination, report_content)
    processes = sorted({cast(str, record["process"]) for record in records})
    if metadata["secondary"] and not any(process.endswith(":secondary") for process in processes):
        raise CheckError("secondary probe run did not execute in the secondary process")
    if not metadata["secondary"] and any(process.endswith(":secondary") for process in processes):
        raise CheckError("main probe run unexpectedly executed in the secondary process")
    report.kv("run_id", run_id)
    report.kv("variant", metadata["variant"])
    report.kv("application_id", package)
    report.kv("group", metadata["requested_group"])
    report.kv("record_count", len(records))
    report.kv("processes", processes)
    report.kv("verdict", verdict)
    report.kv("jsonl", destination.relative_to(ROOT))
    report.kv("artifact_class", "non_attestable_poc" if metadata.get("poc") else "standard")
    if metadata.get("detector_group") == "location":
        report.kv("raw_gnss_mode", metadata["raw_gnss_mode"])
        report.kv("observation_window_ms", metadata["observation_window_ms"])
        report.kv("location_oracle_required", metadata["location_oracle_required"])
        if metadata["location_oracle_required"]:
            report.kv("expected_config_generation", metadata["expected_config_generation"])
            if metadata.get("poc") is True:
                report.kv("config_hash_comparison", "skipped")
            else:
                report.kv("expected_config_sha256", metadata["expected_config_sha256"])
        report.kv("coordinates_in_report", "absent")
    enforce_location_verdict(metadata, verdict, records)


def run_probe(report: Report, args: argparse.Namespace) -> str:
    adb = Adb.select(args.adb_serial, report)
    package = variant_package(args.variant)
    supported_groups = {
        "sync",
        "async",
        "active",
        "link",
        "schema",
        "data-plane",
        "location",
        *SERVER_VPN_GROUPS,
    }
    secondary_groups = {
        "secondary-sync",
        "secondary-async",
        "secondary-active",
        "secondary-link",
        "secondary-data-plane",
        "secondary-location",
        *(f"secondary-{group}" for group in SERVER_VPN_GROUPS),
    }
    if args.group not in supported_groups | secondary_groups:
        raise CheckError(f"unsupported probe group: {args.group}")
    if adb.shell("pm", "path", package, check=False).returncode != 0:
        raise CheckError(f"probe package is not installed: {package}")
    run_id = f"probe-{utc_compact()}-{uuid.uuid4().hex[:8]}"
    secondary = args.group in secondary_groups
    detector_group = args.group.removeprefix("secondary-") if secondary else args.group
    poc = bool(getattr(args, "poc", False))
    reuse_process = bool(getattr(args, "reuse_process", False))
    poc_no_oracle = bool(getattr(args, "poc_no_oracle", False))
    vpn_expected: bool | None = None
    module_expected: bool | None = None
    if detector_group != "location":
        vpn_expected = parse_expected(args.vpn_expected, "VPN_EXPECTED")
        module_expected = parse_expected(args.module_expected, "MODULE_EXPECTED")
    if poc and (
        detector_group not in {"location", "data-plane", *SERVER_VPN_GROUPS}
        or (detector_group == "location" and args.variant != "canary")
    ):
        raise CheckError(
            "POC mode is limited to canary location or universal-probe server-VPN sessions"
        )
    if reuse_process and (
        not poc or args.variant != "canary" or detector_group != "location" or secondary
    ):
        raise CheckError("process reuse is limited to the main canary location POC")
    if poc_no_oracle and (
        not poc or args.variant != "canary" or detector_group != "location" or secondary
    ):
        raise CheckError("oracle-free triggering is limited to the main canary location POC")
    raw_gnss_mode = "not_applicable"
    observation_window_ms = 0
    oracle_content = ""
    private_decimal_values: tuple[str, ...] = ()
    expected_config_generation: int | None = None
    expected_config_sha256: str | None = None
    if detector_group == "location":
        if args.raw_gnss_mode not in {"blocked", "passthrough", "unsupported"}:
            raise CheckError("RAW_GNSS_MODE must be blocked, passthrough, or unsupported")
        if args.observation_window_ms < 5_000 or args.observation_window_ms > 120_000:
            raise CheckError("OBSERVATION_WINDOW_MS must be between 5000 and 120000")
        raw_gnss_mode = args.raw_gnss_mode
        observation_window_ms = args.observation_window_ms
        if args.location_oracle or (poc and not poc_no_oracle):
            oracle_input = (
                read_private_oracle_input(args.location_oracle)
                if args.location_oracle
                else read_poc_current_oracle_input(adb)
            )
            private_decimal_values = tuple(
                oracle_input[key] for key in LOCATION_ORACLE_INPUT_KEYS[1:]
            )
            oracle_content, expected_config_generation, expected_config_sha256 = (
                build_location_oracle(adb, oracle_input, raw_gnss_mode, poc=poc)
            )
    oracle_required = bool(oracle_content)
    expected_spatial_mismatch = getattr(args, "expected_spatial_mismatch", False)
    if expected_spatial_mismatch and (
        detector_group != "location" or not oracle_required or poc or secondary
    ):
        raise CheckError("expected spatial mismatch is limited to standard main location runs")
    ensure_device_ui_ready(adb, report)
    metadata: dict[str, object] = {
        "run_id": run_id,
        "variant": args.variant,
        "application_id": package,
        "requested_group": args.group,
        "detector_group": detector_group,
        "secondary": secondary,
        "raw_gnss_mode": raw_gnss_mode,
        "observation_window_ms": observation_window_ms,
        "location_oracle_required": oracle_required,
        "expected_spatial_mismatch": expected_spatial_mismatch,
        "poc": poc,
        "reuse_process": reuse_process,
    }
    if detector_group != "location":
        metadata["vpn_expected"] = vpn_expected
        metadata["module_expected"] = module_expected
    if oracle_required:
        metadata["expected_config_generation"] = expected_config_generation
        metadata["expected_config_sha256"] = expected_config_sha256
    write_run_state(run_id, metadata, poc)
    reused_pid = ""
    if reuse_process:
        pid_result = adb.shell("pidof", package, check=False)
        pids = [value for value in pid_result.stdout.split() if value.isdigit()]
        if pid_result.returncode != 0 or len(pids) != 1:
            raise CheckError("process-reuse POC requires exactly one running canary process")
        reused_pid = pids[0]
        report.kv("process_reuse_pid_before", reused_pid)
    else:
        stopped = adb.shell("am", "force-stop", package, check=False)
        if stopped.returncode != 0:
            raise CheckError("could not stop the probe before the bounded run")
    if detector_group == "location":
        remove_location_oracle(adb, package)
    try:
        if oracle_required:
            write_location_oracle(adb, package, oracle_content)
        common = [
            "--es",
            "run_id",
            run_id,
            "--es",
            "group",
            args.group,
        ]
        if detector_group == "location":
            common.extend(
                [
                    "--es",
                    "raw_gnss_mode",
                    raw_gnss_mode,
                    "--el",
                    "observation_window_ms",
                    str(observation_window_ms),
                    "--ez",
                    "location_oracle_required",
                    str(oracle_required).lower(),
                ]
            )
        else:
            common.extend(
                [
                    "--ez",
                    "vpn_expected",
                    str(vpn_expected).lower(),
                    "--ez",
                    "module_expected",
                    str(module_expected).lower(),
                ]
            )
        launch_arguments = ["am", "start", "-W"]
        if reuse_process:
            launch_arguments.extend(["-f", "0x58000000"])
        launch_arguments.extend(["-n", f"{package}/dev.zygveil.probe.ProbeActivity", *common])
        launch = adb.shell(*launch_arguments, timeout=30, check=False)
        report.kv("launch_exit", launch.returncode)
        report.kv("launch_result", launch.stdout.strip())
        if launch.returncode != 0 or "Error:" in launch.stdout:
            raise CheckError("could not launch probe run")
        if detector_group == "location":
            oracle_deadline = time.monotonic() + LOCATION_STARTUP_TIMEOUT_SECONDS
            while time.monotonic() < oracle_deadline:
                if location_oracle_absent(adb, package):
                    break
                time.sleep(0.1)
            else:
                raise CheckError("probe did not unlink the location oracle before callbacks")
            report.kv("location_oracle_unlinked_before_callbacks", "true")
            service_active = False
            service_deadline = time.monotonic() + LOCATION_STARTUP_TIMEOUT_SECONDS
            expected_service = (
                "dev.zygveil.probe.SecondaryLocationProbeService"
                if secondary
                else "dev.zygveil.probe.LocationProbeService"
            )
            while time.monotonic() < service_deadline:
                service = adb.shell(
                    "dumpsys", "activity", "services", package, timeout=30, check=False
                )
                service_active = (
                    service.returncode == 0
                    and expected_service in service.stdout
                    and "isForeground=true" in service.stdout
                    and "types=0x00000008" in service.stdout
                )
                if service_active:
                    break
                time.sleep(0.25)
            report.kv("location_foreground_service_active", str(service_active).lower())
            report.kv(
                "location_foreground_service_type", "location" if service_active else "missing"
            )
            if not service_active:
                raise CheckError("location probe foreground service did not become active")
        deadline = time.monotonic() + 35 + observation_window_ms / 1000
        while time.monotonic() < deadline:
            result = adb.shell(
                "run-as",
                package,
                "/system/bin/cat",
                f"files/runs/{run_id}.jsonl",
                check=False,
            )
            if result.returncode == 0 and '"record_type":"summary"' in result.stdout:
                break
            time.sleep(0.5)
        else:
            raise CheckError("probe run did not publish a bounded summary")
        collect_and_validate(adb, report, run_id, metadata, private_decimal_values)
        if reuse_process:
            pid_result = adb.shell("pidof", package, check=False)
            pids = [value for value in pid_result.stdout.split() if value.isdigit()]
            if pid_result.returncode != 0 or pids != [reused_pid]:
                raise CheckError("canary process identity changed during the reuse POC")
            report.kv("process_reuse_pid_after", reused_pid)
            report.kv("process_reused", "true")
            report.kv("device_mutation", "launch bounded session in existing canary process")
        else:
            report.kv("device_mutation", "force-stop and launch selected independent probe process")
        return run_id
    finally:
        if detector_group == "location":
            remove_location_oracle(adb, package)
        if poc and detector_group in {"data-plane", *SERVER_VPN_GROUPS}:
            adb.shell("am", "force-stop", package, check=False)
            report.kv("poc_probe_process_restored", "stopped")


def results(report: Report, args: argparse.Namespace) -> None:
    if not args.run_id:
        raise CheckError("RUN_ID is required")
    metadata = load_run_state(args.run_id, args.poc)
    adb = Adb.select(args.adb_serial, report)
    collect_and_validate(adb, report, args.run_id, metadata)
    report.kv("device_mutation", "none")


def cleanup(report: Report, args: argparse.Namespace) -> None:
    if not args.run_id:
        raise CheckError("RUN_ID is required")
    metadata = load_run_state(args.run_id, args.poc)
    package = cast(str, metadata["application_id"])
    adb = Adb.select(args.adb_serial, report)
    result = adb.shell("am", "force-stop", package, check=False)
    report.kv("force_stop_exit", result.returncode)
    if result.returncode != 0:
        raise CheckError("could not stop the probe process")
    report.kv("run_id", args.run_id)
    report.kv("application_id", package)
    report.kv("result_file_preserved", "true")
    report.kv("device_mutation", "force-stop selected independent probe package")


def run_probe_command(report: Report, args: argparse.Namespace) -> None:
    run_probe(report, args)


def run_concurrent_server_vpn(report: Report, args: argparse.Namespace) -> dict[str, str]:
    requested_group = args.group
    secondary = requested_group.startswith("secondary-")
    detector_group = requested_group.removeprefix("secondary-")
    if detector_group not in {
        "server-vpn-active",
        "server-vpn-async",
        "server-vpn-link",
    }:
        raise CheckError("concurrent probe requires a callback-bearing server-VPN group")
    adb = Adb.select(args.adb_serial, report)
    poc = bool(getattr(args, "poc", False))
    runs: dict[str, tuple[str, dict[str, object]]] = {}
    for variant in SERVER_VPN_CONCURRENT_VARIANTS:
        package = variant_package(variant)
        if adb.shell("pm", "path", package, check=False).returncode != 0:
            raise CheckError(f"probe package is not installed: {package}")
    ensure_device_ui_ready(adb, report)
    for variant in SERVER_VPN_CONCURRENT_VARIANTS:
        package = variant_package(variant)
        stopped = adb.shell("am", "force-stop", package, check=False)
        if stopped.returncode != 0:
            raise CheckError(f"could not stop {variant} before coordinated launch")
    coordinated_start_elapsed_realtime_ms = coordinated_start_target(adb)
    run_ids = {
        variant: f"probe-{utc_compact()}-{uuid.uuid4().hex[:8]}"
        for variant in SERVER_VPN_CONCURRENT_VARIANTS
    }
    for variant in SERVER_VPN_CONCURRENT_VARIANTS:
        package = variant_package(variant)
        run_id = run_ids[variant]
        partner = next(
            candidate for candidate in SERVER_VPN_CONCURRENT_VARIANTS if candidate != variant
        )
        metadata: dict[str, object] = {
            "run_id": run_id,
            "variant": variant,
            "application_id": package,
            "requested_group": requested_group,
            "detector_group": detector_group,
            "secondary": secondary,
            "raw_gnss_mode": "not_applicable",
            "observation_window_ms": 0,
            "location_oracle_required": False,
            "expected_spatial_mismatch": False,
            "poc": poc,
            "reuse_process": False,
            "vpn_expected": True,
            "module_expected": True,
            "concurrent_launch_mode": "canary_ready_then_primary_nonblocking_activity",
            "concurrent_partner_run_id": run_ids[partner],
            "concurrent_canary_ready_latency_ms": "pending",
            "concurrent_primary_dispatch_delay_ms": "pending",
            "concurrent_start_elapsed_realtime_ms": coordinated_start_elapsed_realtime_ms,
        }
        write_run_state(run_id, metadata, poc)
        runs[variant] = (run_id, metadata)

    try:

        def launch_variant(variant: str) -> CommandResult:
            package = variant_package(variant)
            run_id, _metadata = runs[variant]
            return adb.shell(
                "am",
                "start",
                "-n",
                f"{package}/dev.zygveil.probe.ProbeActivity",
                "--es",
                "run_id",
                run_id,
                "--es",
                "group",
                requested_group,
                "--ez",
                "vpn_expected",
                "true",
                "--ez",
                "module_expected",
                "true",
                "--el",
                "coordinated_start_elapsed_realtime_ms",
                str(coordinated_start_elapsed_realtime_ms),
                timeout=30,
                check=False,
            )

        canary_launch_started_ns = time.monotonic_ns()
        canary_launch = launch_variant("canary")
        report.kv("canary_launch_exit", canary_launch.returncode)
        report.kv("canary_launch_result", canary_launch.stdout.strip())
        if canary_launch.returncode != 0 or "Error:" in canary_launch.stdout:
            raise CheckError("could not schedule coordinated canary probe")
        canary_run_id, _canary_metadata = runs["canary"]
        canary_ready_latency_ms = wait_for_run_result_ready(
            adb, variant_package("canary"), canary_run_id, canary_launch_started_ns
        )
        ready_ns = time.monotonic_ns()
        primary_dispatch_ns = time.monotonic_ns()
        primary_dispatch_delay_ms = (primary_dispatch_ns - ready_ns + 999_999) // 1_000_000
        if primary_dispatch_delay_ms > SERVER_VPN_PRIMARY_DISPATCH_MAX_DELAY_MS:
            raise CheckError("primary probe dispatch was delayed after canary readiness")
        primary_launch = launch_variant("primary")
        report.kv("primary_launch_exit", primary_launch.returncode)
        report.kv("primary_launch_result", primary_launch.stdout.strip())
        if primary_launch.returncode != 0 or "Error:" in primary_launch.stdout:
            raise CheckError("could not schedule coordinated primary probe")
        for variant in SERVER_VPN_CONCURRENT_VARIANTS:
            run_id, metadata = runs[variant]
            metadata["concurrent_canary_ready_latency_ms"] = canary_ready_latency_ms
            metadata["concurrent_primary_dispatch_delay_ms"] = primary_dispatch_delay_ms
            write_run_state(run_id, metadata, poc)
        report.kv("concurrent_canary_ready_latency_ms", canary_ready_latency_ms)
        report.kv("concurrent_primary_dispatch_delay_ms", primary_dispatch_delay_ms)
        report.kv("concurrent_start_elapsed_realtime_ms", coordinated_start_elapsed_realtime_ms)

        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            completed = 0
            for variant in SERVER_VPN_CONCURRENT_VARIANTS:
                package = variant_package(variant)
                run_id, _metadata = runs[variant]
                result = adb.shell(
                    "run-as",
                    package,
                    "/system/bin/cat",
                    f"files/runs/{run_id}.jsonl",
                    check=False,
                )
                completed += int(
                    result.returncode == 0 and '"record_type":"summary"' in result.stdout
                )
            if completed == 2:
                break
            time.sleep(0.25)
        else:
            raise CheckError("concurrent server-VPN probes did not complete in time")

        collected: dict[str, list[dict[str, object]]] = {}
        run_root = (
            ROOT / ".artifacts/poc/reports/probe/runs"
            if poc
            else ROOT / ".artifacts/reports/probe/runs"
        )
        run_root.mkdir(parents=True, exist_ok=True)
        for variant in SERVER_VPN_CONCURRENT_VARIANTS:
            package = variant_package(variant)
            run_id, metadata = runs[variant]
            content = read_device_jsonl(adb, package, run_id)
            records, verdict = validate_jsonl(content, metadata)
            destination = run_root / f"{run_id}.jsonl"
            write_private_text(destination, content)
            collected[variant] = records
            report.kv(f"{variant}_run_id", run_id)
            report.kv(f"{variant}_verdict", verdict)
            report.kv(f"{variant}_jsonl", destination.relative_to(ROOT))

        primary = collected["primary"]
        canary = collected["canary"]
        if set(detector_records(primary)) != set(detector_records(canary)):
            raise CheckError("concurrent target/canary catalogs differ")
        require_phase(primary, target_active=True)
        require_phase(canary, target_active=False)
        primary_start, primary_end = run_interval(primary)
        canary_start, canary_end = run_interval(canary)
        overlap_ms = int(
            max(
                0.0,
                min(primary_end, canary_end) - max(primary_start, canary_start),
            )
            * 1000
        )
        if overlap_ms <= 0:
            raise CheckError("target/canary server-VPN sessions did not overlap")
        report.kv("group", detector_group)
        report.kv("process_role", "secondary" if secondary else "main")
        report.kv("detector_count", len(detector_records(primary)))
        report.kv("measured_overlap_ms", overlap_ms)
        report.kv("target_projection", "present_sanitized")
        report.kv("canary_projection", "present_stock")
        report.kv("artifact_class", "non_attestable_poc" if poc else "standard")
        report.kv("device_mutation", "controlled concurrent probe launches")
        return {variant: runs[variant][0] for variant in SERVER_VPN_CONCURRENT_VARIANTS}
    finally:
        for package in (variant_package("primary"), variant_package("canary")):
            adb.shell("am", "force-stop", package, check=False)


COMMANDS: dict[str, Callable[[Report, argparse.Namespace], object]] = {
    "probe-install": install_primary,
    "probe-install-canary": install_canary,
    "probe-install-canary-poc": install_canary_poc,
    "probe-install-primary-poc": install_primary_poc,
    "probe-run": run_probe_command,
    "probe-server-vpn-concurrent": run_concurrent_server_vpn,
    "probe-results": results,
    "probe-cleanup": cleanup,
}


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--adb-serial", default="")
    parser.add_argument("--variant", default="primary")
    parser.add_argument("--vpn-expected", default="")
    parser.add_argument("--module-expected", default="")
    parser.add_argument("--group", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--raw-gnss-mode", default="")
    parser.add_argument("--observation-window-ms", type=int, default=20_000)
    parser.add_argument("--location-oracle", default="")
    parser.add_argument("--poc", action="store_true")
    parser.add_argument("--reuse-process", action="store_true")
    parser.add_argument("--poc-no-oracle", action="store_true")
    parser.add_argument("command", choices=sorted(COMMANDS))
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    try:
        with Report(ROOT / args.report_dir, args.command) as report:
            private_decimal_values: tuple[str, ...] = ()
            try:
                if args.location_oracle:
                    private_values = read_private_oracle_input(args.location_oracle)
                    private_decimal_values = tuple(
                        private_values[key] for key in LOCATION_ORACLE_INPUT_KEYS[1:]
                    )
                COMMANDS[args.command](report, args)
            finally:
                report.assert_redacted(
                    [
                        r"(?i)\b(?:center_latitude_deg|center_longitude_deg|"
                        r"altitude_ellipsoid_m|altitude_msl_m)\s*=",
                        r"\$[A-Z]",
                        r"\.state/",
                        r"location-oracle\.properties",
                    ],
                    [
                        lambda content: contains_private_decimal_values(
                            content, private_decimal_values
                        )
                    ],
                )
    except CheckError:
        return 1
    except Exception:
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
