# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

#!/usr/bin/env python3
"""Make-wrapped exact-generation location device acceptance."""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import hashlib
import json
import math
import re
import stat
import time
import traceback
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from adb import Adb, installed_apk_sha256
from location_controller_device import (
    PACKAGE as CONTROLLER_PACKAGE,
)
from location_controller_device import (
    require_artifact as require_controller_artifact,
)
from location_controller_device import (
    validate_installed as validate_controller_installed,
)
from location_device import (
    MODULE_DIR,
    MODULE_ZIP,
    current_boot_id_sha256,
    inspect_module,
    read_text,
    report_values,
    require_artifact,
    select_root_adbd,
    sha256,
    system_server_identity,
)
from probe import (
    APKS,
    PACKAGES,
    load_run_state,
    parse_location_helper_status,
    read_device_jsonl,
    read_private_oracle_input,
    run_probe,
    validate_location_jsonl,
)
from reporting import CheckError, DeferredPrivateText, Report, contains_private_decimal_values

ROOT = Path(__file__).resolve().parents[2]
PROBE_ROOT = ROOT / "components/probe"
STATE_DIR = ROOT / ".state/location-phases"
PROBE_BUILD_REPORT = ROOT / ".artifacts/reports/probe/build-probe.txt"
PROBE_SOURCE_HASH = ROOT / "dist/probe-detector-source.sha256"
REBOOT_REPORT = ROOT / ".artifacts/reports/location/location-reboot.txt"
RECOVERY_REPORT = ROOT / ".artifacts/reports/location/location-recover.txt"
SERVER_VPN_REBOOT_REPORT = ROOT / ".artifacts/reports/server-vpn-final/final-reboot.txt"
SERVER_VPN_RECOVERY_REPORT = ROOT / ".artifacts/reports/server-vpn-final/final-recover.txt"
CONTROLLER_STATUS_REPORT = ROOT / ".artifacts/reports/location/location-controller-status.txt"
IMMUTABLE_MODULE_MEMBERS = (
    "bridge.dex",
    "guard.sh",
    "libshadowhook_nothing.so",
    "live-control.properties",
    "locationctl",
    "module.prop",
    "post-fs-data.sh",
    "server-vpn-bridge.dex",
    "server-vpn-config.properties",
    "zygisk/arm64-v8a.so",
)
ACTIVE_PHASES = {"blocked", "isolation", "passthrough", "stability"}
PHASE_MODE = {
    "baseline": "passthrough",
    "disabled": "passthrough",
    "blocked": "blocked",
    "isolation": "blocked",
    "stability": "blocked",
    "passthrough": "passthrough",
    "restored": "passthrough",
}
PHASE_STATE = {
    "baseline": "absent",
    "disabled": "disabled",
    "blocked": "active",
    "isolation": "active",
    "stability": "active",
    "passthrough": "active",
    "restored": "disabled",
}
LIVE_INPUT_KEYS = (
    "schema_version",
    "center_latitude_deg",
    "center_longitude_deg",
    "altitude_ellipsoid_m",
    "altitude_msl_m",
)
STRESS_UPDATE_COUNT = 5
STRESS_LAUNCH_STAGGER_SECONDS = 2
PROC_MAP_PATTERN = re.compile(
    r"^(?P<start>[0-9a-f]+)-(?P<end>[0-9a-f]+)\s+(?P<perms>\S+)\s+"
    r"(?P<offset>[0-9a-f]+)\s+(?P<device>\S+)\s+(?P<inode>\d+)\s*(?P<path>.*)$"
)
PHASE_WRITE = DeferredPrivateText()


def phase_generation_id(args: argparse.Namespace, phase: str) -> str:
    if phase == "baseline":
        return "baseline-independent"
    generation_id = getattr(args, "final_generation_id", "")
    return generation_id if generation_id else "unbound"


APPLICATION_MEMFD_MARKERS = ("zygveil", "hookbridge", "bridge.dex")


@dataclass(frozen=True)
class MappedFileIdentity:
    device: str
    inode: str
    sha256: str


class SelfTestReport(Report):
    def __init__(self) -> None:
        pass

    def kv(self, key: str, value: object) -> None:
        del key, value

    def line(self, value: str = "") -> None:
        del value

    def section(self, value: str) -> None:
        del value


def location_probe_source_hash() -> str:
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
        raise CheckError("location probe source inventory is incomplete")
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(ROOT).as_posix().encode("utf-8") + b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def require_probe_artifacts(adb: Adb, report: Report) -> dict[str, str]:
    build = report_values(PROBE_BUILD_REPORT)
    expected_keys = {
        "primary": "primary_apk_sha256",
        "canary": "canary_apk_sha256",
    }
    identities: dict[str, str] = {}
    for variant, key in expected_keys.items():
        path = APKS[variant]
        if not path.is_file():
            raise CheckError(f"{variant} probe artifact is missing; run make build-probe")
        digest = sha256(path)
        if build.get(key) != digest:
            raise CheckError(f"{variant} probe artifact/build report mismatch")
        installed = installed_apk_sha256(adb, PACKAGES[variant])
        report.kv(f"probe.{variant}.artifact_sha256", digest)
        report.kv(f"probe.{variant}.installed_sha256", installed)
        if installed != digest:
            raise CheckError(f"installed {variant} probe does not match current artifact")
        identities[f"{variant}_apk_sha256"] = digest
    fields = PROBE_SOURCE_HASH.read_text(encoding="utf-8").split()
    source_digest = fields[0] if fields else ""
    if not re.fullmatch(r"[0-9a-f]{64}", source_digest):
        raise CheckError("probe detector source identity is malformed")
    if build.get("detector_source_sha256") != source_digest:
        raise CheckError("probe detector source/build report mismatch")
    report.kv("probe.detector_source_sha256", source_digest)
    identities["detector_source_sha256"] = source_digest
    location_digest = location_probe_source_hash()
    if build.get("location_source_sha256") != location_digest:
        raise CheckError("location probe source/build report mismatch")
    report.kv("probe.location_source_sha256", location_digest)
    identities["location_source_sha256"] = location_digest
    return identities


def require_installed_module(adb: Adb, report: Report) -> None:
    with zipfile.ZipFile(MODULE_ZIP) as archive:
        for member in IMMUTABLE_MODULE_MEMBERS:
            expected = hashlib.sha256(archive.read(member)).hexdigest()
            result = adb.shell("sha256sum", f"{MODULE_DIR}/{member}", timeout=60, check=False)
            actual = result.stdout.split()[0] if result.returncode == 0 and result.stdout else ""
            report.kv(f"installed.{member}.sha256", actual)
            if actual != expected:
                raise CheckError(f"installed location module member mismatch: {member}")


def current_config_digest(adb: Adb) -> str:
    result = adb.shell("sha256sum", f"{MODULE_DIR}/config.properties", check=False)
    fields = result.stdout.split()
    if (
        result.returncode != 0
        or len(fields) != 2
        or re.fullmatch(r"[0-9a-f]{64}", fields[0]) is None
    ):
        raise CheckError("current location configuration digest is unavailable")
    return fields[0]


def boot_evidence_matches(
    evidence: dict[str, str],
    expected_state: str,
    current_pid: str,
    current_start_ticks: str,
    boot_id_digest: str,
) -> bool:
    state = evidence.get("state")
    location_state = evidence.get("location_state")
    if state is None:
        state = location_state
    elif location_state is not None and location_state != state:
        return False
    return (
        evidence.get("exit_status") == "0"
        and evidence.get("system_server_stable") == "true"
        and state == expected_state
        and evidence.get("system_server_pid") == current_pid
        and evidence.get("system_server_start_ticks") == current_start_ticks
        and evidence.get("boot_id_sha256") == boot_id_digest
    )


def require_boot_evidence(
    adb: Adb, expected_state: str, current_pid: str, current_start_ticks: str
) -> str:
    boot_id_digest = current_boot_id_sha256(adb)
    for path in (
        REBOOT_REPORT,
        RECOVERY_REPORT,
        SERVER_VPN_REBOOT_REPORT,
        SERVER_VPN_RECOVERY_REPORT,
    ):
        if not path.is_file():
            continue
        evidence = report_values(path)
        if boot_evidence_matches(
            evidence, expected_state, current_pid, current_start_ticks, boot_id_digest
        ):
            return boot_id_digest
    raise CheckError(f"current {expected_state} boot lacks matching reboot/recovery evidence")


def crash_snapshot(adb: Adb) -> collections.Counter[str]:
    result = adb.run(
        "logcat",
        "-b",
        "crash",
        "-b",
        "system",
        "-d",
        "-v",
        "threadtime",
        "-t",
        "1600",
        timeout=60,
        check=False,
    )
    return collections.Counter(result.stdout.splitlines())


def reject_new_runtime_crashes(
    before: collections.Counter[str], after: collections.Counter[str], report: Report
) -> None:
    new_lines = list((after - before).elements())
    pattern = re.compile(
        r"fatal exception|fatal signal|watchdog.*system_server|system_server.*(?:crash|killed)",
        re.IGNORECASE,
    )
    matches = [line for line in new_lines if pattern.search(line)]
    report.kv("new_runtime_log_lines", len(new_lines))
    report.kv("new_fatal_watchdog_lines", len(matches))
    report.kv(
        "new_runtime_log_digest",
        hashlib.sha256("\n".join(new_lines).encode()).hexdigest(),
    )
    if matches:
        raise CheckError("new fatal/watchdog evidence appeared during the location session")


def summary_payload(records: list[dict[str, object]]) -> dict[str, object]:
    summaries = [record for record in records if record["record_type"] == "summary"]
    return cast(dict[str, object], summaries[0]["payload"])


def provider_inventory(records: list[dict[str, object]]) -> dict[str, object]:
    for record in records:
        if record["observation_type"] != "provider_inventory" or record["status"] != "SUCCESS":
            continue
        payload = cast(dict[str, object], record["payload"])
        providers = payload.get("providers")
        enabled = payload.get("enabled_providers")
        if isinstance(providers, list) and isinstance(enabled, list):
            return {
                "providers": sorted(str(value) for value in providers),
                "enabled_providers": sorted(str(value) for value in enabled),
                "location_enabled": payload.get("location_enabled"),
            }
    raise CheckError("location session has no valid provider inventory")


def numeric(payload: dict[str, object], key: str) -> float:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CheckError(f"location payload field is not numeric: {key}")
    parsed = float(value)
    if not math.isfinite(parsed):
        raise CheckError(f"location payload field is not finite: {key}")
    return parsed


def location_payloads(
    records: list[dict[str, object]], *, live_only: bool = False
) -> list[tuple[str, str, dict[str, object]]]:
    values: list[tuple[str, str, dict[str, object]]] = []
    accepted_types = {"current", "location_update", "location_batch"}
    if not live_only:
        accepted_types.add("last_known")
    for record in records:
        observation_type = cast(str, record["observation_type"])
        if observation_type not in accepted_types or record["status"] != "SUCCESS":
            continue
        source = cast(str, record["source"])
        payload = cast(dict[str, object], record["payload"])
        if observation_type == "location_batch":
            batch = payload.get("locations")
            if isinstance(batch, list):
                values.extend(
                    (observation_type, source, cast(dict[str, object], item))
                    for item in batch
                    if isinstance(item, dict)
                )
        elif "coordinates_finite" in payload:
            values.append((observation_type, source, payload))
    return values


def distance_m(
    latitude: float, longitude: float, center_latitude: float, center_longitude: float
) -> float:
    radius = 6_378_137.0
    latitude_1 = math.radians(center_latitude)
    latitude_2 = math.radians(latitude)
    delta_latitude = latitude_2 - latitude_1
    delta_longitude = math.radians(longitude - center_longitude)
    value = (
        math.sin(delta_latitude / 2.0) ** 2
        + math.cos(latitude_1) * math.cos(latitude_2) * math.sin(delta_longitude / 2.0) ** 2
    )
    return 2.0 * radius * math.asin(min(1.0, math.sqrt(value)))


def accuracy_bounds(provider: str) -> tuple[float, float]:
    return {
        "gps": (3.0, 12.0),
        "fused": (4.0, 20.0),
        "network": (20.0, 150.0),
        "passive": (4.0, 30.0),
    }.get(provider, (5.0, 50.0))


def validate_active_locations(records: list[dict[str, object]], report: Report) -> None:
    locations = location_payloads(records)
    if not locations:
        raise CheckError("active session delivered no public Location object")
    maximum_distance = 0.0
    last_elapsed: dict[tuple[str, str], float] = {}
    for observation_type, source, payload in locations:
        center_distance = numeric(payload, "expected_center_distance_m")
        maximum_distance = max(maximum_distance, center_distance)
        if (
            payload.get("coordinates_finite") is not True
            or payload.get("latitude_in_range") is not True
            or payload.get("longitude_in_range") is not True
            or payload.get("within_expected_radius") is not True
        ):
            raise CheckError("synthetic location left the private-oracle bounds")
        if numeric(payload, "displacement_from_first_sample_m") < 0.0:
            raise CheckError("synthetic location displacement is invalid")
        if "cross_channel_distance_m" in payload and (
            numeric(payload, "cross_channel_distance_m") < 0.0
            or payload.get("cross_channel_consistent") is not True
        ):
            raise CheckError("synthetic Location/NMEA channels disagree")
        if payload.get("complete") is not True or not isinstance(payload.get("mock"), bool):
            raise CheckError("synthetic Location completeness/mock state is invalid")
        if not all(
            payload.get(flag) is True
            for flag in (
                "has_accuracy",
                "has_altitude",
                "has_vertical_accuracy",
                "has_msl_altitude",
                "has_msl_altitude_accuracy",
                "has_speed",
                "has_speed_accuracy",
            )
        ):
            raise CheckError("synthetic Location optional-field contract is incomplete")
        for flag in (
            "numeric_fields_finite",
            "accuracy_non_negative",
            "vertical_accuracy_non_negative",
            "speed_non_negative",
            "bearing_in_range",
            "bearing_presence_consistent",
            "speed_within_expected_bound",
            "stationary_bearing_absent",
            "altitude_pair_consistent",
        ):
            if payload.get(flag) is not True:
                raise CheckError(f"synthetic Location consistency bound failed: {flag}")
        if numeric(payload, "time_ms") <= 0 or numeric(payload, "elapsed_realtime_ns") <= 0:
            raise CheckError("synthetic Location timestamp is invalid")
        if observation_type != "last_known":
            key = (observation_type, source)
            elapsed = numeric(payload, "elapsed_realtime_ns")
            if elapsed < last_elapsed.get(key, 0.0):
                raise CheckError("synthetic elapsed realtime regressed")
            last_elapsed[key] = elapsed
    report.kv("synthetic_location_count", len(locations))
    report.kv("synthetic_maximum_center_distance_m", f"{maximum_distance:.3f}")
    report.kv("coordinates", "absent")


def validate_active_gnss(
    records: list[dict[str, object]],
    report: Report,
    *,
    require_callbacks: bool,
) -> tuple[bool, bool]:
    status_payloads: list[dict[str, object]] = []
    nmea_payloads: list[dict[str, object]] = []
    for record in records:
        if record["status"] != "SUCCESS":
            continue
        payload = cast(dict[str, object], record["payload"])
        if record["observation_type"] == "gnss_status" and "satellite_count" in payload:
            status_payloads.append(payload)
        if record["observation_type"] == "nmea" and "sentence_type" in payload:
            nmea_payloads.append(payload)
    status_observed = bool(status_payloads)
    nmea_observed = bool(nmea_payloads)
    report.kv("synthetic_gnss_status_observed", str(status_observed).lower())
    report.kv("synthetic_nmea_observed", str(nmea_observed).lower())
    for payload in status_payloads:
        if (
            payload.get("satellite_count") != 16
            or payload.get("used_in_fix_count") != 10
            or payload.get("ephemeris_count") != 16
            or payload.get("almanac_count") != 16
            or payload.get("carrier_frequency_count") != 16
        ):
            raise CheckError("synthetic GNSS status count model mismatch")
        if not 18.0 <= numeric(payload, "cn0_min_dbhz") <= numeric(payload, "cn0_max_dbhz") <= 48.0:
            raise CheckError("synthetic GNSS status C/N0 range mismatch")
    sentence_types = {str(payload.get("sentence_type")) for payload in nmea_payloads}
    if nmea_payloads and not {"GGA", "RMC", "GSA", "GSV"}.issubset(sentence_types):
        raise CheckError("synthetic NMEA session lacks GGA/RMC/GSA/GSV")
    for payload in nmea_payloads:
        if (
            payload.get("valid") is not True
            or payload.get("valid_shape") is not True
            or payload.get("checksum_valid") is not True
            or payload.get("supported_sentence") is not True
            or payload.get("raw_sentence_redacted") is not True
        ):
            raise CheckError("synthetic NMEA validation/checksum contract failed")
        if payload.get("coordinate_fields_present") is True:
            if (
                payload.get("coordinate_parse_valid") is not True
                or payload.get("coordinates_finite") is not True
                or payload.get("latitude_in_range") is not True
                or payload.get("longitude_in_range") is not True
                or payload.get("within_expected_radius") is not True
            ):
                raise CheckError("synthetic NMEA position failed private-oracle bounds")
            numeric(payload, "expected_center_distance_m")
            if "cross_channel_distance_m" in payload and (
                numeric(payload, "cross_channel_distance_m") < 0.0
                or payload.get("cross_channel_consistent") is not True
            ):
                raise CheckError("synthetic NMEA/Location channels disagree")
        if payload.get("sentence_type") == "GGA":
            if payload.get("satellites") != 10 or payload.get("fix_quality") != 1:
                raise CheckError("synthetic GGA fix/satellite count mismatch")
            for flag in (
                "hdop_parse_valid",
                "hdop_finite",
                "hdop_non_negative",
                "altitude_msl_parse_valid",
                "altitude_msl_finite",
                "geoid_separation_parse_valid",
                "geoid_separation_finite",
                "altitude_fields_finite",
                "altitude_msl_consistent",
                "geoid_separation_consistent",
            ):
                if payload.get(flag) is not True:
                    raise CheckError(f"synthetic GGA consistency bound failed: {flag}")
        if payload.get("sentence_type") == "RMC":
            for flag in (
                "speed_parse_valid",
                "speed_finite",
                "speed_non_negative",
                "course_parse_valid",
                "course_finite",
                "course_in_range",
                "speed_within_expected_bound",
                "stationary_course_absent",
            ):
                if payload.get(flag) is not True:
                    raise CheckError(f"synthetic RMC consistency bound failed: {flag}")
        if payload.get("sentence_type") == "GSA" and payload.get("satellite_id_count") != 10:
            raise CheckError("synthetic GSA satellite count mismatch")
        if payload.get("sentence_type") == "GSA":
            for prefix in ("pdop", "hdop", "vdop"):
                for suffix in ("parse_valid", "finite", "non_negative"):
                    flag = f"{prefix}_{suffix}"
                    if payload.get(flag) is not True:
                        raise CheckError(f"synthetic GSA consistency bound failed: {flag}")
        if payload.get("sentence_type") == "GSV" and payload.get("satellites") != 16:
            raise CheckError("synthetic GSV satellite count mismatch")
    report.kv("synthetic_gnss_status_count", len(status_payloads))
    report.kv("synthetic_nmea_count", len(nmea_payloads))
    report.kv("synthetic_nmea_types", sorted(sentence_types))
    if require_callbacks and (not status_observed or not nmea_observed):
        raise CheckError("active session lacks detailed GNSS status or NMEA callbacks")
    return status_observed, nmea_observed


def compare_stock_contract(summary: dict[str, object], baseline: dict[str, object]) -> None:
    baseline_summary = baseline.get("summary")
    if not isinstance(baseline_summary, dict):
        raise CheckError("baseline phase summary is unavailable")
    for key in (
        "reported_measurement_capability",
        "reported_navigation_capability",
        "measurement_registration_result",
        "navigation_registration_result",
    ):
        if summary.get(key) != baseline_summary.get(key):
            raise CheckError(f"stock phase differs from baseline: {key}")


def validate_restored_stock(records: list[dict[str, object]], report: Report) -> None:
    live = location_payloads(records, live_only=True)
    if not live:
        raise CheckError("restored phase delivered no fresh stock Location")
    outside = sum(
        payload.get("outside_expected_center_exclusion") is True for _, _, payload in live
    )
    report.kv("restored_live_location_count", len(live))
    report.kv("restored_locations_outside_synthetic_exclusion", outside)
    report.kv("coordinates", "absent")
    if outside == 0:
        raise CheckError("fresh stock locations remain indistinguishable from the synthetic center")


def deleted_memfd_identities(adb: Adb, pid: str, maps: str) -> list[MappedFileIdentity]:
    identities: list[MappedFileIdentity] = []
    seen: set[tuple[str, str]] = set()
    for line in maps.splitlines():
        match = PROC_MAP_PATTERN.fullmatch(line)
        if match is None:
            continue
        device_inode = (match["device"], match["inode"])
        if (
            int(match["offset"], 16) != 0
            or match["inode"] == "0"
            or not match["path"].startswith("/memfd:")
            or not match["path"].endswith(" (deleted)")
            or device_inode in seen
        ):
            continue
        seen.add(device_inode)
        map_file = f"/proc/{pid}/map_files/{match['start']}-{match['end']}"
        digest_result = adb.shell("sha256sum", map_file, timeout=60, check=False)
        digest = digest_result.stdout.split(maxsplit=1)[0] if digest_result.stdout else ""
        if digest_result.returncode != 0 or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise CheckError(
                f"cannot identify deleted memfd backing {device_inode[0]}:{device_inode[1]}"
            )
        identities.append(MappedFileIdentity(*device_inode, digest))
    return identities


def module_native_sha256() -> str:
    with zipfile.ZipFile(MODULE_ZIP) as archive:
        return hashlib.sha256(archive.read("zygisk/arm64-v8a.so")).hexdigest()


def forbidden_application_descriptor_count(listing: str) -> int:
    count = 0
    module_prefix = f"{MODULE_DIR}/"
    for line in listing.splitlines():
        _metadata, separator, target = line.partition(" -> ")
        if not separator:
            continue
        normalized = target.removesuffix(" (deleted)")
        lower = normalized.lower()
        if (
            normalized == "anon_inode:[pidfd]"
            or normalized == MODULE_DIR
            or normalized.startswith(module_prefix)
            or (
                lower.startswith("/memfd:")
                and any(marker in lower for marker in APPLICATION_MEMFD_MARKERS)
            )
        ):
            count += 1
    return count


def validate_process_isolation(adb: Adb, records: list[dict[str, object]], report: Report) -> None:
    expected_native_sha256 = module_native_sha256()
    system_server_pid, _, _ = system_server_identity(adb)
    system_server_maps = adb.shell(
        "cat", f"/proc/{system_server_pid}/maps", timeout=30, check=False
    )
    if system_server_maps.returncode != 0:
        raise CheckError("system_server maps are unavailable for module identity")
    system_server_memfds = deleted_memfd_identities(
        adb, system_server_pid, system_server_maps.stdout
    )
    server_module = [
        identity for identity in system_server_memfds if identity.sha256 == expected_native_sha256
    ]
    if len(server_module) != 1:
        raise CheckError("current location module ELF is not uniquely mapped in system_server")

    package = PACKAGES["primary"]
    result = adb.shell("pidof", package, check=False)
    pids = [value for value in result.stdout.split() if value.isdigit()]
    if result.returncode != 0 or len(pids) != 1:
        raise CheckError("primary probe process is unavailable or ambiguous for isolation")
    pid = pids[0]
    maps = adb.shell("cat", f"/proc/{pid}/maps", timeout=30, check=False)
    if maps.returncode != 0:
        raise CheckError("probe process maps are unavailable")
    probe_memfds = deleted_memfd_identities(adb, pid, maps.stdout)
    exact_digest_matches = sum(
        identity.sha256 == expected_native_sha256 for identity in probe_memfds
    )
    exact_backing_matches = sum(
        (identity.device, identity.inode) == (server_module[0].device, server_module[0].inode)
        for identity in probe_memfds
    )
    application_control_path = "/data/adb/modules/zygveil/.app-control"
    application_control_mappings = []
    for line in maps.stdout.splitlines():
        match = PROC_MAP_PATTERN.fullmatch(line)
        if match is not None and match["path"] == application_control_path:
            application_control_mappings.append(match)
    application_control_read_only = (
        len(application_control_mappings) == 1
        and application_control_mappings[0]["perms"].startswith("r--")
        and "w" not in application_control_mappings[0]["perms"]
        and int(application_control_mappings[0]["offset"], 16) == 0
        and int(application_control_mappings[0]["end"], 16)
        - int(application_control_mappings[0]["start"], 16)
        == 4096
    )
    tasks = adb.shell("ls", "-1", f"/proc/{pid}/task", check=False)
    thread_matches = 0
    for task in tasks.stdout.split():
        if not task.isdigit():
            continue
        name = read_text(adb, f"/proc/{pid}/task/{task}/comm", required=False)
        thread_matches += "ZygVeil" in name
    descriptors = adb.shell("ls", "-l", f"/proc/{pid}/fd", check=False)
    descriptor_matches = forbidden_application_descriptor_count(descriptors.stdout)
    observations = [
        record
        for record in records
        if record["observation_type"] == "process_isolation"
        and record["record_type"] == "observation"
    ]
    if not observations:
        raise CheckError("probe process-isolation observation is missing")
    payload = cast(dict[str, object], observations[-1]["payload"])
    probe_classloader_isolated = (
        observations[-1]["status"] == "SUCCESS"
        and payload.get("bridge_class_visible") is False
        and payload.get("persistent_matching_thread_count") == 0
        and payload.get("maps_status") == "readable"
    )
    report.kv("probe_process_pid", pid)
    report.kv("module_native_sha256", expected_native_sha256)
    report.kv("system_server_module_memfd_match_count", len(server_module))
    report.kv("probe_module_digest_match_count", exact_digest_matches)
    report.kv("probe_module_backing_match_count", exact_backing_matches)
    report.kv("application_control_mapping_count", len(application_control_mappings))
    report.kv("application_control_mapping_read_only", str(application_control_read_only).lower())
    report.kv("module_thread_match_count", thread_matches)
    report.kv("module_named_fd_match_count", descriptor_matches)
    report.kv("bridge_delivery_observed", "true")
    report.kv("bridge_visible_to_application_classloader", "false")
    report.kv("probe_classloader_isolated", str(probe_classloader_isolated).lower())
    if (
        exact_digest_matches != 1
        or exact_backing_matches != 1
        or not application_control_read_only
        or thread_matches
        or descriptor_matches
        or not probe_classloader_isolated
    ):
        raise CheckError("global application delivery process containment failed")


def location_enabled(adb: Adb) -> bool:
    result = adb.shell("cmd", "location", "is-location-enabled", "--user", "0", check=False)
    value = result.stdout.strip()
    if result.returncode != 0 or value not in {"true", "false"}:
        raise CheckError("cannot read the Android location master switch")
    return value == "true"


def set_location_enabled(adb: Adb, enabled: bool) -> None:
    value = str(enabled).lower()
    result = adb.shell("cmd", "location", "set-location-enabled", value, "--user", "0", check=False)
    if result.returncode != 0:
        raise CheckError(f"cannot set the Android location master switch to {value}")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if location_enabled(adb) == enabled:
            return
        time.sleep(0.5)
    raise CheckError(f"Android location master switch did not become {value}")


def wakefulness(adb: Adb) -> str:
    result = adb.shell("dumpsys", "power", timeout=30, check=False)
    match = re.search(r"^\s*mWakefulness=(\w+)\s*$", result.stdout, re.MULTILINE)
    if result.returncode != 0 or match is None:
        raise CheckError("cannot read device wakefulness")
    return match.group(1)


def wait_for_wakefulness(adb: Adb, expected_awake: bool) -> str:
    deadline = time.monotonic() + 10
    last = "unknown"
    while time.monotonic() < deadline:
        last = wakefulness(adb)
        if (last == "Awake") == expected_awake:
            return last
        time.sleep(0.5)
    raise CheckError(f"device wakefulness transition did not complete: {last}")


def set_awake(adb: Adb, awake: bool) -> str:
    keycode = "KEYCODE_WAKEUP" if awake else "KEYCODE_SLEEP"
    result = adb.shell("input", "keyevent", keycode, check=False)
    if result.returncode != 0:
        raise CheckError(f"cannot inject {keycode}")
    return wait_for_wakefulness(adb, awake)


def active_probe_session(
    adb: Adb,
    report: Report,
    args: argparse.Namespace,
) -> tuple[str, str]:
    probe_args = argparse.Namespace(
        adb_serial=args.adb_serial,
        variant="primary",
        group="location",
        run_id="",
        raw_gnss_mode="blocked",
        observation_window_ms=args.observation_window_ms,
        location_oracle=args.location_oracle,
    )
    run_id = run_probe(report, probe_args)
    metadata = load_run_state(run_id)
    records, verdict = validate_location_jsonl(
        read_device_jsonl(adb, PACKAGES["primary"], run_id), metadata
    )
    summary = summary_payload(records)
    if verdict != "PASS" or summary.get("ordinary_location_event_count", 0) == 0:
        raise CheckError("stability session did not complete with ordinary location activity")
    if (
        summary.get("measurement_event_count") != 0
        or summary.get("navigation_event_count") != 0
        or summary.get("unexpected_event_detected") is not False
    ):
        raise CheckError("stability session delivered a blocked Raw GNSS event")
    validate_active_locations(records, report)
    validate_active_gnss(records, report, require_callbacks=False)
    process = adb.shell("pidof", PACKAGES["primary"], check=False)
    pids = [value for value in process.stdout.split() if value.isdigit()]
    if process.returncode != 0 or len(pids) != 1:
        raise CheckError("stability session has no unique primary probe process")
    return run_id, pids[0]


def apply_pending_generation(
    adb: Adb,
    report: Report,
    args: argparse.Namespace,
    helper_status: dict[str, str],
    generation: int,
    config_digest: str,
    system_server_pid: str,
    system_server_start_ticks: str,
) -> tuple[dict[str, str], str | None]:
    if helper_status["control_state"] == "applied":
        return helper_status, None
    if helper_status["control_state"] != "saved_pending_upstream":
        raise CheckError("live generation cannot be advanced by an upstream trigger")
    trigger_args = argparse.Namespace(
        adb_serial=args.adb_serial,
        variant="primary",
        group="location",
        run_id="",
        raw_gnss_mode="blocked",
        observation_window_ms=min(10_000, max(5_000, args.observation_window_ms)),
        location_oracle="",
    )
    run_id = run_probe(report, trigger_args)
    metadata = load_run_state(run_id)
    records, verdict = validate_location_jsonl(
        read_device_jsonl(adb, PACKAGES["primary"], run_id), metadata
    )
    summary = summary_payload(records)
    if (
        verdict != "PASS"
        or summary.get("measurement_event_count") != 0
        or summary.get("navigation_event_count") != 0
        or summary.get("unexpected_event_detected") is not False
    ):
        raise CheckError("upstream trigger session violated the blocked Raw GNSS boundary")
    result = adb.shell(f"{MODULE_DIR}/locationctl", "status", check=False)
    if result.returncode != 0:
        raise CheckError("post-trigger live helper status is unavailable")
    applied = parse_location_helper_status(result.stdout)
    current_pid, current_start_ticks, _ = system_server_identity(adb)
    if (
        applied["control_state"] != "applied"
        or applied["persisted_generation"] != str(generation)
        or applied["published_generation"] != str(generation)
        or applied["applied_generation"] != str(generation)
        or applied["system_server_pid"] != system_server_pid
        or applied["system_server_start_ticks"] != system_server_start_ticks
        or current_pid != system_server_pid
        or current_start_ticks != system_server_start_ticks
        or current_config_digest(adb) != config_digest
    ):
        raise CheckError("no upstream event applied the pending live generation")
    report.kv("pending_trigger_run_id", run_id)
    return applied, run_id


def stability(report: Report, args: argparse.Namespace) -> None:
    if not args.location_oracle:
        raise CheckError("location stability requires LOCATION_ORACLE")
    location_zip_sha256 = require_artifact(report)
    controller_apk_sha256 = require_controller_artifact(report)
    adb = select_root_adbd(report, args)
    probes = require_probe_artifacts(adb, report)
    state = inspect_module(adb, report)
    if state.get("state") != "active" or not state.get("runtime_attested"):
        raise CheckError("location stability requires an active current-boot runtime")
    require_installed_module(adb, report)
    before_pid, before_start_ticks = inspection_process_identity(state)
    boot_id_sha256 = require_boot_evidence(adb, "active", before_pid, before_start_ticks)
    config = state.get("config")
    if not isinstance(config, dict) or config.get("raw_gnss_mode") != "blocked":
        raise CheckError("location stability requires blocked configuration")
    original_location_enabled = location_enabled(adb)
    if not original_location_enabled:
        raise CheckError("location stability requires Android location enabled")
    original_wakefulness = wakefulness(adb)
    original_awake = original_wakefulness == "Awake"
    crash_before = crash_snapshot(adb)
    run_ids: list[str] = []
    process_pids: list[str] = []
    try:
        run_id, process_pid = active_probe_session(adb, report, args)
        run_ids.append(run_id)
        process_pids.append(process_pid)
        stopped = adb.shell("am", "force-stop", PACKAGES["primary"], check=False)
        if stopped.returncode != 0:
            raise CheckError("cannot stop the primary probe during restart cycle")
        if adb.shell("pidof", PACKAGES["primary"], check=False).stdout.strip():
            raise CheckError("primary probe survived the force-stop restart boundary")

        run_id, process_pid = active_probe_session(adb, report, args)
        run_ids.append(run_id)
        process_pids.append(process_pid)

        set_location_enabled(adb, False)
        time.sleep(3)
        if inspect_module(adb, SelfTestReport()).get("state") != "active":
            raise CheckError("location runtime did not survive provider disable")
        set_location_enabled(adb, True)
        time.sleep(3)

        set_awake(adb, True)
        set_awake(adb, False)
        time.sleep(3)
        set_awake(adb, True)
    finally:
        if location_enabled(adb) != original_location_enabled:
            set_location_enabled(adb, original_location_enabled)
        if (wakefulness(adb) == "Awake") != original_awake:
            set_awake(adb, original_awake)

    after_pid, after_start_ticks, _ = system_server_identity(adb)
    after_state = inspect_module(adb, SelfTestReport())
    reject_new_runtime_crashes(crash_before, crash_snapshot(adb), report)
    report.kv("system_server_pid_before", before_pid)
    report.kv("system_server_pid_after", after_pid)
    report.kv("system_server_start_ticks_before", before_start_ticks)
    report.kv("system_server_start_ticks_after", after_start_ticks)
    report.kv(
        "system_server_stable_during_stability_cycles",
        str((before_pid, before_start_ticks) == (after_pid, after_start_ticks)).lower(),
    )
    report.kv("probe_process_pids", process_pids)
    report.kv("probe_process_restarted", str(len(set(process_pids)) == 2).lower())
    report.kv("provider_disable_enable_cycle", "PASS")
    report.kv("screen_off_on_cycle", "PASS")
    report.kv("original_wakefulness", original_wakefulness)
    report.kv("restored_location_enabled", str(location_enabled(adb)).lower())
    report.kv("restored_awake_state", str((wakefulness(adb) == "Awake") == original_awake).lower())
    if (
        (before_pid, before_start_ticks) != (after_pid, after_start_ticks)
        or after_state.get("state") != "active"
        or not after_state.get("runtime_attested")
        or len(set(process_pids)) != 2
    ):
        raise CheckError("location runtime failed a stability transition")
    config_digest = current_config_digest(adb)
    helper_result = adb.shell(f"{MODULE_DIR}/locationctl", "status", check=False)
    if helper_result.returncode != 0:
        raise CheckError("stability helper status is unavailable")
    helper_status = parse_location_helper_status(helper_result.stdout)
    if (
        helper_status["system_server_pid"] != after_pid
        or helper_status["system_server_start_ticks"] != after_start_ticks
    ):
        raise CheckError("stability helper status has a stale process identity")
    config_generation = int(helper_status["persisted_generation"])
    write_phase(
        "stability",
        {
            "schema_version": 2,
            "phase": "stability",
            "final_generation_id": phase_generation_id(args, "stability"),
            "run_ids": run_ids,
            "location_zip_sha256": location_zip_sha256,
            "controller_apk_sha256": controller_apk_sha256,
            **probes,
            "system_server_pid": after_pid,
            "system_server_start_ticks": after_start_ticks,
            "boot_id_sha256": boot_id_sha256,
            "raw_gnss_mode": "blocked",
            "config_sha256": config_digest,
            "config_generation": config_generation,
            "result": "PASS",
        },
    )
    report.kv("stability_run_ids", run_ids)
    report.kv("phase_state", "private")
    report.kv("phase_result", "PASS")
    report.kv("device_mutation", "restored provider and screen state cycles plus probe restart")


def failure_containment(report: Report, args: argparse.Namespace) -> None:
    location_zip_sha256 = require_artifact(report)
    controller_apk_sha256 = require_controller_artifact(report)
    adb = select_root_adbd(report, args)
    validate_controller_installed(adb, report, controller_apk_sha256)
    probes = require_probe_artifacts(adb, report)
    state = inspect_module(adb, report)
    runtime = state.get("runtime")
    if (
        state.get("state") != "active"
        or not state.get("runtime_attested")
        or not isinstance(runtime, dict)
        or runtime.get("raw_gnss_mode") != "blocked"
    ):
        raise CheckError("failure containment requires an active blocked runtime")
    require_installed_module(adb, report)
    before_pid, before_start_ticks = inspection_process_identity(state)
    boot_id_sha256 = require_boot_evidence(adb, "active", before_pid, before_start_ticks)
    helper = f"{MODULE_DIR}/locationctl"
    before_result = adb.shell(helper, "status", check=False)
    if before_result.returncode != 0:
        raise CheckError("failure containment helper status is unavailable")
    before = parse_location_helper_status(before_result.stdout)
    if (
        before["control_state"] != "applied"
        or before["system_server_pid"] != before_pid
        or before["system_server_start_ticks"] != before_start_ticks
    ):
        raise CheckError("failure containment requires one fully applied generation")
    before_digest = current_config_digest(adb)
    crash_before = crash_snapshot(adb)
    valid_shape = (
        "schema_version=1\n"
        "center_latitude_deg=0\n"
        "center_longitude_deg=0\n"
        "altitude_ellipsoid_m=0\n"
        "altitude_msl_m=0\n"
    )
    cases = (
        ("missing_fields", "schema_version=1\n", "invalid_input_schema"),
        ("unknown_key", valid_shape + "unknown=0\n", "invalid_input_keys"),
        (
            "non_finite",
            valid_shape.replace("center_latitude_deg=0", "center_latitude_deg=nan"),
            "invalid_decimal_input",
        ),
        (
            "out_of_range",
            valid_shape.replace("center_latitude_deg=0", "center_latitude_deg=91"),
            "input_out_of_range",
        ),
        (
            "excess_precision",
            valid_shape.replace("center_longitude_deg=0", "center_longitude_deg=1.000000001"),
            "invalid_decimal_input",
        ),
        ("oversized", "x" * 1025, "stdin_oversized"),
    )
    for name, payload, expected_reason in cases:
        result = adb.shell_input(helper, "apply", input_text=payload, timeout=15, check=False)
        status = parse_location_helper_status(result.stdout)
        if (
            result.returncode == 0
            or status["control_state"] != "rejected"
            or status["reason"] != expected_reason
        ):
            raise CheckError(f"invalid live-input case was not rejected: {name}")
    non_root = adb.shell("run-as", CONTROLLER_PACKAGE, helper, "status", check=False)
    if non_root.returncode == 0:
        raise CheckError("ordinary controller identity executed the root helper directly")
    if re.search(
        r"center_(?:latitude|longitude)_deg|altitude_(?:ellipsoid|msl)_m", non_root.stdout
    ):
        raise CheckError("denied direct helper invocation exposed private fields")
    stopped = adb.shell("am", "force-stop", CONTROLLER_PACKAGE, check=False)
    if (
        stopped.returncode != 0
        or adb.shell("pidof", CONTROLLER_PACKAGE, check=False).stdout.strip()
    ):
        raise CheckError("controller force-stop boundary failed")
    after_result = adb.shell(helper, "status", check=False)
    if after_result.returncode != 0:
        raise CheckError("post-failure helper status is unavailable")
    after = parse_location_helper_status(after_result.stdout)
    after_pid, after_start_ticks, _ = system_server_identity(adb)
    after_state = inspect_module(adb, SelfTestReport())
    reject_new_runtime_crashes(crash_before, crash_snapshot(adb), report)
    stable_keys = (
        "boot_config_generation",
        "persisted_generation",
        "published_generation",
        "applied_generation",
        "raw_gnss_mode",
        "system_server_pid",
        "system_server_start_ticks",
        "boot_id",
    )
    if (
        any(before[key] != after[key] for key in stable_keys)
        or after["control_state"] != "applied"
        or before_digest != current_config_digest(adb)
        or (after_pid, after_start_ticks) != (before_pid, before_start_ticks)
        or after_state.get("state") != "active"
        or not after_state.get("runtime_attested")
    ):
        raise CheckError("invalid update or app stop changed the active generation")
    write_phase(
        "failures",
        {
            "schema_version": 2,
            "phase": "failures",
            "final_generation_id": phase_generation_id(args, "failures"),
            "run_ids": [],
            "location_zip_sha256": location_zip_sha256,
            "controller_apk_sha256": controller_apk_sha256,
            **probes,
            "system_server_pid": before_pid,
            "system_server_start_ticks": before_start_ticks,
            "boot_id_sha256": boot_id_sha256,
            "raw_gnss_mode": "blocked",
            "config_sha256": before_digest,
            "config_generation": int(before["persisted_generation"]),
            "failure_case_count": len(cases),
            "non_root_denial": True,
            "controller_force_stop": True,
            "result": "PASS",
        },
    )
    report.kv("invalid_case_count", len(cases))
    report.kv("non_root_helper_denied", "true")
    report.kv("controller_force_stopped", "true")
    report.kv("generation_unchanged", "true")
    report.kv("coordinates", "absent")
    report.kv("phase_result", "PASS")
    report.kv("device_mutation", "rejected helper calls and controller force-stop")


def stress(report: Report, args: argparse.Namespace) -> None:
    if not args.location_oracle:
        raise CheckError("location stress requires LOCATION_ORACLE")
    location_zip_sha256 = require_artifact(report)
    controller_apk_sha256 = require_controller_artifact(report)
    adb = select_root_adbd(report, args)
    validate_controller_installed(adb, report, controller_apk_sha256)
    probes = require_probe_artifacts(adb, report)
    state = inspect_module(adb, report)
    runtime = state.get("runtime")
    if (
        state.get("state") != "active"
        or not state.get("runtime_attested")
        or not isinstance(runtime, dict)
        or runtime.get("raw_gnss_mode") != "blocked"
    ):
        raise CheckError("location stress requires an active blocked runtime")
    require_installed_module(adb, report)
    before_pid, before_start_ticks = inspection_process_identity(state)
    boot_id_sha256 = require_boot_evidence(adb, "active", before_pid, before_start_ticks)
    input_values = read_private_oracle_input(args.location_oracle)
    helper_input = "".join(f"{key}={input_values[key]}\n" for key in LIVE_INPUT_KEYS)
    if len(helper_input.encode("ascii")) > 1024:
        raise CheckError("private stress input is oversized")
    helper = f"{MODULE_DIR}/locationctl"
    before_result = adb.shell(helper, "status", check=False)
    if before_result.returncode != 0:
        raise CheckError("stress helper status is unavailable")
    before = parse_location_helper_status(before_result.stdout)
    if (
        before["control_state"] != "applied"
        or before["system_server_pid"] != before_pid
        or before["system_server_start_ticks"] != before_start_ticks
    ):
        raise CheckError("location stress requires an applied starting generation")
    generation = int(before["persisted_generation"])
    crash_before = crash_snapshot(adb)
    stopped = adb.shell("am", "force-stop", CONTROLLER_PACKAGE, check=False)
    if stopped.returncode != 0:
        raise CheckError("controller force-stop failed before stress")
    for _ in range(STRESS_UPDATE_COUNT):
        result = adb.shell_input(helper, "apply", input_text=helper_input, timeout=15, check=False)
        status = parse_location_helper_status(result.stdout)
        generation += 1
        if (
            result.returncode != 0
            or status["control_state"] not in {"applied", "saved_pending_upstream"}
            or status["persisted_generation"] != str(generation)
            or status["published_generation"] != str(generation)
            or status["system_server_pid"] != before_pid
            or status["system_server_start_ticks"] != before_start_ticks
        ):
            raise CheckError("bounded repeated live update failed")
    digest = current_config_digest(adb)
    _, trigger_run_id = apply_pending_generation(
        adb, report, args, status, generation, digest, before_pid, before_start_ticks
    )

    def concurrent_probe(variant: str, launch_delay_seconds: int) -> str:
        if launch_delay_seconds:
            time.sleep(launch_delay_seconds)
        probe_args = argparse.Namespace(
            adb_serial=args.adb_serial,
            variant=variant,
            group="location",
            run_id="",
            raw_gnss_mode="blocked",
            observation_window_ms=args.observation_window_ms,
            location_oracle=args.location_oracle,
        )
        return run_probe(SelfTestReport(), probe_args)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = {
            "primary": executor.submit(concurrent_probe, "primary", 0),
            "canary": executor.submit(concurrent_probe, "canary", STRESS_LAUNCH_STAGGER_SECONDS),
        }
        run_ids = {variant: future.result() for variant, future in futures.items()}
    intervals: list[tuple[int, int]] = []
    for variant, run_id in run_ids.items():
        metadata = load_run_state(run_id)
        if (
            metadata.get("expected_config_generation") != generation
            or metadata.get("expected_config_sha256") != digest
        ):
            raise CheckError("concurrent stress role used a different generation")
        records, verdict = validate_location_jsonl(
            read_device_jsonl(adb, PACKAGES[variant], run_id), metadata
        )
        summary = summary_payload(records)
        if (
            verdict != "PASS"
            or summary.get("ordinary_location_event_count", 0) == 0
            or summary.get("measurement_event_count") != 0
            or summary.get("navigation_event_count") != 0
        ):
            raise CheckError("concurrent stress role failed its blocked location session")
        validate_active_locations(records, report)
        validate_active_gnss(records, report, require_callbacks=False)
        timestamps: list[int] = []
        for record in records:
            value = record.get("monotonic_ns")
            if isinstance(value, int):
                timestamps.append(value)
        if len(timestamps) < 2:
            raise CheckError("concurrent stress role has no bounded time interval")
        intervals.append((min(timestamps), max(timestamps)))
    overlap_ns = min(end for _, end in intervals) - max(start for start, _ in intervals)
    minimum_overlap_ns = max(1_000_000_000, args.observation_window_ms * 250_000)
    if overlap_ns < minimum_overlap_ns:
        raise CheckError("primary and canary stress sessions did not overlap")
    after_result = adb.shell(helper, "status", check=False)
    if after_result.returncode != 0:
        raise CheckError("post-stress helper status is unavailable")
    after = parse_location_helper_status(after_result.stdout)
    after_pid, after_start_ticks, _ = system_server_identity(adb)
    after_state = inspect_module(adb, SelfTestReport())
    reject_new_runtime_crashes(crash_before, crash_snapshot(adb), report)
    if (
        after["control_state"] != "applied"
        or after["persisted_generation"] != str(generation)
        or after["published_generation"] != str(generation)
        or after["applied_generation"] != str(generation)
        or after["system_server_pid"] != before_pid
        or after["system_server_start_ticks"] != before_start_ticks
        or (after_pid, after_start_ticks) != (before_pid, before_start_ticks)
        or after_state.get("state") != "active"
        or not after_state.get("runtime_attested")
    ):
        raise CheckError("location stress changed runtime identity or lost its latest generation")
    write_phase(
        "stress",
        {
            "schema_version": 2,
            "phase": "stress",
            "final_generation_id": phase_generation_id(args, "stress"),
            "run_ids": ([trigger_run_id] if trigger_run_id is not None else [])
            + list(run_ids.values()),
            "location_zip_sha256": location_zip_sha256,
            "controller_apk_sha256": controller_apk_sha256,
            **probes,
            "system_server_pid": before_pid,
            "system_server_start_ticks": before_start_ticks,
            "boot_id_sha256": boot_id_sha256,
            "boot_config_generation": int(after["boot_config_generation"]),
            "config_generation": generation,
            "config_sha256": digest,
            "raw_gnss_mode": "blocked",
            "update_count": STRESS_UPDATE_COUNT,
            "concurrent_role_count": len(run_ids),
            "overlap_ms": overlap_ns // 1_000_000,
            "result": "PASS",
        },
    )
    report.kv("update_count", STRESS_UPDATE_COUNT)
    report.kv("config_generation", generation)
    report.kv("config_sha256", digest)
    report.kv("concurrent_role_count", len(run_ids))
    report.kv("concurrent_overlap_ms", overlap_ns // 1_000_000)
    report.kv("system_server_pid_unchanged", "true")
    report.kv("system_server_start_ticks_unchanged", "true")
    report.kv("coordinates", "absent")
    report.kv("phase_result", "PASS")
    report.kv("device_mutation", "five helper updates, controller stop, concurrent probe launch")


def persistence(report: Report, args: argparse.Namespace) -> None:
    if not args.location_oracle:
        raise CheckError("location persistence requires LOCATION_ORACLE")
    stress_phase = load_phase(
        "stress",
        phase_generation_id(args, "stress"),
    )
    location_zip_sha256 = require_artifact(report)
    controller_apk_sha256 = require_controller_artifact(report)
    adb = select_root_adbd(report, args)
    validate_controller_installed(adb, report, controller_apk_sha256)
    probes = require_probe_artifacts(adb, report)
    state = inspect_module(adb, report)
    runtime = state.get("runtime")
    if (
        state.get("state") != "active"
        or not state.get("runtime_attested")
        or not isinstance(runtime, dict)
        or runtime.get("raw_gnss_mode") != "blocked"
    ):
        raise CheckError("persistence validation requires an active blocked runtime after reboot")
    require_installed_module(adb, report)
    pid, start_ticks = inspection_process_identity(state)
    boot_id_sha256 = require_boot_evidence(adb, "active", pid, start_ticks)
    helper_result = adb.shell(f"{MODULE_DIR}/locationctl", "status", check=False)
    if helper_result.returncode != 0:
        raise CheckError("persistence helper status is unavailable")
    helper = parse_location_helper_status(helper_result.stdout)
    generation = stress_phase.get("config_generation")
    digest = stress_phase.get("config_sha256")
    prior_boot_id_sha256 = stress_phase.get("boot_id_sha256")
    if (
        not isinstance(generation, int)
        or not isinstance(digest, str)
        or not isinstance(prior_boot_id_sha256, str)
        or helper["control_state"] != "applied"
        or helper["boot_config_generation"] != str(generation)
        or helper["persisted_generation"] != str(generation)
        or helper["published_generation"] != str(generation)
        or helper["applied_generation"] != str(generation)
        or helper["system_server_pid"] != pid
        or helper["system_server_start_ticks"] != start_ticks
        or boot_id_sha256 == prior_boot_id_sha256
        or current_config_digest(adb) != digest
    ):
        raise CheckError("latest stress generation did not become the next boot generation")
    crash_before = crash_snapshot(adb)
    run_id, _ = active_probe_session(adb, report, args)
    after_pid, after_start_ticks, _ = system_server_identity(adb)
    after_state = inspect_module(adb, SelfTestReport())
    reject_new_runtime_crashes(crash_before, crash_snapshot(adb), report)
    if (
        (after_pid, after_start_ticks) != (pid, start_ticks)
        or after_state.get("state") != "active"
        or not after_state.get("runtime_attested")
        or current_config_digest(adb) != digest
    ):
        raise CheckError("persisted generation changed during its post-reboot session")
    write_phase(
        "persistence",
        {
            "schema_version": 2,
            "phase": "persistence",
            "final_generation_id": phase_generation_id(args, "persistence"),
            "run_id": run_id,
            "location_zip_sha256": location_zip_sha256,
            "controller_apk_sha256": controller_apk_sha256,
            **probes,
            "system_server_pid": pid,
            "system_server_start_ticks": start_ticks,
            "boot_id_sha256": boot_id_sha256,
            "boot_config_generation": generation,
            "config_generation": generation,
            "config_sha256": digest,
            "raw_gnss_mode": "blocked",
            "prior_boot_id_changed": True,
            "result": "PASS",
        },
    )
    report.kv("config_generation", generation)
    report.kv("config_sha256", digest)
    report.kv("boot_id_changed", "true")
    report.kv("system_server_stable_during_session", "true")
    report.kv("coordinates", "absent")
    report.kv("phase_result", "PASS")
    report.kv("device_mutation", "force-stop and launch primary probe after explicit reboot")


def live_generation(report: Report, args: argparse.Namespace, phase: str) -> None:
    if not args.location_oracle:
        raise CheckError(f"{phase} requires LOCATION_ORACLE")
    location_zip_sha256 = require_artifact(report)
    controller_apk_sha256 = require_controller_artifact(report)
    adb = select_root_adbd(report, args)
    validate_controller_installed(adb, report, controller_apk_sha256)
    probes = require_probe_artifacts(adb, report)
    state = inspect_module(adb, report)
    runtime = state.get("runtime")
    if (
        state.get("state") != "active"
        or not state.get("runtime_attested")
        or not isinstance(runtime, dict)
        or runtime.get("state") != "ready"
        or runtime.get("hook_count") != "5"
        or runtime.get("raw_gnss_mode") != "blocked"
    ):
        raise CheckError("live generation validation requires an active five-hook blocked runtime")
    require_installed_module(adb, report)
    before_pid, before_start_ticks = inspection_process_identity(state)
    boot_id_sha256 = require_boot_evidence(adb, "active", before_pid, before_start_ticks)
    helper_result = adb.shell(f"{MODULE_DIR}/locationctl", "status", check=False)
    if helper_result.returncode != 0:
        raise CheckError("live generation helper status is unavailable")
    before_helper = parse_location_helper_status(helper_result.stdout)
    if (
        before_helper["module_state"] != "active"
        or before_helper["runtime_state"] != "active"
        or before_helper["control_state"] not in {"applied", "saved_pending_upstream"}
        or before_helper["raw_gnss_mode"] != "blocked"
        or before_helper["system_server_pid"] != before_pid
        or before_helper["system_server_start_ticks"] != before_start_ticks
    ):
        raise CheckError("live generation is neither applied nor waiting for an upstream event")
    generation = int(before_helper["persisted_generation"])
    if before_helper["published_generation"] != str(generation):
        raise CheckError("live generation is not the current published generation")
    if generation <= int(before_helper["boot_config_generation"]):
        raise CheckError("live generation did not advance beyond the boot configuration")
    digest = current_config_digest(adb)
    crash_before = crash_snapshot(adb)
    initial_control_state = before_helper["control_state"]
    before_helper, trigger_run_id = apply_pending_generation(
        adb,
        report,
        args,
        before_helper,
        generation,
        digest,
        before_pid,
        before_start_ticks,
    )
    run_ids: list[str] = [] if trigger_run_id is None else [trigger_run_id]
    roles = (
        ("primary", "location"),
        ("primary", "secondary-location"),
        ("canary", "location"),
        ("canary", "secondary-location"),
    )
    for variant, group in roles:
        probe_args = argparse.Namespace(
            adb_serial=args.adb_serial,
            variant=variant,
            group=group,
            run_id="",
            raw_gnss_mode="blocked",
            observation_window_ms=args.observation_window_ms,
            location_oracle=args.location_oracle,
        )
        run_id = run_probe(report, probe_args)
        metadata = load_run_state(run_id)
        if (
            metadata.get("expected_config_generation") != generation
            or metadata.get("expected_config_sha256") != digest
        ):
            raise CheckError("live role is not bound to the same private oracle identity")
        records, verdict = validate_location_jsonl(
            read_device_jsonl(adb, PACKAGES[variant], run_id), metadata
        )
        summary = summary_payload(records)
        if verdict != "PASS" or summary.get("ordinary_location_event_count", 0) == 0:
            raise CheckError("live role did not complete with ordinary location activity")
        if (
            summary.get("measurement_event_count") != 0
            or summary.get("navigation_event_count") != 0
            or summary.get("unexpected_event_detected") is not False
        ):
            raise CheckError("live role delivered a blocked Raw GNSS event")
        validate_active_locations(records, report)
        validate_active_gnss(records, report, require_callbacks=False)
        run_ids.append(run_id)
    after_pid, after_start_ticks, _ = system_server_identity(adb)
    after_state = inspect_module(adb, SelfTestReport())
    after_helper_result = adb.shell(f"{MODULE_DIR}/locationctl", "status", check=False)
    if after_helper_result.returncode != 0:
        raise CheckError("post-session live helper status is unavailable")
    after_helper = parse_location_helper_status(after_helper_result.stdout)
    reject_new_runtime_crashes(crash_before, crash_snapshot(adb), report)
    if (
        (after_pid, after_start_ticks) != (before_pid, before_start_ticks)
        or after_state.get("state") != "active"
        or not after_state.get("runtime_attested")
        or after_helper["control_state"] != "applied"
        or after_helper["persisted_generation"] != str(generation)
        or after_helper["published_generation"] != str(generation)
        or after_helper["applied_generation"] != str(generation)
        or after_helper["system_server_pid"] != before_pid
        or after_helper["system_server_start_ticks"] != before_start_ticks
        or current_config_digest(adb) != digest
    ):
        raise CheckError("live generation identity changed during the four-role matrix")
    if phase == "live-edge":
        previous = load_phase(
            "live",
            phase_generation_id(args, "live"),
        )
        previous_generation = previous.get("config_generation")
        if (
            not isinstance(previous_generation, int)
            or generation <= previous_generation
            or previous.get("config_sha256") == digest
            or previous.get("system_server_pid") != before_pid
            or previous.get("system_server_start_ticks") != before_start_ticks
        ):
            raise CheckError("edge generation is not a newer same-runtime live update")
    write_phase(
        phase,
        {
            "schema_version": 2,
            "phase": phase,
            "final_generation_id": phase_generation_id(args, phase),
            "run_ids": run_ids,
            "location_zip_sha256": location_zip_sha256,
            "controller_apk_sha256": controller_apk_sha256,
            **probes,
            "system_server_pid": before_pid,
            "system_server_start_ticks": before_start_ticks,
            "boot_id_sha256": boot_id_sha256,
            "boot_config_generation": int(before_helper["boot_config_generation"]),
            "initial_control_state": initial_control_state,
            "config_generation": generation,
            "config_sha256": digest,
            "raw_gnss_mode": "blocked",
            "role_count": len(roles),
            "result": "PASS",
        },
    )
    report.kv("phase", phase)
    report.kv("config_generation", generation)
    report.kv("config_sha256", digest)
    report.kv("role_count", len(roles))
    report.kv("run_ids", run_ids)
    report.kv("system_server_pid_unchanged", "true")
    report.kv("system_server_start_ticks_unchanged", "true")
    report.kv("hook_count_unchanged", "true")
    report.kv("coordinates", "absent")
    report.kv("phase_result", "PASS")
    report.kv("device_mutation", "force-stop and launch four independent probe roles")


def phase_path(phase: str) -> Path:
    return STATE_DIR / f"{phase}.json"


def write_phase(phase: str, data: dict[str, object]) -> None:
    PHASE_WRITE.stage(
        phase_path(phase),
        json.dumps(data, sort_keys=True, indent=2) + "\n",
    )


def validate_phase_header(
    value: object, phase: str, expected_generation_id: str | None = None
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CheckError(f"location phase is not an object: {phase}")
    generation_id = value.get("final_generation_id")
    generation_valid = (
        generation_id == "baseline-independent"
        if phase == "baseline"
        else isinstance(generation_id, str)
        and (generation_id == "unbound" or re.fullmatch(r"[0-9a-f]{64}", generation_id) is not None)
    )
    if (
        value.get("schema_version") != 2
        or value.get("phase") != phase
        or not generation_valid
        or (expected_generation_id is not None and generation_id != expected_generation_id)
    ):
        raise CheckError(f"location phase schema or frozen generation mismatch: {phase}")
    return cast(dict[str, object], value)


def load_phase(phase: str, expected_generation_id: str | None = None) -> dict[str, object]:
    path = phase_path(phase)
    if not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise CheckError(f"required location phase is missing or not mode 0600: {phase}")
    try:
        value: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CheckError(f"location phase is unreadable: {phase}") from error
    return validate_phase_header(value, phase, expected_generation_id)


def inspection_pid(state: dict[str, object]) -> str:
    pid = state.get("pid")
    if not isinstance(pid, str) or not pid.isdigit():
        raise CheckError("location module inspection has no valid system_server PID")
    return pid


def inspection_process_identity(state: dict[str, object]) -> tuple[str, str]:
    pid = inspection_pid(state)
    start_ticks = state.get("system_server_start_ticks")
    if not isinstance(start_ticks, str) or not start_ticks.isdigit() or int(start_ticks) == 0:
        raise CheckError("location module inspection has no valid system_server start time")
    return pid, start_ticks


def run_phase(report: Report, args: argparse.Namespace, phase: str) -> None:
    oracle_required = phase in ACTIVE_PHASES or phase == "restored"
    if oracle_required and not args.location_oracle:
        raise CheckError(f"location phase {phase} requires LOCATION_ORACLE")
    location_zip_sha256 = require_artifact(report)
    controller_apk_sha256 = require_controller_artifact(report)
    adb = select_root_adbd(report, args)
    probes = require_probe_artifacts(adb, report)
    before_state = inspect_module(adb, report)
    expected_state = PHASE_STATE[phase]
    if before_state["state"] != expected_state:
        raise CheckError(
            f"location phase {phase} requires {expected_state}, got {before_state['state']}"
        )
    if phase == "baseline":
        if before_state["native_mapped"]:
            raise CheckError("baseline unexpectedly maps the location module")
    else:
        require_installed_module(adb, report)
    before_pid, before_start_ticks = inspection_process_identity(before_state)
    boot_id_sha256 = current_boot_id_sha256(adb)
    if phase in {"disabled", "restored"}:
        boot_id_sha256 = require_boot_evidence(adb, "disabled", before_pid, before_start_ticks)
    elif phase in ACTIVE_PHASES:
        boot_id_sha256 = require_boot_evidence(adb, "active", before_pid, before_start_ticks)
    config = before_state.get("config")
    if phase != "baseline" and not isinstance(config, dict):
        raise CheckError("installed location config is unavailable")
    config_values = cast(dict[str, str], config) if isinstance(config, dict) else {}
    if phase in ACTIVE_PHASES:
        runtime = before_state.get("runtime")
        if (
            not before_state.get("runtime_attested")
            or not isinstance(runtime, dict)
            or runtime.get("state") != "ready"
            or runtime.get("hook_count") != "5"
            or config_values.get("raw_gnss_mode") != PHASE_MODE[phase]
        ):
            raise CheckError("active location runtime/hook/mode contract mismatch")
        if phase == "passthrough" and "physical_raw_warning" not in str(runtime.get("reason")):
            raise CheckError("passthrough runtime status omits the physical Raw GNSS warning")
    crash_before = crash_snapshot(adb)
    probe_args = argparse.Namespace(
        adb_serial=args.adb_serial,
        variant="primary",
        group="location",
        run_id="",
        raw_gnss_mode=PHASE_MODE[phase],
        observation_window_ms=args.observation_window_ms,
        location_oracle=args.location_oracle if oracle_required else "",
        expected_spatial_mismatch=phase == "restored",
    )
    run_id = run_probe(report, probe_args)
    metadata = load_run_state(run_id)
    content = read_device_jsonl(adb, PACKAGES["primary"], run_id)
    records, verdict = validate_location_jsonl(content, metadata)
    after_pid, after_start_ticks, _ = system_server_identity(adb)
    after_state = inspect_module(adb, SelfTestReport())
    reject_new_runtime_crashes(crash_before, crash_snapshot(adb), report)
    report.kv("system_server_pid_before", before_pid)
    report.kv("system_server_pid_after", after_pid)
    report.kv("system_server_start_ticks_before", before_start_ticks)
    report.kv("system_server_start_ticks_after", after_start_ticks)
    report.kv(
        "system_server_stable_during_session",
        str((before_pid, before_start_ticks) == (after_pid, after_start_ticks)).lower(),
    )
    if (before_pid, before_start_ticks) != (after_pid, after_start_ticks):
        raise CheckError("system_server restarted during the location session")
    if phase in ACTIVE_PHASES and after_state.get("state") != "active":
        raise CheckError("active location runtime attestation disappeared during the session")
    if phase not in ACTIVE_PHASES and after_state.get("runtime_attested"):
        raise CheckError("inactive location phase has a current-boot runtime attestation")
    summary = summary_payload(records)
    inventory = provider_inventory(records)
    expected_verdict = "FAIL" if phase == "restored" else "PASS"
    if verdict != expected_verdict or summary.get("ordinary_location_event_count", 0) == 0:
        raise CheckError("location session did not complete with ordinary public location activity")
    baseline: dict[str, object] | None = None
    if phase != "baseline":
        baseline = load_phase("baseline")
        compare_stock_contract(summary, baseline)
        if inventory != baseline.get("provider_inventory"):
            raise CheckError("provider inventory differs from the no-module baseline")
    gnss_status_validated = False
    nmea_validated = False
    if phase in ACTIVE_PHASES:
        validate_active_locations(records, report)
        gnss_status_validated, nmea_validated = validate_active_gnss(
            records,
            report,
            require_callbacks=False,
        )
    if phase in {"blocked", "isolation"} and (
        summary.get("measurement_event_count") != 0
        or summary.get("navigation_event_count") != 0
        or summary.get("unexpected_event_detected") is not False
    ):
        raise CheckError("blocked Raw GNSS firewall delivered a physical event")
    if phase == "isolation":
        validate_process_isolation(adb, records, report)
    if phase == "restored":
        validate_restored_stock(records, report)
    if phase == "passthrough":
        report.kv("physical_raw_exposure_warning", "true")
    config_digest = "not-installed"
    if phase != "baseline":
        config_digest = current_config_digest(adb)
    phase_data: dict[str, object] = {
        "schema_version": 2,
        "phase": phase,
        "final_generation_id": phase_generation_id(args, phase),
        "run_id": run_id,
        "location_zip_sha256": location_zip_sha256,
        "controller_apk_sha256": controller_apk_sha256,
        **probes,
        "system_server_pid": after_pid,
        "system_server_start_ticks": after_start_ticks,
        "boot_id_sha256": boot_id_sha256,
        "raw_gnss_mode": PHASE_MODE[phase],
        "config_sha256": config_digest,
        "config_generation": summary.get("expected_config_generation"),
        "provider_inventory": inventory,
        "gnss_status_model_validated": gnss_status_validated,
        "nmea_model_validated": nmea_validated,
        "summary": {
            key: summary.get(key)
            for key in (
                "reported_measurement_capability",
                "reported_navigation_capability",
                "measurement_registration_result",
                "navigation_registration_result",
                "measurement_event_count",
                "navigation_event_count",
                "ordinary_location_event_count",
                "location_batch_event_count",
                "gnss_status_event_count",
                "nmea_event_count",
            )
        },
        "result": "PASS",
    }
    write_phase(phase, phase_data)
    report.kv("phase", phase)
    report.kv("phase_state", "private")
    report.kv("phase_result", "PASS")
    report.kv("coordinates_in_report", "absent")


def phase_command(phase: str) -> Callable[[Report, argparse.Namespace], None]:
    return lambda report, args: run_phase(report, args, phase)


def phase_identity_is_current(
    phase: str,
    state: dict[str, object],
    location_hash: str,
    controller_hash: str,
    probe_hashes: dict[str, str],
    source_hash: str,
) -> bool:
    process_pid = state.get("system_server_pid")
    process_start_ticks = state.get("system_server_start_ticks")
    return (
        state.get("result") == "PASS"
        and isinstance(process_pid, str)
        and process_pid.isdigit()
        and int(process_pid) > 0
        and isinstance(process_start_ticks, str)
        and process_start_ticks.isdigit()
        and int(process_start_ticks) > 0
        and isinstance(state.get("boot_id_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", cast(str, state["boot_id_sha256"])) is not None
        and (
            phase == "baseline"
            or (
                state.get("location_zip_sha256") == location_hash
                and state.get("controller_apk_sha256") == controller_hash
            )
        )
        and state.get("primary_apk_sha256") == probe_hashes["primary"]
        and state.get("canary_apk_sha256") == probe_hashes["canary"]
        and state.get("location_source_sha256") == source_hash
    )


def aggregate(report: Report, args: argparse.Namespace) -> None:
    required = (
        "baseline",
        "disabled",
        "passthrough",
        "blocked",
        "live",
        "live-edge",
        "isolation",
        "stability",
        "failures",
        "stress",
        "persistence",
        "restored",
    )
    expected_generation_id = getattr(args, "final_generation_id", "")
    phases = {
        phase: load_phase(
            phase,
            (
                "baseline-independent"
                if phase == "baseline"
                else expected_generation_id or "unbound"
            ),
        )
        for phase in required
    }
    phase_generation_ids = {
        phases[phase].get("final_generation_id") for phase in required if phase != "baseline"
    }
    if len(phase_generation_ids) != 1 or (
        expected_generation_id and phase_generation_ids != {expected_generation_id}
    ):
        raise CheckError("location phases are unbound or belong to different frozen generations")
    current_location_hash = require_artifact(report)
    current_controller_hash = require_controller_artifact(report)
    current_probe_hashes = {variant: sha256(path) for variant, path in APKS.items()}
    current_location_source_hash = location_probe_source_hash()
    run_ids: set[object] = set()
    for phase, state in phases.items():
        if not phase_identity_is_current(
            phase,
            state,
            current_location_hash,
            current_controller_hash,
            current_probe_hashes,
            current_location_source_hash,
        ):
            raise CheckError(f"location phase is stale or failed: {phase}")
        phase_run_ids = state.get("run_ids")
        if isinstance(phase_run_ids, list):
            run_ids.update(phase_run_ids)
        else:
            run_ids.add(state.get("run_id"))
    expected_run_count = sum(
        len(cast(list[object], state["run_ids"])) if isinstance(state.get("run_ids"), list) else 1
        for state in phases.values()
    )
    if len(run_ids) != expected_run_count or None in run_ids:
        raise CheckError("location acceptance phase run IDs are not unique")
    blocked_generation = phases["blocked"].get("config_generation")
    live_generation_value = phases["live"].get("config_generation")
    edge_generation = phases["live-edge"].get("config_generation")
    stress_generation = phases["stress"].get("config_generation")
    persistence_generation = phases["persistence"].get("config_generation")
    edge_process_identity = (
        phases["live-edge"].get("system_server_pid"),
        phases["live-edge"].get("system_server_start_ticks"),
    )
    same_runtime_phases = (
        "blocked",
        "live",
        "isolation",
        "stability",
        "failures",
        "stress",
    )
    same_boot_phases = (*same_runtime_phases, "live-edge")
    blocked_boot_id_sha256 = phases["blocked"].get("boot_id_sha256")
    if (
        not isinstance(blocked_generation, int)
        or not isinstance(live_generation_value, int)
        or not isinstance(edge_generation, int)
        or not isinstance(stress_generation, int)
        or not isinstance(persistence_generation, int)
        or not blocked_generation < live_generation_value < edge_generation < stress_generation
        or persistence_generation != stress_generation
        or phases["blocked"].get("config_sha256") == phases["live"].get("config_sha256")
        or phases["live"].get("config_sha256") == phases["live-edge"].get("config_sha256")
        or any(
            (
                phases[phase].get("system_server_pid"),
                phases[phase].get("system_server_start_ticks"),
            )
            != edge_process_identity
            for phase in same_runtime_phases
        )
        or phases["persistence"].get("config_sha256") != phases["stress"].get("config_sha256")
        or phases["persistence"].get("boot_config_generation") != stress_generation
        or any(
            phases[phase].get("boot_id_sha256") != blocked_boot_id_sha256
            for phase in same_boot_phases
        )
        or phases["passthrough"].get("boot_id_sha256") == blocked_boot_id_sha256
        or phases["persistence"].get("boot_id_sha256") == blocked_boot_id_sha256
        or (
            phases["persistence"].get("system_server_pid"),
            phases["persistence"].get("system_server_start_ticks"),
        )
        == edge_process_identity
    ):
        raise CheckError("live/stress/persistence generations or boot identities are inconsistent")
    edge_config = phases["live-edge"].get("config_sha256")
    if any(
        phases[phase].get("config_sha256") != edge_config
        for phase in ("isolation", "stability", "failures")
    ):
        raise CheckError("edge/isolation/stability/failure phases use different configurations")
    if (
        phases["failures"].get("config_generation") != edge_generation
        or phases["failures"].get("non_root_denial") is not True
        or phases["failures"].get("controller_force_stop") is not True
        or phases["stress"].get("update_count") != STRESS_UPDATE_COUNT
        or phases["stress"].get("concurrent_role_count") != 2
        or phases["persistence"].get("prior_boot_id_changed") is not True
    ):
        raise CheckError("failure/stress/persistence acceptance evidence is incomplete")
    recovery = report_values(RECOVERY_REPORT)
    persistence_reboot = report_values(REBOOT_REPORT)
    with zipfile.ZipFile(MODULE_ZIP) as archive:
        expected_recovery_native = hashlib.sha256(archive.read("zygisk/arm64-v8a.so")).hexdigest()
        expected_recovery_helper = hashlib.sha256(archive.read("locationctl")).hexdigest()
    if (
        recovery.get("exit_status") != "0"
        or recovery.get("recovery_status") != "PASS"
        or recovery.get("state") != "disabled"
        or recovery.get("system_server_stable") != "true"
        or recovery.get("system_server_pid") != phases["restored"].get("system_server_pid")
        or recovery.get("system_server_start_ticks")
        != phases["restored"].get("system_server_start_ticks")
        or recovery.get("boot_id_sha256") != phases["restored"].get("boot_id_sha256")
        or recovery.get("reboot_source_boot_id_sha256")
        != phases["persistence"].get("boot_id_sha256")
        or recovery.get("recovery_host_artifact_sha256") != current_location_hash
        or recovery.get("native_sha256") != expected_recovery_native
        or recovery.get("helper_sha256") != expected_recovery_helper
        or recovery.get("runtime_prerequisites_valid") != "true"
    ):
        raise CheckError("exact-generation location recovery evidence is missing")
    if (
        persistence_reboot.get("exit_status") != "0"
        or persistence_reboot.get("state") != "active"
        or persistence_reboot.get("system_server_stable") != "true"
        or persistence_reboot.get("system_server_pid")
        != phases["persistence"].get("system_server_pid")
        or persistence_reboot.get("system_server_start_ticks")
        != phases["persistence"].get("system_server_start_ticks")
        or persistence_reboot.get("boot_id_sha256") != phases["persistence"].get("boot_id_sha256")
        or persistence_reboot.get("reboot_source_boot_id_sha256")
        != phases["stress"].get("boot_id_sha256")
    ):
        raise CheckError("exact persistence reboot evidence is missing")
    controller_status = report_values(CONTROLLER_STATUS_REPORT)
    if (
        controller_status.get("exit_status") != "0"
        or controller_status.get("artifact_sha256") != current_controller_hash
        or controller_status.get("installed_apk_sha256") != current_controller_hash
        or controller_status.get("authorization") != "granted"
        or controller_status.get("module_state") != "active"
        or controller_status.get("runtime_state") != "active"
        or controller_status.get("control_state") != "applied"
        or controller_status.get("reason") != "none"
        or any(
            controller_status.get(key) != str(blocked_generation)
            for key in (
                "boot_config_generation",
                "persisted_generation",
                "published_generation",
                "applied_generation",
            )
        )
        or controller_status.get("coordinates") != "absent"
        or controller_status.get("redaction_check") != "pass"
    ):
        raise CheckError("exact controller authorization/status evidence is missing")
    blocked_summary = cast(dict[str, object], phases["blocked"]["summary"])
    report.kv(
        "blocked_gnss_status_model_observed",
        str(phases["blocked"].get("gnss_status_model_validated") is True).lower(),
    )
    report.kv(
        "blocked_nmea_model_observed",
        str(phases["blocked"].get("nmea_model_validated") is True).lower(),
    )
    report.kv("location_zip_sha256", current_location_hash)
    report.kv("controller_apk_sha256", current_controller_hash)
    report.kv("primary_probe_sha256", current_probe_hashes["primary"])
    report.kv("canary_probe_sha256", current_probe_hashes["canary"])
    report.kv("phase_count", len(phases))
    report.kv("final_generation_id", next(iter(phase_generation_ids)))
    report.kv("phase_run_ids", sorted(cast(Iterable[str], run_ids)))
    report.kv("blocked_measurement_event_count", blocked_summary["measurement_event_count"])
    report.kv("blocked_navigation_event_count", blocked_summary["navigation_event_count"])
    report.kv(
        "live_generations",
        [
            blocked_generation,
            live_generation_value,
            edge_generation,
            stress_generation,
            persistence_generation,
        ],
    )
    report.kv("recovery", "PASS")
    report.kv("coordinates", "absent")
    report.kv("acceptance", "PASS")
    report.kv("device_mutation", "none")


def oracle_self_test() -> None:
    final_generation_id = "f" * 64
    final_phase = {
        "schema_version": 2,
        "phase": "blocked",
        "final_generation_id": final_generation_id,
    }
    validate_phase_header(final_phase, "blocked", final_generation_id)
    validate_phase_header(
        {
            "schema_version": 2,
            "phase": "baseline",
            "final_generation_id": "baseline-independent",
        },
        "baseline",
        "baseline-independent",
    )
    for invalid in (
        dict(final_phase, final_generation_id="unbound"),
        dict(final_phase, final_generation_id="e" * 64),
        dict(final_phase, final_generation_id=[final_generation_id]),
    ):
        try:
            validate_phase_header(invalid, "blocked", final_generation_id)
        except CheckError:
            pass
        else:
            raise CheckError("location final-generation phase self-test accepted a mismatch")
    if inspection_pid({"pid": "123"}) != "123":
        raise CheckError("location inspection PID self-test failed")
    if inspection_process_identity({"pid": "123", "system_server_start_ticks": "456"}) != (
        "123",
        "456",
    ):
        raise CheckError("location inspection process-identity self-test failed")
    try:
        inspection_pid({"state": "absent"})
    except CheckError:
        pass
    else:
        raise CheckError("location inspection missing-PID self-test failed")
    boot_evidence = {
        "exit_status": "0",
        "system_server_stable": "true",
        "state": "active",
        "system_server_pid": "123",
        "system_server_start_ticks": "456",
        "boot_id_sha256": "a" * 64,
    }
    if not boot_evidence_matches(boot_evidence, "active", "123", "456", "a" * 64):
        raise CheckError("current boot evidence self-test failed")
    if boot_evidence_matches(boot_evidence, "active", "123", "456", "b" * 64):
        raise CheckError("stale boot evidence self-test failed")
    if boot_evidence_matches(boot_evidence, "active", "123", "457", "a" * 64):
        raise CheckError("PID-reused boot evidence self-test failed")
    shared_host_evidence = dict(boot_evidence)
    shared_host_evidence.pop("state")
    shared_host_evidence["location_state"] = "disabled"
    if not boot_evidence_matches(shared_host_evidence, "disabled", "123", "456", "a" * 64):
        raise CheckError("shared-host boot evidence self-test failed")
    if boot_evidence_matches(
        dict(boot_evidence, location_state="disabled"), "active", "123", "456", "a" * 64
    ):
        raise CheckError("conflicting shared-host boot evidence self-test failed")
    phase_identity: dict[str, object] = {
        "result": "PASS",
        "location_zip_sha256": "old-location",
        "controller_apk_sha256": "old-controller",
        "primary_apk_sha256": "primary",
        "canary_apk_sha256": "canary",
        "location_source_sha256": "source",
        "system_server_pid": "123",
        "system_server_start_ticks": "456",
        "boot_id_sha256": "a" * 64,
    }
    identity_arguments = (
        "new-location",
        "new-controller",
        {"primary": "primary", "canary": "canary"},
        "source",
    )
    if not phase_identity_is_current("baseline", phase_identity, *identity_arguments):
        raise CheckError("artifact-independent baseline self-test failed")
    if phase_identity_is_current("blocked", phase_identity, *identity_arguments):
        raise CheckError("stale active artifact identity self-test failed")
    stale_probe = dict(phase_identity, primary_apk_sha256="old-primary")
    if phase_identity_is_current("baseline", stale_probe, *identity_arguments):
        raise CheckError("stale baseline probe identity self-test failed")
    ordinary_descriptors = "\n".join(
        (
            "lr-x------ 1 u0_a187 u0_a187 64 Jan 01 00:00 82 -> "
            "/data/app/example/dev.zygveil.probe.primary/base.apk",
            "lr-x------ 1 u0_a187 u0_a187 64 Jan 01 00:00 106 -> "
            "/data/data/dev.zygveil.probe.primary/no_backup/location-oracle.properties (deleted)",
        )
    )
    if forbidden_application_descriptor_count(ordinary_descriptors) != 0:
        raise CheckError("ordinary ZygVeil application descriptor self-test failed")
    forbidden_descriptors = "\n".join(
        (
            f"lr-x------ 1 root root 64 Jan 01 00:00 7 -> {MODULE_DIR}/.app-control",
            "lr-x------ 1 root root 64 Jan 01 00:00 8 -> /memfd:libzygveil (deleted)",
            "lr-x------ 1 root root 64 Jan 01 00:00 9 -> anon_inode:[pidfd]",
        )
    )
    if forbidden_application_descriptor_count(forbidden_descriptors) != 3:
        raise CheckError("forbidden ZygVeil application descriptor self-test failed")
    location = {
        "provider": "gps",
        "time_ms": 1_700_000_000_000,
        "elapsed_realtime_ns": 1_000_000_000,
        "mock": False,
        "complete": True,
        "has_accuracy": True,
        "has_altitude": True,
        "has_vertical_accuracy": True,
        "has_msl_altitude": True,
        "has_msl_altitude_accuracy": True,
        "has_speed": True,
        "has_speed_accuracy": True,
        "has_bearing": False,
        "has_bearing_accuracy": False,
        "coordinates_finite": True,
        "latitude_in_range": True,
        "longitude_in_range": True,
        "displacement_from_first_sample_m": 0.0,
        "expected_center_distance_m": 0.2,
        "within_expected_radius": True,
        "outside_expected_center_exclusion": False,
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
    records: list[dict[str, object]] = [
        {
            "record_type": "observation",
            "observation_type": "location_update",
            "status": "SUCCESS",
            "source": "gps",
            "payload": location,
        },
        {
            "record_type": "observation",
            "observation_type": "gnss_status",
            "status": "SUCCESS",
            "source": "gnss",
            "payload": {
                "satellite_count": 16,
                "used_in_fix_count": 10,
                "ephemeris_count": 16,
                "almanac_count": 16,
                "carrier_frequency_count": 16,
                "cn0_min_dbhz": 25.0,
                "cn0_max_dbhz": 42.0,
            },
        },
    ]
    for sentence_type in ("GGA", "RMC", "GSA", "GSV"):
        payload: dict[str, object] = {
            "sentence_type": sentence_type,
            "valid": True,
            "valid_shape": True,
            "checksum_valid": True,
            "supported_sentence": True,
            "raw_sentence_redacted": True,
        }
        if sentence_type in {"GGA", "RMC"}:
            payload.update(
                {
                    "coordinate_fields_present": True,
                    "coordinate_parse_valid": True,
                    "coordinates_finite": True,
                    "latitude_in_range": True,
                    "longitude_in_range": True,
                    "displacement_from_first_sample_m": 0.1,
                    "expected_center_distance_m": 0.3,
                    "within_expected_radius": True,
                    "outside_expected_center_exclusion": False,
                    "cross_channel_distance_m": 0.2,
                    "cross_channel_consistent": True,
                }
            )
        if sentence_type == "GGA":
            payload.update(
                {
                    "satellites": 10,
                    "fix_quality": 1,
                    "hdop_present": True,
                    "hdop_parse_valid": True,
                    "hdop_finite": True,
                    "hdop_non_negative": True,
                    "altitude_msl_present": True,
                    "altitude_msl_parse_valid": True,
                    "altitude_msl_finite": True,
                    "geoid_separation_present": True,
                    "geoid_separation_parse_valid": True,
                    "geoid_separation_finite": True,
                    "altitude_fields_finite": True,
                    "altitude_msl_consistent": True,
                    "geoid_separation_consistent": True,
                }
            )
        elif sentence_type == "RMC":
            payload.update(
                {
                    "speed_present": True,
                    "speed_parse_valid": True,
                    "speed_finite": True,
                    "speed_non_negative": True,
                    "course_present": False,
                    "course_parse_valid": True,
                    "course_finite": True,
                    "course_in_range": True,
                    "speed_within_expected_bound": True,
                    "stationary_course_absent": True,
                }
            )
        elif sentence_type == "GSA":
            payload["satellite_id_count"] = 10
            for prefix in ("pdop", "hdop", "vdop"):
                payload[f"{prefix}_present"] = True
                payload[f"{prefix}_parse_valid"] = True
                payload[f"{prefix}_finite"] = True
                payload[f"{prefix}_non_negative"] = True
        elif sentence_type == "GSV":
            payload["satellites"] = 16
        records.append(
            {
                "record_type": "observation",
                "observation_type": "nmea",
                "status": "SUCCESS",
                "source": "gnss",
                "payload": payload,
            }
        )
    report = SelfTestReport()
    validate_active_locations(records, report)
    validate_active_gnss(records, report, require_callbacks=True)
    restored: list[dict[str, object]] = [
        {
            "record_type": "observation",
            "observation_type": "location_update",
            "status": "SUCCESS",
            "source": "gps",
            "payload": {
                **location,
                "expected_center_distance_m": 500.0,
                "within_expected_radius": False,
                "outside_expected_center_exclusion": True,
            },
        }
    ]
    validate_restored_stock(restored, report)


COMMANDS: dict[str, Callable[[Report, argparse.Namespace], None]] = {
    "test-location-acceptance": aggregate,
    "test-location-baseline": phase_command("baseline"),
    "test-location-blocked": phase_command("blocked"),
    "test-location-disabled": phase_command("disabled"),
    "test-location-failures": failure_containment,
    "test-location-isolation": phase_command("isolation"),
    "test-location-live": lambda report, args: live_generation(report, args, "live"),
    "test-location-live-edge": lambda report, args: live_generation(report, args, "live-edge"),
    "test-location-passthrough": phase_command("passthrough"),
    "test-location-persistence": persistence,
    "test-location-restored": phase_command("restored"),
    "test-location-stability": stability,
    "test-location-stress": stress,
}


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--adb-serial", default="")
    parser.add_argument("--observation-window-ms", type=int, default=20_000)
    parser.add_argument("--location-oracle", default="")
    parser.add_argument("--builder-tag", default="")
    parser.add_argument("--dependency-key", default="")
    parser.add_argument("--final-context", action="store_true")
    parser.add_argument("--boot-blocked", default=".state/location-boot-blocked.properties")
    parser.add_argument("--boot-passthrough", default=".state/location-boot-passthrough.properties")
    parser.add_argument("--oracle-blocked", default=".state/location-oracle-blocked.properties")
    parser.add_argument(
        "--oracle-passthrough", default=".state/location-oracle-passthrough.properties"
    )
    parser.add_argument("--live", default=".state/location-live-second.properties")
    parser.add_argument("--edge", default=".state/location-live-edge.properties")
    parser.add_argument("command", choices=sorted(COMMANDS))
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    try:
        with Report(ROOT / args.report_dir, args.command) as report:
            private_decimals: tuple[str, ...] = ()
            try:
                args.final_generation_id = ""
                if args.final_context:
                    from location_final_inputs import verify_final_input_receipt
                    from server_vpn_final import load_generation

                    generation = load_generation(report, args)
                    args.final_generation_id = cast(str, generation["generation_id"])
                    private_decimals = verify_final_input_receipt(report, args, generation)
                if args.location_oracle:
                    private_values = read_private_oracle_input(args.location_oracle)
                    private_decimals += tuple(private_values[key] for key in LIVE_INPUT_KEYS[1:])
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
                    [lambda content: contains_private_decimal_values(content, private_decimals)],
                )
        PHASE_WRITE.commit()
    except CheckError:
        PHASE_WRITE.discard()
        return 1
    except Exception:
        PHASE_WRITE.discard()
        traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
