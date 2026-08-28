// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.location.controller;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public record HelperStatus(
    String moduleState,
    String runtimeState,
    String controlState,
    String reason,
    String bootGeneration,
    String persistedGeneration,
    String publishedGeneration,
    String appliedGeneration,
    CoordinateInput.Values coordinates) {
  private static final int MAXIMUM_OUTPUT_BYTES = 16 * 1024;
  private static final BigInteger MAXIMUM_UNSIGNED_LONG = new BigInteger("18446744073709551615");
  private static final BigInteger MAXIMUM_UNSIGNED_INT = new BigInteger("4294967295");
  private static final BigInteger MAXIMUM_CONFIG_GENERATION = new BigInteger("4611686018427387903");
  private static final Set<String> REQUIRED_KEYS =
      Set.of(
          "schema_version",
          "module_state",
          "runtime_state",
          "control_state",
          "reason",
          "raw_gnss_mode",
          "boot_config_generation",
          "persisted_generation",
          "published_generation",
          "applied_generation",
          "system_server_pid",
          "system_server_start_ticks",
          "boot_id");
  private static final Set<String> COORDINATE_KEYS =
      Set.of(
          "center_latitude_deg", "center_longitude_deg", "altitude_ellipsoid_m", "altitude_msl_m");
  private static final Set<String> MODULE_STATES = Set.of("waiting", "active", "inactive");
  private static final Set<String> RUNTIME_STATES =
      Set.of("unavailable", "uninitialized", "arming", "waiting", "active", "inactive");
  private static final Set<String> CONTROL_STATES =
      Set.of(
          "unavailable",
          "awaiting_first_coordinates",
          "saved_pending_upstream",
          "saved_pending_reboot",
          "recovery_required",
          "applied",
          "rejected");

  public static HelperStatus parse(String text) throws ProtocolException {
    if (text == null
        || text.isEmpty()
        || text.length() > MAXIMUM_OUTPUT_BYTES
        || text.indexOf('\0') >= 0) {
      throw new ProtocolException("invalid_output_size");
    }
    Map<String, String> values = new HashMap<>();
    for (String line : text.split("\\n", -1)) {
      if (line.isEmpty()) {
        continue;
      }
      int separator = line.indexOf('=');
      if (separator <= 0
          || separator + 1 >= line.length()
          || line.indexOf('=', separator + 1) >= 0) {
        throw new ProtocolException("invalid_output_shape");
      }
      String key = line.substring(0, separator);
      String value = line.substring(separator + 1);
      if ((!REQUIRED_KEYS.contains(key) && !COORDINATE_KEYS.contains(key))
          || values.putIfAbsent(key, value) != null) {
        throw new ProtocolException("invalid_output_keys");
      }
    }
    if (!values.keySet().containsAll(REQUIRED_KEYS) || !"1".equals(values.get("schema_version"))) {
      throw new ProtocolException("invalid_output_schema");
    }
    int coordinateCount = 0;
    for (String key : COORDINATE_KEYS) {
      coordinateCount += values.containsKey(key) ? 1 : 0;
    }
    if (coordinateCount != 0 && coordinateCount != COORDINATE_KEYS.size()) {
      throw new ProtocolException("partial_coordinates");
    }
    requireMember(values.get("module_state"), MODULE_STATES, "invalid_module_state");
    requireMember(values.get("runtime_state"), RUNTIME_STATES, "invalid_runtime_state");
    requireMember(values.get("control_state"), CONTROL_STATES, "invalid_control_state");
    requireToken(values.get("reason"));
    String rawMode = values.get("raw_gnss_mode");
    if (!"blocked".equals(rawMode) && !"passthrough".equals(rawMode)) {
      throw new ProtocolException("invalid_raw_mode");
    }
    BigInteger boot = requireUnsigned(values.get("boot_config_generation"));
    BigInteger persisted = requireUnsigned(values.get("persisted_generation"));
    BigInteger published = requireUnsigned(values.get("published_generation"));
    BigInteger applied = requireUnsigned(values.get("applied_generation"));
    BigInteger systemServerPid = requireUnsigned(values.get("system_server_pid"));
    BigInteger systemServerStartTicks = requireUnsigned(values.get("system_server_start_ticks"));
    requireBootId(values.get("boot_id"));
    if (boot.compareTo(MAXIMUM_CONFIG_GENERATION) > 0
        || persisted.compareTo(MAXIMUM_CONFIG_GENERATION) > 0
        || published.compareTo(MAXIMUM_CONFIG_GENERATION) > 0
        || applied.compareTo(MAXIMUM_CONFIG_GENERATION) > 0
        || systemServerPid.compareTo(MAXIMUM_UNSIGNED_INT) > 0
        || systemServerStartTicks.compareTo(MAXIMUM_UNSIGNED_LONG) > 0) {
      throw new ProtocolException("invalid_integer_range");
    }
    requireStateConsistency(
        values, boot, persisted, published, applied, systemServerPid, systemServerStartTicks);

    CoordinateInput.Values coordinates = null;
    if (coordinateCount == COORDINATE_KEYS.size()) {
      if (persisted.signum() == 0) {
        throw new ProtocolException("coordinates_without_config");
      }
      try {
        coordinates =
            CoordinateInput.parse(
                values.get("center_latitude_deg"),
                values.get("center_longitude_deg"),
                values.get("altitude_ellipsoid_m"),
                values.get("altitude_msl_m"),
                '.');
      } catch (CoordinateInput.InvalidInput error) {
        throw new ProtocolException("invalid_coordinates");
      }
    }
    return new HelperStatus(
        values.get("module_state"),
        values.get("runtime_state"),
        values.get("control_state"),
        values.get("reason"),
        values.get("boot_config_generation"),
        values.get("persisted_generation"),
        values.get("published_generation"),
        values.get("applied_generation"),
        coordinates);
  }

  private static void requireToken(String value) throws ProtocolException {
    if (value == null || value.isEmpty() || value.length() > 64) {
      throw new ProtocolException("invalid_token");
    }
    for (int index = 0; index < value.length(); index++) {
      char character = value.charAt(index);
      if ((character < 'a' || character > 'z') && character != '_') {
        throw new ProtocolException("invalid_token");
      }
    }
    for (String coordinateKey : COORDINATE_KEYS) {
      if (value.contains(coordinateKey)) {
        throw new ProtocolException("invalid_token");
      }
    }
  }

  private static void requireMember(String value, Set<String> allowed, String error)
      throws ProtocolException {
    if (!allowed.contains(value)) {
      throw new ProtocolException(error);
    }
  }

  private static BigInteger requireUnsigned(String value) throws ProtocolException {
    if (value == null || value.isEmpty() || value.length() > 20) {
      throw new ProtocolException("invalid_generation");
    }
    for (int index = 0; index < value.length(); index++) {
      if (value.charAt(index) < '0' || value.charAt(index) > '9') {
        throw new ProtocolException("invalid_generation");
      }
    }
    BigInteger parsed = new BigInteger(value);
    if (parsed.compareTo(MAXIMUM_UNSIGNED_LONG) > 0) {
      throw new ProtocolException("invalid_generation");
    }
    return parsed;
  }

  private static void requireBootId(String value) throws ProtocolException {
    if ("unavailable".equals(value)) {
      return;
    }
    if (value == null || value.length() != 36) {
      throw new ProtocolException("invalid_boot_id");
    }
    for (int index = 0; index < value.length(); index++) {
      char character = value.charAt(index);
      boolean separator = index == 8 || index == 13 || index == 18 || index == 23;
      boolean hexadecimal =
          (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
      if ((separator && character != '-') || (!separator && !hexadecimal)) {
        throw new ProtocolException("invalid_boot_id");
      }
    }
  }

  private static void requireStateConsistency(
      Map<String, String> values,
      BigInteger boot,
      BigInteger persisted,
      BigInteger published,
      BigInteger applied,
      BigInteger systemServerPid,
      BigInteger systemServerStartTicks)
      throws ProtocolException {
    String control = values.get("control_state");
    boolean active =
        "active".equals(values.get("module_state")) && "active".equals(values.get("runtime_state"));
    boolean waiting =
        "waiting".equals(values.get("module_state"))
            && "waiting".equals(values.get("runtime_state"));
    if ((active || waiting)
        && (systemServerPid.signum() == 0
            || systemServerStartTicks.signum() == 0
            || "unavailable".equals(values.get("boot_id")))) {
      throw new ProtocolException("invalid_active_identity");
    }
    if ((systemServerPid.signum() == 0) != (systemServerStartTicks.signum() == 0)) {
      throw new ProtocolException("invalid_process_identity");
    }
    boolean errorEnvelope =
        "inactive".equals(values.get("module_state"))
            && "unavailable".equals(values.get("runtime_state"))
            && "rejected".equals(control)
            && !"none".equals(values.get("reason"))
            && "unavailable".equals(values.get("boot_id"))
            && boot.signum() == 0
            && persisted.signum() == 0
            && published.signum() == 0
            && applied.signum() == 0
            && systemServerPid.signum() == 0
            && systemServerStartTicks.signum() == 0;
    if (!"unavailable".equals(control) && !active && !waiting && !errorEnvelope) {
      throw new ProtocolException("invalid_state_envelope");
    }
    if ("awaiting_first_coordinates".equals(control)
        && !(waiting
            && "none".equals(values.get("reason"))
            && boot.signum() > 0
            && persisted.equals(published)
            && published.equals(applied)
            && applied.equals(boot))) {
      throw new ProtocolException("invalid_waiting_state");
    }
    String reason = values.get("reason");
    if ("unavailable".equals(control) && (active || "none".equals(reason))) {
      throw new ProtocolException("invalid_unavailable_state");
    }
    if ("applied".equals(control)
        && !("none".equals(reason)
            && boot.signum() > 0
            && persisted.equals(published)
            && published.equals(applied)
            && applied.compareTo(boot) >= 0)) {
      throw new ProtocolException("invalid_applied_state");
    }
    if ("saved_pending_upstream".equals(control)
        && !("none".equals(reason)
            && boot.signum() > 0
            && persisted.equals(published)
            && published.compareTo(applied) > 0
            && applied.compareTo(boot) >= 0)) {
      throw new ProtocolException("invalid_pending_state");
    }
    if ("saved_pending_reboot".equals(control)
        && !(boot.signum() > 0
            && persisted.compareTo(published) > 0
            && published.compareTo(applied) >= 0
            && applied.compareTo(boot) >= 0
            && "publish_unavailable".equals(reason))) {
      throw new ProtocolException("invalid_reboot_state");
    }
    boolean rejectedPersistenceRecovery =
        ("persisted_runtime_rejection".equals(reason) || "rollback_failed".equals(reason))
            && persisted.equals(published)
            && published.compareTo(applied) > 0;
    boolean uncertainRollbackRecovery =
        "rollback_persistence_uncertain".equals(reason)
            && persisted.equals(applied)
            && published.compareTo(applied) > 0;
    boolean uncertainPersistenceRecovery =
        "persistence_uncertain".equals(reason)
            && persisted.compareTo(published) > 0
            && published.equals(applied);
    if ("recovery_required".equals(control)
        && !(boot.signum() > 0
            && applied.compareTo(boot) >= 0
            && (rejectedPersistenceRecovery
                || uncertainRollbackRecovery
                || uncertainPersistenceRecovery))) {
      throw new ProtocolException("invalid_recovery_state");
    }
    if ("rejected".equals(control)
        && !errorEnvelope
        && !(!"none".equals(reason)
            && boot.signum() > 0
            && published.compareTo(applied) > 0
            && persisted.equals(applied)
            && applied.compareTo(boot) >= 0)) {
      throw new ProtocolException("invalid_rejected_state");
    }
  }

  public static final class ProtocolException extends Exception {
    private static final long serialVersionUID = 1L;

    ProtocolException(String code) {
      super(code);
    }
  }
}
