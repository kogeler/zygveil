// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe.detector;

import org.json.JSONException;
import org.json.JSONObject;

public final class ProbeRecord {
  public static final int LEGACY_NETWORK_SCHEMA_VERSION = 1;
  public static final int SERVER_VPN_SCHEMA_VERSION = 2;

  private ProbeRecord() {}

  public static JSONObject detector(
      RunConfig config,
      String testId,
      boolean mandatory,
      ProbeStatus status,
      JSONObject raw,
      Throwable exception,
      long elapsedMs,
      String cleanupStatus)
      throws JSONException {
    JSONObject record = base(config, "detector", testId);
    record.put("mandatory", mandatory);
    record.put("status", status.name());
    if (config.isServerVpnGroup()) {
      record.put("projection_outcome", projectionOutcome(config, mandatory, status));
    }
    record.put("raw_observations", raw);
    record.put(
        "exception",
        exception == null ? JSONObject.NULL : exceptionShape(exception, config.isServerVpnGroup()));
    record.put("elapsed_ms", elapsedMs);
    record.put("cleanup_status", cleanupStatus);
    return record;
  }

  public static JSONObject summary(
      RunConfig config, JSONObject counts, String verdict, int detectorCount, long elapsedMs)
      throws JSONException {
    JSONObject record = base(config, "summary", "summary");
    record.put("mandatory", true);
    record.put("status", verdict);
    record.put("raw_observations", counts);
    record.put("exception", JSONObject.NULL);
    record.put("elapsed_ms", elapsedMs);
    record.put("cleanup_status", "complete");
    record.put("detector_count", detectorCount);
    return record;
  }

  private static JSONObject base(RunConfig config, String recordType, String testId)
      throws JSONException {
    JSONObject record = new JSONObject();
    record.put(
        "schema_version",
        config.isServerVpnGroup() ? SERVER_VPN_SCHEMA_VERSION : LEGACY_NETWORK_SCHEMA_VERSION);
    record.put("record_type", recordType);
    record.put("run_id", config.runId);
    record.put("variant", config.variant);
    record.put("application_id", config.applicationId);
    record.put("process", config.process);
    record.put("vpn_expected", config.vpnExpected);
    record.put("module_expected", config.moduleExpected);
    record.put("group", config.group);
    record.put("test_id", testId);
    record.put("started_at", config.startedAt);
    return record;
  }

  private static String projectionOutcome(RunConfig config, boolean mandatory, ProbeStatus status) {
    return switch (status) {
      case ERROR -> "error";
      case UNAVAILABLE -> "unavailable";
      case INCONCLUSIVE -> "inconclusive";
      case POSITIVE -> "present_stock";
      case NEGATIVE ->
          config.isActiveServerVpnTarget()
              ? "present_sanitized"
              : mandatory ? "absent" : "present_stock";
    };
  }

  private static JSONObject exceptionShape(Throwable exception, boolean redactMessage)
      throws JSONException {
    JSONObject shape = new JSONObject();
    shape.put("class", exception.getClass().getName());
    shape.put(
        "message",
        redactMessage || exception.getMessage() == null ? JSONObject.NULL : exception.getMessage());
    return shape;
  }
}
