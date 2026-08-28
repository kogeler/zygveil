// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe.location;

import android.os.SystemClock;
import dev.zygveil.probe.detector.RunConfig;
import org.json.JSONException;
import org.json.JSONObject;

final class LocationRecord {
  static final int SCHEMA_VERSION = 4;

  private LocationRecord() {}

  static JSONObject observation(
      RunConfig config,
      String observationType,
      String source,
      String status,
      JSONObject payload,
      boolean summary)
      throws JSONException {
    JSONObject record = new JSONObject();
    record.put("schema_version", SCHEMA_VERSION);
    record.put("record_type", summary ? "summary" : "observation");
    record.put("session_id", config.runId);
    record.put("variant", config.variant);
    record.put("application_id", config.applicationId);
    record.put("process", config.process);
    record.put("observation_type", observationType);
    record.put("monotonic_ns", SystemClock.elapsedRealtimeNanos());
    record.put("wall_time_ms", System.currentTimeMillis());
    record.put("source", source);
    record.put("status", status);
    record.put("payload", payload);
    return record;
  }
}
