// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe.location;

import android.content.Context;
import android.content.Intent;
import dev.zygveil.probe.detector.RunConfig;
import java.util.List;
import java.util.concurrent.Executor;
import org.json.JSONException;
import org.json.JSONObject;

public final class VariantGmsLocationClient implements GmsLocationClient {
  private static final List<String> OBSERVATION_TYPES =
      List.of(
          "gms_last_known",
          "gms_current",
          "gms_location_update",
          "gms_location_batch",
          "gms_location_availability",
          "gms_pending_intent");

  VariantGmsLocationClient(Context context, RunConfig config, Executor callbackExecutor) {}

  public static boolean handlePendingIntent(Context context, Intent intent) {
    return false;
  }

  @Override
  public boolean required() {
    return false;
  }

  @Override
  public String state() {
    return "not_enabled";
  }

  @Override
  public boolean requiredSurfaceComplete() {
    return true;
  }

  @Override
  public void start(Observer observer) {
    for (String type : OBSERVATION_TYPES) {
      observer.onObservation(
          type, "gms_fused", "UNAVAILABLE", payload("reason", "variant_not_enabled"));
    }
  }

  @Override
  public void flush() {}

  @Override
  public void close() {}

  private static JSONObject payload(String key, Object value) {
    try {
      return new JSONObject().put(key, value);
    } catch (JSONException error) {
      throw new IllegalStateException("could not build GMS payload", error);
    }
  }
}
