// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe.location;

import android.content.Context;
import android.location.Location;
import dev.zygveil.probe.detector.RunConfig;
import java.util.List;
import java.util.concurrent.Executor;
import org.json.JSONObject;

interface GmsLocationClient {
  interface Observer {
    void onObservation(String type, String source, String status, JSONObject payload);

    void onLocation(String type, String source, Location location);

    void onLocations(String type, String source, List<Location> locations);

    void onCleanupFailure(String failure);
  }

  static GmsLocationClient create(Context context, RunConfig config, Executor callbackExecutor) {
    return new VariantGmsLocationClient(context, config, callbackExecutor);
  }

  boolean required();

  String state();

  boolean requiredSurfaceComplete();

  void start(Observer observer);

  void flush();

  void close();
}
