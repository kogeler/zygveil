// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe;

import android.content.Context;
import android.content.Intent;
import dev.zygveil.probe.detector.DetectorCatalog;
import dev.zygveil.probe.detector.ProbeStatus;
import dev.zygveil.probe.detector.ResultStore;
import dev.zygveil.probe.detector.RunConfig;
import dev.zygveil.probe.location.LocationSessionCoordinator;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import org.json.JSONException;
import org.json.JSONObject;

public final class ProbeCoordinator {
  private ProbeCoordinator() {}

  public static String execute(Context context, Intent intent) {
    RunConfig config = RunConfig.fromIntent(context, intent);
    if ("location".equals(config.group)) {
      try {
        return LocationSessionCoordinator.execute(context, config);
      } catch (IOException | JSONException error) {
        throw new IllegalStateException("could not persist location probe result", error);
      }
    }
    try {
      ResultStore store = new ResultStore(context, config, true);
      config = config.awaitCoordinatedStart();
      long started = System.nanoTime();
      try {
        DetectorCatalog.run(context, config, store);
      } catch (IOException | JSONException | RuntimeException error) {
        store.detector(
            config,
            "group.failure",
            true,
            ProbeStatus.ERROR,
            new JSONObject().put("group", config.group),
            error,
            elapsed(started),
            "complete");
      }
      return store.summary(config, elapsed(started));
    } catch (IOException | JSONException error) {
      throw new IllegalStateException("could not persist probe result", error);
    }
  }

  private static long elapsed(long started) {
    return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
  }
}
