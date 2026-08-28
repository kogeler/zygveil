// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe.detector;

import android.app.Application;
import android.content.Context;
import android.content.Intent;
import android.os.SystemClock;
import dev.zygveil.probe.BuildConfig;
import java.time.Instant;
import java.util.Objects;
import java.util.regex.Pattern;

public final class RunConfig {
  public static final String EXTRA_RUN_ID = "run_id";
  public static final String EXTRA_VPN_EXPECTED = "vpn_expected";
  public static final String EXTRA_MODULE_EXPECTED = "module_expected";
  public static final String EXTRA_GROUP = "group";
  public static final String EXTRA_RAW_GNSS_MODE = "raw_gnss_mode";
  public static final String EXTRA_OBSERVATION_WINDOW_MS = "observation_window_ms";
  public static final String EXTRA_LOCATION_ORACLE_REQUIRED = "location_oracle_required";
  public static final String EXTRA_COORDINATED_START_ELAPSED_REALTIME_MS =
      "coordinated_start_elapsed_realtime_ms";
  private static final long MAX_COORDINATED_START_FUTURE_MS = 10_000;
  private static final long MAX_COORDINATED_START_LATE_MS = 1_000;
  private static final Pattern SAFE_VALUE = Pattern.compile("[a-zA-Z0-9._-]{1,96}");

  public final String runId;
  public final boolean vpnExpected;
  public final boolean moduleExpected;
  public final String group;
  public final String variant;
  public final String applicationId;
  public final String process;
  public final String startedAt;
  public final String rawGnssMode;
  public final long observationWindowMs;
  public final boolean locationOracleRequired;
  public final long coordinatedStartElapsedRealtimeMs;

  private RunConfig(
      String runId,
      boolean vpnExpected,
      boolean moduleExpected,
      String group,
      String applicationId,
      String rawGnssMode,
      long observationWindowMs,
      boolean locationOracleRequired,
      long coordinatedStartElapsedRealtimeMs,
      String startedAt) {
    this.runId = runId;
    this.vpnExpected = vpnExpected;
    this.moduleExpected = moduleExpected;
    this.group = group;
    this.variant = BuildConfig.PROBE_VARIANT;
    this.applicationId = applicationId;
    this.process = Application.getProcessName();
    this.startedAt = startedAt;
    this.rawGnssMode = rawGnssMode;
    this.observationWindowMs = observationWindowMs;
    this.locationOracleRequired = locationOracleRequired;
    this.coordinatedStartElapsedRealtimeMs = coordinatedStartElapsedRealtimeMs;
  }

  public static RunConfig fromIntent(Context context, Intent intent) {
    String runId = requireSafe(intent.getStringExtra(EXTRA_RUN_ID), EXTRA_RUN_ID);
    String group = requireSafe(intent.getStringExtra(EXTRA_GROUP), EXTRA_GROUP);
    boolean locationGroup = "location".equals(group);
    if (!locationGroup
        && (!intent.hasExtra(EXTRA_VPN_EXPECTED) || !intent.hasExtra(EXTRA_MODULE_EXPECTED))) {
      throw new IllegalArgumentException("expected-state labels are missing");
    }
    String rawGnssMode = "not_applicable";
    long observationWindowMs = 0;
    boolean locationOracleRequired = false;
    long coordinatedStartElapsedRealtimeMs = 0;
    if (locationGroup) {
      rawGnssMode = requireSafe(intent.getStringExtra(EXTRA_RAW_GNSS_MODE), EXTRA_RAW_GNSS_MODE);
      if (!rawGnssMode.matches("blocked|passthrough|unsupported")) {
        throw new IllegalArgumentException("unsupported Raw GNSS mode");
      }
      if (!intent.hasExtra(EXTRA_OBSERVATION_WINDOW_MS)) {
        throw new IllegalArgumentException("observation window is missing");
      }
      observationWindowMs = intent.getLongExtra(EXTRA_OBSERVATION_WINDOW_MS, 0);
      if (observationWindowMs < 5_000 || observationWindowMs > 120_000) {
        throw new IllegalArgumentException("observation window is outside the bounded range");
      }
      if (!intent.hasExtra(EXTRA_LOCATION_ORACLE_REQUIRED)) {
        throw new IllegalArgumentException("location oracle requirement is missing");
      }
      locationOracleRequired = intent.getBooleanExtra(EXTRA_LOCATION_ORACLE_REQUIRED, false);
    }
    if (intent.hasExtra(EXTRA_COORDINATED_START_ELAPSED_REALTIME_MS)) {
      if (locationGroup || !group.startsWith("server-vpn-")) {
        throw new IllegalArgumentException("coordinated start is limited to server-VPN runs");
      }
      coordinatedStartElapsedRealtimeMs =
          intent.getLongExtra(EXTRA_COORDINATED_START_ELAPSED_REALTIME_MS, 0);
      long remainingMs = coordinatedStartElapsedRealtimeMs - SystemClock.elapsedRealtime();
      if (coordinatedStartElapsedRealtimeMs <= 0
          || remainingMs < -MAX_COORDINATED_START_LATE_MS
          || remainingMs > MAX_COORDINATED_START_FUTURE_MS) {
        throw new IllegalArgumentException("coordinated start is outside the bounded range");
      }
    }
    return new RunConfig(
        runId,
        intent.getBooleanExtra(EXTRA_VPN_EXPECTED, false),
        intent.getBooleanExtra(EXTRA_MODULE_EXPECTED, false),
        group,
        context.getPackageName(),
        rawGnssMode,
        observationWindowMs,
        locationOracleRequired,
        coordinatedStartElapsedRealtimeMs,
        Instant.now().toString());
  }

  public RunConfig awaitCoordinatedStart() {
    if (coordinatedStartElapsedRealtimeMs == 0) {
      return this;
    }
    long remainingMs = coordinatedStartElapsedRealtimeMs - SystemClock.elapsedRealtime();
    if (remainingMs > 0) {
      SystemClock.sleep(remainingMs);
    }
    return new RunConfig(
        runId,
        vpnExpected,
        moduleExpected,
        group,
        applicationId,
        rawGnssMode,
        observationWindowMs,
        locationOracleRequired,
        coordinatedStartElapsedRealtimeMs,
        Instant.now().toString());
  }

  public void copyTo(Intent intent) {
    intent.putExtra(EXTRA_RUN_ID, runId);
    intent.putExtra(EXTRA_GROUP, group);
    if ("location".equals(group)) {
      intent.putExtra(EXTRA_RAW_GNSS_MODE, rawGnssMode);
      intent.putExtra(EXTRA_OBSERVATION_WINDOW_MS, observationWindowMs);
      intent.putExtra(EXTRA_LOCATION_ORACLE_REQUIRED, locationOracleRequired);
    } else {
      intent.putExtra(EXTRA_VPN_EXPECTED, vpnExpected);
      intent.putExtra(EXTRA_MODULE_EXPECTED, moduleExpected);
    }
  }

  public boolean isServerVpnGroup() {
    return group.startsWith("server-vpn-");
  }

  public boolean isActiveServerVpnTarget() {
    return isServerVpnGroup() && vpnExpected && moduleExpected && "primary".equals(variant);
  }

  private static String requireSafe(String value, String name) {
    String required = Objects.requireNonNull(value, name + " is missing");
    if (!SAFE_VALUE.matcher(required).matches()) {
      throw new IllegalArgumentException(name + " contains unsupported characters");
    }
    return required;
  }
}
