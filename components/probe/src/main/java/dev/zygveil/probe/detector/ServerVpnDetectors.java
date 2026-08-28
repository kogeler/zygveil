// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe.detector;

import android.content.Context;
import android.net.ConnectivityDiagnosticsManager;
import android.net.ConnectivityDiagnosticsManager.ConnectivityDiagnosticsCallback;
import android.net.ConnectivityDiagnosticsManager.ConnectivityReport;
import android.net.ConnectivityDiagnosticsManager.DataStallReport;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.ProxyInfo;
import android.os.Parcel;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

final class ServerVpnDetectors {
  private static final long DIAGNOSTICS_TIMEOUT_MS = 3_000;

  private ServerVpnDetectors() {}

  @SuppressWarnings("deprecation")
  static void runSynchronous(ConnectivityManager manager, RunConfig config, ResultStore store)
      throws IOException, JSONException {
    recordDefaultProxy(manager, config, store);
    recordBooleanControl(
        config, store, "scalar.active_metered", "metered", manager::isActiveNetworkMetered);

    Network active = manager.getActiveNetwork();
    recordActiveMultipath(manager, config, store, active);
    recordAllMultipath(manager, config, store);
    recordLinkStructure(manager, config, store, active);
    recordRequestStructure(config, store, false);
    recordRequestStructure(config, store, true);
  }

  static void runDiagnostics(Context context, RunConfig config, ResultStore store)
      throws IOException, JSONException {
    ConnectivityDiagnosticsManager manager =
        context.getSystemService(ConnectivityDiagnosticsManager.class);
    if (manager == null) {
      recordDiagnosticsUnavailable(config, store);
      return;
    }

    NetworkRequest request =
        new NetworkRequest.Builder()
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build();
    ExecutorService executor = Executors.newSingleThreadExecutor();
    CountDownLatch delivery = new CountDownLatch(1);
    List<DiagnosticSnapshot> reports = Collections.synchronizedList(new ArrayList<>());
    List<DiagnosticSnapshot> stalls = Collections.synchronizedList(new ArrayList<>());
    List<Boolean> connectivityResults = Collections.synchronizedList(new ArrayList<>());
    ConnectivityDiagnosticsCallback callback =
        new ConnectivityDiagnosticsCallback() {
          @Override
          public void onConnectivityReportAvailable(ConnectivityReport report) {
            reports.add(
                DiagnosticSnapshot.from(
                    report.getNetwork(),
                    report.getNetworkCapabilities(),
                    report.getLinkProperties()));
            delivery.countDown();
          }

          @Override
          public void onDataStallSuspected(DataStallReport report) {
            stalls.add(
                DiagnosticSnapshot.from(
                    report.getNetwork(),
                    report.getNetworkCapabilities(),
                    report.getLinkProperties()));
            delivery.countDown();
          }

          @Override
          public void onNetworkConnectivityReported(Network network, boolean hasConnectivity) {
            connectivityResults.add(hasConnectivity);
            delivery.countDown();
          }
        };

    long started = System.nanoTime();
    Throwable failure = null;
    String cleanup = "complete";
    boolean registered = false;
    boolean completed = false;
    try {
      manager.registerConnectivityDiagnosticsCallback(request, executor, callback);
      registered = true;
      completed = delivery.await(DIAGNOSTICS_TIMEOUT_MS, TimeUnit.MILLISECONDS);
    } catch (InterruptedException error) {
      Thread.currentThread().interrupt();
      failure = error;
    } catch (RuntimeException error) {
      failure = error;
    } finally {
      if (registered) {
        try {
          manager.unregisterConnectivityDiagnosticsCallback(callback);
        } catch (RuntimeException error) {
          cleanup = "error:" + error.getClass().getName();
          if (failure == null) {
            failure = error;
          }
        }
      }
      executor.shutdownNow();
      try {
        if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
          cleanup = "executor_timeout";
        }
      } catch (InterruptedException error) {
        Thread.currentThread().interrupt();
        cleanup = "executor_interrupted";
        if (failure == null) {
          failure = error;
        }
      }
    }

    ProbeStatus lifecycleStatus =
        failure == null && "complete".equals(cleanup) ? ProbeStatus.NEGATIVE : ProbeStatus.ERROR;
    store.detector(
        config,
        "diagnostics.lifecycle",
        true,
        lifecycleStatus,
        new JSONObject().put("registered", registered).put("delivery_observed", completed),
        failure,
        elapsed(started),
        cleanup);
    recordDiagnosticSnapshots(
        config, store, "diagnostics.connectivity_report", true, reports, failure, cleanup, started);
    recordDiagnosticSnapshots(
        config, store, "diagnostics.data_stall_report", false, stalls, failure, cleanup, started);
    recordConnectivityResults(config, store, connectivityResults, failure, cleanup, started);
  }

  private static void recordDefaultProxy(
      ConnectivityManager manager, RunConfig config, ResultStore store)
      throws IOException, JSONException {
    long started = System.nanoTime();
    try {
      ProxyInfo proxy = manager.getDefaultProxy();
      JSONObject raw = new JSONObject().put("present", proxy != null);
      if (proxy != null) {
        raw.put("valid", proxy.isValid());
        raw.put(
            "pac_present",
            proxy.getPacFileUrl() != null && !proxy.getPacFileUrl().toString().isEmpty());
      }
      store.detector(
          config,
          "sync.default_proxy",
          false,
          ProbeStatus.NEGATIVE,
          raw,
          null,
          elapsed(started),
          "complete");
    } catch (RuntimeException error) {
      recordError(config, store, "sync.default_proxy", false, error, started);
    }
  }

  private static void recordBooleanControl(
      RunConfig config, ResultStore store, String testId, String key, BooleanSupplier supplier)
      throws IOException, JSONException {
    long started = System.nanoTime();
    try {
      store.detector(
          config,
          testId,
          false,
          ProbeStatus.NEGATIVE,
          new JSONObject().put(key, supplier.get()),
          null,
          elapsed(started),
          "complete");
    } catch (RuntimeException error) {
      recordError(config, store, testId, false, error, started);
    }
  }

  private static void recordActiveMultipath(
      ConnectivityManager manager, RunConfig config, ResultStore store, Network active)
      throws IOException, JSONException {
    long started = System.nanoTime();
    if (active == null) {
      store.detector(
          config,
          "scalar.active_multipath",
          false,
          ProbeStatus.INCONCLUSIVE,
          new JSONObject().put("network_present", false),
          null,
          elapsed(started),
          "complete");
      return;
    }
    try {
      store.detector(
          config,
          "scalar.active_multipath",
          false,
          ProbeStatus.NEGATIVE,
          new JSONObject()
              .put("network_present", true)
              .put("preference", manager.getMultipathPreference(active)),
          null,
          elapsed(started),
          "complete");
    } catch (RuntimeException error) {
      recordError(config, store, "scalar.active_multipath", false, error, started);
    }
  }

  @SuppressWarnings("deprecation")
  private static void recordAllMultipath(
      ConnectivityManager manager, RunConfig config, ResultStore store)
      throws IOException, JSONException {
    long started = System.nanoTime();
    try {
      List<Integer> preferences = new ArrayList<>();
      for (Network network : manager.getAllNetworks()) {
        preferences.add(manager.getMultipathPreference(network));
      }
      Collections.sort(preferences);
      store.detector(
          config,
          "scalar.all_multipath",
          false,
          ProbeStatus.NEGATIVE,
          new JSONObject()
              .put("network_count", preferences.size())
              .put("preferences", new JSONArray(preferences)),
          null,
          elapsed(started),
          "complete");
    } catch (RuntimeException error) {
      recordError(config, store, "scalar.all_multipath", false, error, started);
    }
  }

  private static void recordLinkStructure(
      ConnectivityManager manager, RunConfig config, ResultStore store, Network active)
      throws IOException, JSONException {
    String testId = "structure.link.active.parcel";
    long started = System.nanoTime();
    try {
      LinkProperties original = active == null ? null : manager.getLinkProperties(active);
      if (original == null) {
        store.detector(
            config,
            testId,
            true,
            ProbeStatus.INCONCLUSIVE,
            new JSONObject().put("source_present", false),
            null,
            elapsed(started),
            "complete");
        return;
      }
      LinkProperties copy;
      Parcel parcel = Parcel.obtain();
      try {
        original.writeToParcel(parcel, 0);
        parcel.setDataPosition(0);
        copy = LinkProperties.CREATOR.createFromParcel(parcel);
      } finally {
        parcel.recycle();
      }
      boolean consistent = original.equals(copy);
      store.detector(
          config,
          testId,
          true,
          consistent ? ProbeStatus.NEGATIVE : ProbeStatus.ERROR,
          new JSONObject().put("source_present", true).put("consistent", consistent),
          null,
          elapsed(started),
          "complete");
    } catch (RuntimeException error) {
      recordError(config, store, testId, true, error, started);
    }
  }

  private static void recordRequestStructure(
      RunConfig config, ResultStore store, boolean parcelRoundTrip)
      throws IOException, JSONException {
    String testId =
        parcelRoundTrip ? "structure.request.default.parcel" : "structure.request.default.copy";
    long started = System.nanoTime();
    try {
      NetworkRequest original = new NetworkRequest.Builder().build();
      NetworkRequest copy;
      if (parcelRoundTrip) {
        Parcel parcel = Parcel.obtain();
        try {
          original.writeToParcel(parcel, 0);
          parcel.setDataPosition(0);
          copy = NetworkRequest.CREATOR.createFromParcel(parcel);
        } finally {
          parcel.recycle();
        }
      } else {
        copy = new NetworkRequest.Builder(original).build();
      }
      boolean consistent = requestEquivalent(original, copy);
      store.detector(
          config,
          testId,
          true,
          consistent ? ProbeStatus.NEGATIVE : ProbeStatus.ERROR,
          new JSONObject().put("consistent", consistent),
          null,
          elapsed(started),
          "complete");
    } catch (RuntimeException error) {
      recordError(config, store, testId, true, error, started);
    }
  }

  private static boolean requestEquivalent(NetworkRequest left, NetworkRequest right) {
    return Arrays.equals(left.getCapabilities(), right.getCapabilities())
        && Arrays.equals(left.getTransportTypes(), right.getTransportTypes())
        && left.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            == right.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        && left.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            == right.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        && sameClass(left.getNetworkSpecifier(), right.getNetworkSpecifier())
        && sorted(left.getSubscriptionIds()).equals(sorted(right.getSubscriptionIds()));
  }

  private static boolean sameClass(Object left, Object right) {
    return left == null ? right == null : right != null && left.getClass().equals(right.getClass());
  }

  private static List<Integer> sorted(Set<Integer> values) {
    List<Integer> result = new ArrayList<>(values);
    Collections.sort(result);
    return result;
  }

  private static void recordDiagnosticsUnavailable(RunConfig config, ResultStore store)
      throws IOException, JSONException {
    IllegalStateException error =
        new IllegalStateException("ConnectivityDiagnosticsManager is unavailable");
    for (String testId :
        List.of(
            "diagnostics.lifecycle",
            "diagnostics.connectivity_report",
            "diagnostics.data_stall_report",
            "diagnostics.connectivity_result")) {
      store.detector(
          config,
          testId,
          testId.equals("diagnostics.lifecycle")
              || testId.equals("diagnostics.connectivity_report"),
          ProbeStatus.UNAVAILABLE,
          new JSONObject(),
          error,
          0,
          "complete");
    }
  }

  private static void recordDiagnosticSnapshots(
      RunConfig config,
      ResultStore store,
      String testId,
      boolean mandatory,
      List<DiagnosticSnapshot> values,
      Throwable failure,
      String cleanup,
      long started)
      throws IOException, JSONException {
    List<DiagnosticSnapshot> snapshot;
    synchronized (values) {
      snapshot = List.copyOf(values);
    }
    int vpnCount = 0;
    int notVpnCount = 0;
    int networkCount = 0;
    int capabilitiesCount = 0;
    int linkCount = 0;
    for (DiagnosticSnapshot value : snapshot) {
      vpnCount += value.vpnTransport ? 1 : 0;
      notVpnCount += value.notVpnCapability ? 1 : 0;
      networkCount += value.networkPresent ? 1 : 0;
      capabilitiesCount += value.capabilitiesPresent ? 1 : 0;
      linkCount += value.linkPropertiesPresent ? 1 : 0;
    }
    ProbeStatus status;
    if (failure != null || !"complete".equals(cleanup)) {
      status = ProbeStatus.ERROR;
    } else if (snapshot.isEmpty()) {
      status = ProbeStatus.INCONCLUSIVE;
    } else {
      status = vpnCount > 0 ? ProbeStatus.POSITIVE : ProbeStatus.NEGATIVE;
    }
    store.detector(
        config,
        testId,
        mandatory,
        status,
        new JSONObject()
            .put("delivery_count", snapshot.size())
            .put("network_present_count", networkCount)
            .put("capabilities_present_count", capabilitiesCount)
            .put("link_properties_present_count", linkCount)
            .put("vpn_transport_count", vpnCount)
            .put("not_vpn_capability_count", notVpnCount),
        failure,
        elapsed(started),
        cleanup);
  }

  private static void recordConnectivityResults(
      RunConfig config,
      ResultStore store,
      List<Boolean> values,
      Throwable failure,
      String cleanup,
      long started)
      throws IOException, JSONException {
    List<Boolean> snapshot;
    synchronized (values) {
      snapshot = List.copyOf(values);
    }
    int connectedCount = 0;
    for (boolean value : snapshot) {
      connectedCount += value ? 1 : 0;
    }
    ProbeStatus status;
    if (failure != null || !"complete".equals(cleanup)) {
      status = ProbeStatus.ERROR;
    } else if (snapshot.isEmpty()) {
      status = ProbeStatus.INCONCLUSIVE;
    } else {
      status = ProbeStatus.NEGATIVE;
    }
    store.detector(
        config,
        "diagnostics.connectivity_result",
        false,
        status,
        new JSONObject()
            .put("delivery_count", snapshot.size())
            .put("reported_connected_count", connectedCount),
        failure,
        elapsed(started),
        cleanup);
  }

  private static void recordError(
      RunConfig config,
      ResultStore store,
      String testId,
      boolean mandatory,
      RuntimeException error,
      long started)
      throws IOException, JSONException {
    store.detector(
        config,
        testId,
        mandatory,
        ProbeStatus.ERROR,
        new JSONObject(),
        error,
        elapsed(started),
        "complete");
  }

  private static long elapsed(long started) {
    return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
  }

  @FunctionalInterface
  private interface BooleanSupplier {
    boolean get();
  }

  private static final class DiagnosticSnapshot {
    private final boolean networkPresent;
    private final boolean capabilitiesPresent;
    private final boolean linkPropertiesPresent;
    private final boolean vpnTransport;
    private final boolean notVpnCapability;

    private DiagnosticSnapshot(
        boolean networkPresent,
        boolean capabilitiesPresent,
        boolean linkPropertiesPresent,
        boolean vpnTransport,
        boolean notVpnCapability) {
      this.networkPresent = networkPresent;
      this.capabilitiesPresent = capabilitiesPresent;
      this.linkPropertiesPresent = linkPropertiesPresent;
      this.vpnTransport = vpnTransport;
      this.notVpnCapability = notVpnCapability;
    }

    private static DiagnosticSnapshot from(
        Network network, NetworkCapabilities capabilities, LinkProperties linkProperties) {
      return new DiagnosticSnapshot(
          network != null,
          capabilities != null,
          linkProperties != null,
          capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
          capabilities != null
              && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN));
    }
  }
}
