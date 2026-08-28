// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe.detector;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.os.Handler;
import android.os.HandlerThread;
import dev.zygveil.probe.ProbePendingIntentReceiver;
import dev.zygveil.probe.SecondaryProbePendingIntentReceiver;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public final class DetectorCatalog {
  private static final int CALLBACK_TIMEOUT_MS = 2500;

  private DetectorCatalog() {}

  public static void run(Context context, RunConfig config, ResultStore store)
      throws IOException, JSONException {
    ConnectivityManager manager = context.getSystemService(ConnectivityManager.class);
    if (manager == null) {
      store.detector(
          config,
          "connectivity.service",
          true,
          ProbeStatus.ERROR,
          new JSONObject(),
          new IllegalStateException("ConnectivityManager is unavailable"),
          0,
          "not_started");
      return;
    }
    switch (config.group) {
      case "sync" -> runSynchronous(manager, config, store);
      case "async" -> runAsynchronous(context, manager, config, store);
      case "active" -> runActiveRequest(context, manager, config, store);
      case "link" -> runLinkProperties(manager, config, store);
      case "server-vpn-sync" -> {
        runSynchronous(manager, config, store);
        ServerVpnDetectors.runSynchronous(manager, config, store);
      }
      case "server-vpn-async" -> runAsynchronous(context, manager, config, store);
      case "server-vpn-active" -> runActiveRequest(context, manager, config, store);
      case "server-vpn-link" -> runLinkProperties(manager, config, store);
      case "server-vpn-diagnostics" -> ServerVpnDetectors.runDiagnostics(context, config, store);
      case "data-plane" -> DataPlaneDetectors.run(config, store);
      case "schema" ->
          store.detector(
              config,
              "schema.self_test",
              true,
              ProbeStatus.NEGATIVE,
              new JSONObject().put("schema_version", ProbeRecord.LEGACY_NETWORK_SCHEMA_VERSION),
              null,
              0,
              "complete");
      default ->
          store.detector(
              config,
              "group.unsupported",
              true,
              ProbeStatus.ERROR,
              new JSONObject().put("group", config.group),
              new IllegalArgumentException("unsupported detector group"),
              0,
              "not_started");
    }
  }

  @SuppressWarnings("deprecation")
  private static void runLinkProperties(
      ConnectivityManager manager, RunConfig config, ResultStore store)
      throws IOException, JSONException {
    Network active = manager.getActiveNetwork();
    LinkProperties activeLink = active == null ? null : manager.getLinkProperties(active);
    NetworkCapabilities activeCapabilities =
        active == null ? null : manager.getNetworkCapabilities(active);
    LinkPropertiesDetectors.recordSingle(
        store, config, "link.active", activeLink, activeCapabilities, active != null);

    Network[] networks = manager.getAllNetworks();
    List<LinkPropertiesDetectors.Observation> observations = new ArrayList<>();
    for (Network network : networks) {
      observations.add(
          LinkPropertiesDetectors.observation(
              manager.getLinkProperties(network), manager.getNetworkCapabilities(network)));
    }
    LinkPropertiesDetectors.recordMany(store, config, "link.all", observations, false);

    runLinkCallback(
        manager,
        config,
        store,
        "link.callback.default",
        (callback, handler) -> manager.registerDefaultNetworkCallback(callback, handler));
    NetworkRequest broadRequest =
        new NetworkRequest.Builder()
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build();
    runLinkCallback(
        manager,
        config,
        store,
        "link.callback.broad",
        (callback, handler) -> manager.registerNetworkCallback(broadRequest, callback, handler));
  }

  private static void runLinkCallback(
      ConnectivityManager manager,
      RunConfig config,
      ResultStore store,
      String prefix,
      CallbackRegistrar registrar)
      throws IOException, JSONException {
    long started = System.nanoTime();
    HandlerThread thread = new HandlerThread("probe-" + prefix.replace('.', '-'));
    thread.start();
    Handler handler = new Handler(thread.getLooper());
    CountDownLatch latch = new CountDownLatch(1);
    List<String> events = Collections.synchronizedList(new ArrayList<>());
    Object snapshotLock = new Object();
    Map<Network, LinkProperties> links = new HashMap<>();
    Map<Network, NetworkCapabilities> capabilitySnapshots = new HashMap<>();
    ConnectivityManager.NetworkCallback callback =
        new ConnectivityManager.NetworkCallback() {
          @Override
          public void onAvailable(Network network) {
            events.add("onAvailable");
          }

          @Override
          public void onCapabilitiesChanged(
              Network network, NetworkCapabilities networkCapabilities) {
            events.add("onCapabilitiesChanged");
            synchronized (snapshotLock) {
              capabilitySnapshots.put(network, networkCapabilities);
              if (links.containsKey(network)) {
                latch.countDown();
              }
            }
          }

          @Override
          public void onLinkPropertiesChanged(Network network, LinkProperties linkProperties) {
            events.add("onLinkPropertiesChanged");
            synchronized (snapshotLock) {
              links.put(network, linkProperties);
              if (capabilitySnapshots.containsKey(network)) {
                latch.countDown();
              }
            }
          }

          @Override
          public void onLost(Network network) {
            events.add("onLost");
          }

          @Override
          public void onUnavailable() {
            events.add("onUnavailable");
            latch.countDown();
          }
        };
    Throwable failure = null;
    String cleanup = "complete";
    boolean completed = false;
    try {
      registrar.register(callback, handler);
      completed = latch.await(CALLBACK_TIMEOUT_MS + 500L, TimeUnit.MILLISECONDS);
      if (completed) {
        Thread.sleep(100L);
      }
    } catch (InterruptedException error) {
      Thread.currentThread().interrupt();
      failure = error;
    } catch (RuntimeException error) {
      failure = error;
    } finally {
      try {
        manager.unregisterNetworkCallback(callback);
      } catch (RuntimeException error) {
        cleanup = "error:" + error.getClass().getName();
        if (failure == null) {
          failure = error;
        }
      }
      thread.quitSafely();
    }
    List<LinkPropertiesDetectors.Observation> snapshot;
    synchronized (snapshotLock) {
      List<Network> networks = new ArrayList<>(links.keySet());
      for (Network network : capabilitySnapshots.keySet()) {
        if (!networks.contains(network)) {
          networks.add(network);
        }
      }
      List<LinkPropertiesDetectors.Observation> values = new ArrayList<>();
      for (Network network : networks) {
        values.add(
            LinkPropertiesDetectors.observation(
                links.get(network), capabilitySnapshots.get(network)));
      }
      snapshot = List.copyOf(values);
    }
    if (failure == null && "complete".equals(cleanup)) {
      LinkPropertiesDetectors.recordMany(store, config, prefix, snapshot, completed);
    } else {
      for (String suffix : LinkPropertiesDetectors.FIELD_SUFFIXES) {
        store.detector(
            config,
            prefix + "." + suffix,
            false,
            ProbeStatus.ERROR,
            new JSONObject().put("comparison", new JSONObject()),
            failure,
            elapsed(started),
            cleanup);
      }
    }
    List<String> eventSnapshot;
    synchronized (events) {
      eventSnapshot = List.copyOf(events);
    }
    List<String> eventTypes = new ArrayList<>(eventSnapshot);
    Collections.sort(eventTypes);
    ProbeStatus lifecycleStatus =
        failure != null || !"complete".equals(cleanup)
            ? ProbeStatus.ERROR
            : completed ? ProbeStatus.NEGATIVE : ProbeStatus.INCONCLUSIVE;
    store.detector(
        config,
        prefix + ".lifecycle",
        false,
        lifecycleStatus,
        new JSONObject()
            .put("comparison", new JSONObject().put("event_types", new JSONArray(eventTypes)))
            .put("diagnostic", new JSONObject().put("events", new JSONArray(eventSnapshot))),
        failure,
        elapsed(started),
        cleanup);
  }

  @SuppressWarnings("deprecation")
  private static void runSynchronous(
      ConnectivityManager manager, RunConfig config, ResultStore store)
      throws IOException, JSONException {
    Network active = manager.getActiveNetwork();
    NetworkCapabilities activeCaps = active == null ? null : manager.getNetworkCapabilities(active);
    CapabilityDetectors.recordSingle(
        store, config, "sync.active", activeCaps, active == null ? 0 : 1);

    Network[] networks = manager.getAllNetworks();
    List<NetworkCapabilities> observations = new ArrayList<>();
    for (Network network : networks) {
      NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
      if (capabilities == null) {
        continue;
      }
      observations.add(capabilities);
    }
    CapabilityDetectors.recordMany(store, config, "sync.all", observations);

    recordMatchers(store, config, networks, manager);
    recordLegacy(store, config, manager, networks);
  }

  private static void recordMatchers(
      ResultStore store, RunConfig config, Network[] networks, ConnectivityManager manager)
      throws IOException, JSONException {
    NetworkRequest defaultRequest = new NetworkRequest.Builder().build();
    NetworkRequest inclusive =
        new NetworkRequest.Builder()
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build();
    NetworkRequest exclusive =
        new NetworkRequest.Builder()
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            .build();
    int physicalTransport = observedPhysicalTransport(networks, manager);
    NetworkRequest mixed =
        new NetworkRequest.Builder()
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            .addTransportType(physicalTransport)
            .build();
    recordRequestMatch(store, config, "matcher.default", defaultRequest, networks, manager, false);
    recordRequestMatch(store, config, "matcher.vpn_inclusive", inclusive, networks, manager, false);
    recordRequestMatch(store, config, "matcher.vpn_exclusive", exclusive, networks, manager, true);
    recordRequestMatch(store, config, "matcher.mixed", mixed, networks, manager, false);
  }

  private static void recordRequestMatch(
      ResultStore store,
      RunConfig config,
      String testId,
      NetworkRequest request,
      Network[] networks,
      ConnectivityManager manager,
      boolean mandatory)
      throws IOException, JSONException {
    boolean matched = false;
    int matchCount = 0;
    for (Network network : networks) {
      NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
      if (capabilities != null && request.canBeSatisfiedBy(capabilities)) {
        matched = true;
        matchCount++;
      }
    }
    JSONObject raw = requestObservation(request, config).put("match_count", matchCount);
    store.detector(
        config,
        testId,
        mandatory,
        matched ? ProbeStatus.POSITIVE : ProbeStatus.NEGATIVE,
        raw,
        null,
        0,
        "complete");
  }

  public static JSONObject requestObservation(NetworkRequest request, RunConfig config)
      throws JSONException {
    JSONObject raw = new JSONObject();
    raw.put("not_vpn", request.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN));
    raw.put("vpn_transport", request.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
    raw.put("capabilities", intArray(request.getCapabilities(), config.isServerVpnGroup()));
    raw.put("transports", intArray(request.getTransportTypes(), config.isServerVpnGroup()));
    raw.put(
        "network_specifier",
        request.getNetworkSpecifier() == null
            ? JSONObject.NULL
            : request.getNetworkSpecifier().getClass().getName());
    List<Integer> subscriptions = new ArrayList<>(request.getSubscriptionIds());
    if (config.isServerVpnGroup()) {
      Collections.sort(subscriptions);
    }
    raw.put("subscription_ids", new JSONArray(subscriptions));
    return raw;
  }

  @SuppressWarnings("deprecation")
  private static void recordLegacy(
      ResultStore store, RunConfig config, ConnectivityManager manager, Network[] networks)
      throws IOException, JSONException {
    recordLegacyActive(store, config, manager);
    recordLegacyNetworks(store, config, manager, networks);
    recordLegacyAll(store, config, manager);
  }

  @SuppressWarnings("deprecation")
  private static void recordLegacyActive(
      ResultStore store, RunConfig config, ConnectivityManager manager)
      throws IOException, JSONException {
    try {
      NetworkInfo active = manager.getActiveNetworkInfo();
      boolean positive = active != null && isConnectedOrConnectingVpn(active);
      store.detector(
          config,
          "legacy.active",
          true,
          positive ? ProbeStatus.POSITIVE : ProbeStatus.NEGATIVE,
          new JSONObject()
              .put(
                  "observation", active == null ? JSONObject.NULL : networkInfoObservation(active)),
          null,
          0,
          "complete");
    } catch (RuntimeException error) {
      store.detector(
          config, "legacy.active", true, ProbeStatus.ERROR, new JSONObject(), error, 0, "complete");
    }
  }

  @SuppressWarnings("deprecation")
  private static void recordLegacyNetworks(
      ResultStore store, RunConfig config, ConnectivityManager manager, Network[] networks)
      throws IOException, JSONException {
    try {
      boolean positive = false;
      JSONArray raw = new JSONArray();
      for (Network network : networks) {
        NetworkInfo info = manager.getNetworkInfo(network);
        if (info != null) {
          positive |= isConnectedOrConnectingVpn(info);
          raw.put(networkInfoObservation(info));
        }
      }
      store.detector(
          config,
          "legacy.network",
          true,
          positive ? ProbeStatus.POSITIVE : ProbeStatus.NEGATIVE,
          new JSONObject().put("observations", raw),
          null,
          0,
          "complete");
    } catch (RuntimeException error) {
      store.detector(
          config,
          "legacy.network",
          true,
          ProbeStatus.ERROR,
          new JSONObject(),
          error,
          0,
          "complete");
    }
  }

  @SuppressWarnings("deprecation")
  private static void recordLegacyAll(
      ResultStore store, RunConfig config, ConnectivityManager manager)
      throws IOException, JSONException {
    try {
      boolean positive = false;
      JSONArray raw = new JSONArray();
      NetworkInfo[] all = manager.getAllNetworkInfo();
      if (all != null) {
        for (NetworkInfo info : all) {
          positive |= isConnectedOrConnectingVpn(info);
          raw.put(networkInfoObservation(info));
        }
      }
      store.detector(
          config,
          "legacy.all",
          true,
          positive ? ProbeStatus.POSITIVE : ProbeStatus.NEGATIVE,
          new JSONObject().put("observations", raw),
          null,
          0,
          "complete");
    } catch (RuntimeException error) {
      store.detector(
          config, "legacy.all", true, ProbeStatus.ERROR, new JSONObject(), error, 0, "complete");
    }
  }

  @SuppressWarnings("deprecation")
  private static boolean isConnectedOrConnectingVpn(NetworkInfo info) {
    return info.getType() == ConnectivityManager.TYPE_VPN && info.isConnectedOrConnecting();
  }

  @SuppressWarnings("deprecation")
  private static JSONObject networkInfoObservation(NetworkInfo info) throws JSONException {
    return new JSONObject()
        .put("type", info.getType())
        .put("type_name", info.getTypeName())
        .put("connected", info.isConnected())
        .put("connected_or_connecting", info.isConnectedOrConnecting())
        .put("state", info.getState().name())
        .put("detailed_state", info.getDetailedState().name());
  }

  private static void runAsynchronous(
      Context context, ConnectivityManager manager, RunConfig config, ResultStore store)
      throws IOException, JSONException {
    runCallback(
        manager,
        config,
        store,
        "callback.default",
        true,
        false,
        (callback, handler) -> manager.registerDefaultNetworkCallback(callback));
    runCallback(
        manager,
        config,
        store,
        "callback.default_handler",
        true,
        false,
        (callback, handler) -> manager.registerDefaultNetworkCallback(callback, handler));
    NetworkRequest broad = new NetworkRequest.Builder().build();
    runCallback(
        manager,
        config,
        store,
        "callback.broad",
        false,
        false,
        (callback, handler) -> manager.registerNetworkCallback(broad, callback));
    runCallback(
        manager,
        config,
        store,
        "callback.broad_handler",
        false,
        false,
        (callback, handler) -> manager.registerNetworkCallback(broad, callback, handler));
    NetworkRequest inclusive = vpnInclusiveRequest();
    runCallback(
        manager,
        config,
        store,
        "callback.vpn_inclusive",
        false,
        false,
        (callback, handler) -> manager.registerNetworkCallback(inclusive, callback));
    NetworkRequest vpnRequest = vpnExclusiveRequest(false);
    runCallback(
        manager,
        config,
        store,
        "callback.vpn_exclusive",
        true,
        true,
        (callback, handler) -> manager.registerNetworkCallback(vpnRequest, callback, handler));
    NetworkRequest mixed = vpnMixedRequest(manager);
    runCallback(
        manager,
        config,
        store,
        "callback.vpn_mixed",
        false,
        true,
        (callback, handler) -> manager.registerNetworkCallback(mixed, callback));
    NetworkRequest includeOtherUids = vpnExclusiveRequest(true);
    runCallback(
        manager,
        config,
        store,
        "callback.vpn_exclusive_other_uid",
        false,
        true,
        (callback, handler) -> manager.registerNetworkCallback(includeOtherUids, callback));
    runCallback(
        manager,
        config,
        store,
        "callback.best_matching",
        false,
        false,
        (callback, handler) ->
            manager.registerBestMatchingNetworkCallback(broad, callback, handler));
    registerPendingListen(context, manager, config, store, vpnRequest);
  }

  private static void runActiveRequest(
      Context context, ConnectivityManager manager, RunConfig config, ResultStore store)
      throws IOException, JSONException {
    NetworkRequest vpnRequest = vpnExclusiveRequest(false);
    runCallback(
        manager,
        config,
        store,
        "request.callback.default",
        true,
        true,
        (callback, handler) -> manager.requestNetwork(vpnRequest, callback));
    runCallback(
        manager,
        config,
        store,
        "request.callback.timeout",
        true,
        true,
        (callback, handler) -> manager.requestNetwork(vpnRequest, callback, CALLBACK_TIMEOUT_MS));
    runCallback(
        manager,
        config,
        store,
        "request.callback.handler",
        true,
        true,
        (callback, handler) -> manager.requestNetwork(vpnRequest, callback, handler));
    runCallback(
        manager,
        config,
        store,
        "request.callback.handler_timeout",
        true,
        true,
        (callback, handler) ->
            manager.requestNetwork(vpnRequest, callback, handler, CALLBACK_TIMEOUT_MS));
    registerPendingRequest(context, manager, config, store, vpnRequest);
    runReserve(manager, config, store, vpnRequest);
  }

  private static NetworkRequest vpnInclusiveRequest() {
    return new NetworkRequest.Builder()
        .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .build();
  }

  private static NetworkRequest vpnExclusiveRequest(boolean includeOtherUids) {
    return new NetworkRequest.Builder()
        .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
        .setIncludeOtherUidNetworks(includeOtherUids)
        .build();
  }

  @SuppressWarnings("deprecation")
  private static NetworkRequest vpnMixedRequest(ConnectivityManager manager) {
    int physicalTransport = observedPhysicalTransport(manager.getAllNetworks(), manager);
    return new NetworkRequest.Builder()
        .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
        .addTransportType(physicalTransport)
        .build();
  }

  private static void runCallback(
      ConnectivityManager manager,
      RunConfig config,
      ResultStore store,
      String testId,
      boolean mandatory,
      boolean availabilityIsPositive,
      CallbackRegistrar registrar)
      throws IOException, JSONException {
    long started = System.nanoTime();
    HandlerThread thread = new HandlerThread("probe-" + testId.replace('.', '-'));
    thread.start();
    Handler handler = new Handler(thread.getLooper());
    CountDownLatch latch = new CountDownLatch(1);
    AtomicBoolean available = new AtomicBoolean();
    AtomicBoolean vpn = new AtomicBoolean();
    List<String> events = Collections.synchronizedList(new ArrayList<>());
    ConnectivityManager.NetworkCallback callback =
        new ConnectivityManager.NetworkCallback() {
          @Override
          public void onAvailable(Network network) {
            events.add("onAvailable");
            available.set(true);
            if (availabilityIsPositive) {
              latch.countDown();
            }
          }

          @Override
          public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) {
            events.add("onCapabilitiesChanged");
            available.set(true);
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
              vpn.set(true);
            }
            latch.countDown();
          }

          @Override
          public void onLinkPropertiesChanged(
              Network network, android.net.LinkProperties linkProperties) {
            events.add("onLinkPropertiesChanged");
          }

          @Override
          public void onBlockedStatusChanged(Network network, boolean blocked) {
            events.add("onBlockedStatusChanged:" + blocked);
          }

          @Override
          public void onLosing(Network network, int maxMsToLive) {
            events.add("onLosing");
          }

          @Override
          public void onLost(Network network) {
            events.add("onLost");
          }

          @Override
          public void onUnavailable() {
            events.add("onUnavailable");
            latch.countDown();
          }
        };
    Throwable failure = null;
    String cleanup = "complete";
    boolean completed = false;
    try {
      registrar.register(callback, handler);
      completed = latch.await(CALLBACK_TIMEOUT_MS + 500L, TimeUnit.MILLISECONDS);
      if (completed) {
        Thread.sleep(100L);
      }
    } catch (InterruptedException error) {
      Thread.currentThread().interrupt();
      failure = error;
    } catch (RuntimeException error) {
      failure = error;
    } finally {
      try {
        manager.unregisterNetworkCallback(callback);
      } catch (RuntimeException error) {
        cleanup = "error:" + error.getClass().getName();
        if (failure == null) {
          failure = error;
        }
      }
      thread.quitSafely();
    }
    ProbeStatus status;
    if (failure != null || !"complete".equals(cleanup)) {
      status = ProbeStatus.ERROR;
    } else if (!completed) {
      boolean expectedSilentProjection =
          config.isActiveServerVpnTarget()
              && (testId.contains("vpn_exclusive") || testId.startsWith("request.callback."));
      status = expectedSilentProjection ? ProbeStatus.NEGATIVE : ProbeStatus.INCONCLUSIVE;
    } else if (vpn.get() || (availabilityIsPositive && available.get())) {
      status = ProbeStatus.POSITIVE;
    } else {
      status = ProbeStatus.NEGATIVE;
    }
    store.detector(
        config,
        testId,
        mandatory,
        status,
        new JSONObject()
            .put("available", available.get())
            .put("vpn", vpn.get())
            .put("events", new JSONArray(events)),
        failure,
        elapsed(started),
        cleanup);
  }

  private static void registerPendingListen(
      Context context,
      ConnectivityManager manager,
      RunConfig config,
      ResultStore store,
      NetworkRequest request)
      throws IOException, JSONException {
    runPendingIntent(context, manager, config, store, request, false);
  }

  private static void registerPendingRequest(
      Context context,
      ConnectivityManager manager,
      RunConfig config,
      ResultStore store,
      NetworkRequest request)
      throws IOException, JSONException {
    runPendingIntent(context, manager, config, store, request, true);
  }

  private static void runPendingIntent(
      Context context,
      ConnectivityManager manager,
      RunConfig config,
      ResultStore store,
      NetworkRequest request,
      boolean activeRequest)
      throws IOException, JSONException {
    long started = System.nanoTime();
    String testId =
        activeRequest ? "request.pending.vpn_exclusive" : "pending.listen.vpn_exclusive";
    PendingIntentSignal.prepare(config.runId, testId);
    PendingIntent pendingIntent = pendingIntent(context, config, testId);
    Throwable failure = null;
    String cleanup = "complete";
    boolean registered = false;
    PendingIntentSignal.Observation observation = null;
    try {
      if (activeRequest) {
        manager.requestNetwork(request, pendingIntent);
      } else {
        manager.registerNetworkCallback(request, pendingIntent);
      }
      registered = true;
      observation = PendingIntentSignal.await(config.runId, testId, CALLBACK_TIMEOUT_MS + 500L);
    } catch (InterruptedException error) {
      Thread.currentThread().interrupt();
      failure = error;
    } catch (RuntimeException error) {
      failure = error;
    } finally {
      if (registered) {
        try {
          if (activeRequest) {
            manager.releaseNetworkRequest(pendingIntent);
          } else {
            manager.unregisterNetworkCallback(pendingIntent);
          }
        } catch (RuntimeException error) {
          cleanup = "error:" + error.getClass().getName();
          if (failure == null) {
            failure = error;
          }
        }
      }
      pendingIntent.cancel();
      PendingIntentSignal.clear(config.runId, testId);
    }
    JSONObject raw = requestObservation(request, config);
    if (observation != null) {
      raw.put("delivery", observation.raw);
    }
    ProbeStatus status;
    if (failure != null || !"complete".equals(cleanup)) {
      status = ProbeStatus.ERROR;
    } else if (observation == null) {
      status = config.isActiveServerVpnTarget() ? ProbeStatus.NEGATIVE : ProbeStatus.INCONCLUSIVE;
    } else {
      status = observation.vpn ? ProbeStatus.POSITIVE : ProbeStatus.NEGATIVE;
    }
    store.detector(config, testId, true, status, raw, failure, elapsed(started), cleanup);
  }

  private static void runReserve(
      ConnectivityManager manager, RunConfig config, ResultStore store, NetworkRequest request)
      throws IOException, JSONException {
    long started = System.nanoTime();
    HandlerThread thread = new HandlerThread("probe-reserve-signature");
    thread.start();
    Handler handler = new Handler(thread.getLooper());
    CountDownLatch latch = new CountDownLatch(1);
    List<String> events = Collections.synchronizedList(new ArrayList<>());
    AtomicBoolean vpn = new AtomicBoolean();
    ConnectivityManager.NetworkCallback callback =
        new ConnectivityManager.NetworkCallback() {
          @Override
          public void onReserved(NetworkCapabilities capabilities) {
            events.add("onReserved");
            vpn.set(capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
            latch.countDown();
          }

          @Override
          public void onUnavailable() {
            events.add("onUnavailable");
            latch.countDown();
          }
        };
    Throwable failure = null;
    String cleanup = "complete";
    boolean registered = false;
    boolean completed = false;
    try {
      manager.reserveNetwork(request, handler, callback);
      registered = true;
      completed = latch.await(CALLBACK_TIMEOUT_MS + 500L, TimeUnit.MILLISECONDS);
    } catch (InterruptedException error) {
      Thread.currentThread().interrupt();
      failure = error;
    } catch (RuntimeException error) {
      failure = error;
    } finally {
      if (registered) {
        try {
          manager.unregisterNetworkCallback(callback);
        } catch (RuntimeException error) {
          cleanup = "error:" + error.getClass().getName();
          if (failure == null) {
            failure = error;
          }
        }
      }
      thread.quitSafely();
    }
    ProbeStatus status;
    if (!"complete".equals(cleanup)) {
      status = ProbeStatus.ERROR;
    } else if (failure != null) {
      status = ProbeStatus.UNAVAILABLE;
    } else if (!completed) {
      status = ProbeStatus.INCONCLUSIVE;
    } else {
      status = vpn.get() ? ProbeStatus.POSITIVE : ProbeStatus.NEGATIVE;
    }
    store.detector(
        config,
        "reserve.signature",
        false,
        status,
        new JSONObject().put("events", new JSONArray(events)).put("vpn", vpn.get()),
        failure,
        elapsed(started),
        cleanup);
  }

  private static PendingIntent pendingIntent(Context context, RunConfig config, String testId) {
    Class<?> receiver =
        config.process.endsWith(":secondary")
            ? SecondaryProbePendingIntentReceiver.class
            : ProbePendingIntentReceiver.class;
    Intent intent = new Intent(context, receiver);
    intent.setAction(context.getPackageName() + ".PROBE_NETWORK");
    intent.putExtra("test_id", testId);
    config.copyTo(intent);
    return PendingIntent.getBroadcast(
        context,
        Math.abs((config.runId + testId).hashCode()),
        intent,
        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE);
  }

  public static void compileReserveSignature(
      ConnectivityManager manager,
      NetworkRequest request,
      Handler handler,
      ConnectivityManager.NetworkCallback callback) {
    manager.reserveNetwork(request, handler, callback);
  }

  @SuppressWarnings("deprecation")
  public static void compileRequestBearingSurface(
      ConnectivityManager manager,
      NetworkRequest request,
      Handler handler,
      ConnectivityManager.NetworkCallback callback,
      PendingIntent pendingIntent) {
    manager.registerDefaultNetworkCallback(callback);
    manager.registerDefaultNetworkCallback(callback, handler);
    manager.registerNetworkCallback(request, callback);
    manager.registerNetworkCallback(request, callback, handler);
    manager.registerNetworkCallback(request, pendingIntent);
    manager.registerBestMatchingNetworkCallback(request, callback, handler);
    manager.requestNetwork(request, callback);
    manager.requestNetwork(request, callback, CALLBACK_TIMEOUT_MS);
    manager.requestNetwork(request, callback, handler);
    manager.requestNetwork(request, callback, handler, CALLBACK_TIMEOUT_MS);
    manager.requestNetwork(request, pendingIntent);
    manager.reserveNetwork(request, handler, callback);
  }

  private static int observedPhysicalTransport(Network[] networks, ConnectivityManager manager) {
    int[] physical = {
      NetworkCapabilities.TRANSPORT_WIFI,
      NetworkCapabilities.TRANSPORT_CELLULAR,
      NetworkCapabilities.TRANSPORT_ETHERNET,
      NetworkCapabilities.TRANSPORT_BLUETOOTH
    };
    for (Network network : networks) {
      NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
      if (capabilities == null) {
        continue;
      }
      for (int transport : physical) {
        if (capabilities.hasTransport(transport)) {
          return transport;
        }
      }
    }
    return NetworkCapabilities.TRANSPORT_WIFI;
  }

  private static JSONArray intArray(int[] values, boolean sort) {
    if (sort) {
      java.util.Arrays.sort(values);
    }
    JSONArray array = new JSONArray();
    for (int value : values) {
      array.put(value);
    }
    return array;
  }

  private static long elapsed(long started) {
    return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
  }

  @FunctionalInterface
  private interface CallbackRegistrar {
    void register(ConnectivityManager.NetworkCallback callback, Handler handler);
  }
}
