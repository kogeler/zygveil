// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe.location;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageManager;
import android.location.GnssCapabilities;
import android.location.GnssMeasurementsEvent;
import android.location.GnssNavigationMessage;
import android.location.GnssStatus;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.location.LocationRequest;
import android.location.OnNmeaMessageListener;
import android.os.CancellationSignal;
import android.os.SystemClock;
import dev.zygveil.probe.detector.RunConfig;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public final class LocationSessionCoordinator {
  private static final long CALLBACK_DRAIN_MS = 2_000;
  private static final Set<String> REQUIRED_GMS_LOCATION_SOURCES =
      Set.of(
          "gms_fused.last.default",
          "gms_fused.last.request",
          "gms_fused.current.priority",
          "gms_fused.current.request",
          "gms_fused.update.callback",
          "gms_fused.update.listener",
          "gms_fused.update.pending_intent");
  private static final List<String> EVENT_TYPES =
      List.of(
          "provider_inventory",
          "last_known",
          "current",
          "location_update",
          "location_batch",
          "gnss_capabilities",
          "gnss_status",
          "nmea",
          "raw_measurement_status",
          "raw_measurement_event",
          "navigation_status",
          "navigation_event",
          "gms_last_known",
          "gms_current",
          "gms_location_update",
          "gms_location_batch",
          "gms_location_availability",
          "gms_pending_intent",
          "process_isolation");

  private final Context context;
  private final RunConfig config;
  private final LocationResultStore store;
  private final LocationManager manager;
  private final LocationOracle oracle;
  private final ExecutorService callbacks = Executors.newSingleThreadExecutor();
  private final GmsLocationClient gmsClient;
  private final LocationChannelComparison channelComparison = new LocationChannelComparison();
  private final List<LocationListener> locationListeners = new ArrayList<>();
  private final List<CancellationSignal> currentLocationSignals = new ArrayList<>();
  private final Set<String> emittedTypes = new HashSet<>();
  private final Set<String> gmsLocationSources = ConcurrentHashMap.newKeySet();
  private final List<String> cleanupFailures = new ArrayList<>();
  private final Object observationLock = new Object();
  private final AtomicInteger ordinaryLocationEvents = new AtomicInteger();
  private final AtomicInteger batchEvents = new AtomicInteger();
  private final AtomicInteger gnssStatusEvents = new AtomicInteger();
  private final AtomicInteger nmeaEvents = new AtomicInteger();
  private final AtomicInteger measurementEvents = new AtomicInteger();
  private final AtomicInteger navigationEvents = new AtomicInteger();
  private final AtomicInteger gmsLastKnownLocations = new AtomicInteger();
  private final AtomicInteger gmsCurrentLocations = new AtomicInteger();
  private final AtomicInteger gmsCallbackLocations = new AtomicInteger();
  private final AtomicInteger gmsListenerLocations = new AtomicInteger();
  private final AtomicInteger gmsPendingIntentLocations = new AtomicInteger();
  private final AtomicLong firstMeasurementLatencyMs = new AtomicLong(-1);
  private final AtomicLong firstNavigationLatencyMs = new AtomicLong(-1);
  private final long sessionStartedNs = SystemClock.elapsedRealtimeNanos();

  private GnssStatus.Callback gnssStatusCallback;
  private OnNmeaMessageListener nmeaListener;
  private GnssMeasurementsEvent.Callback measurementCallback;
  private GnssNavigationMessage.Callback navigationCallback;
  private LocationListener batchListener;
  private String batchProvider;
  private boolean gnssStatusRegistered;
  private boolean nmeaRegistered;
  private boolean measurementRegistered;
  private boolean navigationRegistered;
  private Boolean measurementCapability;
  private Boolean navigationCapability;
  private String measurementRegistrationResult = "NOT_ATTEMPTED";
  private String navigationRegistrationResult = "NOT_ATTEMPTED";
  private String measurementCallbackStatus = "NO_CALLBACK";
  private String navigationCallbackStatus = "NO_CALLBACK";
  private boolean callbackObservationsOpen = true;

  private LocationSessionCoordinator(
      Context context, RunConfig config, LocationResultStore store, LocationOracle oracle) {
    this.context = context;
    this.config = config;
    this.store = store;
    this.oracle = oracle;
    manager = context.getSystemService(LocationManager.class);
    gmsClient = GmsLocationClient.create(context, config, callbacks);
  }

  public static String execute(Context context, RunConfig config)
      throws IOException, JSONException {
    LocationResultStore store = new LocationResultStore(context, config);
    LocationOracle oracle = LocationOracle.load(context, config.locationOracleRequired);
    return new LocationSessionCoordinator(context, config, store, oracle).run();
  }

  private String run() throws IOException, JSONException {
    if (!oracle.unlinked() || (config.locationOracleRequired && !oracle.ready())) {
      for (String type : EVENT_TYPES) {
        record(
            type,
            "session",
            "ERROR",
            payload("reason", "oracle_unavailable", "oracle_status", oracle.status()));
      }
      return publishSummary("ERROR", "not_started");
    }
    if (!hasLocationPermissions() || manager == null) {
      String reason = manager == null ? "location_service_unavailable" : "permission_denied";
      for (String type : EVENT_TYPES) {
        record(type, "session", "ERROR", payload("reason", reason));
      }
      return publishSummary("ERROR", "not_started");
    }

    List<String> providers = providerInventory();
    observeLastKnown(providers);
    observeCurrent(providers);
    registerContinuousUpdates(providers);
    registerBatchedUpdates(providers);
    observeGnssCapabilities();
    registerGnssStatus();
    registerNmea();
    registerMeasurements();
    registerNavigation();
    startGmsClient();
    observeProcessIsolation();

    boolean interrupted = false;
    try {
      TimeUnit.MILLISECONDS.sleep(config.observationWindowMs);
      flushBatch();
      gmsClient.flush();
      TimeUnit.MILLISECONDS.sleep(500);
    } catch (InterruptedException error) {
      Thread.currentThread().interrupt();
      interrupted = true;
      record("location_update", "session", "ERROR", errorPayload(error));
    } finally {
      cleanup();
    }
    callbacks.shutdown();
    try {
      if (!callbacks.awaitTermination(CALLBACK_DRAIN_MS, TimeUnit.MILLISECONDS)) {
        cleanupFailures.add("callback_executor_timeout");
        callbacks.shutdownNow();
      }
    } catch (InterruptedException error) {
      Thread.currentThread().interrupt();
      cleanupFailures.add("callback_executor_interrupted");
      callbacks.shutdownNow();
    }
    closeCallbackObservations();
    publishAggregateObservations();
    String cleanupStatus = cleanupFailures.isEmpty() ? "complete" : "failed";
    boolean unexpectedRaw =
        "blocked".equals(config.rawGnssMode)
            && (measurementEvents.get() > 0 || navigationEvents.get() > 0);
    String verdict =
        interrupted
                || !cleanupFailures.isEmpty()
                || unexpectedRaw
                || oracle.locationSpatialFailure()
                || gmsFailure()
            ? "FAIL"
            : "PASS";
    return publishSummary(verdict, cleanupStatus);
  }

  private boolean hasLocationPermissions() {
    return context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION)
            == PackageManager.PERMISSION_GRANTED
        && context.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION)
            == PackageManager.PERMISSION_GRANTED;
  }

  private List<String> providerInventory() {
    try {
      List<String> providers = new ArrayList<>(manager.getAllProviders());
      providers.sort(Comparator.naturalOrder());
      List<String> enabled = new ArrayList<>(manager.getProviders(true));
      enabled.sort(Comparator.naturalOrder());
      record(
          "provider_inventory",
          "location_manager",
          "SUCCESS",
          payload(
              "providers",
              new JSONArray(providers),
              "enabled_providers",
              new JSONArray(enabled),
              "location_enabled",
              manager.isLocationEnabled()));
      return providers;
    } catch (RuntimeException error) {
      record("provider_inventory", "location_manager", "ERROR", errorPayload(error));
      return List.of();
    }
  }

  @SuppressLint("MissingPermission")
  private void observeLastKnown(List<String> providers) {
    if (providers.isEmpty()) {
      record("last_known", "location_manager", "UNAVAILABLE", payload("reason", "no_providers"));
      return;
    }
    for (String provider : providers) {
      try {
        Location location = manager.getLastKnownLocation(provider);
        if (location == null) {
          record("last_known", provider, "UNAVAILABLE", payload("reason", "null_location"));
        } else {
          recordLocation("last_known", provider, location, false);
        }
      } catch (RuntimeException error) {
        record("last_known", provider, "ERROR", errorPayload(error));
      }
    }
  }

  @SuppressLint("MissingPermission")
  private void observeCurrent(List<String> providers) {
    int registrations = 0;
    for (String provider : providers) {
      if (LocationManager.PASSIVE_PROVIDER.equals(provider) || !providerEnabled(provider)) {
        continue;
      }
      CancellationSignal signal = new CancellationSignal();
      currentLocationSignals.add(signal);
      try {
        manager.getCurrentLocation(
            provider,
            signal,
            callbacks,
            location -> {
              if (location == null) {
                record("current", provider, "UNAVAILABLE", payload("reason", "null_location"));
              } else {
                ordinaryLocationEvents.incrementAndGet();
                recordLocation("current", provider, location, true);
              }
            });
        registrations++;
        record("current", provider, "REGISTERED", payload("registration", "accepted"));
      } catch (RuntimeException error) {
        signal.cancel();
        record("current", provider, "ERROR", errorPayload(error));
      }
    }
    if (registrations == 0) {
      record(
          "current", "location_manager", "UNAVAILABLE", payload("reason", "no_enabled_provider"));
    }
  }

  @SuppressLint("MissingPermission")
  private void registerContinuousUpdates(List<String> providers) {
    LocationRequest request =
        new LocationRequest.Builder(1_000).setMinUpdateIntervalMillis(500).build();
    int registrations = 0;
    for (String provider : providers) {
      if (!providerEnabled(provider)) {
        continue;
      }
      LocationListener listener =
          location -> {
            ordinaryLocationEvents.incrementAndGet();
            recordLocation("location_update", provider, location, true);
          };
      try {
        manager.requestLocationUpdates(provider, request, callbacks, listener);
        locationListeners.add(listener);
        registrations++;
        record("location_update", provider, "REGISTERED", payload("registration", "accepted"));
      } catch (RuntimeException error) {
        record("location_update", provider, "ERROR", errorPayload(error));
      }
    }
    if (registrations == 0) {
      record(
          "location_update", "location_manager", "UNAVAILABLE", payload("reason", "no_provider"));
    }
  }

  @SuppressLint("MissingPermission")
  private void registerBatchedUpdates(List<String> providers) {
    batchProvider = preferredProvider(providers);
    if (batchProvider == null) {
      record("location_batch", "location_manager", "UNAVAILABLE", payload("reason", "no_provider"));
      return;
    }
    LocationRequest request =
        new LocationRequest.Builder(1_000)
            .setMinUpdateIntervalMillis(500)
            .setMaxUpdateDelayMillis(Math.min(5_000, config.observationWindowMs / 2))
            .build();
    batchListener =
        new LocationListener() {
          @Override
          public void onLocationChanged(Location location) {
            onLocationChanged(List.of(location));
          }

          @Override
          public void onLocationChanged(List<Location> locations) {
            ordinaryLocationEvents.addAndGet(locations.size());
            batchEvents.incrementAndGet();
            try {
              for (Location location : locations) {
                channelComparison.observePlatform(location);
              }
              record(
                  "location_batch",
                  batchProvider,
                  "SUCCESS",
                  LocationPayloads.locationBatch(locations, oracle));
            } catch (JSONException error) {
              record("location_batch", batchProvider, "ERROR", errorPayload(error));
            }
          }
        };
    try {
      manager.requestLocationUpdates(batchProvider, request, callbacks, batchListener);
      locationListeners.add(batchListener);
      record("location_batch", batchProvider, "REGISTERED", payload("registration", "accepted"));
    } catch (RuntimeException error) {
      batchListener = null;
      record("location_batch", batchProvider, "ERROR", errorPayload(error));
    }
  }

  private void observeGnssCapabilities() {
    try {
      GnssCapabilities capabilities = manager.getGnssCapabilities();
      measurementCapability = capabilities.hasMeasurements();
      navigationCapability = capabilities.hasNavigationMessages();
      record(
          "gnss_capabilities",
          "gnss",
          "SUCCESS",
          payload(
              "reported_measurement_capability",
              measurementCapability,
              "reported_navigation_capability",
              navigationCapability,
              "antenna_info",
              capabilities.hasAntennaInfo(),
              "low_power_mode",
              capabilities.hasLowPowerMode(),
              "measurement_corrections",
              capabilities.hasMeasurementCorrections()));
    } catch (RuntimeException error) {
      record("gnss_capabilities", "gnss", "ERROR", errorPayload(error));
    }
  }

  @SuppressLint("MissingPermission")
  private void registerGnssStatus() {
    gnssStatusCallback =
        new GnssStatus.Callback() {
          @Override
          public void onStarted() {
            record("gnss_status", "gnss", "SUCCESS", payload("engine", "started"));
          }

          @Override
          public void onStopped() {
            record("gnss_status", "gnss", "SUCCESS", payload("engine", "stopped"));
          }

          @Override
          public void onFirstFix(int timeToFirstFixMillis) {
            record("gnss_status", "gnss", "SUCCESS", payload("first_fix_ms", timeToFirstFixMillis));
          }

          @Override
          public void onSatelliteStatusChanged(GnssStatus status) {
            gnssStatusEvents.incrementAndGet();
            try {
              record("gnss_status", "gnss", "SUCCESS", LocationPayloads.gnssStatus(status));
            } catch (JSONException error) {
              record("gnss_status", "gnss", "ERROR", errorPayload(error));
            }
          }
        };
    try {
      gnssStatusRegistered = manager.registerGnssStatusCallback(callbacks, gnssStatusCallback);
      record(
          "gnss_status",
          "gnss",
          gnssStatusRegistered ? "REGISTERED" : "UNAVAILABLE",
          payload("registration_accepted", gnssStatusRegistered));
    } catch (RuntimeException error) {
      record("gnss_status", "gnss", "ERROR", errorPayload(error));
    }
  }

  @SuppressLint("MissingPermission")
  private void registerNmea() {
    nmeaListener =
        (message, timestamp) -> {
          nmeaEvents.incrementAndGet();
          try {
            record("nmea", "gnss", "SUCCESS", LocationPayloads.nmea(message, timestamp, oracle));
          } catch (JSONException error) {
            record("nmea", "gnss", "ERROR", errorPayload(error));
          }
        };
    try {
      nmeaRegistered = manager.addNmeaListener(callbacks, nmeaListener);
      record(
          "nmea",
          "gnss",
          nmeaRegistered ? "REGISTERED" : "UNAVAILABLE",
          payload("registration_accepted", nmeaRegistered));
    } catch (RuntimeException error) {
      record("nmea", "gnss", "ERROR", errorPayload(error));
    }
  }

  @SuppressWarnings("deprecation")
  @SuppressLint("MissingPermission")
  private void registerMeasurements() {
    measurementCallback =
        new GnssMeasurementsEvent.Callback() {
          @Override
          public void onStatusChanged(int status) {
            measurementCallbackStatus = measurementStatus(status);
            record(
                "raw_measurement_status",
                "gnss",
                "SUCCESS",
                payload("callback_status", measurementCallbackStatus));
          }

          @Override
          public void onGnssMeasurementsReceived(GnssMeasurementsEvent event) {
            measurementEvents.incrementAndGet();
            firstMeasurementLatencyMs.compareAndSet(-1, sessionElapsedMs());
            try {
              record(
                  "raw_measurement_event", "gnss", "SUCCESS", LocationPayloads.measurements(event));
            } catch (JSONException error) {
              record("raw_measurement_event", "gnss", "ERROR", errorPayload(error));
            }
          }
        };
    try {
      measurementRegistered =
          manager.registerGnssMeasurementsCallback(callbacks, measurementCallback);
      measurementRegistrationResult = measurementRegistered ? "REGISTERED" : "REJECTED";
      record(
          "raw_measurement_status",
          "gnss",
          measurementRegistered ? "REGISTERED" : "UNAVAILABLE",
          payload("registration_result", measurementRegistrationResult));
    } catch (RuntimeException error) {
      measurementRegistrationResult = "ERROR";
      record("raw_measurement_status", "gnss", "ERROR", errorPayload(error));
    }
  }

  @SuppressWarnings("deprecation")
  @SuppressLint("MissingPermission")
  private void registerNavigation() {
    navigationCallback =
        new GnssNavigationMessage.Callback() {
          @Override
          public void onStatusChanged(int status) {
            navigationCallbackStatus = navigationStatus(status);
            record(
                "navigation_status",
                "gnss",
                "SUCCESS",
                payload("callback_status", navigationCallbackStatus));
          }

          @Override
          public void onGnssNavigationMessageReceived(GnssNavigationMessage event) {
            navigationEvents.incrementAndGet();
            firstNavigationLatencyMs.compareAndSet(-1, sessionElapsedMs());
            try {
              record("navigation_event", "gnss", "SUCCESS", LocationPayloads.navigation(event));
            } catch (JSONException error) {
              record("navigation_event", "gnss", "ERROR", errorPayload(error));
            }
          }
        };
    try {
      navigationRegistered =
          manager.registerGnssNavigationMessageCallback(callbacks, navigationCallback);
      navigationRegistrationResult = navigationRegistered ? "REGISTERED" : "REJECTED";
      record(
          "navigation_status",
          "gnss",
          navigationRegistered ? "REGISTERED" : "UNAVAILABLE",
          payload("registration_result", navigationRegistrationResult));
    } catch (RuntimeException error) {
      navigationRegistrationResult = "ERROR";
      record("navigation_status", "gnss", "ERROR", errorPayload(error));
    }
  }

  private void startGmsClient() {
    try {
      gmsClient.start(
          new GmsLocationClient.Observer() {
            @Override
            public void onObservation(
                String type, String source, String status, JSONObject payload) {
              record(type, source, status, payload);
            }

            @Override
            public void onLocation(String type, String source, Location location) {
              recordGmsLocation(type, source, location);
            }

            @Override
            public void onLocations(String type, String source, List<Location> locations) {
              recordGmsLocations(type, source, locations);
            }

            @Override
            public void onCleanupFailure(String failure) {
              cleanupFailures.add(failure);
            }
          });
    } catch (RuntimeException error) {
      record("gms_location_update", "gms_fused", "ERROR", errorPayload(error));
    }
  }

  private void observeProcessIsolation() {
    boolean nativeMapped = false;
    String mapsStatus = "readable";
    try {
      nativeMapped =
          new String(Files.readAllBytes(Path.of("/proc/self/maps")), StandardCharsets.UTF_8)
              .contains("libzygveil.so");
    } catch (IOException | RuntimeException error) {
      mapsStatus = "unavailable";
    }
    boolean bridgeVisible;
    try {
      Class.forName("dev.zygveil.location.bridge.HookBridge", false, context.getClassLoader());
      bridgeVisible = true;
    } catch (ClassNotFoundException error) {
      bridgeVisible = false;
    }
    int matchingThreads = 0;
    for (Thread thread : Thread.getAllStackTraces().keySet()) {
      if (thread.getName().contains("ZygVeil")) {
        matchingThreads++;
      }
    }
    record(
        "process_isolation",
        "process",
        nativeMapped || bridgeVisible || matchingThreads > 0 ? "ERROR" : "SUCCESS",
        payload(
            "native_library_mapped",
            nativeMapped,
            "bridge_class_visible",
            bridgeVisible,
            "persistent_matching_thread_count",
            matchingThreads,
            "maps_status",
            mapsStatus));
  }

  private void flushBatch() {
    if (batchListener == null || batchProvider == null) {
      return;
    }
    try {
      manager.requestFlush(batchProvider, batchListener, 1);
    } catch (RuntimeException error) {
      record("location_batch", batchProvider, "ERROR", errorPayload(error));
    }
  }

  private void cleanup() {
    for (CancellationSignal signal : currentLocationSignals) {
      signal.cancel();
    }
    for (LocationListener listener : locationListeners) {
      cleanupStep("location_listener", () -> manager.removeUpdates(listener));
    }
    if (gnssStatusRegistered) {
      cleanupStep("gnss_status", () -> manager.unregisterGnssStatusCallback(gnssStatusCallback));
    }
    if (nmeaRegistered) {
      cleanupStep("nmea", () -> manager.removeNmeaListener(nmeaListener));
    }
    if (measurementRegistered) {
      cleanupStep(
          "raw_measurement", () -> manager.unregisterGnssMeasurementsCallback(measurementCallback));
    }
    if (navigationRegistered) {
      cleanupStep(
          "navigation", () -> manager.unregisterGnssNavigationMessageCallback(navigationCallback));
    }
    cleanupStep("gms_client", gmsClient::close);
  }

  private void cleanupStep(String name, Runnable operation) {
    try {
      operation.run();
    } catch (RuntimeException error) {
      cleanupFailures.add(name + ":" + error.getClass().getSimpleName());
    }
  }

  private void publishAggregateObservations() {
    recordFinal(
        "raw_measurement_event",
        "gnss",
        "SUCCESS",
        payload(
            "aggregate",
            true,
            "event_count",
            measurementEvents.get(),
            "first_event_latency_ms",
            nullableLatency(firstMeasurementLatencyMs.get())));
    recordFinal(
        "navigation_event",
        "gnss",
        "SUCCESS",
        payload(
            "aggregate",
            true,
            "event_count",
            navigationEvents.get(),
            "first_event_latency_ms",
            nullableLatency(firstNavigationLatencyMs.get())));
    recordFinal(
        "location_update",
        "location_manager",
        "SUCCESS",
        payload("aggregate", true, "event_count", ordinaryLocationEvents.get()));
    recordFinal(
        "location_batch",
        "location_manager",
        "SUCCESS",
        payload("aggregate", true, "batch_event_count", batchEvents.get()));
    recordFinal(
        "gnss_status",
        "gnss",
        "SUCCESS",
        payload("aggregate", true, "event_count", gnssStatusEvents.get()));
    recordFinal(
        "nmea", "gnss", "SUCCESS", payload("aggregate", true, "event_count", nmeaEvents.get()));
    for (String type : EVENT_TYPES) {
      if (!emittedTypes.contains(type)) {
        recordFinal(type, "session", "UNAVAILABLE", payload("reason", "no_observation"));
      }
    }
  }

  private String publishSummary(String verdict, String cleanupStatus)
      throws IOException, JSONException {
    boolean unexpectedRaw =
        "blocked".equals(config.rawGnssMode)
            && (measurementEvents.get() > 0 || navigationEvents.get() > 0);
    JSONObject summary =
        new JSONObject()
            .put("configured_raw_gnss_mode", config.rawGnssMode)
            .put("oracle_required", config.locationOracleRequired)
            .put("oracle_status", oracle.status())
            .put("oracle_unlinked", oracle.unlinked())
            .put(
                "expected_config_generation",
                oracle.ready() ? oracle.generation() : JSONObject.NULL)
            .put("expected_config_sha256", oracle.ready() ? oracle.configDigest() : JSONObject.NULL)
            .put("reported_measurement_capability", nullableBoolean(measurementCapability))
            .put("reported_navigation_capability", nullableBoolean(navigationCapability))
            .put("measurement_registration_result", measurementRegistrationResult)
            .put("navigation_registration_result", navigationRegistrationResult)
            .put("measurement_callback_status", measurementCallbackStatus)
            .put("navigation_callback_status", navigationCallbackStatus)
            .put("measurement_event_count", measurementEvents.get())
            .put("navigation_event_count", navigationEvents.get())
            .put(
                "first_measurement_event_latency_ms",
                nullableLatency(firstMeasurementLatencyMs.get()))
            .put(
                "first_navigation_event_latency_ms",
                nullableLatency(firstNavigationLatencyMs.get()))
            .put("observation_window_ms", config.observationWindowMs)
            .put("unexpected_event_detected", unexpectedRaw)
            .put("ordinary_location_event_count", ordinaryLocationEvents.get())
            .put("location_batch_event_count", batchEvents.get())
            .put("gnss_status_event_count", gnssStatusEvents.get())
            .put("nmea_event_count", nmeaEvents.get())
            .put("gms_client_required", gmsClient.required())
            .put("gms_client_status", gmsClient.state())
            .put("gms_required_surface_complete", gmsClient.requiredSurfaceComplete())
            .put("gms_last_known_location_count", gmsLastKnownLocations.get())
            .put("gms_current_location_count", gmsCurrentLocations.get())
            .put("gms_callback_location_count", gmsCallbackLocations.get())
            .put("gms_listener_location_count", gmsListenerLocations.get())
            .put("gms_pending_intent_location_count", gmsPendingIntentLocations.get())
            .put("gms_total_location_count", channelComparison.gmsSamples())
            .put("platform_location_sample_count", channelComparison.platformSamples())
            .put("platform_gms_comparison_count", channelComparison.comparisons())
            .put(
                "platform_gms_max_distance_m",
                nullableDouble(channelComparison.maximumDistanceMeters()))
            .put(
                "platform_gms_consistency_threshold_m",
                LocationChannelComparison.CONSISTENCY_THRESHOLD_M)
            .put("platform_gms_consistent", nullableBoolean(channelComparison.consistent()))
            .put("platform_gms_object_comparison_count", channelComparison.objectComparisons())
            .put(
                "platform_gms_max_object_distance_m",
                nullableDouble(channelComparison.maximumObjectDistanceMeters()))
            .put(
                "platform_gms_object_consistent",
                nullableBoolean(channelComparison.objectConsistent()))
            .put("cleanup_status", cleanupStatus)
            .put("cleanup_failures", new JSONArray(cleanupFailures))
            .put("session_verdict", verdict);
    synchronized (observationLock) {
      callbackObservationsOpen = false;
      store.summary(config, verdict, summary);
    }
    return verdict;
  }

  private void recordLocation(
      String type, String source, Location location, boolean platformComparable) {
    if (platformComparable) {
      channelComparison.observePlatform(location);
    }
    try {
      record(type, source, "SUCCESS", LocationPayloads.location(location, oracle));
    } catch (JSONException error) {
      record(type, source, "ERROR", errorPayload(error));
    }
  }

  private void recordGmsLocation(String type, String source, Location location) {
    channelComparison.observeGms(location);
    incrementGmsLocationCount(type, source, 1);
    try {
      JSONObject payload = LocationPayloads.location(location, oracle);
      gmsLocationSources.add(source);
      record(type, source, "SUCCESS", payload);
    } catch (JSONException error) {
      record(type, source, "ERROR", errorPayload(error));
    }
  }

  private void recordGmsLocations(String type, String source, List<Location> locations) {
    for (Location location : locations) {
      channelComparison.observeGms(location);
    }
    incrementGmsLocationCount(type, source, locations.size());
    try {
      JSONObject payload = LocationPayloads.locationBatch(locations, oracle);
      if (!locations.isEmpty()) {
        gmsLocationSources.add(source);
      }
      record(type, source, "SUCCESS", payload);
    } catch (JSONException error) {
      record(type, source, "ERROR", errorPayload(error));
    }
  }

  private void incrementGmsLocationCount(String type, String source, int count) {
    switch (type) {
      case "gms_last_known" -> gmsLastKnownLocations.addAndGet(count);
      case "gms_current" -> gmsCurrentLocations.addAndGet(count);
      case "gms_pending_intent" -> gmsPendingIntentLocations.addAndGet(count);
      case "gms_location_batch" -> gmsCallbackLocations.addAndGet(count);
      case "gms_location_update" -> {
        if (source.endsWith(".listener")) {
          gmsListenerLocations.addAndGet(count);
        } else {
          gmsCallbackLocations.addAndGet(count);
        }
      }
      default -> throw new IllegalArgumentException("unsupported GMS location type: " + type);
    }
  }

  private void record(String observationType, String source, String status, JSONObject payload) {
    synchronized (observationLock) {
      if (!callbackObservationsOpen) {
        return;
      }
      recordLocked(observationType, source, status, payload);
    }
  }

  private void recordFinal(
      String observationType, String source, String status, JSONObject payload) {
    synchronized (observationLock) {
      recordLocked(observationType, source, status, payload);
    }
  }

  private void recordLocked(
      String observationType, String source, String status, JSONObject payload) {
    emittedTypes.add(observationType);
    store.observation(config, observationType, source, status, payload);
  }

  private void closeCallbackObservations() {
    synchronized (observationLock) {
      callbackObservationsOpen = false;
    }
  }

  private boolean providerEnabled(String provider) {
    try {
      return manager.isProviderEnabled(provider);
    } catch (RuntimeException ignored) {
      return false;
    }
  }

  private String preferredProvider(List<String> providers) {
    for (String candidate :
        List.of(
            LocationManager.FUSED_PROVIDER,
            LocationManager.GPS_PROVIDER,
            LocationManager.NETWORK_PROVIDER)) {
      if (providers.contains(candidate) && providerEnabled(candidate)) {
        return candidate;
      }
    }
    return null;
  }

  private long sessionElapsedMs() {
    return TimeUnit.NANOSECONDS.toMillis(SystemClock.elapsedRealtimeNanos() - sessionStartedNs);
  }

  private boolean gmsFailure() {
    if (!gmsClient.required()) {
      return false;
    }
    return !gmsClient.requiredSurfaceComplete()
        || !gmsLocationSources.equals(REQUIRED_GMS_LOCATION_SOURCES)
        || gmsLastKnownLocations.get() == 0
        || gmsCurrentLocations.get() == 0
        || gmsCallbackLocations.get() == 0
        || gmsListenerLocations.get() == 0
        || gmsPendingIntentLocations.get() == 0
        || channelComparison.gmsSamples() == 0
        || channelComparison.comparisons() == 0
        || !Boolean.TRUE.equals(channelComparison.consistent())
        || channelComparison.objectComparisons() == 0
        || !Boolean.TRUE.equals(channelComparison.objectConsistent());
  }

  @SuppressWarnings("deprecation")
  private static String measurementStatus(int status) {
    return switch (status) {
      case GnssMeasurementsEvent.Callback.STATUS_READY -> "READY";
      case GnssMeasurementsEvent.Callback.STATUS_LOCATION_DISABLED -> "LOCATION_DISABLED";
      case GnssMeasurementsEvent.Callback.STATUS_NOT_SUPPORTED -> "NOT_SUPPORTED";
      default -> "UNKNOWN_" + status;
    };
  }

  @SuppressWarnings("deprecation")
  private static String navigationStatus(int status) {
    return switch (status) {
      case GnssNavigationMessage.Callback.STATUS_READY -> "READY";
      case GnssNavigationMessage.Callback.STATUS_LOCATION_DISABLED -> "LOCATION_DISABLED";
      case GnssNavigationMessage.Callback.STATUS_NOT_SUPPORTED -> "NOT_SUPPORTED";
      default -> "UNKNOWN_" + status;
    };
  }

  private static JSONObject payload(Object... values) {
    if (values.length % 2 != 0) {
      throw new IllegalArgumentException("payload requires key/value pairs");
    }
    JSONObject payload = new JSONObject();
    try {
      for (int index = 0; index < values.length; index += 2) {
        payload.put((String) values[index], values[index + 1]);
      }
    } catch (JSONException error) {
      throw new IllegalStateException("could not build payload", error);
    }
    return payload;
  }

  private static JSONObject errorPayload(Throwable error) {
    try {
      return LocationPayloads.error(error);
    } catch (JSONException nested) {
      return payload("error_class", error.getClass().getName());
    }
  }

  private static Object nullableLatency(long latency) {
    return latency < 0 ? JSONObject.NULL : latency;
  }

  private static Object nullableBoolean(Boolean value) {
    return value == null ? JSONObject.NULL : value;
  }

  private static Object nullableDouble(Double value) {
    return value == null ? JSONObject.NULL : value;
  }
}
