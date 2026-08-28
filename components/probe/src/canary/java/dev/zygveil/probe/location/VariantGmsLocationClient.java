// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe.location;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.location.Location;
import com.google.android.gms.location.CurrentLocationRequest;
import com.google.android.gms.location.FusedLocationProviderClient;
import com.google.android.gms.location.LastLocationRequest;
import com.google.android.gms.location.LocationAvailability;
import com.google.android.gms.location.LocationCallback;
import com.google.android.gms.location.LocationRequest;
import com.google.android.gms.location.LocationResult;
import com.google.android.gms.location.LocationServices;
import com.google.android.gms.location.Priority;
import com.google.android.gms.tasks.CancellationTokenSource;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.Tasks;
import dev.zygveil.probe.ProbePendingIntentReceiver;
import dev.zygveil.probe.SecondaryProbePendingIntentReceiver;
import dev.zygveil.probe.detector.RunConfig;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONException;
import org.json.JSONObject;

public final class VariantGmsLocationClient implements GmsLocationClient {
  private static final String ACTION_GMS_LOCATION = "dev.zygveil.probe.action.GMS_LOCATION_UPDATE";
  private static final String EXTRA_SESSION_ID = "gms_location_session_id";
  private static final long TASK_TIMEOUT_SECONDS = 3;
  private static final ConcurrentHashMap<String, VariantGmsLocationClient> ACTIVE =
      new ConcurrentHashMap<>();

  private final Context context;
  private final RunConfig config;
  private final Executor callbackExecutor;
  private FusedLocationProviderClient client;
  private final AtomicBoolean surfaceFailed = new AtomicBoolean();
  private final CancellationTokenSource priorityCurrentToken = new CancellationTokenSource();
  private final CancellationTokenSource requestCurrentToken = new CancellationTokenSource();

  private Observer observer;
  private LocationCallback locationCallback;
  private com.google.android.gms.location.LocationListener locationListener;
  private PendingIntent pendingIntent;
  private volatile String state = "created";
  private volatile boolean lastDefaultCompleted;
  private volatile boolean lastRequestCompleted;
  private volatile boolean currentPriorityCompleted;
  private volatile boolean currentRequestCompleted;
  private volatile boolean availabilityCompleted;
  private volatile boolean callbackRegistered;
  private volatile boolean listenerRegistered;
  private volatile boolean pendingIntentRegistered;
  private volatile boolean flushCompleted;
  private volatile boolean cleanupCompleted;

  VariantGmsLocationClient(Context context, RunConfig config, Executor callbackExecutor) {
    this.context = context;
    this.config = config;
    this.callbackExecutor = callbackExecutor;
  }

  public static boolean handlePendingIntent(Context context, Intent intent) {
    if (!ACTION_GMS_LOCATION.equals(intent.getAction())) {
      return false;
    }
    String sessionId = intent.getStringExtra(EXTRA_SESSION_ID);
    VariantGmsLocationClient active = sessionId == null ? null : ACTIVE.get(sessionId);
    if (active == null || !active.context.getPackageName().equals(context.getPackageName())) {
      return true;
    }
    active.observePendingIntent(intent);
    return true;
  }

  @Override
  public boolean required() {
    return true;
  }

  @Override
  public String state() {
    return state;
  }

  @Override
  public boolean requiredSurfaceComplete() {
    return "complete".equals(state)
        && lastDefaultCompleted
        && lastRequestCompleted
        && currentPriorityCompleted
        && currentRequestCompleted
        && availabilityCompleted
        && callbackRegistered
        && listenerRegistered
        && pendingIntentRegistered
        && flushCompleted
        && cleanupCompleted
        && !surfaceFailed.get();
  }

  @Override
  @SuppressLint("MissingPermission")
  public void start(Observer observer) {
    this.observer = observer;
    state = "started";
    if (!hasLocationPermissions()) {
      markFailure();
      observer.onObservation(
          "gms_location_update", "gms_fused", "ERROR", payload("reason", "permission_denied"));
      return;
    }
    try {
      client = LocationServices.getFusedLocationProviderClient(context);
      observeLocationTask(
          client.getLastLocation(),
          "gms_last_known",
          "gms_fused.last.default",
          () -> lastDefaultCompleted = true);
      observeLocationTask(
          client.getLastLocation(new LastLocationRequest.Builder().build()),
          "gms_last_known",
          "gms_fused.last.request",
          () -> lastRequestCompleted = true);
      observeLocationTask(
          client.getCurrentLocation(
              Priority.PRIORITY_HIGH_ACCURACY, priorityCurrentToken.getToken()),
          "gms_current",
          "gms_fused.current.priority",
          () -> currentPriorityCompleted = true);
      observeLocationTask(
          client.getCurrentLocation(
              new CurrentLocationRequest.Builder()
                  .setPriority(Priority.PRIORITY_HIGH_ACCURACY)
                  .setMaxUpdateAgeMillis(0)
                  .build(),
              requestCurrentToken.getToken()),
          "gms_current",
          "gms_fused.current.request",
          () -> currentRequestCompleted = true);
      observeAvailability();
      registerUpdates();
    } catch (RuntimeException error) {
      markFailure();
      observer.onObservation("gms_location_update", "gms_fused", "ERROR", errorPayload(error));
    }
  }

  @Override
  public void flush() {
    if (observer == null || client == null || "created".equals(state)) {
      return;
    }
    try {
      Tasks.await(client.flushLocations(), TASK_TIMEOUT_SECONDS, TimeUnit.SECONDS);
      flushCompleted = true;
      observer.onObservation(
          "gms_location_batch", "gms_fused.flush", "SUCCESS", payload("flush_completed", true));
    } catch (Exception error) {
      preserveInterrupt(error);
      markFailure();
      observer.onObservation("gms_location_batch", "gms_fused.flush", "ERROR", errorPayload(error));
    }
  }

  @Override
  public void close() {
    priorityCurrentToken.cancel();
    requestCurrentToken.cancel();
    boolean cleanupOk = true;
    cleanupOk &=
        remove(
            "gms_callback",
            client == null || locationCallback == null
                ? null
                : client.removeLocationUpdates(locationCallback));
    cleanupOk &=
        remove(
            "gms_listener",
            client == null || locationListener == null
                ? null
                : client.removeLocationUpdates(locationListener));
    cleanupOk &=
        remove(
            "gms_pending_intent",
            client == null || pendingIntent == null
                ? null
                : client.removeLocationUpdates(pendingIntent));
    ACTIVE.remove(config.runId, this);
    if (pendingIntent != null) {
      pendingIntent.cancel();
    }
    cleanupCompleted = cleanupOk;
    if (cleanupOk && !surfaceFailed.get()) {
      state = "complete";
    } else {
      state = "failed";
    }
  }

  private void observeLocationTask(
      Task<Location> task, String type, String source, Runnable completion) {
    observer.onObservation(type, source, "REGISTERED", payload("request_accepted", true));
    task.addOnSuccessListener(
            callbackExecutor,
            location -> {
              completion.run();
              if (location == null) {
                observer.onObservation(
                    type, source, "UNAVAILABLE", payload("reason", "null_location"));
              } else {
                observer.onLocation(type, source, location);
              }
            })
        .addOnFailureListener(
            callbackExecutor,
            error -> {
              completion.run();
              markFailure();
              observer.onObservation(type, source, "ERROR", errorPayload(error));
            })
        .addOnCanceledListener(
            callbackExecutor,
            () -> {
              completion.run();
              observer.onObservation(type, source, "UNAVAILABLE", payload("reason", "cancelled"));
            });
  }

  @SuppressLint("MissingPermission")
  private void observeAvailability() {
    String source = "gms_fused.availability.task";
    observer.onObservation(
        "gms_location_availability", source, "REGISTERED", payload("request_accepted", true));
    client
        .getLocationAvailability()
        .addOnSuccessListener(
            callbackExecutor,
            availability -> {
              availabilityCompleted = true;
              if (availability == null) {
                observer.onObservation(
                    "gms_location_availability",
                    source,
                    "UNAVAILABLE",
                    payload("reason", "null_availability"));
              } else {
                observer.onObservation(
                    "gms_location_availability",
                    source,
                    "SUCCESS",
                    availabilityPayload(availability));
              }
            })
        .addOnFailureListener(
            callbackExecutor,
            error -> {
              availabilityCompleted = true;
              markFailure();
              observer.onObservation(
                  "gms_location_availability", source, "ERROR", errorPayload(error));
            })
        .addOnCanceledListener(
            callbackExecutor,
            () -> {
              availabilityCompleted = true;
              observer.onObservation(
                  "gms_location_availability",
                  source,
                  "UNAVAILABLE",
                  payload("reason", "cancelled"));
            });
  }

  @SuppressLint("MissingPermission")
  private void registerUpdates() {
    long maximumDelay = Math.min(5_000, Math.max(1_000, config.observationWindowMs / 2));
    LocationRequest request =
        new LocationRequest.Builder(Priority.PRIORITY_HIGH_ACCURACY, 1_000)
            .setMinUpdateIntervalMillis(500)
            .setMaxUpdateDelayMillis(maximumDelay)
            .build();
    locationCallback =
        new LocationCallback() {
          @Override
          public void onLocationResult(LocationResult result) {
            if (result == null) {
              observer.onObservation(
                  "gms_location_batch",
                  "gms_fused.update.callback",
                  "UNAVAILABLE",
                  payload("reason", "null_result"));
              return;
            }
            observer.onLocations(
                "gms_location_batch", "gms_fused.update.callback", result.getLocations());
          }

          @Override
          public void onLocationAvailability(LocationAvailability availability) {
            observer.onObservation(
                "gms_location_availability",
                "gms_fused.update.callback",
                "SUCCESS",
                availabilityPayload(availability));
          }
        };
    locationListener =
        location ->
            observer.onLocation("gms_location_update", "gms_fused.update.listener", location);
    pendingIntent = buildPendingIntent();
    ACTIVE.put(config.runId, this);
    observeRegistration(
        client.requestLocationUpdates(request, callbackExecutor, locationCallback),
        "gms_location_batch",
        "gms_fused.update.callback",
        () -> callbackRegistered = true);
    observeRegistration(
        client.requestLocationUpdates(request, callbackExecutor, locationListener),
        "gms_location_update",
        "gms_fused.update.listener",
        () -> listenerRegistered = true);
    observeRegistration(
        client.requestLocationUpdates(request, pendingIntent),
        "gms_pending_intent",
        "gms_fused.update.pending_intent",
        () -> pendingIntentRegistered = true);
  }

  private void observeRegistration(Task<Void> task, String type, String source, Runnable accepted) {
    task.addOnSuccessListener(
            callbackExecutor,
            ignored -> {
              accepted.run();
              observer.onObservation(
                  type, source, "REGISTERED", payload("registration_accepted", true));
            })
        .addOnFailureListener(
            callbackExecutor,
            error -> {
              markFailure();
              observer.onObservation(type, source, "ERROR", errorPayload(error));
            })
        .addOnCanceledListener(
            callbackExecutor,
            () -> {
              markFailure();
              observer.onObservation(
                  type, source, "UNAVAILABLE", payload("reason", "registration_cancelled"));
            });
  }

  private PendingIntent buildPendingIntent() {
    Class<?> receiver =
        config.process.endsWith(":secondary")
            ? SecondaryProbePendingIntentReceiver.class
            : ProbePendingIntentReceiver.class;
    Intent intent =
        new Intent(ACTION_GMS_LOCATION)
            .setComponent(new ComponentName(context, receiver))
            .putExtra(EXTRA_SESSION_ID, config.runId);
    return PendingIntent.getBroadcast(
        context,
        config.process.endsWith(":secondary") ? 2002 : 2001,
        intent,
        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE);
  }

  private boolean hasLocationPermissions() {
    return context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION)
            == PackageManager.PERMISSION_GRANTED
        && context.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION)
            == PackageManager.PERMISSION_GRANTED;
  }

  private void observePendingIntent(Intent intent) {
    boolean observed = false;
    if (LocationResult.hasResult(intent)) {
      LocationResult result = LocationResult.extractResult(intent);
      List<Location> locations = result == null ? List.of() : result.getLocations();
      if (locations.isEmpty()) {
        observer.onObservation(
            "gms_pending_intent",
            "gms_fused.update.pending_intent",
            "UNAVAILABLE",
            payload("reason", "empty_result"));
      } else {
        observer.onLocations("gms_pending_intent", "gms_fused.update.pending_intent", locations);
      }
      observed = true;
    }
    if (LocationAvailability.hasLocationAvailability(intent)) {
      LocationAvailability availability = LocationAvailability.extractLocationAvailability(intent);
      observer.onObservation(
          "gms_location_availability",
          "gms_fused.update.pending_intent",
          availability == null ? "UNAVAILABLE" : "SUCCESS",
          availability == null
              ? payload("reason", "null_availability")
              : availabilityPayload(availability));
      observed = true;
    }
    if (!observed) {
      observer.onObservation(
          "gms_pending_intent",
          "gms_fused.update.pending_intent",
          "UNAVAILABLE",
          payload("reason", "no_location_or_availability"));
    }
  }

  private boolean remove(String name, Task<Void> task) {
    if (task == null) {
      return true;
    }
    try {
      Tasks.await(task, TASK_TIMEOUT_SECONDS, TimeUnit.SECONDS);
      return true;
    } catch (Exception error) {
      preserveInterrupt(error);
      surfaceFailed.set(true);
      observer.onCleanupFailure(name + ":" + error.getClass().getSimpleName());
      return false;
    }
  }

  private void markFailure() {
    surfaceFailed.set(true);
    state = "failed";
  }

  private static JSONObject availabilityPayload(LocationAvailability availability) {
    return payload("location_available", availability.isLocationAvailable());
  }

  private static JSONObject errorPayload(Throwable error) {
    return payload("error_class", error.getClass().getName());
  }

  private static JSONObject payload(Object... values) {
    JSONObject payload = new JSONObject();
    try {
      for (int index = 0; index < values.length; index += 2) {
        payload.put((String) values[index], values[index + 1]);
      }
    } catch (JSONException error) {
      throw new IllegalStateException("could not build GMS payload", error);
    }
    return payload;
  }

  private static void preserveInterrupt(Exception error) {
    if (error instanceof InterruptedException) {
      Thread.currentThread().interrupt();
    }
  }
}
