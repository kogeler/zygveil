// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe.location;

import android.content.Context;
import android.os.Process;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.json.JSONException;
import org.json.JSONObject;

final class LocationOracle {
  static final String FILE_NAME = "location-oracle.properties";
  private static final int MAXIMUM_BYTES = 2048;
  private static final long MAXIMUM_CONFIG_GENERATION = (1L << 62) - 1;
  private static final Pattern DECIMAL = Pattern.compile("-?[0-9]+(?:\\.[0-9]+)?");
  private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");
  private static final Set<String> KEYS =
      Set.of(
          "schema_version",
          "config_generation",
          "config_sha256",
          "center_latitude_deg",
          "center_longitude_deg",
          "altitude_ellipsoid_m",
          "altitude_msl_m",
          "horizontal_jitter_radius_m",
          "speed_max_mps",
          "bearing_min_speed_mps");

  private final boolean ready;
  private final boolean unlinked;
  private final String status;
  private final long generation;
  private final String configDigest;
  private final double latitude;
  private final double longitude;
  private final double altitudeEllipsoid;
  private final double altitudeMsl;
  private final double jitterRadius;
  private final double speedMaximum;
  private final double bearingMinimumSpeed;
  private Double firstLatitude;
  private Double firstLongitude;
  private Double latestLocationLatitude;
  private Double latestLocationLongitude;
  private Double latestNmeaLatitude;
  private Double latestNmeaLongitude;
  private int locationSampleCount;
  private boolean locationModelFailure;

  private LocationOracle(
      boolean ready,
      boolean unlinked,
      String status,
      long generation,
      String configDigest,
      double latitude,
      double longitude,
      double altitudeEllipsoid,
      double altitudeMsl,
      double jitterRadius,
      double speedMaximum,
      double bearingMinimumSpeed) {
    this.ready = ready;
    this.unlinked = unlinked;
    this.status = status;
    this.generation = generation;
    this.configDigest = configDigest;
    this.latitude = latitude;
    this.longitude = longitude;
    this.altitudeEllipsoid = altitudeEllipsoid;
    this.altitudeMsl = altitudeMsl;
    this.jitterRadius = jitterRadius;
    this.speedMaximum = speedMaximum;
    this.bearingMinimumSpeed = bearingMinimumSpeed;
  }

  static LocationOracle load(Context context, boolean required) {
    File file = new File(context.getNoBackupFilesDir(), FILE_NAME);
    if (!required) {
      return unavailable("not_requested", discard(file));
    }
    if (absentNoFollow(file)) {
      return unavailable("missing", true);
    }
    FileDescriptor descriptor = null;
    boolean unlinked = false;
    try {
      descriptor =
          Os.open(
              file.getAbsolutePath(),
              OsConstants.O_RDONLY | OsConstants.O_CLOEXEC | OsConstants.O_NOFOLLOW,
              0);
      StructStat identity = Os.fstat(descriptor);
      if ((identity.st_mode & OsConstants.S_IFMT) != OsConstants.S_IFREG
          || (identity.st_mode & 0777) != 0600
          || identity.st_uid != Process.myUid()
          || identity.st_nlink != 1
          || identity.st_size <= 0
          || identity.st_size > MAXIMUM_BYTES) {
        throw new IOException("oracle_identity_invalid");
      }
      Files.delete(file.toPath());
      StructStat unlinkedIdentity = Os.fstat(descriptor);
      if (unlinkedIdentity.st_dev != identity.st_dev
          || unlinkedIdentity.st_ino != identity.st_ino
          || unlinkedIdentity.st_nlink != 0) {
        throw new IOException("oracle_unlink_invalid");
      }
      unlinked = true;
      byte[] data;
      try (FileInputStream input = new FileInputStream(descriptor)) {
        descriptor = null;
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[512];
        int count;
        while ((count = input.read(buffer)) >= 0) {
          if (count == 0) {
            continue;
          }
          if (output.size() + count > MAXIMUM_BYTES) {
            throw new IOException("oracle_oversized");
          }
          output.write(buffer, 0, count);
        }
        data = output.toByteArray();
      }
      return parse(new String(data, StandardCharsets.US_ASCII), true);
    } catch (ErrnoException | IOException | RuntimeException error) {
      return unavailable("invalid", unlinked);
    } finally {
      if (descriptor != null) {
        try {
          Os.close(descriptor);
        } catch (ErrnoException ignored) {
          // The fixed descriptor is already unusable; the session will fail closed.
        }
      }
      if (!unlinked) {
        discard(file);
      }
    }
  }

  private static LocationOracle parse(String text, boolean unlinked) throws IOException {
    Map<String, String> values = new HashMap<>();
    for (String line : text.split("\\n", -1)) {
      String stripped = line.trim();
      if (stripped.isEmpty()) {
        continue;
      }
      int separator = stripped.indexOf('=');
      if (separator <= 0 || separator + 1 >= stripped.length()) {
        throw new IOException("oracle_shape_invalid");
      }
      String key = stripped.substring(0, separator).trim();
      String value = stripped.substring(separator + 1).trim();
      if (!KEYS.contains(key) || value.isEmpty() || values.putIfAbsent(key, value) != null) {
        throw new IOException("oracle_key_invalid");
      }
    }
    if (values.size() != KEYS.size() || !"1".equals(values.get("schema_version"))) {
      throw new IOException("oracle_schema_invalid");
    }
    long generation = parsePositiveLong(values.get("config_generation"));
    String digest = values.get("config_sha256");
    if (!SHA256.matcher(digest).matches()) {
      throw new IOException("oracle_digest_invalid");
    }
    double latitude = parseDecimal(values.get("center_latitude_deg"), -90.0, 90.0);
    double longitude = parseDecimal(values.get("center_longitude_deg"), -180.0, 180.0);
    double ellipsoid = parseDecimal(values.get("altitude_ellipsoid_m"), -12000.0, 100000.0);
    double msl = parseDecimal(values.get("altitude_msl_m"), -12000.0, 100000.0);
    double radius = parseDecimal(values.get("horizontal_jitter_radius_m"), 0.0, 10000.0);
    double speed = parseDecimal(values.get("speed_max_mps"), 0.0, 1000.0);
    double bearingSpeed = parseDecimal(values.get("bearing_min_speed_mps"), 0.0, speed);
    return new LocationOracle(
        true,
        unlinked,
        "loaded",
        generation,
        digest,
        latitude,
        longitude,
        ellipsoid,
        msl,
        radius,
        speed,
        bearingSpeed);
  }

  private static long parsePositiveLong(String value) throws IOException {
    try {
      long parsed = Long.parseLong(value);
      if (parsed <= 0 || parsed > MAXIMUM_CONFIG_GENERATION) {
        throw new IOException("oracle_generation_invalid");
      }
      return parsed;
    } catch (NumberFormatException error) {
      throw new IOException("oracle_generation_invalid");
    }
  }

  private static double parseDecimal(String value, double minimum, double maximum)
      throws IOException {
    if (!DECIMAL.matcher(value).matches()) {
      throw new IOException("oracle_decimal_invalid");
    }
    try {
      double parsed = Double.parseDouble(value);
      if (!Double.isFinite(parsed) || parsed < minimum || parsed > maximum) {
        throw new IOException("oracle_range_invalid");
      }
      return parsed;
    } catch (NumberFormatException error) {
      throw new IOException("oracle_decimal_invalid");
    }
  }

  private static LocationOracle unavailable(String status, boolean unlinked) {
    return new LocationOracle(
        false, unlinked, status, 0, "absent", 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0);
  }

  private static boolean discard(File file) {
    try {
      Files.deleteIfExists(file.toPath());
    } catch (IOException | SecurityException ignored) {
      // Missing or invalid stale input is represented by the returned oracle state.
    }
    return absentNoFollow(file);
  }

  private static boolean absentNoFollow(File file) {
    try {
      Os.lstat(file.getAbsolutePath());
      return false;
    } catch (ErrnoException error) {
      return error.errno == OsConstants.ENOENT;
    }
  }

  boolean ready() {
    return ready;
  }

  boolean unlinked() {
    return unlinked;
  }

  String status() {
    return status;
  }

  long generation() {
    return generation;
  }

  String configDigest() {
    return configDigest;
  }

  synchronized void addCoordinateMetrics(
      JSONObject payload, double sampleLatitude, double sampleLongitude, boolean nmea)
      throws JSONException {
    boolean finite = Double.isFinite(sampleLatitude) && Double.isFinite(sampleLongitude);
    boolean latitudeInRange = finite && sampleLatitude >= -90.0 && sampleLatitude <= 90.0;
    boolean longitudeInRange = finite && sampleLongitude >= -180.0 && sampleLongitude <= 180.0;
    payload.put("coordinates_finite", finite);
    payload.put("latitude_in_range", latitudeInRange);
    payload.put("longitude_in_range", longitudeInRange);
    if (!nmea) {
      locationSampleCount++;
      locationModelFailure |= !latitudeInRange || !longitudeInRange;
    }
    if (!latitudeInRange || !longitudeInRange) {
      return;
    }
    if (firstLatitude == null || firstLongitude == null) {
      firstLatitude = sampleLatitude;
      firstLongitude = sampleLongitude;
    }
    payload.put(
        "displacement_from_first_sample_m",
        distance(sampleLatitude, sampleLongitude, firstLatitude, firstLongitude));
    if (ready) {
      double centerDistance = distance(sampleLatitude, sampleLongitude, latitude, longitude);
      boolean withinExpectedRadius = centerDistance <= jitterRadius + 1.5;
      payload.put("expected_center_distance_m", centerDistance);
      payload.put("within_expected_radius", withinExpectedRadius);
      payload.put("outside_expected_center_exclusion", centerDistance > jitterRadius + 100.0);
      if (!nmea) {
        locationModelFailure |= !withinExpectedRadius;
      }
    }
    Double otherLatitude = nmea ? latestLocationLatitude : latestNmeaLatitude;
    Double otherLongitude = nmea ? latestLocationLongitude : latestNmeaLongitude;
    if (otherLatitude != null && otherLongitude != null) {
      double crossChannelDistance =
          distance(sampleLatitude, sampleLongitude, otherLatitude, otherLongitude);
      payload.put("cross_channel_distance_m", crossChannelDistance);
      if (ready) {
        payload.put("cross_channel_consistent", crossChannelDistance <= 2.0 * jitterRadius + 3.0);
      }
    }
    if (nmea) {
      latestNmeaLatitude = sampleLatitude;
      latestNmeaLongitude = sampleLongitude;
    } else {
      latestLocationLatitude = sampleLatitude;
      latestLocationLongitude = sampleLongitude;
    }
  }

  synchronized void addLocationBounds(JSONObject payload, android.location.Location location)
      throws JSONException {
    boolean numericFinite =
        (!location.hasAccuracy() || Float.isFinite(location.getAccuracy()))
            && (!location.hasAltitude() || Double.isFinite(location.getAltitude()))
            && (!location.hasVerticalAccuracy()
                || Float.isFinite(location.getVerticalAccuracyMeters()))
            && (!location.hasMslAltitude() || Double.isFinite(location.getMslAltitudeMeters()))
            && (!location.hasMslAltitudeAccuracy()
                || Float.isFinite(location.getMslAltitudeAccuracyMeters()))
            && (!location.hasSpeed() || Float.isFinite(location.getSpeed()))
            && (!location.hasSpeedAccuracy()
                || Float.isFinite(location.getSpeedAccuracyMetersPerSecond()))
            && (!location.hasBearing() || Float.isFinite(location.getBearing()))
            && (!location.hasBearingAccuracy()
                || Float.isFinite(location.getBearingAccuracyDegrees()));
    payload.put("numeric_fields_finite", numericFinite);
    payload.put("accuracy_non_negative", !location.hasAccuracy() || location.getAccuracy() >= 0.0f);
    payload.put(
        "vertical_accuracy_non_negative",
        !location.hasVerticalAccuracy() || location.getVerticalAccuracyMeters() >= 0.0f);
    payload.put("speed_non_negative", !location.hasSpeed() || location.getSpeed() >= 0.0f);
    payload.put(
        "bearing_in_range",
        !location.hasBearing()
            || (location.getBearing() >= 0.0f && location.getBearing() < 360.0f));
    payload.put(
        "bearing_presence_consistent", location.hasBearing() == location.hasBearingAccuracy());
    boolean requiredFieldsPresent =
        location.isComplete()
            && location.hasAccuracy()
            && location.hasAltitude()
            && location.hasVerticalAccuracy()
            && location.hasMslAltitude()
            && location.hasMslAltitudeAccuracy()
            && location.hasSpeed()
            && location.hasSpeedAccuracy();
    boolean basicBoundsValid =
        numericFinite
            && (!location.hasAccuracy() || location.getAccuracy() >= 0.0f)
            && (!location.hasVerticalAccuracy() || location.getVerticalAccuracyMeters() >= 0.0f)
            && (!location.hasSpeed() || location.getSpeed() >= 0.0f)
            && (!location.hasBearing()
                || (location.getBearing() >= 0.0f && location.getBearing() < 360.0f))
            && location.hasBearing() == location.hasBearingAccuracy();
    locationModelFailure |= !requiredFieldsPresent || !basicBoundsValid;
    if (ready) {
      boolean speedWithinExpectedBound =
          !location.hasSpeed() || location.getSpeed() <= speedMaximum + 1e-6;
      boolean stationaryBearingAbsent =
          !location.hasSpeed()
              || location.getSpeed() >= bearingMinimumSpeed
              || (!location.hasBearing() && !location.hasBearingAccuracy());
      boolean altitudePairConsistent =
          !location.hasAltitude()
              || !location.hasMslAltitude()
              || Math.abs(
                      (location.getAltitude() - location.getMslAltitudeMeters())
                          - (altitudeEllipsoid - altitudeMsl))
                  <= 1e-6;
      payload.put("speed_within_expected_bound", speedWithinExpectedBound);
      payload.put("stationary_bearing_absent", stationaryBearingAbsent);
      payload.put("altitude_pair_consistent", altitudePairConsistent);
      locationModelFailure |=
          !speedWithinExpectedBound || !stationaryBearingAbsent || !altitudePairConsistent;
    }
  }

  synchronized boolean locationSpatialFailure() {
    return ready && (locationSampleCount == 0 || locationModelFailure);
  }

  void addNmeaAltitudeBounds(JSONObject payload, Double mslAltitude, Double geoidSeparation)
      throws JSONException {
    payload.put(
        "altitude_fields_finite",
        (mslAltitude == null || Double.isFinite(mslAltitude))
            && (geoidSeparation == null || Double.isFinite(geoidSeparation)));
    if (ready) {
      payload.put(
          "altitude_msl_consistent",
          mslAltitude == null || Math.abs(mslAltitude - altitudeMsl) <= 5.0);
      payload.put(
          "geoid_separation_consistent",
          geoidSeparation == null
              || Math.abs(geoidSeparation - (altitudeEllipsoid - altitudeMsl)) <= 0.11);
    }
  }

  void addNmeaSpeedBounds(JSONObject payload, Double speedKnots, Double courseDegrees)
      throws JSONException {
    payload.put("speed_finite", speedKnots == null || Double.isFinite(speedKnots));
    payload.put("course_finite", courseDegrees == null || Double.isFinite(courseDegrees));
    payload.put("speed_non_negative", speedKnots == null || speedKnots >= 0.0);
    payload.put(
        "course_in_range",
        courseDegrees == null || (courseDegrees >= 0.0 && courseDegrees < 360.0));
    if (ready) {
      payload.put(
          "speed_within_expected_bound",
          speedKnots == null || speedKnots * 0.5144444444444445 <= speedMaximum + 1e-6);
      payload.put(
          "stationary_course_absent",
          speedKnots == null
              || speedKnots * 0.5144444444444445 >= bearingMinimumSpeed
              || courseDegrees == null);
    }
  }

  private static double distance(
      double sampleLatitude,
      double sampleLongitude,
      double referenceLatitude,
      double referenceLongitude) {
    double latitude1 = Math.toRadians(referenceLatitude);
    double latitude2 = Math.toRadians(sampleLatitude);
    double deltaLatitude = latitude2 - latitude1;
    double deltaLongitude = Math.toRadians(sampleLongitude - referenceLongitude);
    double value =
        Math.sin(deltaLatitude / 2.0) * Math.sin(deltaLatitude / 2.0)
            + Math.cos(latitude1)
                * Math.cos(latitude2)
                * Math.sin(deltaLongitude / 2.0)
                * Math.sin(deltaLongitude / 2.0);
    return 2.0 * 6371008.8 * Math.asin(Math.min(1.0, Math.sqrt(value)));
  }
}
