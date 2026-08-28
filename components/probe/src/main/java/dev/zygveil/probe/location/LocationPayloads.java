// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe.location;

import android.location.GnssClock;
import android.location.GnssMeasurement;
import android.location.GnssMeasurementsEvent;
import android.location.GnssNavigationMessage;
import android.location.GnssStatus;
import android.location.Location;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

final class LocationPayloads {
  private LocationPayloads() {}

  static JSONObject location(Location location, LocationOracle oracle) throws JSONException {
    JSONObject payload = new JSONObject();
    payload.put("provider", nullable(location.getProvider()));
    payload.put("time_ms", location.getTime());
    payload.put("elapsed_realtime_ns", location.getElapsedRealtimeNanos());
    payload.put("mock", location.isMock());
    payload.put("complete", location.isComplete());
    payload.put("has_accuracy", location.hasAccuracy());
    payload.put("has_altitude", location.hasAltitude());
    payload.put("has_vertical_accuracy", location.hasVerticalAccuracy());
    payload.put("has_msl_altitude", location.hasMslAltitude());
    payload.put("has_msl_altitude_accuracy", location.hasMslAltitudeAccuracy());
    payload.put("has_speed", location.hasSpeed());
    payload.put("has_speed_accuracy", location.hasSpeedAccuracy());
    payload.put("has_bearing", location.hasBearing());
    payload.put("has_bearing_accuracy", location.hasBearingAccuracy());
    oracle.addCoordinateMetrics(payload, location.getLatitude(), location.getLongitude(), false);
    oracle.addLocationBounds(payload, location);
    return payload;
  }

  static JSONObject locationBatch(List<Location> locations, LocationOracle oracle)
      throws JSONException {
    JSONArray values = new JSONArray();
    for (Location location : locations) {
      values.put(location(location, oracle));
    }
    return new JSONObject().put("batch_size", locations.size()).put("locations", values);
  }

  static JSONObject gnssStatus(GnssStatus status) throws JSONException {
    int used = 0;
    int ephemeris = 0;
    int almanac = 0;
    int carrierFrequency = 0;
    double cn0Total = 0.0;
    double cn0Minimum = Double.POSITIVE_INFINITY;
    double cn0Maximum = Double.NEGATIVE_INFINITY;
    JSONObject constellations = new JSONObject();
    for (int index = 0; index < status.getSatelliteCount(); index++) {
      if (status.usedInFix(index)) {
        used++;
      }
      if (status.hasEphemerisData(index)) {
        ephemeris++;
      }
      if (status.hasAlmanacData(index)) {
        almanac++;
      }
      if (status.hasCarrierFrequencyHz(index)) {
        carrierFrequency++;
      }
      double cn0 = status.getCn0DbHz(index);
      cn0Total += cn0;
      cn0Minimum = Math.min(cn0Minimum, cn0);
      cn0Maximum = Math.max(cn0Maximum, cn0);
      String constellation = Integer.toString(status.getConstellationType(index));
      constellations.put(constellation, constellations.optInt(constellation) + 1);
    }
    int count = status.getSatelliteCount();
    JSONObject payload = new JSONObject();
    payload.put("satellite_count", count);
    payload.put("used_in_fix_count", used);
    payload.put("ephemeris_count", ephemeris);
    payload.put("almanac_count", almanac);
    payload.put("carrier_frequency_count", carrierFrequency);
    payload.put("constellation_counts", constellations);
    payload.put("cn0_min_dbhz", count == 0 ? JSONObject.NULL : cn0Minimum);
    payload.put("cn0_max_dbhz", count == 0 ? JSONObject.NULL : cn0Maximum);
    payload.put("cn0_mean_dbhz", count == 0 ? JSONObject.NULL : cn0Total / count);
    return payload;
  }

  static JSONObject measurements(GnssMeasurementsEvent event) throws JSONException {
    Collection<GnssMeasurement> measurements = event.getMeasurements();
    int carrierFrequency = 0;
    int basebandCn0 = 0;
    JSONObject constellations = new JSONObject();
    for (GnssMeasurement measurement : measurements) {
      if (measurement.hasCarrierFrequencyHz()) {
        carrierFrequency++;
      }
      if (measurement.hasBasebandCn0DbHz()) {
        basebandCn0++;
      }
      String constellation = Integer.toString(measurement.getConstellationType());
      constellations.put(constellation, constellations.optInt(constellation) + 1);
    }
    GnssClock clock = event.getClock();
    return new JSONObject()
        .put("measurement_count", measurements.size())
        .put("constellation_counts", constellations)
        .put("carrier_frequency_present_count", carrierFrequency)
        .put("baseband_cn0_present_count", basebandCn0)
        .put("clock_has_bias", clock.hasBiasNanos())
        .put("clock_has_drift", clock.hasDriftNanosPerSecond())
        .put("clock_has_full_bias", clock.hasFullBiasNanos())
        .put("clock_has_leap_second", clock.hasLeapSecond());
  }

  static JSONObject navigation(GnssNavigationMessage event) throws JSONException {
    return new JSONObject()
        .put("message_type", event.getType())
        .put("status", event.getStatus())
        .put("message_id", event.getMessageId())
        .put("submessage_id", event.getSubmessageId())
        .put("data_length", event.getData().length)
        .put("data_redacted", true);
  }

  static JSONObject nmea(String message, long callbackTimestampMs, LocationOracle oracle)
      throws JSONException {
    JSONObject payload = new JSONObject();
    payload.put("callback_timestamp_ms", callbackTimestampMs);
    if (message == null) {
      return payload.put("valid", false).put("reason", "null_sentence");
    }
    String sentence = message.trim();
    int checksumMarker = sentence.lastIndexOf('*');
    boolean shapeValid = sentence.startsWith("$") && checksumMarker > 1;
    payload.put("valid_shape", shapeValid);
    if (!shapeValid) {
      return payload.put("valid", false).put("reason", "invalid_shape");
    }
    int expectedChecksum = parseHex(sentence.substring(checksumMarker + 1));
    int actualChecksum = 0;
    for (int index = 1; index < checksumMarker; index++) {
      actualChecksum ^= sentence.charAt(index);
    }
    payload.put("checksum_valid", expectedChecksum >= 0 && expectedChecksum == actualChecksum);
    String[] fields = sentence.substring(1, checksumMarker).split(",", -1);
    String identifier = fields.length == 0 ? "" : fields[0];
    String type =
        identifier.length() < 3 ? identifier : identifier.substring(identifier.length() - 3);
    payload.put("sentence_type", type);
    payload.put("field_count", fields.length);
    switch (type) {
      case "GGA" -> parseGga(fields, payload, oracle);
      case "RMC" -> parseRmc(fields, payload, oracle);
      case "GSA" -> parseGsa(fields, payload);
      case "GSV" -> parseGsv(fields, payload);
      default -> payload.put("supported_sentence", false);
    }
    payload.put("raw_sentence_redacted", true);
    payload.put("valid", true);
    return payload;
  }

  static JSONObject error(Throwable error) throws JSONException {
    return new JSONObject().put("error_class", error.getClass().getName());
  }

  private static void parseGga(String[] fields, JSONObject payload, LocationOracle oracle)
      throws JSONException {
    payload.put("supported_sentence", true);
    putString(payload, "utc", fields, 1);
    addPositionMetrics(payload, fields, 2, 3, 4, 5, oracle);
    putInteger(payload, "fix_quality", fields, 6);
    putInteger(payload, "satellites", fields, 7);
    addNumericBounds(payload, "hdop", fields, 8, true);
    ParsedDouble altitude = parsedDouble(fields, 9);
    ParsedDouble geoid = parsedDouble(fields, 11);
    addParsedState(payload, "altitude_msl", altitude);
    addParsedState(payload, "geoid_separation", geoid);
    oracle.addNmeaAltitudeBounds(payload, altitude.value(), geoid.value());
  }

  private static void parseRmc(String[] fields, JSONObject payload, LocationOracle oracle)
      throws JSONException {
    payload.put("supported_sentence", true);
    putString(payload, "utc", fields, 1);
    putString(payload, "navigation_status", fields, 2);
    addPositionMetrics(payload, fields, 3, 4, 5, 6, oracle);
    ParsedDouble speed = parsedDouble(fields, 7);
    ParsedDouble course = parsedDouble(fields, 8);
    addParsedState(payload, "speed", speed);
    addParsedState(payload, "course", course);
    oracle.addNmeaSpeedBounds(payload, speed.value(), course.value());
    putString(payload, "date", fields, 9);
  }

  private static void parseGsa(String[] fields, JSONObject payload) throws JSONException {
    payload.put("supported_sentence", true);
    putString(payload, "selection_mode", fields, 1);
    putInteger(payload, "fix_type", fields, 2);
    int satellites = 0;
    for (int index = 3; index <= 14 && index < fields.length; index++) {
      if (!fields[index].isEmpty()) {
        satellites++;
      }
    }
    payload.put("satellite_id_count", satellites);
    addNumericBounds(payload, "pdop", fields, 15, true);
    addNumericBounds(payload, "hdop", fields, 16, true);
    addNumericBounds(payload, "vdop", fields, 17, true);
  }

  private static void parseGsv(String[] fields, JSONObject payload) throws JSONException {
    payload.put("supported_sentence", true);
    putInteger(payload, "total_sentences", fields, 1);
    putInteger(payload, "sentence_number", fields, 2);
    putInteger(payload, "satellites", fields, 3);
    payload.put("satellite_block_count", Math.max(0, (fields.length - 4) / 4));
  }

  private static void addPositionMetrics(
      JSONObject payload,
      String[] fields,
      int latitudeIndex,
      int latitudeHemisphereIndex,
      int longitudeIndex,
      int longitudeHemisphereIndex,
      LocationOracle oracle)
      throws JSONException {
    boolean present =
        fieldPresent(fields, latitudeIndex)
            || fieldPresent(fields, latitudeHemisphereIndex)
            || fieldPresent(fields, longitudeIndex)
            || fieldPresent(fields, longitudeHemisphereIndex);
    payload.put("coordinate_fields_present", present);
    if (!present) {
      return;
    }
    Double latitude = parseNmeaCoordinate(fields, latitudeIndex, latitudeHemisphereIndex, true);
    Double longitude = parseNmeaCoordinate(fields, longitudeIndex, longitudeHemisphereIndex, false);
    boolean valid = latitude != null && longitude != null;
    payload.put("coordinate_parse_valid", valid);
    if (valid) {
      oracle.addCoordinateMetrics(payload, latitude, longitude, true);
    }
  }

  private static Double parseNmeaCoordinate(
      String[] fields, int valueIndex, int hemisphereIndex, boolean latitude) {
    if (!fieldPresent(fields, valueIndex) || !fieldPresent(fields, hemisphereIndex)) {
      return null;
    }
    String hemisphere = fields[hemisphereIndex].toUpperCase(Locale.ROOT);
    boolean hemisphereValid =
        latitude
            ? "N".equals(hemisphere) || "S".equals(hemisphere)
            : "E".equals(hemisphere) || "W".equals(hemisphere);
    if (!hemisphereValid) {
      return null;
    }
    try {
      double packed = Double.parseDouble(fields[valueIndex]);
      if (!Double.isFinite(packed) || packed < 0.0) {
        return null;
      }
      double degrees = Math.floor(packed / 100.0);
      double minutes = packed - degrees * 100.0;
      double maximumDegrees = latitude ? 90.0 : 180.0;
      if (minutes < 0.0
          || minutes >= 60.0
          || degrees > maximumDegrees
          || (degrees == maximumDegrees && minutes != 0.0)) {
        return null;
      }
      double coordinate = degrees + minutes / 60.0;
      if ("S".equals(hemisphere) || "W".equals(hemisphere)) {
        coordinate = -coordinate;
      }
      return coordinate;
    } catch (NumberFormatException ignored) {
      return null;
    }
  }

  private static void addNumericBounds(
      JSONObject payload, String name, String[] fields, int index, boolean nonNegative)
      throws JSONException {
    ParsedDouble parsed = parsedDouble(fields, index);
    addParsedState(payload, name, parsed);
    if (parsed.value() != null && nonNegative) {
      payload.put(name + "_non_negative", parsed.value() >= 0.0);
    }
  }

  private static void addParsedState(JSONObject payload, String name, ParsedDouble parsed)
      throws JSONException {
    payload.put(name + "_present", parsed.present());
    payload.put(name + "_parse_valid", !parsed.present() || parsed.value() != null);
    payload.put(name + "_finite", parsed.value() == null || Double.isFinite(parsed.value()));
  }

  private static ParsedDouble parsedDouble(String[] fields, int index) {
    if (!fieldPresent(fields, index)) {
      return new ParsedDouble(false, null);
    }
    try {
      double parsed = Double.parseDouble(fields[index]);
      return new ParsedDouble(true, Double.isFinite(parsed) ? parsed : null);
    } catch (NumberFormatException ignored) {
      return new ParsedDouble(true, null);
    }
  }

  private static boolean fieldPresent(String[] fields, int index) {
    return index < fields.length && !fields[index].isEmpty();
  }

  private static void putInteger(JSONObject payload, String key, String[] fields, int index)
      throws JSONException {
    if (!fieldPresent(fields, index)) {
      return;
    }
    try {
      payload.put(key, Integer.parseInt(fields[index]));
    } catch (NumberFormatException ignored) {
      payload.put(key + "_parse_error", true);
    }
  }

  private static void putString(JSONObject payload, String key, String[] fields, int index)
      throws JSONException {
    if (fieldPresent(fields, index)) {
      payload.put(key, fields[index]);
    }
  }

  private static int parseHex(String value) {
    if (value.length() < 2) {
      return -1;
    }
    try {
      return Integer.parseInt(value.substring(0, 2), 16);
    } catch (NumberFormatException ignored) {
      return -1;
    }
  }

  private static Object nullable(String value) {
    return value == null ? JSONObject.NULL : value;
  }

  private record ParsedDouble(boolean present, Double value) {}
}
