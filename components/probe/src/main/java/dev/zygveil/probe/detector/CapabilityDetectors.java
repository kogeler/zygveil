// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe.detector;

import android.net.NetworkCapabilities;
import android.os.Parcel;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

final class CapabilityDetectors {
  private static final int[] TRANSPORT_TYPES = {
    NetworkCapabilities.TRANSPORT_CELLULAR,
    NetworkCapabilities.TRANSPORT_WIFI,
    NetworkCapabilities.TRANSPORT_BLUETOOTH,
    NetworkCapabilities.TRANSPORT_ETHERNET,
    NetworkCapabilities.TRANSPORT_VPN,
    NetworkCapabilities.TRANSPORT_WIFI_AWARE,
    NetworkCapabilities.TRANSPORT_LOWPAN,
    NetworkCapabilities.TRANSPORT_USB,
    NetworkCapabilities.TRANSPORT_THREAD,
    NetworkCapabilities.TRANSPORT_SATELLITE
  };

  private CapabilityDetectors() {}

  static void recordSingle(
      ResultStore store,
      RunConfig config,
      String prefix,
      NetworkCapabilities capabilities,
      int networkCount)
      throws IOException, JSONException {
    if (capabilities == null) {
      JSONObject raw = new JSONObject().put("network_count", networkCount);
      for (String suffix :
          List.of(
              "transport.vpn",
              "capability.not_vpn",
              "capabilities.not_vpn",
              "transport_info.vpn_token",
              "caps_string.vpn_token",
              "getter.down_kbps",
              "getter.up_kbps",
              "getter.signal_strength",
              "getter.owner_uid",
              "getter.enterprise_ids",
              "getter.network_specifier",
              "getter.subscription_ids",
              "copy.consistency",
              "parcel.consistency")) {
        store.detector(
            config,
            prefix + "." + suffix,
            isMandatorySuffix(suffix),
            ProbeStatus.INCONCLUSIVE,
            raw,
            null,
            0,
            "complete");
      }
      return;
    }
    recordTransport(store, config, prefix, capabilities);
    recordNotVpnCapability(store, config, prefix, capabilities);
    recordCapabilitiesArray(store, config, prefix, capabilities);
    recordTransportInfo(store, config, prefix, capabilities);
    recordString(store, config, prefix, capabilities);
    recordIntegerGetter(
        store,
        config,
        prefix + ".getter.down_kbps",
        "value",
        capabilities::getLinkDownstreamBandwidthKbps);
    recordIntegerGetter(
        store,
        config,
        prefix + ".getter.up_kbps",
        "value",
        capabilities::getLinkUpstreamBandwidthKbps);
    recordIntegerGetter(
        store,
        config,
        prefix + ".getter.signal_strength",
        "value",
        capabilities::getSignalStrength);
    recordIntegerGetter(
        store, config, prefix + ".getter.owner_uid", "value", capabilities::getOwnerUid);
    recordEnterpriseIds(store, config, prefix, capabilities);
    recordNetworkSpecifier(store, config, prefix, capabilities);
    recordSubscriptionIds(store, config, prefix, capabilities);
    recordCopyConsistency(store, config, prefix, capabilities);
    recordParcelConsistency(store, config, prefix, capabilities);
  }

  static void recordMany(
      ResultStore store, RunConfig config, String prefix, List<NetworkCapabilities> capabilities)
      throws IOException, JSONException {
    recordManySignal(
        store,
        config,
        prefix + ".transport.vpn",
        capabilities,
        item -> item.hasTransport(NetworkCapabilities.TRANSPORT_VPN));
    recordManySignal(
        store,
        config,
        prefix + ".capability.not_vpn",
        capabilities,
        item -> !item.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN));
    recordManySignal(
        store,
        config,
        prefix + ".capabilities.not_vpn",
        capabilities,
        item -> !contains(item.getCapabilities(), NetworkCapabilities.NET_CAPABILITY_NOT_VPN));
    recordManySignal(
        store,
        config,
        prefix + ".transport_info.vpn_token",
        capabilities,
        item -> objectContainsVpn(item.getTransportInfo()));
    recordManySignal(
        store,
        config,
        prefix + ".caps_string.vpn_token",
        capabilities,
        item -> containsVpnTransportToken(item.toString()));
    recordManyConsistency(store, config, prefix + ".copy.consistency", capabilities, false);
    recordManyConsistency(store, config, prefix + ".parcel.consistency", capabilities, true);
  }

  private static void recordTransport(
      ResultStore store, RunConfig config, String prefix, NetworkCapabilities capabilities)
      throws IOException, JSONException {
    long started = System.nanoTime();
    try {
      boolean value = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
      JSONArray transports = new JSONArray();
      for (int transport : TRANSPORT_TYPES) {
        if (capabilities.hasTransport(transport)) {
          transports.put(transport);
        }
      }
      store.detector(
          config,
          prefix + ".transport.vpn",
          true,
          value ? ProbeStatus.POSITIVE : ProbeStatus.NEGATIVE,
          new JSONObject().put("vpn_transport", value).put("transports", transports),
          null,
          elapsed(started),
          "complete");
    } catch (RuntimeException error) {
      recordError(store, config, prefix + ".transport.vpn", true, error, started);
    }
  }

  private static void recordNotVpnCapability(
      ResultStore store, RunConfig config, String prefix, NetworkCapabilities capabilities)
      throws IOException, JSONException {
    long started = System.nanoTime();
    try {
      boolean value = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
      store.detector(
          config,
          prefix + ".capability.not_vpn",
          false,
          value ? ProbeStatus.NEGATIVE : ProbeStatus.POSITIVE,
          new JSONObject().put("not_vpn_capability", value),
          null,
          elapsed(started),
          "complete");
    } catch (RuntimeException error) {
      recordError(store, config, prefix + ".capability.not_vpn", false, error, started);
    }
  }

  private static void recordCapabilitiesArray(
      ResultStore store, RunConfig config, String prefix, NetworkCapabilities capabilities)
      throws IOException, JSONException {
    long started = System.nanoTime();
    try {
      int[] values = capabilities.getCapabilities();
      boolean notVpn = contains(values, NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
      if (config.isServerVpnGroup()) {
        java.util.Arrays.sort(values);
      }
      store.detector(
          config,
          prefix + ".capabilities.not_vpn",
          false,
          notVpn ? ProbeStatus.NEGATIVE : ProbeStatus.POSITIVE,
          new JSONObject().put("not_vpn_capability", notVpn).put("capabilities", array(values)),
          null,
          elapsed(started),
          "complete");
    } catch (RuntimeException error) {
      recordError(store, config, prefix + ".capabilities.not_vpn", false, error, started);
    }
  }

  private static void recordTransportInfo(
      ResultStore store, RunConfig config, String prefix, NetworkCapabilities capabilities)
      throws IOException, JSONException {
    long started = System.nanoTime();
    try {
      Object value = capabilities.getTransportInfo();
      JSONObject shape = objectShape(value, config.isServerVpnGroup());
      store.detector(
          config,
          prefix + ".transport_info.vpn_token",
          false,
          objectContainsVpn(value) ? ProbeStatus.POSITIVE : ProbeStatus.NEGATIVE,
          shape,
          null,
          elapsed(started),
          "complete");
    } catch (RuntimeException error) {
      recordError(store, config, prefix + ".transport_info.vpn_token", false, error, started);
    }
  }

  private static void recordString(
      ResultStore store, RunConfig config, String prefix, NetworkCapabilities capabilities)
      throws IOException, JSONException {
    long started = System.nanoTime();
    try {
      String value = capabilities.toString();
      boolean vpnTransportToken = containsVpnTransportToken(value);
      store.detector(
          config,
          prefix + ".caps_string.vpn_token",
          false,
          vpnTransportToken ? ProbeStatus.POSITIVE : ProbeStatus.NEGATIVE,
          capabilitiesStringShape(value, config.isServerVpnGroup()),
          null,
          elapsed(started),
          "complete");
    } catch (RuntimeException error) {
      recordError(store, config, prefix + ".caps_string.vpn_token", false, error, started);
    }
  }

  private static void recordIntegerGetter(
      ResultStore store, RunConfig config, String testId, String key, IntegerSupplier supplier)
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
      recordError(store, config, testId, false, error, started);
    }
  }

  private static void recordEnterpriseIds(
      ResultStore store, RunConfig config, String prefix, NetworkCapabilities capabilities)
      throws IOException, JSONException {
    long started = System.nanoTime();
    try {
      int[] values = capabilities.getEnterpriseIds();
      if (config.isServerVpnGroup()) {
        java.util.Arrays.sort(values);
      }
      boolean firstPresent = values.length > 0 && capabilities.hasEnterpriseId(values[0]);
      store.detector(
          config,
          prefix + ".getter.enterprise_ids",
          false,
          ProbeStatus.NEGATIVE,
          new JSONObject().put("values", array(values)).put("first_present", firstPresent),
          null,
          elapsed(started),
          "complete");
    } catch (RuntimeException error) {
      recordError(store, config, prefix + ".getter.enterprise_ids", false, error, started);
    }
  }

  private static void recordNetworkSpecifier(
      ResultStore store, RunConfig config, String prefix, NetworkCapabilities capabilities)
      throws IOException, JSONException {
    long started = System.nanoTime();
    try {
      Object value = capabilities.getNetworkSpecifier();
      store.detector(
          config,
          prefix + ".getter.network_specifier",
          false,
          ProbeStatus.NEGATIVE,
          new JSONObject()
              .put("class", value == null ? JSONObject.NULL : value.getClass().getName()),
          null,
          elapsed(started),
          "complete");
    } catch (RuntimeException error) {
      recordError(store, config, prefix + ".getter.network_specifier", false, error, started);
    }
  }

  private static void recordSubscriptionIds(
      ResultStore store, RunConfig config, String prefix, NetworkCapabilities capabilities)
      throws IOException, JSONException {
    long started = System.nanoTime();
    try {
      Set<Integer> values = capabilities.getSubscriptionIds();
      List<Integer> ordered = new java.util.ArrayList<>(values);
      if (config.isServerVpnGroup()) {
        java.util.Collections.sort(ordered);
      }
      store.detector(
          config,
          prefix + ".getter.subscription_ids",
          false,
          ProbeStatus.NEGATIVE,
          new JSONObject().put("values", new JSONArray(ordered)),
          null,
          elapsed(started),
          "complete");
    } catch (RuntimeException error) {
      recordError(store, config, prefix + ".getter.subscription_ids", false, error, started);
    }
  }

  private static void recordCopyConsistency(
      ResultStore store, RunConfig config, String prefix, NetworkCapabilities original)
      throws IOException, JSONException {
    long started = System.nanoTime();
    try {
      NetworkCapabilities copy = new NetworkCapabilities(original);
      boolean consistent = coreEqual(original, copy);
      store.detector(
          config,
          prefix + ".copy.consistency",
          true,
          consistent ? ProbeStatus.NEGATIVE : ProbeStatus.ERROR,
          new JSONObject().put("consistent", consistent),
          null,
          elapsed(started),
          "complete");
    } catch (RuntimeException error) {
      recordError(store, config, prefix + ".copy.consistency", true, error, started);
    }
  }

  private static void recordParcelConsistency(
      ResultStore store, RunConfig config, String prefix, NetworkCapabilities original)
      throws IOException, JSONException {
    long started = System.nanoTime();
    Parcel parcel = Parcel.obtain();
    try {
      original.writeToParcel(parcel, 0);
      parcel.setDataPosition(0);
      NetworkCapabilities roundTrip = NetworkCapabilities.CREATOR.createFromParcel(parcel);
      boolean consistent = coreEqual(original, roundTrip);
      store.detector(
          config,
          prefix + ".parcel.consistency",
          true,
          consistent ? ProbeStatus.NEGATIVE : ProbeStatus.ERROR,
          new JSONObject().put("consistent", consistent),
          null,
          elapsed(started),
          "complete");
    } catch (RuntimeException error) {
      recordError(store, config, prefix + ".parcel.consistency", true, error, started);
    } finally {
      parcel.recycle();
    }
  }

  private static void recordManySignal(
      ResultStore store,
      RunConfig config,
      String testId,
      List<NetworkCapabilities> capabilities,
      CapabilityPredicate predicate)
      throws IOException, JSONException {
    long started = System.nanoTime();
    try {
      int positiveCount = 0;
      for (NetworkCapabilities item : capabilities) {
        if (predicate.test(item)) {
          positiveCount++;
        }
      }
      store.detector(
          config,
          testId,
          "sync.all.transport.vpn".equals(testId),
          positiveCount > 0 ? ProbeStatus.POSITIVE : ProbeStatus.NEGATIVE,
          new JSONObject()
              .put("network_count", capabilities.size())
              .put("positive_count", positiveCount),
          null,
          elapsed(started),
          "complete");
    } catch (RuntimeException error) {
      recordError(store, config, testId, "sync.all.transport.vpn".equals(testId), error, started);
    }
  }

  private static void recordManyConsistency(
      ResultStore store,
      RunConfig config,
      String testId,
      List<NetworkCapabilities> capabilities,
      boolean parcelRoundTrip)
      throws IOException, JSONException {
    long started = System.nanoTime();
    try {
      boolean consistent = true;
      for (NetworkCapabilities original : capabilities) {
        NetworkCapabilities copy;
        if (parcelRoundTrip) {
          Parcel parcel = Parcel.obtain();
          try {
            original.writeToParcel(parcel, 0);
            parcel.setDataPosition(0);
            copy = NetworkCapabilities.CREATOR.createFromParcel(parcel);
          } finally {
            parcel.recycle();
          }
        } else {
          copy = new NetworkCapabilities(original);
        }
        consistent &= coreEqual(original, copy);
      }
      store.detector(
          config,
          testId,
          true,
          consistent ? ProbeStatus.NEGATIVE : ProbeStatus.ERROR,
          new JSONObject().put("network_count", capabilities.size()).put("consistent", consistent),
          null,
          elapsed(started),
          "complete");
    } catch (RuntimeException error) {
      recordError(store, config, testId, true, error, started);
    }
  }

  private static void recordError(
      ResultStore store,
      RunConfig config,
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

  private static boolean coreEqual(NetworkCapabilities left, NetworkCapabilities right) {
    return left.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            == right.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        && left.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            == right.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        && java.util.Arrays.equals(left.getCapabilities(), right.getCapabilities());
  }

  private static boolean isMandatorySuffix(String suffix) {
    return suffix.equals("transport.vpn")
        || suffix.equals("copy.consistency")
        || suffix.equals("parcel.consistency");
  }

  private static boolean objectContainsVpn(Object value) {
    return value != null
        && (containsVpn(value.getClass().getName()) || containsVpn(value.toString()));
  }

  private static JSONObject objectShape(Object value, boolean canonicalOnly) throws JSONException {
    if (value == null) {
      return new JSONObject().put("present", false);
    }
    if (canonicalOnly) {
      return new JSONObject()
          .put("present", true)
          .put("class", value.getClass().getName())
          .put("contains_vpn", containsVpn(value.toString()));
    }
    return new JSONObject()
        .put("present", true)
        .put("class", value.getClass().getName())
        .put("string", stringShape(value.toString()));
  }

  private static JSONObject stringShape(String value) throws JSONException {
    return new JSONObject()
        .put("length", value.length())
        .put("contains_vpn", containsVpn(value))
        .put("sha256", digest(value));
  }

  private static JSONObject capabilitiesStringShape(String value, boolean canonicalOnly)
      throws JSONException {
    if (canonicalOnly) {
      return new JSONObject()
          .put("transport_section_present", value.contains("Transports:"))
          .put("vpn_transport_token", containsVpnTransportToken(value));
    }
    return new JSONObject()
        .put("length", value.length())
        .put("transport_section_present", value.contains("Transports:"))
        .put("vpn_transport_token", containsVpnTransportToken(value))
        .put("sha256", digest(value));
  }

  private static boolean containsVpnTransportToken(String value) {
    String label = "Transports:";
    int cursor = value.indexOf(label);
    if (cursor < 0) {
      return false;
    }
    cursor += label.length();
    while (cursor < value.length() && Character.isWhitespace(value.charAt(cursor))) {
      cursor++;
    }
    int end = cursor;
    while (end < value.length()
        && !Character.isWhitespace(value.charAt(end))
        && value.charAt(end) != ']') {
      end++;
    }
    for (String token : value.substring(cursor, end).split("\\|", -1)) {
      if (token.equals("VPN")) {
        return true;
      }
    }
    return false;
  }

  private static boolean containsVpn(String value) {
    return value.toLowerCase(Locale.ROOT).contains("vpn");
  }

  private static boolean contains(int[] values, int expected) {
    for (int value : values) {
      if (value == expected) {
        return true;
      }
    }
    return false;
  }

  private static JSONArray array(int[] values) {
    JSONArray result = new JSONArray();
    for (int value : values) {
      result.put(value);
    }
    return result;
  }

  private static String digest(String value) {
    try {
      byte[] bytes =
          MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
      StringBuilder output = new StringBuilder(bytes.length * 2);
      for (byte item : bytes) {
        output.append(String.format(Locale.ROOT, "%02x", item & 0xff));
      }
      return output.toString();
    } catch (NoSuchAlgorithmException error) {
      throw new IllegalStateException("SHA-256 is unavailable", error);
    }
  }

  private static long elapsed(long started) {
    return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
  }

  @FunctionalInterface
  private interface IntegerSupplier {
    int get();
  }

  @FunctionalInterface
  private interface CapabilityPredicate {
    boolean test(NetworkCapabilities capabilities);
  }
}
