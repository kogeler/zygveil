// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe.detector;

import android.net.IpPrefix;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.NetworkCapabilities;
import android.net.RouteInfo;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

final class LinkPropertiesDetectors {
  static final List<String> FIELD_SUFFIXES =
      List.of(
          "interface",
          "addresses",
          "routes",
          "dns",
          "mtu",
          "private_dns",
          "proxy",
          "nat64",
          "dhcp",
          "wake_on_lan",
          "signal_strength");

  private LinkPropertiesDetectors() {}

  static Observation observation(LinkProperties linkProperties, NetworkCapabilities capabilities) {
    return new Observation(linkProperties, capabilities);
  }

  static void recordSingle(
      ResultStore store,
      RunConfig config,
      String prefix,
      LinkProperties linkProperties,
      NetworkCapabilities capabilities,
      boolean networkPresent)
      throws IOException, JSONException {
    Observation observation = observation(linkProperties, capabilities);
    List<Observation> observations = networkPresent ? List.of(observation) : List.of();
    for (String suffix : FIELD_SUFFIXES) {
      recordField(store, config, prefix + "." + suffix, suffix, observations, false);
    }
  }

  static void recordMany(
      ResultStore store,
      RunConfig config,
      String prefix,
      List<Observation> observations,
      boolean callbackComplete)
      throws IOException, JSONException {
    List<Observation> snapshot = List.copyOf(observations);
    for (String suffix : FIELD_SUFFIXES) {
      recordField(store, config, prefix + "." + suffix, suffix, snapshot, callbackComplete);
    }
  }

  private static void recordField(
      ResultStore store,
      RunConfig config,
      String testId,
      String suffix,
      List<Observation> observations,
      boolean callbackComplete)
      throws IOException, JSONException {
    long started = System.nanoTime();
    try {
      List<JSONObject> comparisons = new ArrayList<>();
      List<Object> diagnostics = new ArrayList<>();
      int linkCount = 0;
      for (Observation observation : observations) {
        if (observation.linkProperties != null) {
          linkCount++;
        }
        ProjectedField field = project(suffix, observation);
        comparisons.add(field.comparison);
        if (field.diagnostic != null) {
          diagnostics.add(field.diagnostic);
        }
      }
      comparisons.sort(Comparator.comparing(LinkPropertiesDetectors::canonicalValue));
      diagnostics.sort(Comparator.comparing(LinkPropertiesDetectors::canonicalValue));
      JSONObject comparison =
          new JSONObject()
              .put("network_count", observations.size())
              .put("link_count", linkCount)
              .put("values", jsonArray(comparisons));
      JSONObject raw = new JSONObject().put("comparison", comparison);
      if (!diagnostics.isEmpty()) {
        raw.put("diagnostic", jsonArray(diagnostics));
      }
      boolean complete =
          !observations.isEmpty()
              && (callbackComplete
                  || observations.stream().anyMatch(item -> item.hasValue(suffix)));
      store.detector(
          config,
          testId,
          false,
          complete ? ProbeStatus.NEGATIVE : ProbeStatus.INCONCLUSIVE,
          raw,
          null,
          elapsed(started),
          "complete");
    } catch (RuntimeException error) {
      store.detector(
          config,
          testId,
          false,
          ProbeStatus.ERROR,
          new JSONObject().put("comparison", new JSONObject()),
          error,
          elapsed(started),
          "complete");
    }
  }

  private static ProjectedField project(String suffix, Observation observation)
      throws JSONException {
    LinkProperties link = observation.linkProperties;
    NetworkCapabilities capabilities = observation.capabilities;
    if (suffix.equals("signal_strength")) {
      JSONObject comparison =
          new JSONObject()
              .put("capabilities_present", capabilities != null)
              .put(
                  "specified",
                  capabilities != null
                      && capabilities.getSignalStrength()
                          != NetworkCapabilities.SIGNAL_STRENGTH_UNSPECIFIED);
      Object diagnostic =
          capabilities == null
              ? null
              : new JSONObject().put("value", capabilities.getSignalStrength());
      return new ProjectedField(comparison, diagnostic);
    }
    if (link == null) {
      return new ProjectedField(new JSONObject().put("link_present", false), null);
    }
    return switch (suffix) {
      case "interface" ->
          new ProjectedField(
              new JSONObject()
                  .put("link_present", true)
                  .put("interface_present", link.getInterfaceName() != null),
              null);
      case "addresses" -> new ProjectedField(projectAddresses(link), null);
      case "routes" -> new ProjectedField(projectRoutes(link), null);
      case "dns" -> new ProjectedField(projectDns(link), null);
      case "mtu" ->
          new ProjectedField(
              new JSONObject()
                  .put("link_present", true)
                  .put("configured", link.getMtu() != 0)
                  .put("value", link.getMtu()),
              null);
      case "private_dns" ->
          new ProjectedField(
              new JSONObject()
                  .put("link_present", true)
                  .put("active", link.isPrivateDnsActive())
                  .put("server_name_present", link.getPrivateDnsServerName() != null),
              null);
      case "proxy" ->
          new ProjectedField(
              new JSONObject()
                  .put("link_present", true)
                  .put("present", link.getHttpProxy() != null),
              null);
      case "nat64" -> new ProjectedField(projectPrefix("nat64", link.getNat64Prefix()), null);
      case "dhcp" ->
          new ProjectedField(
              new JSONObject()
                  .put("link_present", true)
                  .put("present", link.getDhcpServerAddress() != null),
              null);
      case "wake_on_lan" ->
          new ProjectedField(
              new JSONObject()
                  .put("link_present", true)
                  .put("supported", link.isWakeOnLanSupported()),
              null);
      default -> throw new IllegalArgumentException("unsupported LinkProperties field");
    };
  }

  private static JSONObject projectAddresses(LinkProperties link) throws JSONException {
    List<JSONObject> values = new ArrayList<>();
    for (LinkAddress address : link.getLinkAddresses()) {
      values.add(
          new JSONObject()
              .put("family", family(address.getAddress()))
              .put("scope", scope(address.getAddress()))
              .put("prefix_length", address.getPrefixLength())
              .put("flags", address.getFlags()));
    }
    values.sort(Comparator.comparing(JSONObject::toString));
    return new JSONObject()
        .put("link_present", true)
        .put("count", values.size())
        .put("values", jsonArray(values));
  }

  private static JSONObject projectRoutes(LinkProperties link) throws JSONException {
    List<JSONObject> values = new ArrayList<>();
    String linkInterface = link.getInterfaceName();
    for (RouteInfo route : link.getRoutes()) {
      IpPrefix destination = route.getDestination();
      InetAddress gateway = route.getGateway();
      String routeInterface = route.getInterface();
      values.add(
          new JSONObject()
              .put(
                  "destination_family",
                  family(destination == null ? null : destination.getAddress()))
              .put("prefix_length", destination == null ? -1 : destination.getPrefixLength())
              .put("default", route.isDefaultRoute())
              .put("has_gateway", route.hasGateway())
              .put("gateway_family", family(gateway))
              .put("gateway_scope", scope(gateway))
              .put("type", route.getType())
              .put("interface_relation", relation(linkInterface, routeInterface)));
    }
    values.sort(Comparator.comparing(JSONObject::toString));
    return new JSONObject()
        .put("link_present", true)
        .put("count", values.size())
        .put("values", jsonArray(values));
  }

  private static JSONObject projectDns(LinkProperties link) throws JSONException {
    List<JSONObject> values = new ArrayList<>();
    for (InetAddress address : link.getDnsServers()) {
      values.add(new JSONObject().put("family", family(address)).put("scope", scope(address)));
    }
    values.sort(Comparator.comparing(JSONObject::toString));
    return new JSONObject()
        .put("link_present", true)
        .put("count", values.size())
        .put("values", jsonArray(values))
        .put("domains_present", link.getDomains() != null);
  }

  private static JSONObject projectPrefix(String name, IpPrefix prefix) throws JSONException {
    return new JSONObject()
        .put("link_present", true)
        .put(name + "_present", prefix != null)
        .put(name + "_family", family(prefix == null ? null : prefix.getAddress()))
        .put(name + "_prefix_length", prefix == null ? -1 : prefix.getPrefixLength());
  }

  private static String relation(String left, String right) {
    if (left == null || right == null) {
      return "missing";
    }
    return left.equals(right) ? "same" : "different";
  }

  private static String family(InetAddress address) {
    if (address == null) {
      return "none";
    }
    if (address instanceof Inet4Address) {
      return "ipv4";
    }
    if (address instanceof Inet6Address) {
      return "ipv6";
    }
    return "other";
  }

  private static String scope(InetAddress address) {
    if (address == null) {
      return "none";
    }
    if (address.isAnyLocalAddress()) {
      return "any_local";
    }
    if (address.isLoopbackAddress()) {
      return "loopback";
    }
    if (address.isLinkLocalAddress()) {
      return "link_local";
    }
    if (address.isSiteLocalAddress()) {
      return "site_local";
    }
    if (address.isMulticastAddress()) {
      return "multicast";
    }
    return "global";
  }

  private static JSONArray jsonArray(List<?> values) {
    JSONArray array = new JSONArray();
    for (Object value : values) {
      array.put(value);
    }
    return array;
  }

  private static String canonicalValue(Object value) {
    if (value == null || value == JSONObject.NULL) {
      return "null";
    }
    if (value instanceof JSONObject object) {
      List<String> keys = new ArrayList<>();
      object.keys().forEachRemaining(keys::add);
      keys.sort(String::compareTo);
      StringBuilder result = new StringBuilder("{");
      for (String key : keys) {
        result
            .append(JSONObject.quote(key))
            .append(':')
            .append(canonicalValue(object.opt(key)))
            .append(',');
      }
      return result.append('}').toString();
    }
    if (value instanceof JSONArray array) {
      StringBuilder result = new StringBuilder("[");
      for (int index = 0; index < array.length(); index++) {
        result.append(canonicalValue(array.opt(index))).append(',');
      }
      return result.append(']').toString();
    }
    if (value instanceof String text) {
      return JSONObject.quote(text);
    }
    return String.valueOf(value);
  }

  private static long elapsed(long started) {
    return (System.nanoTime() - started) / 1_000_000L;
  }

  static final class Observation {
    private final LinkProperties linkProperties;
    private final NetworkCapabilities capabilities;

    private Observation(LinkProperties linkProperties, NetworkCapabilities capabilities) {
      this.linkProperties = linkProperties;
      this.capabilities = capabilities;
    }

    private boolean hasValue(String suffix) {
      return suffix.equals("signal_strength") ? capabilities != null : linkProperties != null;
    }
  }

  private static final class ProjectedField {
    private final JSONObject comparison;
    private final Object diagnostic;

    private ProjectedField(JSONObject comparison, Object diagnostic) {
      this.comparison = comparison;
      this.diagnostic = diagnostic;
    }
  }
}
