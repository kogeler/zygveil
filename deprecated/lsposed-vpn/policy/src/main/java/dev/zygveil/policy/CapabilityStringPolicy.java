// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.policy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class CapabilityStringPolicy {
  private static final String TRANSPORTS = " Transports: ";
  private static final String CAPABILITIES = " Capabilities: ";
  private static final String VPN = "VPN";
  private static final String NOT_VPN = "NOT_VPN";

  private CapabilityStringPolicy() {}

  public static Result sanitize(
      String origin,
      int[] originCapabilities,
      int notVpnCapability,
      String originTransportInfo,
      boolean exactVpnTransportInfo) {
    int transportsStart = uniqueIndex(origin, TRANSPORTS);
    int capabilitiesLabel = uniqueIndex(origin, CAPABILITIES);
    if (transportsStart < 0 || capabilitiesLabel <= transportsStart) {
      return Result.failOpen(origin);
    }

    int transportValueStart = transportsStart + TRANSPORTS.length();
    String transportValue = origin.substring(transportValueStart, capabilitiesLabel);
    List<String> transports = splitExact(transportValue, "|");
    if (transports == null || count(transports, VPN) != 1) {
      return Result.failOpen(origin);
    }
    transports.remove(VPN);

    int capabilityValueStart = capabilitiesLabel + CAPABILITIES.length();
    int capabilityValueEnd = origin.indexOf(' ', capabilityValueStart);
    if (capabilityValueEnd < 0) {
      return Result.failOpen(origin);
    }
    String capabilityValue = origin.substring(capabilityValueStart, capabilityValueEnd);
    List<String> capabilities = splitExact(capabilityValue, "&");
    if (capabilities == null
        || capabilities.size() != originCapabilities.length
        || !strictlyAscending(originCapabilities)) {
      return Result.failOpen(origin);
    }

    int notVpnIndex = Arrays.binarySearch(originCapabilities, notVpnCapability);
    int tokenCount = count(capabilities, NOT_VPN);
    if (notVpnIndex >= 0) {
      if (tokenCount != 1 || !capabilities.get(notVpnIndex).equals(NOT_VPN)) {
        return Result.failOpen(origin);
      }
    } else {
      if (tokenCount != 0) {
        return Result.failOpen(origin);
      }
      capabilities.add(-notVpnIndex - 1, NOT_VPN);
    }

    String transportInfoField = null;
    if (exactVpnTransportInfo) {
      if (originTransportInfo == null) {
        return Result.failOpen(origin);
      }
      transportInfoField = " TransportInfo: <" + originTransportInfo + ">";
      if (uniqueIndex(origin, transportInfoField) < 0) {
        return Result.failOpen(origin);
      }
    }

    String normalized =
        origin.substring(0, transportValueStart)
            + String.join("|", transports)
            + origin.substring(capabilitiesLabel, capabilityValueStart)
            + String.join("&", capabilities)
            + origin.substring(capabilityValueEnd);
    if (transportInfoField != null) {
      normalized = removeOnce(normalized, transportInfoField);
    }
    return Result.success(normalized);
  }

  private static int uniqueIndex(String value, String token) {
    int first = value.indexOf(token);
    if (first < 0 || value.indexOf(token, first + token.length()) >= 0) {
      return -1;
    }
    return first;
  }

  private static List<String> splitExact(String value, String delimiter) {
    if (value.isEmpty()) {
      return new ArrayList<>();
    }
    List<String> parts = new ArrayList<>(Arrays.asList(value.split("\\Q" + delimiter + "\\E", -1)));
    return parts.stream().anyMatch(String::isEmpty) ? null : parts;
  }

  private static int count(List<String> values, String expected) {
    int matches = 0;
    for (String value : values) {
      if (value.equals(expected)) {
        matches++;
      }
    }
    return matches;
  }

  private static boolean strictlyAscending(int[] values) {
    for (int index = 1; index < values.length; index++) {
      if (values[index - 1] >= values[index]) {
        return false;
      }
    }
    return true;
  }

  private static String removeOnce(String value, String token) {
    int start = value.indexOf(token);
    return value.substring(0, start) + value.substring(start + token.length());
  }

  public static final class Result {
    private final boolean sanitized;
    private final String value;

    private Result(boolean sanitized, String value) {
      this.sanitized = sanitized;
      this.value = value;
    }

    public static Result success(String value) {
      return new Result(true, value);
    }

    public static Result failOpen(String origin) {
      return new Result(false, origin);
    }

    public boolean sanitized() {
      return sanitized;
    }

    public String value() {
      return value;
    }
  }
}
