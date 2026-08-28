// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.policy;

import java.util.Arrays;

public final class CapabilityPolicy {
  private CapabilityPolicy() {}

  public static boolean hasTransport(
      boolean rawVpn, int queriedTransport, int vpnTransport, boolean originResult) {
    return rawVpn && queriedTransport == vpnTransport ? false : originResult;
  }

  public static boolean hasCapability(
      boolean rawVpn, int queriedCapability, int notVpnCapability, boolean originResult) {
    return rawVpn && queriedCapability == notVpnCapability ? true : originResult;
  }

  public static int[] capabilities(boolean rawVpn, int[] originCapabilities, int notVpnCapability) {
    if (!rawVpn) {
      return originCapabilities;
    }
    int insertion = Arrays.binarySearch(originCapabilities, notVpnCapability);
    if (insertion >= 0) {
      return Arrays.copyOf(originCapabilities, originCapabilities.length);
    }
    insertion = -insertion - 1;
    int[] normalized = new int[originCapabilities.length + 1];
    System.arraycopy(originCapabilities, 0, normalized, 0, insertion);
    normalized[insertion] = notVpnCapability;
    System.arraycopy(
        originCapabilities,
        insertion,
        normalized,
        insertion + 1,
        originCapabilities.length - insertion);
    return normalized;
  }

  public static Object transportInfo(
      boolean rawVpn, Object originInfo, String exactVpnInfoClassName) {
    if (rawVpn
        && originInfo != null
        && originInfo.getClass().getName().equals(exactVpnInfoClassName)) {
      return null;
    }
    return originInfo;
  }
}
