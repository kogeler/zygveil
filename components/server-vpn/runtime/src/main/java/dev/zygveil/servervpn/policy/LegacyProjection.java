// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.servervpn.policy;

import java.util.Arrays;

public final class LegacyProjection {
  private LegacyProjection() {}

  public static <T> T mask(boolean authorized, T origin, ConnectedVpnClassifier<T> classifier) {
    return authorized && origin != null && classifier.isConnectedVpn(origin) ? null : origin;
  }

  public static <T> T[] filter(
      boolean authorized, T[] origin, ConnectedVpnClassifier<T> classifier) {
    if (!authorized || origin == null) {
      return origin;
    }
    int retained = 0;
    for (T value : origin) {
      if (value == null || !classifier.isConnectedVpn(value)) {
        retained++;
      }
    }
    if (retained == origin.length) {
      return origin;
    }
    T[] result = Arrays.copyOf(origin, retained);
    int output = 0;
    for (T value : origin) {
      if (value == null || !classifier.isConnectedVpn(value)) {
        result[output++] = value;
      }
    }
    return result;
  }

  @FunctionalInterface
  public interface ConnectedVpnClassifier<T> {
    boolean isConnectedVpn(T value);
  }
}
