// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.policy;

import java.util.Arrays;

public final class LegacyPolicy {
  private LegacyPolicy() {}

  public static <T> T maskSingle(T origin, ConnectedVpnClassifier<T> classifier) {
    return origin != null && classifier.isConnectedVpn(origin) ? null : origin;
  }

  public static <T> T[] filter(T[] origin, ConnectedVpnClassifier<T> classifier) {
    if (origin == null) {
      return null;
    }
    int retained = 0;
    for (T entry : origin) {
      if (entry == null || !classifier.isConnectedVpn(entry)) {
        retained++;
      }
    }
    if (retained == origin.length) {
      return origin;
    }
    T[] result = Arrays.copyOf(origin, retained);
    int output = 0;
    for (T entry : origin) {
      if (entry == null || !classifier.isConnectedVpn(entry)) {
        result[output++] = entry;
      }
    }
    return result;
  }

  @FunctionalInterface
  public interface ConnectedVpnClassifier<T> {
    boolean isConnectedVpn(T value);
  }
}
