// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.servervpn.policy;

public final class EgressArguments {
  private EgressArguments() {}

  public static Object[] replaceSource(Object[] origin, int sourceIndex, Object donorSource) {
    if (origin == null || sourceIndex <= 0 || sourceIndex >= origin.length || donorSource == null) {
      return origin;
    }
    Object[] replacement = origin.clone();
    replacement[sourceIndex] = donorSource;
    return replacement;
  }
}
