// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.servervpn.policy;

public final class IngressArguments {
  private IngressArguments() {}

  public static Object[] replacePayload(Object[] origin, int payloadIndex, Object detachedPayload) {
    if (origin == null
        || payloadIndex <= 0
        || payloadIndex >= origin.length
        || detachedPayload == null) {
      return origin;
    }
    Object[] replacement = origin.clone();
    replacement[payloadIndex] = detachedPayload;
    return replacement;
  }
}
