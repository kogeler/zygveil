// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.servervpn.policy;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class RequestNormalization {
  private RequestNormalization() {}

  public static Result normalize(
      boolean authorized, boolean supportedBoundary, RequestShape origin, int notVpnCapability) {
    if (!authorized || !supportedBoundary || origin == null) {
      return Result.origin(origin);
    }
    List<Integer> capabilities = new ArrayList<>(origin.capabilities());
    if (!capabilities.contains(notVpnCapability)) {
      capabilities.add(notVpnCapability);
    }
    RequestShape detached =
        new RequestShape(
            origin.transports(),
            capabilities,
            origin.specifierToken(),
            origin.subscriptionId(),
            origin.otherUid(),
            origin.attributionToken(),
            origin.requestType(),
            origin.timeoutMs(),
            origin.flags());
    return Result.normalized(detached);
  }

  public record RequestShape(
      List<Integer> transports,
      List<Integer> capabilities,
      String specifierToken,
      int subscriptionId,
      boolean otherUid,
      String attributionToken,
      int requestType,
      int timeoutMs,
      int flags) {
    public RequestShape {
      transports = transports == null ? List.of() : List.copyOf(transports);
      capabilities = capabilities == null ? List.of() : List.copyOf(capabilities);
      specifierToken = Objects.requireNonNullElse(specifierToken, "");
      attributionToken = Objects.requireNonNullElse(attributionToken, "");
    }
  }

  public enum Action {
    ORIGIN,
    NORMALIZED
  }

  public record Result(Action action, RequestShape value) {
    private static Result origin(RequestShape value) {
      return new Result(Action.ORIGIN, value);
    }

    private static Result normalized(RequestShape value) {
      return new Result(Action.NORMALIZED, value);
    }
  }
}
