// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.policy;

import android.net.NetworkCapabilities;
import android.net.NetworkRequest;

public final class RequestPolicy {
  private RequestPolicy() {}

  public static NetworkRequest detachedCopy(NetworkRequest origin) {
    return new NetworkRequest.Builder(origin).build();
  }

  public static NetworkRequest normalizeForSystem(NetworkRequest origin) {
    if (origin.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
      return origin;
    }
    NetworkRequest detached = detachedCopy(origin);
    return new NetworkRequest.Builder(detached)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .build();
  }

  public static boolean canBeSatisfiedBy(
      NetworkRequest request,
      NetworkCapabilities capabilities,
      RawVpnClassifier classifier,
      OriginMatcher originMatcher) {
    if (capabilities == null) {
      return originMatcher.matches(request, null);
    }
    boolean rawVpn = classifier.isVpn(capabilities);
    int[] transports = request.getTransportTypes();
    MatcherPolicy.Plan plan =
        MatcherPolicy.plan(
            true,
            rawVpn,
            request.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN),
            request.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
            transports.length);
    if (plan.action() == MatcherPolicy.Action.ORIGIN) {
      return originMatcher.matches(request, capabilities);
    }
    if (plan.action() == MatcherPolicy.Action.NO_MATCH) {
      return false;
    }

    NetworkRequest detached = detachedCopy(request);
    NetworkRequest.Builder builder = new NetworkRequest.Builder(detached);
    if (plan.removeNotVpn()) {
      builder.removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
    }
    if (plan.removeVpn()) {
      builder.removeTransportType(NetworkCapabilities.TRANSPORT_VPN);
    }
    return originMatcher.matches(builder.build(), capabilities);
  }

  @FunctionalInterface
  public interface RawVpnClassifier {
    boolean isVpn(NetworkCapabilities capabilities);
  }

  @FunctionalInterface
  public interface OriginMatcher {
    boolean matches(NetworkRequest request, NetworkCapabilities capabilities);
  }
}
