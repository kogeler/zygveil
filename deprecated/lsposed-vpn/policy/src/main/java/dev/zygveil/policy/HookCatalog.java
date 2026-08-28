// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.policy;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class HookCatalog {
  private static final String CAPABILITIES = "android.net.NetworkCapabilities";
  private static final String REQUEST = "android.net.NetworkRequest";
  private static final String MANAGER = "android.net.ConnectivityManager";
  private static final String CALLBACK = "android.net.ConnectivityManager$NetworkCallback";
  private static final String HANDLER = "android.os.Handler";
  private static final String PENDING_INTENT = "android.app.PendingIntent";

  private static final List<MethodSpec> METHODS =
      List.of(
          method("capability", CAPABILITIES, "hasTransport", "int"),
          method("capability", CAPABILITIES, "hasCapability", "int"),
          method("capability", CAPABILITIES, "getCapabilities"),
          method("capability", CAPABILITIES, "getTransportInfo"),
          method("capability", CAPABILITIES, "toString"),
          method("request-observation", REQUEST, "hasTransport", "int"),
          method("request-observation", REQUEST, "hasCapability", "int"),
          method("request-observation", REQUEST, "getCapabilities"),
          method("request-observation", REQUEST, "toString"),
          method("request-matcher", REQUEST, "canBeSatisfiedBy", CAPABILITIES),
          method("request-boundary", MANAGER, "registerNetworkCallback", REQUEST, CALLBACK),
          method(
              "request-boundary", MANAGER, "registerNetworkCallback", REQUEST, CALLBACK, HANDLER),
          method("request-boundary", MANAGER, "registerNetworkCallback", REQUEST, PENDING_INTENT),
          method(
              "request-boundary",
              MANAGER,
              "registerBestMatchingNetworkCallback",
              REQUEST,
              CALLBACK,
              HANDLER),
          method("request-boundary", MANAGER, "requestNetwork", REQUEST, CALLBACK),
          method("request-boundary", MANAGER, "requestNetwork", REQUEST, CALLBACK, "int"),
          method("request-boundary", MANAGER, "requestNetwork", REQUEST, CALLBACK, HANDLER),
          method("request-boundary", MANAGER, "requestNetwork", REQUEST, CALLBACK, HANDLER, "int"),
          method("request-boundary", MANAGER, "requestNetwork", REQUEST, PENDING_INTENT),
          method("request-boundary", MANAGER, "reserveNetwork", REQUEST, HANDLER, CALLBACK),
          method("manager-snapshot", MANAGER, "getNetworkCapabilities", "android.net.Network"),
          method("manager-snapshot", MANAGER, "getLinkProperties", "android.net.Network"),
          method("legacy", MANAGER, "getNetworkInfo", "android.net.Network"),
          method("legacy", MANAGER, "getAllNetworkInfo"));

  private static final List<MethodSpec> SUPPORT_METHODS =
      List.of(method("support", MANAGER, "getAllNetworks"));

  private HookCatalog() {}

  public static List<MethodSpec> methods() {
    return METHODS;
  }

  public static List<MethodSpec> supportMethods() {
    return SUPPORT_METHODS;
  }

  public static void validate() {
    if (METHODS.size() != 24) {
      throw new IllegalStateException("hook catalog size is not 24");
    }
    if (SUPPORT_METHODS.size() != 1) {
      throw new IllegalStateException("support catalog size is not 1");
    }
    Set<String> keys = new HashSet<>();
    for (MethodSpec method : METHODS) {
      if (!keys.add(method.key())) {
        throw new IllegalStateException("duplicate hook method: " + method.key());
      }
    }
    for (MethodSpec method : SUPPORT_METHODS) {
      if (!keys.add(method.key())) {
        throw new IllegalStateException("duplicate support method: " + method.key());
      }
    }
  }

  private static MethodSpec method(
      String policy, String declaringClass, String name, String... parameterTypes) {
    return new MethodSpec(policy, declaringClass, name, List.of(parameterTypes));
  }

  public static final class MethodSpec {
    private final String policy;
    private final String declaringClass;
    private final String name;
    private final List<String> parameterTypes;

    private MethodSpec(
        String policy, String declaringClass, String name, List<String> parameterTypes) {
      this.policy = policy;
      this.declaringClass = declaringClass;
      this.name = name;
      this.parameterTypes = List.copyOf(parameterTypes);
    }

    public String policy() {
      return policy;
    }

    public String declaringClass() {
      return declaringClass;
    }

    public String name() {
      return name;
    }

    public List<String> parameterTypes() {
      return parameterTypes;
    }

    public String key() {
      return declaringClass + "#" + name + "(" + String.join(",", parameterTypes) + ")";
    }
  }
}
