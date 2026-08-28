// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.module;

import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.os.Parcel;
import dev.zygveil.policy.CapabilityPolicy;
import dev.zygveil.policy.CapabilityStringPolicy;
import dev.zygveil.policy.DonorPolicy;
import dev.zygveil.policy.HookCatalog;
import dev.zygveil.policy.LegacyPolicy;
import dev.zygveil.policy.RequestObservationContext;
import dev.zygveil.policy.RequestPolicy;
import io.github.libxposed.api.XposedInterface;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

final class HookInstaller {
  private static final String CAPABILITIES = "android.net.NetworkCapabilities";
  private static final String REQUEST = "android.net.NetworkRequest";
  private static final String MANAGER = "android.net.ConnectivityManager";
  private static final String VPN_INFO_CLASS = "android.net.VpnTransportInfo";

  private final ZygVeilModule module;
  private final Set<String> loggedFailures = ConcurrentHashMap.newKeySet();
  private final List<XposedInterface.HookHandle> installedHandles = new ArrayList<>();
  private boolean attempted;
  private boolean installed;

  HookInstaller(ZygVeilModule module) {
    this.module = module;
  }

  synchronized boolean install(ClassLoader classLoader, String packageName) {
    if (attempted) {
      return installed;
    }
    attempted = true;
    List<XposedInterface.HookHandle> acquired = new ArrayList<>();
    try {
      ResolvedCatalog catalog = resolveCatalog(classLoader);
      List<PreparedHook> prepared = prepareHooks(catalog);
      for (PreparedHook hook : prepared) {
        XposedInterface.HookHandle handle =
            module
                .hook(hook.method.method)
                .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                .intercept(hook.hooker);
        acquired.add(handle);
      }
      installedHandles.addAll(acquired);
      installed = true;
      return true;
    } catch (Throwable error) {
      rethrowIfFatal(error);
      rollback(acquired);
      logOnce("catalog", "install", error);
      module.logHookEvent(
          "event=hook_install_failed package="
              + packageName
              + " acquired="
              + acquired.size()
              + " origin_only=true");
      return false;
    }
  }

  synchronized int installedCount() {
    return installedHandles.size();
  }

  private ResolvedCatalog resolveCatalog(ClassLoader classLoader)
      throws ReflectiveOperationException {
    HookCatalog.validate();
    List<ResolvedMethod> methods = new ArrayList<>();
    Map<String, ResolvedMethod> byKey = new HashMap<>();
    for (HookCatalog.MethodSpec spec : HookCatalog.methods()) {
      Class<?> declaringClass = Class.forName(spec.declaringClass(), false, classLoader);
      Class<?>[] parameters = new Class<?>[spec.parameterTypes().size()];
      for (int index = 0; index < parameters.length; index++) {
        parameters[index] = resolveType(spec.parameterTypes().get(index), classLoader);
      }
      Method method = declaringClass.getMethod(spec.name(), parameters);
      XposedInterface.Invoker<?, Method> invoker = module.getInvoker(method);
      invoker.setType(XposedInterface.Invoker.Type.ORIGIN);
      ResolvedMethod resolved = new ResolvedMethod(spec, method, invoker);
      if (byKey.put(spec.key(), resolved) != null) {
        throw new IllegalStateException("duplicate resolved method");
      }
      methods.add(resolved);
    }
    for (HookCatalog.MethodSpec spec : HookCatalog.supportMethods()) {
      Class<?> declaringClass = Class.forName(spec.declaringClass(), false, classLoader);
      Class<?>[] parameters = new Class<?>[spec.parameterTypes().size()];
      for (int index = 0; index < parameters.length; index++) {
        parameters[index] = resolveType(spec.parameterTypes().get(index), classLoader);
      }
      Method method = declaringClass.getMethod(spec.name(), parameters);
      XposedInterface.Invoker<?, Method> invoker = module.getInvoker(method);
      invoker.setType(XposedInterface.Invoker.Type.ORIGIN);
      ResolvedMethod resolved = new ResolvedMethod(spec, method, invoker);
      if (byKey.put(spec.key(), resolved) != null) {
        throw new IllegalStateException("duplicate resolved support method");
      }
    }
    if (methods.size() != 24 || byKey.size() != 25) {
      throw new IllegalStateException("resolved catalog size mismatch");
    }
    return new ResolvedCatalog(methods, byKey);
  }

  private static Class<?> resolveType(String name, ClassLoader classLoader)
      throws ClassNotFoundException {
    return name.equals("int") ? int.class : Class.forName(name, false, classLoader);
  }

  private List<PreparedHook> prepareHooks(ResolvedCatalog catalog) {
    List<PreparedHook> prepared = new ArrayList<>();
    for (ResolvedMethod method : catalog.methods) {
      XposedInterface.Hooker hooker = createHooker(method, catalog);
      prepared.add(new PreparedHook(method, hooker));
    }
    return prepared;
  }

  private XposedInterface.Hooker createHooker(ResolvedMethod method, ResolvedCatalog catalog) {
    return switch (method.spec.policy()) {
      case "capability" -> chain -> interceptCapability(method, catalog, chain);
      case "request-observation" -> this::interceptRequestObservation;
      case "request-matcher" -> chain -> interceptMatcher(method, catalog, chain);
      case "request-boundary" -> chain -> interceptRequestBoundary(method, chain);
      case "manager-snapshot" -> chain -> interceptManagerSnapshot(method, catalog, chain);
      case "legacy" -> chain -> interceptLegacy(method, chain);
      default -> throw new IllegalStateException("unknown policy binding");
    };
  }

  private Object interceptCapability(
      ResolvedMethod method, ResolvedCatalog catalog, XposedInterface.Chain chain)
      throws Throwable {
    Object receiver = chain.getThisObject();
    Object[] arguments = chain.getArgs().toArray();
    Object origin = invokeOrigin(method, receiver, arguments);
    if (RequestObservationContext.isActive()) {
      return origin;
    }
    try {
      boolean rawVpn = rawVpn(method, catalog, receiver, arguments, origin);
      return switch (method.spec.name()) {
        case "hasTransport" ->
            CapabilityPolicy.hasTransport(
                rawVpn,
                (Integer) arguments[0],
                NetworkCapabilities.TRANSPORT_VPN,
                (Boolean) origin);
        case "hasCapability" ->
            CapabilityPolicy.hasCapability(
                rawVpn,
                (Integer) arguments[0],
                NetworkCapabilities.NET_CAPABILITY_NOT_VPN,
                (Boolean) origin);
        case "getCapabilities" ->
            CapabilityPolicy.capabilities(
                rawVpn, (int[]) origin, NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
        case "getTransportInfo" -> CapabilityPolicy.transportInfo(rawVpn, origin, VPN_INFO_CLASS);
        case "toString" -> sanitizeCapabilitiesString(catalog, receiver, rawVpn, (String) origin);
        default -> throw new IllegalStateException("unknown capability method");
      };
    } catch (Throwable error) {
      rethrowIfFatal(error);
      logOnce(method.spec.key(), "policy", error);
      return origin;
    }
  }

  private boolean rawVpn(
      ResolvedMethod current,
      ResolvedCatalog catalog,
      Object receiver,
      Object[] arguments,
      Object origin)
      throws Throwable {
    if (current.spec.name().equals("hasTransport")
        && (Integer) arguments[0] == NetworkCapabilities.TRANSPORT_VPN) {
      return (Boolean) origin;
    }
    ResolvedMethod hasTransport = catalog.required(key(CAPABILITIES, "hasTransport", "int"));
    return (Boolean) invokeOrigin(hasTransport, receiver, NetworkCapabilities.TRANSPORT_VPN);
  }

  private Object sanitizeCapabilitiesString(
      ResolvedCatalog catalog, Object receiver, boolean rawVpn, String origin) throws Throwable {
    if (!rawVpn) {
      return origin;
    }
    int[] capabilities =
        (int[]) invokeOrigin(catalog.required(key(CAPABILITIES, "getCapabilities")), receiver);
    Object transportInfo =
        invokeOrigin(catalog.required(key(CAPABILITIES, "getTransportInfo")), receiver);
    boolean exactVpnInfo =
        transportInfo != null && transportInfo.getClass().getName().equals(VPN_INFO_CLASS);
    CapabilityStringPolicy.Result result =
        CapabilityStringPolicy.sanitize(
            origin,
            capabilities,
            NetworkCapabilities.NET_CAPABILITY_NOT_VPN,
            transportInfo == null ? null : transportInfo.toString(),
            exactVpnInfo);
    if (!result.sanitized()) {
      logOnce(key(CAPABILITIES, "toString"), "ambiguous_string", null);
    }
    return result.value();
  }

  private Object interceptRequestObservation(XposedInterface.Chain chain) throws Throwable {
    RequestObservationContext.Scope scope = RequestObservationContext.enter();
    try {
      return chain.proceed();
    } finally {
      scope.close();
    }
  }

  private Object interceptMatcher(
      ResolvedMethod method, ResolvedCatalog catalog, XposedInterface.Chain chain)
      throws Throwable {
    NetworkRequest request = (NetworkRequest) chain.getThisObject();
    NetworkCapabilities capabilities = (NetworkCapabilities) chain.getArg(0);
    ResolvedMethod hasTransport = catalog.required(key(CAPABILITIES, "hasTransport", "int"));
    try {
      return RequestPolicy.canBeSatisfiedBy(
          request,
          capabilities,
          candidate -> {
            try {
              return (Boolean)
                  invokeOrigin(hasTransport, candidate, NetworkCapabilities.TRANSPORT_VPN);
            } catch (Throwable error) {
              throw new OriginFailure(error);
            }
          },
          (candidateRequest, candidateCapabilities) -> {
            try {
              return (Boolean) invokeOrigin(method, candidateRequest, candidateCapabilities);
            } catch (Throwable error) {
              throw new OriginFailure(error);
            }
          });
    } catch (OriginFailure failure) {
      throw failure.origin;
    } catch (Throwable error) {
      rethrowIfFatal(error);
      logOnce(method.spec.key(), "policy", error);
      return invokeOrigin(method, request, capabilities);
    }
  }

  private Object interceptRequestBoundary(ResolvedMethod method, XposedInterface.Chain chain)
      throws Throwable {
    NetworkRequest origin = (NetworkRequest) chain.getArg(0);
    NetworkRequest normalized;
    try {
      normalized = RequestPolicy.normalizeForSystem(origin);
    } catch (Throwable error) {
      rethrowIfFatal(error);
      logOnce(method.spec.key(), "policy", error);
      return chain.proceed();
    }
    if (normalized == origin) {
      return chain.proceed();
    }
    Object[] replacement = chain.getArgs().toArray();
    replacement[0] = normalized;
    return chain.proceed(replacement);
  }

  private Object interceptManagerSnapshot(
      ResolvedMethod method, ResolvedCatalog catalog, XposedInterface.Chain chain)
      throws Throwable {
    ConnectivityManager manager = (ConnectivityManager) chain.getThisObject();
    Network target = (Network) chain.getArg(0);
    Object origin = invokeOrigin(method, manager, target);
    if (target == null || origin == null) {
      return origin;
    }
    try {
      ResolvedMethod capabilitiesMethod =
          catalog.required(key(MANAGER, "getNetworkCapabilities", "android.net.Network"));
      NetworkCapabilities targetCapabilities =
          method.spec.name().equals("getNetworkCapabilities")
              ? (NetworkCapabilities) origin
              : (NetworkCapabilities) invokeOrigin(capabilitiesMethod, manager, target);
      if (targetCapabilities == null || !isVpn(catalog, targetCapabilities)) {
        return origin;
      }

      DonorPolicy.Selection<Object> selection =
          selectDonor(method, catalog, manager, target, capabilitiesMethod);
      if (selection.outcome() != DonorPolicy.Selection.Outcome.UNIQUE) {
        logOnce(
            method.spec.key(),
            "donor_" + selection.outcome().name().toLowerCase(Locale.ROOT),
            null);
        return origin;
      }
      if (method.spec.name().equals("getNetworkCapabilities")) {
        return new NetworkCapabilities((NetworkCapabilities) selection.value());
      }
      return copyLinkProperties((LinkProperties) selection.value());
    } catch (Throwable error) {
      rethrowIfFatal(error);
      logOnce(method.spec.key(), "policy", error);
      return origin;
    }
  }

  private DonorPolicy.Selection<Object> selectDonor(
      ResolvedMethod intercepted,
      ResolvedCatalog catalog,
      ConnectivityManager manager,
      Network target,
      ResolvedMethod capabilitiesMethod)
      throws Throwable {
    ResolvedMethod allNetworks = catalog.required(key(MANAGER, "getAllNetworks"));
    ResolvedMethod linkPropertiesMethod =
        catalog.required(key(MANAGER, "getLinkProperties", "android.net.Network"));
    Network[] networks = (Network[]) invokeOrigin(allNetworks, manager);
    List<DonorPolicy.Candidate<Object>> candidates = new ArrayList<>();
    if (networks == null) {
      return DonorPolicy.select(candidates);
    }
    for (Network candidate : networks) {
      if (candidate == null) {
        continue;
      }
      boolean sameNetwork = candidate.equals(target);
      NetworkCapabilities capabilities =
          sameNetwork
              ? null
              : (NetworkCapabilities) invokeOrigin(capabilitiesMethod, manager, candidate);
      boolean vpn = capabilities != null && isVpn(catalog, capabilities);
      boolean notVpn =
          capabilities != null
              && hasCapability(catalog, capabilities, NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
      boolean internet =
          capabilities != null
              && hasCapability(catalog, capabilities, NetworkCapabilities.NET_CAPABILITY_INTERNET);
      boolean validated =
          capabilities != null
              && hasCapability(catalog, capabilities, NetworkCapabilities.NET_CAPABILITY_VALIDATED);
      Object value = capabilities;
      if (intercepted.spec.name().equals("getLinkProperties")
          && !sameNetwork
          && !vpn
          && notVpn
          && internet
          && validated) {
        value = invokeOrigin(linkPropertiesMethod, manager, candidate);
      }
      candidates.add(
          new DonorPolicy.Candidate<>(value, sameNetwork, vpn, notVpn, internet, validated));
    }
    return DonorPolicy.select(candidates);
  }

  private boolean isVpn(ResolvedCatalog catalog, NetworkCapabilities capabilities)
      throws Throwable {
    ResolvedMethod hasTransport = catalog.required(key(CAPABILITIES, "hasTransport", "int"));
    return (Boolean) invokeOrigin(hasTransport, capabilities, NetworkCapabilities.TRANSPORT_VPN);
  }

  private boolean hasCapability(
      ResolvedCatalog catalog, NetworkCapabilities capabilities, int capability) throws Throwable {
    ResolvedMethod hasCapability = catalog.required(key(CAPABILITIES, "hasCapability", "int"));
    return (Boolean) invokeOrigin(hasCapability, capabilities, capability);
  }

  private static LinkProperties copyLinkProperties(LinkProperties source) {
    Parcel parcel = Parcel.obtain();
    try {
      source.writeToParcel(parcel, 0);
      parcel.setDataPosition(0);
      return LinkProperties.CREATOR.createFromParcel(parcel);
    } finally {
      parcel.recycle();
    }
  }

  @SuppressWarnings("deprecation") // The two exact legacy methods are required by the API matrix.
  private Object interceptLegacy(ResolvedMethod method, XposedInterface.Chain chain)
      throws Throwable {
    Object receiver = chain.getThisObject();
    Object[] arguments = chain.getArgs().toArray();
    Object origin = invokeOrigin(method, receiver, arguments);
    LegacyPolicy.ConnectedVpnClassifier<NetworkInfo> classifier =
        info -> info.getType() == ConnectivityManager.TYPE_VPN && info.isConnectedOrConnecting();
    try {
      if (method.spec.name().equals("getNetworkInfo")) {
        return LegacyPolicy.maskSingle((NetworkInfo) origin, classifier);
      }
      if (method.spec.name().equals("getAllNetworkInfo")) {
        return LegacyPolicy.filter((NetworkInfo[]) origin, classifier);
      }
      throw new IllegalStateException("unknown legacy method");
    } catch (Throwable error) {
      rethrowIfFatal(error);
      logOnce(method.spec.key(), "policy", error);
      return origin;
    }
  }

  private static Object invokeOrigin(ResolvedMethod method, Object receiver, Object... arguments)
      throws Throwable {
    try {
      return method.invoker.invoke(receiver, arguments);
    } catch (InvocationTargetException error) {
      throw error.getCause();
    }
  }

  private void rollback(List<XposedInterface.HookHandle> acquired) {
    for (int index = acquired.size() - 1; index >= 0; index--) {
      try {
        acquired.get(index).unhook();
      } catch (Throwable error) {
        rethrowIfFatal(error);
        logOnce("catalog", "rollback", error);
      }
    }
  }

  private void logOnce(String method, String stage, Throwable error) {
    String key = method + "#" + stage;
    if (!loggedFailures.add(key)) {
      return;
    }
    module.logHookEvent(
        "event=hook_fail_open method="
            + method
            + " stage="
            + stage
            + " error="
            + (error == null ? "none" : error.getClass().getName()));
  }

  private static void rethrowIfFatal(Throwable error) {
    if (error instanceof VirtualMachineError virtualMachineError) {
      throw virtualMachineError;
    }
    if (error instanceof ThreadDeath threadDeath) {
      throw threadDeath;
    }
  }

  private static String key(String owner, String name, String... parameters) {
    return owner + "#" + name + "(" + String.join(",", parameters) + ")";
  }

  private static final class ResolvedCatalog {
    private final List<ResolvedMethod> methods;
    private final Map<String, ResolvedMethod> byKey;

    private ResolvedCatalog(List<ResolvedMethod> methods, Map<String, ResolvedMethod> byKey) {
      this.methods = List.copyOf(methods);
      this.byKey = Map.copyOf(byKey);
    }

    private ResolvedMethod required(String key) {
      ResolvedMethod method = byKey.get(key);
      if (method == null) {
        throw new IllegalStateException("required catalog binding is absent");
      }
      return method;
    }
  }

  private static final class ResolvedMethod {
    private final HookCatalog.MethodSpec spec;
    private final Method method;
    private final XposedInterface.Invoker<?, Method> invoker;

    private ResolvedMethod(
        HookCatalog.MethodSpec spec, Method method, XposedInterface.Invoker<?, Method> invoker) {
      this.spec = spec;
      this.method = method;
      this.invoker = invoker;
    }
  }

  private static final class PreparedHook {
    private final ResolvedMethod method;
    private final XposedInterface.Hooker hooker;

    private PreparedHook(ResolvedMethod method, XposedInterface.Hooker hooker) {
      this.method = method;
      this.hooker = hooker;
    }
  }

  private static final class OriginFailure extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final transient Throwable origin;

    private OriginFailure(Throwable origin) {
      super(null, null, false, false);
      this.origin = origin;
    }
  }
}
