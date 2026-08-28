// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

package dev.zygveil.servervpn.bridge;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.os.Binder;
import dev.zygveil.servervpn.policy.EgressArguments;
import dev.zygveil.servervpn.policy.IngressArguments;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@SuppressWarnings("deprecation")
final class ServerVpnRuntime {
  private static final int FIRST_APPLICATION_ID = 10_000;
  private static final int LAST_APPLICATION_ID = 19_999;
  private static final int PER_USER_RANGE = 100_000;
  private static final int TYPE_VPN = 17;
  private static final Set<String> EXCLUDED_PACKAGES =
      Set.of(
          "com.wireguard.android",
          "dev.zygveil.location.controller",
          "dev.zygveil.probe.canary",
          "com.topjohnwu.magisk");
  private static final Object LOCK = new Object();
  private static final Method[] BACKUPS = new Method[ServerVpnBridge.HOOK_COUNT];
  private static final ThreadLocal<Integer> DISPATCH_DEPTH = ThreadLocal.withInitial(() -> 0);

  private static volatile ResolvedCatalog catalog;
  private static volatile State state;
  private static volatile boolean terminalPrepareFailure;
  private static volatile boolean activationActive;

  private static final class CatalogResolutionFailure extends ReflectiveOperationException {
    private static final long serialVersionUID = 1L;

    final String code;

    CatalogResolutionFailure(String code, Throwable cause) {
      super(code, cause);
      this.code = code;
    }
  }

  private static final class CatalogMemberFailure extends ReflectiveOperationException {
    private static final long serialVersionUID = 1L;

    final String code;

    CatalogMemberFailure(String code, Throwable cause) {
      super(code, cause);
      this.code = code;
    }
  }

  private static CatalogResolutionFailure catalogFailure(String code, Throwable cause) {
    if (cause instanceof VirtualMachineError fatal) {
      throw fatal;
    }
    if (cause instanceof ThreadDeath fatal) {
      throw fatal;
    }
    return new CatalogResolutionFailure(code, cause);
  }

  private static String memberSuffix(Throwable cause) {
    return cause instanceof CatalogMemberFailure failure ? "_" + failure.code : "";
  }

  private static CatalogMemberFailure memberFailure(String code, Throwable cause) {
    if (cause instanceof VirtualMachineError fatal) {
      throw fatal;
    }
    if (cause instanceof ThreadDeath fatal) {
      throw fatal;
    }
    return new CatalogMemberFailure(code, cause);
  }

  private ServerVpnRuntime() {}

  static String prepare() {
    synchronized (LOCK) {
      if (catalog != null) {
        return "ready";
      }
      if (terminalPrepareFailure) {
        return "error_catalog_resolution_failed";
      }
      try {
        ResolvedCatalog resolved = resolveCatalog();
        if (resolved == null) {
          return "pending_service_unavailable";
        }
        catalog = resolved;
        return "ready";
      } catch (VirtualMachineError | ThreadDeath fatal) {
        throw fatal;
      } catch (CatalogResolutionFailure failure) {
        terminalPrepareFailure = true;
        return "error_" + failure.code;
      } catch (Throwable ignored) {
        terminalPrepareFailure = true;
        return "error_catalog_resolution_failed";
      }
    }
  }

  static boolean configure() {
    synchronized (LOCK) {
      if (catalog == null || state != null) {
        return false;
      }
      state = new State(catalog);
      return true;
    }
  }

  static Method[] hookMethods() {
    ResolvedCatalog local = catalog;
    return local == null ? null : local.hooks.clone();
  }

  static void registerBackup(int hookId, Method backup) {
    synchronized (LOCK) {
      if (hookId < 0 || hookId >= BACKUPS.length || backup == null || BACKUPS[hookId] != null) {
        throw new IllegalStateException("invalid catalog backup");
      }
      BACKUPS[hookId] = backup;
    }
  }

  static boolean readyForActivation() {
    synchronized (LOCK) {
      if (state == null) {
        return false;
      }
      for (Method backup : BACKUPS) {
        if (backup == null) {
          return false;
        }
      }
      return true;
    }
  }

  static void activate() {
    synchronized (LOCK) {
      if (activationActive || state == null) {
        throw new IllegalStateException("runtime is not ready for activation");
      }
      for (Method backup : BACKUPS) {
        if (backup == null) {
          throw new IllegalStateException("runtime is not ready for activation");
        }
      }
      activationActive = true;
    }
  }

  static void deactivate() {
    synchronized (LOCK) {
      activationActive = false;
    }
  }

  static boolean isActive() {
    return activationActive;
  }

  static void reset() {
    synchronized (LOCK) {
      activationActive = false;
      state = null;
      catalog = null;
      terminalPrepareFailure = false;
      Arrays.fill(BACKUPS, null);
    }
  }

  static Object dispatch(int hookId, Method backup, Object[] args, boolean staticTarget)
      throws Throwable {
    State local = state;
    int depth = DISPATCH_DEPTH.get();
    if (!activationActive
        || local == null
        || depth != 0
        || hookId < 0
        || hookId >= BACKUPS.length) {
      return invokeBackup(backup, args, staticTarget);
    }
    DISPATCH_DEPTH.set(depth + 1);
    try {
      if (hookId < 7) {
        return dispatchSynchronous(local, hookId, backup, args, staticTarget);
      }
      if (hookId < 12) {
        return dispatchIngress(local, hookId, backup, args, staticTarget);
      }
      return dispatchEgress(local, hookId, backup, args, staticTarget);
    } finally {
      DISPATCH_DEPTH.set(depth);
    }
  }

  static Object invokeBackup(Method backup, Object[] args, boolean staticTarget) throws Throwable {
    if (backup == null || args == null || (!staticTarget && args.length == 0)) {
      throw new IllegalStateException("origin invocation contract is unavailable");
    }
    Object receiver = staticTarget ? null : args[0];
    Object[] parameters = staticTarget ? args : Arrays.copyOfRange(args, 1, args.length);
    try {
      return backup.invoke(receiver, parameters);
    } catch (InvocationTargetException error) {
      throw error.getCause();
    }
  }

  private static Object dispatchSynchronous(
      State local, int hookId, Method backup, Object[] args, boolean staticTarget)
      throws Throwable {
    String authorizedPackage = null;
    try {
      String claim =
          hookId == 0 && args != null && args.length == 4 && args[2] instanceof String
              ? (String) args[2]
              : null;
      authorizedPackage =
          validSynchronousShape(hookId, args)
              ? authorizedPackage(local, args[0], Binder.getCallingUid(), claim, hookId == 0)
              : null;
    } catch (VirtualMachineError | ThreadDeath fatal) {
      throw fatal;
    } catch (Throwable ignored) {
      authorizedPackage = null;
    }
    Object origin = invokeBackup(backup, args, staticTarget);
    if (authorizedPackage == null) {
      return origin;
    }
    try {
      return projectSynchronous(local, authorizedPackage, hookId, args, origin);
    } catch (VirtualMachineError | ThreadDeath fatal) {
      throw fatal;
    } catch (Throwable ignored) {
      return origin;
    }
  }

  private static Object dispatchIngress(
      State local, int hookId, Method backup, Object[] args, boolean staticTarget)
      throws Throwable {
    Object[] selected = args;
    try {
      int claimIndex = ExactCatalog.INGRESS_CLAIM_INDEXES[hookId];
      String claim =
          args != null && claimIndex < args.length && args[claimIndex] instanceof String
              ? (String) args[claimIndex]
              : null;
      if (validIngressShape(hookId, args)
          && authorizedPackage(local, args[0], Binder.getCallingUid(), claim, true) != null) {
        selected = normalizeIngress(local, hookId, args);
      }
    } catch (VirtualMachineError | ThreadDeath fatal) {
      throw fatal;
    } catch (Throwable ignored) {
      selected = args;
    }
    return invokeBackup(backup, selected, staticTarget);
  }

  private static Object dispatchEgress(
      State local, int hookId, Method backup, Object[] args, boolean staticTarget)
      throws Throwable {
    Object[] selected = args;
    try {
      if (validEgressShape(hookId, args)) {
        int ownerIndex = ExactCatalog.EGRESS_OWNER_INDEXES[hookId];
        int sourceIndex = ExactCatalog.EGRESS_SOURCE_INDEXES[hookId];
        Field uidField = requiredField(local.catalog.ownerFields, "mUid");
        int ownerUid = uidField.getInt(args[ownerIndex]);
        if (authorizedPackage(local, args[0], ownerUid, null, false) != null) {
          Object sourceAgent = args[sourceIndex];
          if (sourceAgent != null && isVpnAgent(local.catalog, sourceAgent)) {
            Network sourceNetwork =
                (Network)
                    requiredField(local.catalog.supportFields, "immutable_network_handle")
                        .get(sourceAgent);
            Donor donor = selectDonor(local.catalog, args[0], sourceNetwork, sourceAgent);
            if (donor != null && donor.agent != sourceAgent) {
              selected = EgressArguments.replaceSource(args, sourceIndex, donor.agent);
            }
          }
        }
      }
    } catch (VirtualMachineError | ThreadDeath fatal) {
      throw fatal;
    } catch (Throwable ignored) {
      selected = args;
    }
    return invokeBackup(backup, selected, staticTarget);
  }

  private static Object projectSynchronous(
      State local, String packageName, int hookId, Object[] args, Object origin) throws Throwable {
    if (hookId >= 2 && hookId <= 4) {
      return isConnectedVpnInfo(origin) ? null : origin;
    }
    if (hookId == 5) {
      return filterLegacyArray(origin);
    }
    if (hookId == 0) {
      if (!(origin instanceof NetworkCapabilities capabilities)
          || !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
        return origin;
      }
      Network source = (Network) args[1];
      Donor donor = selectDonor(local.catalog, args[0], source, null);
      if (donor == null) {
        return origin;
      }
      Object projected =
          invokeBackup(
              requiredBackup(0),
              new Object[] {args[0], donor.network, packageName, args[3]},
              false);
      return projected instanceof NetworkCapabilities ? projected : origin;
    }
    if (hookId == 1) {
      Network source = (Network) args[1];
      NetworkCapabilities capabilities =
          queryCapabilities(local, packageName, args[0], source, null);
      if (capabilities == null || !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
        return origin;
      }
      Donor donor = selectDonor(local.catalog, args[0], source, null);
      if (donor == null) {
        return origin;
      }
      Object projected =
          invokeBackup(requiredBackup(1), new Object[] {args[0], donor.network}, false);
      return projected == null ? origin : projected;
    }
    if (hookId == 6) {
      Network source = (Network) args[1];
      if (source == null) {
        source =
            (Network)
                invokeExact(
                    requiredMethod(
                        local.catalog.supportMethods,
                        "resolve_nullable_default_proxy_source_for_current_binder_caller"),
                    args[0]);
      }
      NetworkCapabilities capabilities =
          queryCapabilities(local, packageName, args[0], source, null);
      if (source == null
          || capabilities == null
          || !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
        return origin;
      }
      Donor donor = selectDonor(local.catalog, args[0], source, null);
      if (donor == null) {
        return origin;
      }
      Object projected =
          invokeBackup(requiredBackup(6), new Object[] {args[0], donor.network}, false);
      return Objects.equals(origin, projected) ? origin : projected;
    }
    return origin;
  }

  private static NetworkCapabilities queryCapabilities(
      State local, String packageName, Object receiver, Network network, Object attributionTag)
      throws Throwable {
    if (network == null) {
      return null;
    }
    Object value =
        invokeBackup(
            requiredBackup(0),
            new Object[] {receiver, network, packageName, attributionTag},
            false);
    return value instanceof NetworkCapabilities ? (NetworkCapabilities) value : null;
  }

  private static Object[] normalizeIngress(State local, int hookId, Object[] args)
      throws Throwable {
    int payloadIndex = ExactCatalog.INGRESS_PAYLOAD_INDEXES[hookId];
    Object payload = args[payloadIndex];
    if (payload == null) {
      return args;
    }
    Object normalized;
    if (ExactCatalog.INGRESS_PAYLOAD_KINDS[hookId] == 2) {
      NetworkRequest request = (NetworkRequest) payload;
      NetworkRequest.Builder builder = new NetworkRequest.Builder(request);
      if (!request.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
        builder.addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
      }
      normalized = builder.build();
    } else {
      NetworkCapabilities capabilities = (NetworkCapabilities) payload;
      NetworkCapabilities copy = new NetworkCapabilities(capabilities);
      if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
        invokeExact(
            requiredMethod(local.catalog.platformMethods, "add_not_vpn_to_detached_capabilities"),
            copy,
            NetworkCapabilities.NET_CAPABILITY_NOT_VPN);
      }
      normalized = copy;
    }
    return IngressArguments.replacePayload(args, payloadIndex, normalized);
  }

  private static boolean isConnectedVpnInfo(Object value) {
    if (!(value instanceof NetworkInfo info)) {
      return false;
    }
    return info.getType() == TYPE_VPN && info.isConnected();
  }

  private static Object filterLegacyArray(Object origin) {
    if (origin == null || !origin.getClass().isArray()) {
      return origin;
    }
    int length = Array.getLength(origin);
    int retained = 0;
    for (int index = 0; index < length; index++) {
      if (!isConnectedVpnInfo(Array.get(origin, index))) {
        retained++;
      }
    }
    if (retained == length) {
      return origin;
    }
    Object copy = Array.newInstance(origin.getClass().getComponentType(), retained);
    int output = 0;
    for (int index = 0; index < length; index++) {
      Object value = Array.get(origin, index);
      if (!isConnectedVpnInfo(value)) {
        Array.set(copy, output++, value);
      }
    }
    return copy;
  }

  private static Donor selectDonor(
      ResolvedCatalog resolved, Object receiver, Network source, Object knownSourceAgent)
      throws Throwable {
    if (source == null) {
      return null;
    }
    Object sourceAgent =
        knownSourceAgent != null ? knownSourceAgent : resolveAgent(resolved, receiver, source);
    if (sourceAgent == null) {
      return null;
    }
    Object declaredValue =
        requiredField(resolved.supportFields, "preferred_donor_handles").get(sourceAgent);
    if (declaredValue instanceof Network[] declared && declared.length > 0) {
      return selectUniqueDeclared(resolved, receiver, source, declared);
    }
    Object candidates =
        invokeExact(
            requiredMethod(resolved.supportMethods, "stable_unique_donor_fallback_candidates"),
            receiver);
    if (candidates == null || !candidates.getClass().isArray()) {
      return null;
    }
    Donor selected = null;
    int length = Array.getLength(candidates);
    for (int index = 0; index < length; index++) {
      Object candidate = Array.get(candidates, index);
      Donor donor = eligibleDonor(resolved, receiver, source, candidate);
      if (donor == null) {
        continue;
      }
      if (selected != null) {
        return null;
      }
      selected = donor;
    }
    return selected;
  }

  private static Donor selectUniqueDeclared(
      ResolvedCatalog resolved, Object receiver, Network source, Network[] declared)
      throws Throwable {
    Donor selected = null;
    for (Network network : declared) {
      Object agent = network == null ? null : resolveAgent(resolved, receiver, network);
      Donor donor = eligibleDonor(resolved, receiver, source, agent);
      if (donor == null) {
        continue;
      }
      if (selected != null) {
        return null;
      }
      selected = donor;
    }
    return selected;
  }

  private static Donor eligibleDonor(
      ResolvedCatalog resolved, Object receiver, Network source, Object candidate)
      throws Throwable {
    if (candidate == null) {
      return null;
    }
    Network network =
        (Network) requiredField(resolved.supportFields, "immutable_network_handle").get(candidate);
    if (network == null || network.equals(source)) {
      return null;
    }
    Object current = resolveAgent(resolved, receiver, network);
    if (current != candidate) {
      return null;
    }
    Object value =
        requiredField(resolved.supportFields, "shared_source_never_mutated_capabilities")
            .get(candidate);
    Object networkInfo =
        requiredField(resolved.supportFields, "connected_network_state").get(candidate);
    if (!(value instanceof NetworkCapabilities capabilities)
        || !(networkInfo instanceof NetworkInfo info)
        || !info.isConnected()
        || capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        || !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        || !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        || !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
      return null;
    }
    return new Donor(candidate, network);
  }

  private static boolean isVpnAgent(ResolvedCatalog resolved, Object agent)
      throws IllegalAccessException {
    Object value =
        requiredField(resolved.supportFields, "shared_source_never_mutated_capabilities")
            .get(agent);
    return value instanceof NetworkCapabilities
        && ((NetworkCapabilities) value).hasTransport(NetworkCapabilities.TRANSPORT_VPN);
  }

  private static Object resolveAgent(ResolvedCatalog resolved, Object receiver, Network network)
      throws Throwable {
    return invokeExact(
        requiredMethod(resolved.supportMethods, "resolve_exact_network_agent_from_handle"),
        receiver,
        network);
  }

  private static String authorizedPackage(
      State local, Object receiver, int uid, String claimedPackage, boolean claimRequired) {
    int applicationId = Math.floorMod(uid, PER_USER_RANGE);
    int userId = Math.floorDiv(uid, PER_USER_RANGE);
    if (userId != 0
        || applicationId < FIRST_APPLICATION_ID
        || applicationId > LAST_APPLICATION_ID) {
      return null;
    }
    long token = Binder.clearCallingIdentity();
    try {
      Object contextValue =
          requiredField(local.catalog.supportFields, "package_manager_authorization_context")
              .get(receiver);
      if (!(contextValue instanceof Context context)) {
        return null;
      }
      PackageManager manager = context.getPackageManager();
      String[] packages = manager.getPackagesForUid(uid);
      if (packages == null || packages.length != 1) {
        return null;
      }
      String packageName = packages[0];
      if (packageName == null
          || packageName.isEmpty()
          || EXCLUDED_PACKAGES.contains(packageName)
          || (claimRequired && !packageName.equals(claimedPackage))) {
        return null;
      }
      ApplicationInfo application = manager.getApplicationInfo(packageName, 0);
      if (application.uid != uid
          || (application.flags
                  & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP))
              != 0) {
        return null;
      }
      int privateFlags =
          requiredField(local.catalog.platformFields, "reject_privileged_application")
              .getInt(application);
      if ((privateFlags & ExactCatalog.PRIVATE_FLAG_PRIVILEGED) != 0) {
        return null;
      }
      return packageName;
    } catch (VirtualMachineError | ThreadDeath fatal) {
      throw fatal;
    } catch (Throwable ignored) {
      return null;
    } finally {
      Binder.restoreCallingIdentity(token);
    }
  }

  private static ResolvedCatalog resolveCatalog() throws ReflectiveOperationException {
    Object service;
    try {
      Class<?> serviceManager = Class.forName("android.os.ServiceManager", false, null);
      Method getService = serviceManager.getDeclaredMethod("getService", String.class);
      service = getService.invoke(null, "connectivity");
    } catch (Throwable error) {
      throw catalogFailure("catalog_service_lookup", error);
    }
    if (service == null) {
      return null;
    }
    Class<?> actual = service.getClass();
    if (!ExactCatalog.SERVICE_CLASS.equals(actual.getName())) {
      throw new CatalogResolutionFailure(
          "catalog_service_class", new ReflectiveOperationException("service class mismatch"));
    }
    ClassLoader loader = actual.getClassLoader();
    try {
      if (loader == null || loader.loadClass(ExactCatalog.SERVICE_CLASS) != actual) {
        throw new ReflectiveOperationException("service loader mismatch");
      }
    } catch (Throwable error) {
      throw catalogFailure("catalog_service_loader", error);
    }
    Method[] hooks = new Method[ExactCatalog.HOOKS.length];
    for (int index = 0; index < ExactCatalog.HOOKS.length; index++) {
      try {
        hooks[index] = resolveMethod(loader, ExactCatalog.HOOKS[index], 1);
      } catch (Throwable error) {
        throw catalogFailure("catalog_hook_" + index + memberSuffix(error), error);
      }
    }
    Map<String, Method> supportMethods = new HashMap<>();
    for (int index = 0; index < ExactCatalog.SUPPORT_METHODS.length; index++) {
      String[] row = ExactCatalog.SUPPORT_METHODS[index];
      try {
        if (supportMethods.put(row[0], resolveMethod(loader, row, 1)) != null) {
          throw new ReflectiveOperationException("duplicate support method role");
        }
      } catch (Throwable error) {
        throw catalogFailure("catalog_support_method_" + index + memberSuffix(error), error);
      }
    }
    Map<String, Method> platformMethods = new HashMap<>();
    for (int index = 0; index < ExactCatalog.PLATFORM_METHODS.length; index++) {
      String[] row = ExactCatalog.PLATFORM_METHODS[index];
      try {
        if (platformMethods.put(row[0], resolveMethod(loader, row, 1)) != null) {
          throw new ReflectiveOperationException("duplicate platform method role");
        }
      } catch (Throwable error) {
        throw catalogFailure("catalog_platform_method_" + index + memberSuffix(error), error);
      }
    }
    Map<String, Field> ownerFields = new HashMap<>();
    for (int index = 0; index < ExactCatalog.OWNER_FIELDS.length; index++) {
      String[] row = ExactCatalog.OWNER_FIELDS[index];
      try {
        if (ownerFields.put(row[0], resolveField(loader, row, 1)) != null) {
          throw new ReflectiveOperationException("duplicate owner field");
        }
      } catch (Throwable error) {
        throw catalogFailure("catalog_owner_field_" + index + memberSuffix(error), error);
      }
    }
    Map<String, Field> supportFields = new HashMap<>();
    for (int index = 0; index < ExactCatalog.SUPPORT_FIELDS.length; index++) {
      String[] row = ExactCatalog.SUPPORT_FIELDS[index];
      try {
        if (supportFields.put(row[0], resolveField(loader, row, 1)) != null) {
          throw new ReflectiveOperationException("duplicate support field role");
        }
      } catch (Throwable error) {
        throw catalogFailure("catalog_support_field_" + index + memberSuffix(error), error);
      }
    }
    Map<String, Field> platformFields = new HashMap<>();
    for (int index = 0; index < ExactCatalog.PLATFORM_FIELDS.length; index++) {
      String[] row = ExactCatalog.PLATFORM_FIELDS[index];
      try {
        if (platformFields.put(row[0], resolveField(null, row, 1)) != null) {
          throw new ReflectiveOperationException("duplicate platform field role");
        }
      } catch (Throwable error) {
        throw catalogFailure("catalog_platform_field_" + index + memberSuffix(error), error);
      }
    }
    return new ResolvedCatalog(
        service,
        loader,
        hooks,
        Map.copyOf(supportMethods),
        Map.copyOf(platformMethods),
        Map.copyOf(ownerFields),
        Map.copyOf(supportFields),
        Map.copyOf(platformFields));
  }

  private static Method resolveMethod(ClassLoader loader, String[] row, int offset)
      throws ReflectiveOperationException {
    Class<?> declaring;
    try {
      declaring = Class.forName(row[offset], false, loader);
    } catch (Throwable error) {
      throw memberFailure("declaring_class", error);
    }
    Class<?>[] parameters = new Class<?>[row.length - offset - 3];
    for (int index = offset + 3; index < row.length; index++) {
      try {
        parameters[index - offset - 3] = resolveType(loader, row[index]);
      } catch (Throwable error) {
        throw memberFailure("parameter_" + (index - offset - 3), error);
      }
    }
    Method method;
    try {
      method = declaring.getDeclaredMethod(row[offset + 1], parameters);
    } catch (Throwable error) {
      throw memberFailure("lookup", error);
    }
    Class<?> returnType;
    try {
      returnType = resolveType(loader, row[offset + 2]);
    } catch (Throwable error) {
      throw memberFailure("return_type", error);
    }
    if (method.getDeclaringClass() != declaring) {
      throw new CatalogMemberFailure(
          "declaring_identity", new ReflectiveOperationException("method identity mismatch"));
    }
    if (method.getReturnType() != returnType) {
      throw new CatalogMemberFailure(
          "return_identity", new ReflectiveOperationException("method identity mismatch"));
    }
    try {
      method.setAccessible(true);
    } catch (Throwable error) {
      throw memberFailure("access_error", error);
    }
    return method;
  }

  private static Field resolveField(ClassLoader loader, String[] row, int offset)
      throws ReflectiveOperationException {
    Class<?> declaring = Class.forName(row[offset], false, loader);
    Field field = declaring.getDeclaredField(row[offset + 1]);
    int expectedModifiers = Integer.parseInt(row[offset + 3]);
    if (field.getDeclaringClass() != declaring
        || field.getType() != resolveType(loader, row[offset + 2])
        || (field.getModifiers() & ExactCatalog.FIELD_MODIFIER_MASK) != expectedModifiers) {
      throw new ReflectiveOperationException("field identity mismatch");
    }
    field.setAccessible(true);
    return field;
  }

  private static Class<?> resolveType(ClassLoader loader, String name)
      throws ClassNotFoundException {
    return switch (name) {
      case "boolean" -> Boolean.TYPE;
      case "byte" -> Byte.TYPE;
      case "char" -> Character.TYPE;
      case "double" -> Double.TYPE;
      case "float" -> Float.TYPE;
      case "int" -> Integer.TYPE;
      case "long" -> Long.TYPE;
      case "short" -> Short.TYPE;
      case "void" -> Void.TYPE;
      default -> Class.forName(name, false, loader);
    };
  }

  private static Object invokeExact(Method method, Object receiver, Object... parameters)
      throws Throwable {
    try {
      return method.invoke(receiver, parameters);
    } catch (InvocationTargetException error) {
      throw error.getCause();
    }
  }

  private static Method requiredMethod(Map<String, Method> methods, String role) {
    Method method = methods.get(role);
    if (method == null) {
      throw new IllegalStateException("missing exact support method");
    }
    return method;
  }

  private static Field requiredField(Map<String, Field> fields, String role) {
    Field field = fields.get(role);
    if (field == null) {
      throw new IllegalStateException("missing exact support field");
    }
    return field;
  }

  private static Method requiredBackup(int hookId) {
    Method method = BACKUPS[hookId];
    if (method == null) {
      throw new IllegalStateException("missing exact backup");
    }
    return method;
  }

  private static boolean validSynchronousShape(int hookId, Object[] args) {
    if (args == null) {
      return false;
    }
    return switch (hookId) {
      case 0 -> args.length == 4 && args[1] instanceof Network && args[2] instanceof String;
      case 1 -> args.length == 2 && args[1] instanceof Network;
      case 2, 5 -> args.length == 1;
      case 3 -> args.length == 2 && args[1] instanceof Integer;
      case 4 ->
          args.length == 4
              && args[1] instanceof Network
              && args[2] instanceof Integer
              && args[3] instanceof Boolean;
      case 6 -> args.length == 2 && (args[1] == null || args[1] instanceof Network);
      default -> false;
    };
  }

  private static boolean validIngressShape(int hookId, Object[] args) {
    if (hookId < 7 || hookId > 11 || args == null) {
      return false;
    }
    int payloadIndex = ExactCatalog.INGRESS_PAYLOAD_INDEXES[hookId];
    if (payloadIndex <= 0
        || args.length != ExactCatalog.HOOKS[hookId].length - 3
        || payloadIndex >= args.length) {
      return false;
    }
    Object payload = args[payloadIndex];
    if (payload == null) {
      return ExactCatalog.INGRESS_NULLABLE_PAYLOADS[hookId];
    }
    return switch (ExactCatalog.INGRESS_PAYLOAD_KINDS[hookId]) {
      case 1 -> payload instanceof NetworkCapabilities;
      case 2 -> payload instanceof NetworkRequest;
      default -> false;
    };
  }

  private static boolean validEgressShape(int hookId, Object[] args) {
    if (hookId < 12 || hookId > 13 || args == null) {
      return false;
    }
    int ownerIndex = ExactCatalog.EGRESS_OWNER_INDEXES[hookId];
    int sourceIndex = ExactCatalog.EGRESS_SOURCE_INDEXES[hookId];
    return args.length == ExactCatalog.HOOKS[hookId].length - 3
        && ownerIndex > 0
        && ownerIndex < args.length
        && sourceIndex > 0
        && sourceIndex < args.length
        && args[ownerIndex] != null;
  }

  private static final class State {
    final ResolvedCatalog catalog;

    State(ResolvedCatalog catalog) {
      this.catalog = catalog;
    }
  }

  private static final class ResolvedCatalog {
    final Object service;
    final ClassLoader loader;
    final Method[] hooks;
    final Map<String, Method> supportMethods;
    final Map<String, Method> platformMethods;
    final Map<String, Field> ownerFields;
    final Map<String, Field> supportFields;
    final Map<String, Field> platformFields;

    ResolvedCatalog(
        Object service,
        ClassLoader loader,
        Method[] hooks,
        Map<String, Method> supportMethods,
        Map<String, Method> platformMethods,
        Map<String, Field> ownerFields,
        Map<String, Field> supportFields,
        Map<String, Field> platformFields) {
      this.service = service;
      this.loader = loader;
      this.hooks = hooks.clone();
      this.supportMethods = supportMethods;
      this.platformMethods = platformMethods;
      this.ownerFields = ownerFields;
      this.supportFields = supportFields;
      this.platformFields = platformFields;
    }
  }

  private static final class Donor {
    final Object agent;
    final Network network;

    Donor(Object agent, Network network) {
      this.agent = agent;
      this.network = network;
    }
  }
}
