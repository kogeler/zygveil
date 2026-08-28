// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

package dev.zygveil.servervpn.bridge;

import java.lang.reflect.Method;

public final class ServerVpnBridge {
  public static final int CATALOG_VERSION = 1;
  public static final int HOOK_COUNT = 14;

  private final int hookId;
  private final boolean staticTarget;
  private volatile Method backup;

  public ServerVpnBridge(int hookId, boolean staticTarget) {
    this.hookId = hookId;
    this.staticTarget = staticTarget;
  }

  public void setBackup(Method backup) {
    if (backup == null || this.backup != null) {
      throw new IllegalStateException("invalid backup assignment");
    }
    ServerVpnRuntime.registerBackup(hookId, backup);
    this.backup = backup;
  }

  public void activate() {
    if (backup == null) {
      throw new IllegalStateException("runtime is not ready for activation");
    }
    ServerVpnRuntime.activate();
  }

  public void deactivate() {
    ServerVpnRuntime.deactivate();
  }

  public Object callback(Object[] args) throws Throwable {
    Method localBackup = backup;
    if (localBackup == null) {
      synchronized (this) {
        localBackup = backup;
      }
    }
    if (ServerVpnRuntime.isActive() && localBackup != null) {
      return ServerVpnRuntime.dispatch(hookId, localBackup, args, staticTarget);
    }
    return ServerVpnRuntime.invokeBackup(localBackup, args, staticTarget);
  }

  public static String prepareRuntime() {
    return ServerVpnRuntime.prepare();
  }

  public static boolean configureRuntime() {
    return ServerVpnRuntime.configure();
  }

  public static Method[] resolvedHookMethods() {
    return ServerVpnRuntime.hookMethods();
  }

  public static boolean runtimeReadyForActivation() {
    return ServerVpnRuntime.readyForActivation();
  }

  public static void resetRuntime() {
    ServerVpnRuntime.reset();
  }
}
