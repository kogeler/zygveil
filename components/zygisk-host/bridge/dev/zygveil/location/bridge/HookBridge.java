// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

package dev.zygveil.location.bridge;

import java.lang.reflect.Method;
import java.util.Arrays;

public final class HookBridge {
  private final int hookId;
  private final boolean staticTarget;
  private volatile Method backup;
  private volatile boolean failClosed;

  public HookBridge(int hookId, boolean staticTarget) {
    this.hookId = hookId;
    this.staticTarget = staticTarget;
  }

  public void setBackup(Method backup) {
    this.backup = backup;
  }

  public void activateFailClosed() {
    failClosed = true;
  }

  public void deactivateFailClosed() {
    failClosed = false;
  }

  public Object callback(Object[] args) {
    Method localBackup = backup;
    if (localBackup == null) {
      synchronized (this) {
        localBackup = backup;
      }
    }
    try {
      return dispatch(hookId, localBackup, args);
    } catch (Throwable ignored) {
      if (failClosed) {
        return null;
      }
      try {
        if (localBackup == null) {
          return null;
        }
        Object receiver = staticTarget ? null : args[0];
        Object[] parameters = staticTarget ? args : Arrays.copyOfRange(args, 1, args.length);
        return localBackup.invoke(receiver, parameters);
      } catch (Throwable ignoredAgain) {
        return null;
      }
    }
  }

  private static native Object dispatch(int hookId, Method backup, Object[] args);
}
