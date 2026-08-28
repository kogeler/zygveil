// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.module;

import android.content.pm.ApplicationInfo;
import android.util.Log;
import io.github.libxposed.api.XposedModule;
import java.util.Set;

public final class ZygVeilModule extends XposedModule {
  public static final String TAG = "ZygVeil";
  private static final Set<String> EXCLUDED_PACKAGES =
      Set.of("dev.zygveil.module", "com.wireguard.android", "com.topjohnwu.magisk");

  private final HookInstaller hookInstaller = new HookInstaller(this);

  @Override
  public void onModuleLoaded(ModuleLoadedParam param) {
    logLifecycle(
        "event=module_loaded process="
            + param.getProcessName()
            + " api="
            + getApiVersion()
            + " framework="
            + getFrameworkName()
            + " version="
            + getFrameworkVersion()
            + " version_code="
            + getFrameworkVersionCode()
            + " properties="
            + getFrameworkProperties());
  }

  @Override
  public void onPackageLoaded(PackageLoadedParam param) {
    if (!param.isFirstPackage() || isExcluded(param)) {
      return;
    }
    boolean installed =
        hookInstaller.install(param.getDefaultClassLoader(), param.getPackageName());
    logLifecycle(
        "event=hook_install package="
            + param.getPackageName()
            + " status="
            + (installed ? "installed" : "origin_only")
            + " count="
            + hookInstaller.installedCount());
  }

  private static boolean isExcluded(PackageLoadedParam param) {
    int flags = param.getApplicationInfo().flags;
    boolean system =
        (flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0;
    return system || EXCLUDED_PACKAGES.contains(param.getPackageName());
  }

  void logHookEvent(String message) {
    log(Log.WARN, TAG, message);
    Log.w(TAG, message);
  }

  private void logLifecycle(String message) {
    log(Log.INFO, TAG, message);
    Log.i(TAG, message);
  }
}
