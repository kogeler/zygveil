// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.module;

import android.app.Application;
import android.util.Log;
import io.github.libxposed.service.XposedService;
import io.github.libxposed.service.XposedServiceHelper;
import java.io.IOException;
import org.json.JSONException;

public final class ModuleApplication extends Application
    implements XposedServiceHelper.OnServiceListener {
  private static volatile XposedService service;

  @Override
  public void onCreate() {
    super.onCreate();
    XposedServiceHelper.registerListener(this);
    Log.i(ZygVeilModule.TAG, "event=service_listener_registered");
  }

  @Override
  public void onServiceBind(XposedService boundService) {
    service = boundService;
    try {
      FrameworkSnapshot.writeBound(this, boundService);
      Log.i(
          ZygVeilModule.TAG,
          "event=service_bound api="
              + boundService.getApiVersion()
              + " framework="
              + boundService.getFrameworkName()
              + " version="
              + boundService.getFrameworkVersion()
              + " version_code="
              + boundService.getFrameworkVersionCode()
              + " properties="
              + boundService.getFrameworkProperties()
              + " scope_count="
              + boundService.getScope().size());
    } catch (IOException | JSONException | RuntimeException error) {
      Log.e(ZygVeilModule.TAG, "event=service_snapshot_failed", error);
    }
  }

  @Override
  public void onServiceDied(XposedService deadService) {
    if (service == deadService) {
      service = null;
    }
    FrameworkSnapshot.writeDead(this);
    Log.w(ZygVeilModule.TAG, "event=service_died");
  }

  static XposedService getService() {
    return service;
  }
}
