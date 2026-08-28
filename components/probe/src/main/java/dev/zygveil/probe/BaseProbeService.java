// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe;

import android.app.Service;
import android.content.Intent;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

abstract class BaseProbeService extends Service {
  private final ExecutorService executor = Executors.newSingleThreadExecutor();

  @Override
  public final int onStartCommand(Intent intent, int flags, int startId) {
    if (intent.getBooleanExtra(ProbeActivity.EXTRA_LOAD_ONLY, false)) {
      new Handler(Looper.getMainLooper()).postDelayed(() -> stopSelf(startId), 30_000);
      return START_NOT_STICKY;
    }
    executor.execute(
        () -> {
          try {
            ProbeCoordinator.execute(this, intent);
          } finally {
            stopSelf(startId);
          }
        });
    return START_NOT_STICKY;
  }

  @Override
  public final IBinder onBind(Intent intent) {
    return null;
  }

  @Override
  public void onDestroy() {
    executor.shutdownNow();
    super.onDestroy();
  }
}
