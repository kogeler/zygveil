// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.IBinder;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

abstract class BaseLocationProbeService extends Service {
  private static final String CHANNEL_ID = "location_probe_session";
  private final ExecutorService executor = Executors.newSingleThreadExecutor();

  protected abstract int notificationId();

  @Override
  public void onCreate() {
    super.onCreate();
    NotificationManager notifications = getSystemService(NotificationManager.class);
    NotificationChannel channel =
        new NotificationChannel(
            CHANNEL_ID,
            getString(R.string.location_probe_channel),
            NotificationManager.IMPORTANCE_LOW);
    channel.setShowBadge(false);
    notifications.createNotificationChannel(channel);
  }

  @Override
  public int onStartCommand(Intent intent, int flags, int startId) {
    Notification notification =
        new Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_probe)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.location_probe_running))
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .build();
    startForeground(notificationId(), notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION);
    executor.execute(
        () -> {
          try {
            ProbeCoordinator.execute(this, intent);
          } finally {
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf(startId);
          }
        });
    return START_NOT_STICKY;
  }

  @Override
  public IBinder onBind(Intent intent) {
    return null;
  }

  @Override
  public void onDestroy() {
    executor.shutdownNow();
    super.onDestroy();
  }
}
