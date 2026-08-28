// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.TextView;
import dev.zygveil.probe.detector.RunConfig;

public final class ProbeActivity extends Activity {
  public static final String EXTRA_LOAD_ONLY = "load_only";
  private TextView status;

  @Override
  protected void onCreate(Bundle state) {
    super.onCreate(state);
    status = new TextView(this);
    status.setGravity(Gravity.CENTER);
    status.setTextSize(20);
    status.setText(R.string.probe_idle);
    setContentView(status);
    dispatch(getIntent());
  }

  @Override
  protected void onNewIntent(Intent intent) {
    super.onNewIntent(intent);
    setIntent(intent);
    dispatch(intent);
  }

  private void dispatch(Intent intent) {
    if (intent.getBooleanExtra(EXTRA_LOAD_ONLY, false)) {
      Intent serviceIntent = new Intent(intent).setClass(this, SecondaryProbeService.class);
      startService(serviceIntent);
      status.setText(R.string.probe_processes_ready);
      return;
    }
    if (intent.hasExtra("run_id")) {
      status.setText(R.string.probe_running);
      String group = intent.getStringExtra(RunConfig.EXTRA_GROUP);
      if ("location".equals(group)) {
        Intent serviceIntent = new Intent(intent).setClass(this, LocationProbeService.class);
        startForegroundService(serviceIntent);
      } else if ("secondary-location".equals(group)) {
        Intent serviceIntent =
            new Intent(intent).setClass(this, SecondaryLocationProbeService.class);
        serviceIntent.putExtra(RunConfig.EXTRA_GROUP, "location");
        startForegroundService(serviceIntent);
      } else if (group != null && group.startsWith("secondary-")) {
        Intent serviceIntent = new Intent(intent).setClass(this, SecondaryProbeService.class);
        serviceIntent.putExtra(RunConfig.EXTRA_GROUP, group.substring("secondary-".length()));
        startService(serviceIntent);
      } else {
        Intent serviceIntent = new Intent(intent).setClass(this, ProbeService.class);
        startService(serviceIntent);
      }
    }
  }
}
