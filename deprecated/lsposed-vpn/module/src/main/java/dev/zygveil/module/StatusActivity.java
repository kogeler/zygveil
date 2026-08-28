// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.module;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import io.github.libxposed.service.XposedService;
import java.io.IOException;
import org.json.JSONException;

public final class StatusActivity extends Activity {
  static final String ACTION_CAPTURE_STATUS = "dev.zygveil.module.action.CAPTURE_STATUS";
  static final String EXTRA_CAPTURE_ID = "capture_id";

  private TextView status;

  @Override
  protected void onCreate(Bundle state) {
    super.onCreate(state);
    LinearLayout layout = new LinearLayout(this);
    layout.setOrientation(LinearLayout.VERTICAL);
    layout.setGravity(Gravity.CENTER_HORIZONTAL);
    layout.setPadding(48, 64, 48, 48);

    TextView title = new TextView(this);
    title.setText(R.string.app_name);
    title.setTextSize(24);
    layout.addView(title, fullWidth());

    status = new TextView(this);
    status.setTextIsSelectable(true);
    status.setText(FrameworkSnapshot.readSummary(this));
    status.setPadding(0, 40, 0, 40);
    layout.addView(status, fullWidth());

    setContentView(layout);

    handleIntent(getIntent());
  }

  @Override
  protected void onNewIntent(Intent intent) {
    super.onNewIntent(intent);
    setIntent(intent);
    handleIntent(intent);
  }

  private LinearLayout.LayoutParams fullWidth() {
    return new LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
  }

  private void handleIntent(Intent intent) {
    XposedService service = ModuleApplication.getService();
    if (service == null) {
      status.setText(R.string.framework_waiting);
      return;
    }
    try {
      String captureId = null;
      if (ACTION_CAPTURE_STATUS.equals(intent.getAction())) {
        captureId = intent.getStringExtra(EXTRA_CAPTURE_ID);
      }
      FrameworkSnapshot.writeBound(this, service, captureId);
      status.setText(FrameworkSnapshot.readSummary(this));
    } catch (IOException | JSONException | RuntimeException error) {
      status.setText(error.getClass().getSimpleName());
    }
  }
}
