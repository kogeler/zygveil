// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public final class SecondaryProbePendingIntentReceiver extends BroadcastReceiver {
  @Override
  public void onReceive(Context context, Intent intent) {
    ProbePendingIntentReceiver.recordDelivery(context, intent);
  }
}
