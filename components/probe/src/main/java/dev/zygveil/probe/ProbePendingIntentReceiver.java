// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import dev.zygveil.probe.detector.DetectorCatalog;
import dev.zygveil.probe.detector.PendingIntentSignal;
import dev.zygveil.probe.detector.RunConfig;
import dev.zygveil.probe.location.VariantGmsLocationClient;
import org.json.JSONObject;

public final class ProbePendingIntentReceiver extends BroadcastReceiver {
  @Override
  public void onReceive(Context context, Intent intent) {
    recordDelivery(context, intent);
  }

  static void recordDelivery(Context context, Intent intent) {
    if (VariantGmsLocationClient.handlePendingIntent(context, intent)) {
      return;
    }
    RunConfig config = RunConfig.fromIntent(context, intent);
    String testId = intent.getStringExtra("test_id");
    try {
      Network network = intent.getParcelableExtra(ConnectivityManager.EXTRA_NETWORK, Network.class);
      NetworkRequest request =
          intent.getParcelableExtra(
              ConnectivityManager.EXTRA_NETWORK_REQUEST, NetworkRequest.class);
      ConnectivityManager manager = context.getSystemService(ConnectivityManager.class);
      NetworkCapabilities capabilities =
          manager == null || network == null ? null : manager.getNetworkCapabilities(network);
      boolean vpn =
          capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
      JSONObject raw =
          new JSONObject()
              .put("network_present", network != null)
              .put("request_present", request != null)
              .put("vpn_transport", vpn);
      if (request != null) {
        raw.put("request", DetectorCatalog.requestObservation(request, config));
      }
      PendingIntentSignal.complete(
          config.runId, testId == null ? "pending.unknown" : testId, raw, vpn);
    } catch (Exception error) {
      throw new IllegalStateException("could not record PendingIntent delivery", error);
    }
  }
}
