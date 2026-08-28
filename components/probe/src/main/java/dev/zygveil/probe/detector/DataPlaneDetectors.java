// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe.detector;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URL;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.HttpsURLConnection;
import org.json.JSONException;
import org.json.JSONObject;

final class DataPlaneDetectors {
  private static final String HOST = "connectivitycheck.gstatic.com";
  private static final String ENDPOINT = "https://connectivitycheck.gstatic.com/generate_204";

  private DataPlaneDetectors() {}

  static void run(RunConfig config, ResultStore store) throws IOException, JSONException {
    boolean dnsReady = recordDns(config, store);
    boolean httpsReady = recordTlsHttps(config, store, dnsReady);
    store.detector(
        config,
        "data_plane.lifecycle",
        true,
        dnsReady && httpsReady ? ProbeStatus.NEGATIVE : ProbeStatus.ERROR,
        new JSONObject().put("complete", dnsReady && httpsReady),
        null,
        0,
        "complete");
  }

  private static boolean recordDns(RunConfig config, ResultStore store)
      throws IOException, JSONException {
    long started = System.nanoTime();
    boolean resolved = false;
    try {
      resolved = InetAddress.getAllByName(HOST).length > 0;
    } catch (IOException | RuntimeException ignored) {
      // The evidence records only the bounded outcome, never resolver data or the queried name.
    }
    store.detector(
        config,
        "data_plane.dns",
        true,
        resolved ? ProbeStatus.NEGATIVE : ProbeStatus.ERROR,
        new JSONObject().put("resolved", resolved),
        null,
        elapsed(started),
        "complete");
    return resolved;
  }

  private static boolean recordTlsHttps(RunConfig config, ResultStore store, boolean dnsReady)
      throws IOException, JSONException {
    long started = System.nanoTime();
    boolean tlsEstablished = false;
    boolean noContent = false;
    HttpsURLConnection connection = null;
    if (dnsReady) {
      try {
        connection = (HttpsURLConnection) new URL(ENDPOINT).openConnection();
        connection.setConnectTimeout(15_000);
        connection.setReadTimeout(15_000);
        connection.setInstanceFollowRedirects(false);
        connection.setUseCaches(false);
        connection.setRequestMethod("GET");
        noContent = connection.getResponseCode() == HttpsURLConnection.HTTP_NO_CONTENT;
        tlsEstablished = connection.getCipherSuite() != null;
      } catch (IOException | RuntimeException ignored) {
        // Do not retain endpoint, resolver, TLS, or provider exception text.
      } finally {
        if (connection != null) {
          connection.disconnect();
        }
      }
    }
    boolean passed = tlsEstablished && noContent;
    store.detector(
        config,
        "data_plane.tls_https",
        true,
        passed ? ProbeStatus.NEGATIVE : ProbeStatus.ERROR,
        new JSONObject()
            .put("tls_session_established", tlsEstablished)
            .put("https_no_content", noContent),
        null,
        elapsed(started),
        "complete");
    return passed;
  }

  private static long elapsed(long started) {
    return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
  }
}
