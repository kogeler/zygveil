// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe.detector;

import android.content.Context;
import android.util.Log;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.EnumMap;
import java.util.Map;
import org.json.JSONException;
import org.json.JSONObject;

public final class ResultStore {
  private static final String TAG = "ZygVeilProbe";
  private final File destination;
  private final Map<ProbeStatus, Integer> counts = new EnumMap<>(ProbeStatus.class);
  private int detectorCount;
  private int mandatoryPositive;
  private int mandatoryNegative;
  private int mandatoryOther;

  public ResultStore(Context context, RunConfig config, boolean truncate) throws IOException {
    File directory = new File(context.getFilesDir(), "runs");
    if (!directory.isDirectory() && !directory.mkdirs()) {
      throw new IOException("could not create result directory");
    }
    destination = new File(directory, config.runId + ".jsonl");
    if (truncate && destination.exists() && !destination.delete()) {
      throw new IOException("could not reset prior result file");
    }
    if (truncate) {
      try (FileOutputStream stream = new FileOutputStream(destination, false)) {
        stream.getFD().sync();
      }
    }
    for (ProbeStatus status : ProbeStatus.values()) {
      counts.put(status, 0);
    }
  }

  public synchronized void detector(
      RunConfig config,
      String testId,
      boolean mandatory,
      ProbeStatus status,
      JSONObject raw,
      Throwable exception,
      long elapsedMs,
      String cleanupStatus)
      throws IOException, JSONException {
    append(
        ProbeRecord.detector(
            config, testId, mandatory, status, raw, exception, elapsedMs, cleanupStatus));
    detectorCount++;
    counts.put(status, counts.get(status) + 1);
    if (mandatory) {
      if (status == ProbeStatus.POSITIVE) {
        mandatoryPositive++;
      } else if (status == ProbeStatus.NEGATIVE && "complete".equals(cleanupStatus)) {
        mandatoryNegative++;
      } else {
        mandatoryOther++;
      }
    }
  }

  public synchronized String summary(RunConfig config, long elapsedMs)
      throws IOException, JSONException {
    String verdict;
    if (mandatoryPositive > 0) {
      verdict = "VPN_DETECTED";
    } else if (mandatoryOther == 0 && mandatoryNegative > 0) {
      verdict = "NO_PUBLIC_VPN_SIGNAL";
    } else {
      verdict = "INCONCLUSIVE";
    }
    JSONObject raw = new JSONObject();
    for (ProbeStatus status : ProbeStatus.values()) {
      raw.put(status.name(), counts.get(status));
    }
    raw.put("mandatory_positive", mandatoryPositive);
    raw.put("mandatory_negative", mandatoryNegative);
    raw.put("mandatory_other", mandatoryOther);
    append(ProbeRecord.summary(config, raw, verdict, detectorCount, elapsedMs));
    return verdict;
  }

  private void append(JSONObject record) throws IOException {
    String line = record.toString();
    try (FileOutputStream stream = new FileOutputStream(destination, true)) {
      stream.write((line + "\n").getBytes(StandardCharsets.UTF_8));
      stream.getFD().sync();
    }
    Log.i(TAG, line);
  }
}
