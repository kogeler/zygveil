// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe.location;

import android.content.Context;
import dev.zygveil.probe.detector.RunConfig;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.json.JSONException;
import org.json.JSONObject;

final class LocationResultStore {
  private final File destination;
  private IOException writeFailure;

  LocationResultStore(Context context, RunConfig config) throws IOException {
    File directory = new File(context.getFilesDir(), "runs");
    if (!directory.isDirectory() && !directory.mkdirs()) {
      throw new IOException("could not create result directory");
    }
    destination = new File(directory, config.runId + ".jsonl");
    if (destination.exists() && !destination.delete()) {
      throw new IOException("could not reset prior result file");
    }
  }

  synchronized void observation(
      RunConfig config, String observationType, String source, String status, JSONObject payload) {
    if (writeFailure != null) {
      return;
    }
    try {
      append(LocationRecord.observation(config, observationType, source, status, payload, false));
    } catch (IOException | JSONException error) {
      writeFailure =
          error instanceof IOException
              ? (IOException) error
              : new IOException("could not serialize location observation", error);
    }
  }

  synchronized void summary(RunConfig config, String status, JSONObject payload)
      throws IOException, JSONException {
    if (writeFailure != null) {
      throw writeFailure;
    }
    append(
        LocationRecord.observation(config, "location_summary", "session", status, payload, true));
  }

  private void append(JSONObject record) throws IOException {
    try (FileOutputStream stream = new FileOutputStream(destination, true)) {
      stream.write((record.toString() + "\n").getBytes(StandardCharsets.UTF_8));
      stream.getFD().sync();
    }
  }
}
