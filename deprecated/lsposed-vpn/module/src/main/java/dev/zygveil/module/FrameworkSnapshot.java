// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.module;

import android.content.Context;
import io.github.libxposed.service.HookedTarget;
import io.github.libxposed.service.XposedService;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

final class FrameworkSnapshot {
  private FrameworkSnapshot() {}

  static void writeBound(Context context, XposedService service) throws IOException, JSONException {
    writeBound(context, service, null);
  }

  static void writeBound(Context context, XposedService service, String captureId)
      throws IOException, JSONException {
    JSONObject json = serviceJson(service, "bound");
    if (captureId != null && !captureId.isBlank()) {
      json.put("capture_id", captureId);
    }
    JSONArray targets = new JSONArray();
    try {
      for (HookedTarget target : service.getRunningTargets()) {
        JSONObject item = new JSONObject();
        item.put("uid", target.getUid());
        item.put("pid", target.getPid());
        item.put("process", target.getProcessName());
        item.put("state", target.getState().name());
        item.put("loaded_version_code", target.getLoadedVersionCode());
        targets.put(item);
      }
      json.put("running_targets", targets);
      json.put("running_target_count", targets.length());
    } catch (RuntimeException error) {
      json.put("running_targets_error", error.getClass().getSimpleName());
    }
    write(context, json);
  }

  private static JSONObject serviceJson(XposedService service, String state) throws JSONException {
    JSONObject json = new JSONObject();
    json.put("schema_version", 3);
    json.put("state", state);
    json.put("api_version", service.getApiVersion());
    json.put("framework_name", service.getFrameworkName());
    json.put("framework_version", service.getFrameworkVersion());
    json.put("framework_version_code", service.getFrameworkVersionCode());
    json.put("framework_properties", service.getFrameworkProperties());
    json.put("scope", new JSONArray(service.getScope()));
    json.put("scope_count", service.getScope().size());
    return json;
  }

  static void writeDead(Context context) {
    JSONObject json = new JSONObject();
    try {
      json.put("schema_version", 3);
      json.put("state", "dead");
      write(context, json);
    } catch (IOException | JSONException ignored) {
      // The framework log remains the secondary death signal.
    }
  }

  static String read(Context context) {
    File file = new File(context.getFilesDir(), "framework.json");
    if (!file.isFile()) {
      return "{\"schema_version\":3,\"state\":\"waiting\"}";
    }
    try {
      return new String(java.nio.file.Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
    } catch (IOException error) {
      return "{\"schema_version\":3,\"state\":\"read_error\"}";
    }
  }

  static String readSummary(Context context) {
    try {
      JSONObject json = new JSONObject(read(context));
      StringBuilder summary = new StringBuilder(json.optString("state", "unknown"));
      for (String key : List.of("scope_count", "running_target_count")) {
        if (json.has(key)) {
          summary.append('\n').append(key).append('=').append(json.opt(key));
        }
      }
      if (json.has("error")) {
        summary.append('\n').append("error=").append(json.optString("error"));
      }
      return summary.toString();
    } catch (JSONException error) {
      return "read_error";
    }
  }

  private static synchronized void write(Context context, JSONObject json) throws IOException {
    File destination = new File(context.getFilesDir(), "framework.json");
    File temporary = new File(context.getFilesDir(), "framework.json.tmp");
    try (FileOutputStream stream = new FileOutputStream(temporary)) {
      stream.write((json.toString() + "\n").getBytes(StandardCharsets.UTF_8));
      stream.getFD().sync();
    }
    if (!temporary.renameTo(destination)) {
      throw new IOException("could not publish framework snapshot");
    }
  }
}
