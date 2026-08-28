// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.location.controller;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.Locale;
import java.util.UUID;

final class RootStatusStore {
  static final String FILE_NAME = "controller-root-status.properties";
  private static final String TEMPORARY_NAME = ".controller-root-status.tmp";

  private RootStatusStore() {}

  static void write(File directory, RootHelper.Result result) throws IOException {
    String body = render(UUID.randomUUID().toString(), System.currentTimeMillis(), result);
    byte[] encoded = body.getBytes(StandardCharsets.US_ASCII);
    File temporary = new File(directory, TEMPORARY_NAME);
    File destination = new File(directory, FILE_NAME);
    boolean committed = false;
    try {
      if (temporary.exists() && (!temporary.isFile() || !temporary.delete())) {
        throw new IOException("root_status_temporary_invalid");
      }
      try (FileOutputStream output = new FileOutputStream(temporary, false)) {
        output.write(encoded);
        output.flush();
        output.getFD().sync();
      }
      if (!temporary.setReadable(false, false)
          || !temporary.setWritable(false, false)
          || !temporary.setReadable(true, true)
          || !temporary.setWritable(true, true)) {
        throw new IOException("root_status_mode_failed");
      }
      Files.move(
          temporary.toPath(),
          destination.toPath(),
          StandardCopyOption.ATOMIC_MOVE,
          StandardCopyOption.REPLACE_EXISTING);
      committed = true;
    } catch (IOException error) {
      throw new IOException("root_status_write_failed");
    } finally {
      Arrays.fill(encoded, (byte) 0);
      if (!committed) {
        temporary.delete();
      }
    }
  }

  static String render(String requestId, long wallTimeMs, RootHelper.Result result) {
    if (!requestId.matches("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}") || wallTimeMs <= 0) {
      throw new IllegalArgumentException("root_status_identity_invalid");
    }
    HelperStatus status = result.status();
    return "schema_version=1\n"
        + "request_id="
        + requestId
        + "\nwall_time_ms="
        + wallTimeMs
        + "\ntransport_status="
        + result.failure().name().toLowerCase(Locale.ROOT)
        + "\nhelper_status_present="
        + (status != null)
        + "\nmodule_state="
        + (status == null ? "unavailable" : status.moduleState())
        + "\nruntime_state="
        + (status == null ? "unavailable" : status.runtimeState())
        + "\ncontrol_state="
        + (status == null ? "unavailable" : status.controlState())
        + "\nreason="
        + (status == null ? "unavailable" : status.reason())
        + "\nboot_config_generation="
        + (status == null ? "0" : status.bootGeneration())
        + "\npersisted_generation="
        + (status == null ? "0" : status.persistedGeneration())
        + "\npublished_generation="
        + (status == null ? "0" : status.publishedGeneration())
        + "\napplied_generation="
        + (status == null ? "0" : status.appliedGeneration())
        + "\ncoordinates=absent\n";
  }
}
