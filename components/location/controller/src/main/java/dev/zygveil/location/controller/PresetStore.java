// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.location.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.List;

final class PresetStore {
  private static final String FILE_NAME = "presets.v1";
  private static final String TEMPORARY_NAME = ".presets.v1.tmp";
  private final File directory;

  PresetStore(File directory) {
    this.directory = directory;
  }

  List<PresetCodec.Preset> load() throws StoreException {
    File source = new File(directory, FILE_NAME);
    if (!source.exists()) {
      return List.of();
    }
    if (!source.isFile() || source.length() <= 0 || source.length() > PresetCodec.MAXIMUM_BYTES) {
      throw new StoreException();
    }
    try (FileInputStream input = new FileInputStream(source)) {
      byte[] encoded = input.readNBytes(PresetCodec.MAXIMUM_BYTES + 1);
      try {
        if (encoded.length > PresetCodec.MAXIMUM_BYTES || input.read() != -1) {
          throw new StoreException();
        }
        return PresetCodec.decode(encoded);
      } finally {
        Arrays.fill(encoded, (byte) 0);
      }
    } catch (IOException | PresetCodec.CodecException error) {
      throw new StoreException();
    }
  }

  void save(List<PresetCodec.Preset> presets) throws StoreException {
    File temporary = new File(directory, TEMPORARY_NAME);
    File destination = new File(directory, FILE_NAME);
    byte[] encoded = null;
    boolean committed = false;
    try {
      encoded = PresetCodec.encode(presets);
      if (temporary.exists() && (!temporary.isFile() || !temporary.delete())) {
        throw new IOException("preset_temporary_invalid");
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
        throw new StoreException();
      }
      Files.move(
          temporary.toPath(),
          destination.toPath(),
          StandardCopyOption.ATOMIC_MOVE,
          StandardCopyOption.REPLACE_EXISTING);
      committed = true;
    } catch (IOException | PresetCodec.CodecException error) {
      throw new StoreException();
    } finally {
      if (encoded != null) {
        Arrays.fill(encoded, (byte) 0);
      }
      if (!committed) {
        temporary.delete();
      }
    }
  }

  static final class StoreException extends Exception {
    private static final long serialVersionUID = 1L;

    StoreException() {
      super("preset_store");
    }
  }
}
