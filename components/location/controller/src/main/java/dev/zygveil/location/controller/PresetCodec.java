// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.location.controller;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class PresetCodec {
  static final int MAXIMUM_PRESETS = 20;
  static final int MAXIMUM_BYTES = 16 * 1024;
  private static final int MAGIC = 0x47504331;
  private static final int SCHEMA_VERSION = 1;

  private PresetCodec() {}

  public record Preset(String name, CoordinateInput.Values values) {
    public Preset {
      Objects.requireNonNull(name);
      Objects.requireNonNull(values);
    }
  }

  public static Preset create(String name, CoordinateInput.Values values) throws CodecException {
    validateName(name);
    return new Preset(name, values);
  }

  public static byte[] encode(List<Preset> presets) throws CodecException {
    if (presets.size() > MAXIMUM_PRESETS) {
      throw new CodecException("preset_limit");
    }
    try {
      ByteArrayOutputStream bytes = new ByteArrayOutputStream();
      try (DataOutputStream output = new DataOutputStream(bytes)) {
        output.writeInt(MAGIC);
        output.writeInt(SCHEMA_VERSION);
        output.writeInt(presets.size());
        for (Preset preset : presets) {
          validateName(preset.name());
          output.writeUTF(preset.name());
          output.writeUTF(preset.values().latitude());
          output.writeUTF(preset.values().longitude());
          output.writeUTF(preset.values().altitudeEllipsoid());
          output.writeUTF(preset.values().altitudeMsl());
        }
      }
      byte[] encoded = bytes.toByteArray();
      if (encoded.length > MAXIMUM_BYTES) {
        throw new CodecException("preset_size");
      }
      return encoded;
    } catch (IOException error) {
      throw new CodecException("preset_encode");
    }
  }

  public static List<Preset> decode(byte[] encoded) throws CodecException {
    if (encoded.length == 0 || encoded.length > MAXIMUM_BYTES) {
      throw new CodecException("preset_size");
    }
    try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(encoded))) {
      if (input.readInt() != MAGIC || input.readInt() != SCHEMA_VERSION) {
        throw new CodecException("preset_schema");
      }
      int count = input.readInt();
      if (count < 0 || count > MAXIMUM_PRESETS) {
        throw new CodecException("preset_limit");
      }
      List<Preset> presets = new ArrayList<>(count);
      for (int index = 0; index < count; index++) {
        String name = input.readUTF();
        validateName(name);
        CoordinateInput.Values values =
            CoordinateInput.parse(
                input.readUTF(), input.readUTF(), input.readUTF(), input.readUTF(), '.');
        presets.add(new Preset(name, values));
      }
      if (input.read() != -1) {
        throw new CodecException("preset_trailing_data");
      }
      return List.copyOf(presets);
    } catch (CoordinateInput.InvalidInput | EOFException error) {
      throw new CodecException("preset_data");
    } catch (IOException error) {
      throw new CodecException("preset_decode");
    }
  }

  private static void validateName(String name) throws CodecException {
    if (name == null || name.isBlank() || name.length() > 32 || !name.equals(name.trim())) {
      throw new CodecException("preset_name");
    }
    for (int index = 0; index < name.length(); index++) {
      char character = name.charAt(index);
      if (character < 0x20 || character > 0x7e) {
        throw new CodecException("preset_name");
      }
    }
  }

  public static final class CodecException extends Exception {
    private static final long serialVersionUID = 1L;

    CodecException(String code) {
      super(code);
    }
  }
}
