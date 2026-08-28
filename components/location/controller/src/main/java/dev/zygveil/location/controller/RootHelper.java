// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.location.controller;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public final class RootHelper {
  static final String HELPER_PATH = "/data/adb/modules/zygveil/locationctl";
  static final String STATUS_COMMAND = HELPER_PATH + " status";
  static final String STATUS_UI_COMMAND = HELPER_PATH + " status-ui";
  static final String APPLY_COMMAND = HELPER_PATH + " apply";
  static final int MAXIMUM_INPUT_BYTES = 1024;
  static final int MAXIMUM_OUTPUT_BYTES = 16 * 1024;
  private static final long PROCESS_TIMEOUT_SECONDS = 8;
  private static final long READER_TIMEOUT_SECONDS = 1;

  private RootHelper() {}

  public enum Flow {
    STATUS,
    STATUS_UI,
    APPLY
  }

  public enum Failure {
    NONE,
    DENIED,
    MISSING_MODULE,
    TIMEOUT,
    CANCELLED,
    OUTPUT_LIMIT,
    PROTOCOL,
    IO
  }

  public record Result(HelperStatus status, Failure failure, int exitCode) {
    static Result failed(Failure failure) {
      return new Result(null, failure, -1);
    }
  }

  public static Result call(Flow flow, String helperInput) {
    String command = commandFor(flow);
    byte[] input = helperInput == null ? new byte[0] : helperInput.getBytes(StandardCharsets.UTF_8);
    if ((flow == Flow.APPLY) != (input.length > 0) || input.length > MAXIMUM_INPUT_BYTES) {
      Arrays.fill(input, (byte) 0);
      return Result.failed(Failure.PROTOCOL);
    }
    Process process = null;
    FutureTask<ReadResult> readerTask = null;
    try {
      ProcessBuilder builder = new ProcessBuilder("su", "-c", command);
      builder.redirectErrorStream(true);
      builder.environment().clear();
      process = builder.start();
      Process runningProcess = process;
      readerTask = new FutureTask<>(() -> readBounded(runningProcess.getInputStream()));
      Thread reader = new Thread(readerTask, "location-helper-output");
      reader.setDaemon(true);
      reader.start();
      try (OutputStream standardInput = process.getOutputStream()) {
        standardInput.write(input);
        standardInput.flush();
      }
      Arrays.fill(input, (byte) 0);
      if (!process.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
        destroy(process);
        return Result.failed(Failure.TIMEOUT);
      }
      ReadResult output = readerTask.get(READER_TIMEOUT_SECONDS, TimeUnit.SECONDS);
      if (output.exceededLimit()) {
        Arrays.fill(output.bytes(), (byte) 0);
        return Result.failed(Failure.OUTPUT_LIMIT);
      }
      int exitCode = process.exitValue();
      String response = new String(output.bytes(), StandardCharsets.UTF_8);
      Arrays.fill(output.bytes(), (byte) 0);
      try {
        HelperStatus status = HelperStatus.parse(response);
        if (!responseMatchesFlow(flow, status, exitCode)) {
          return new Result(null, Failure.PROTOCOL, exitCode);
        }
        if ("module_unavailable".equals(status.reason())) {
          return new Result(status, Failure.MISSING_MODULE, exitCode);
        }
        if ("unauthorized_invocation".equals(status.reason())) {
          return new Result(status, Failure.DENIED, exitCode);
        }
        return new Result(status, Failure.NONE, exitCode);
      } catch (HelperStatus.ProtocolException error) {
        return new Result(null, classifyUnparsedExit(exitCode), exitCode);
      }
    } catch (InterruptedException error) {
      Thread.currentThread().interrupt();
      if (process != null) {
        destroy(process);
      }
      return Result.failed(Failure.CANCELLED);
    } catch (ExecutionException | TimeoutException error) {
      if (process != null) {
        destroy(process);
      }
      return Result.failed(Failure.IO);
    } catch (IOException | SecurityException error) {
      if (process != null) {
        destroy(process);
      }
      return Result.failed(Failure.IO);
    } finally {
      Arrays.fill(input, (byte) 0);
      if (process != null) {
        closeQuietly(process.getInputStream());
        closeQuietly(process.getErrorStream());
        closeQuietly(process.getOutputStream());
      }
      if (readerTask != null && !readerTask.isDone()) {
        readerTask.cancel(true);
      }
    }
  }

  static String commandFor(Flow flow) {
    return switch (flow) {
      case STATUS -> STATUS_COMMAND;
      case STATUS_UI -> STATUS_UI_COMMAND;
      case APPLY -> APPLY_COMMAND;
    };
  }

  static boolean responseMatchesFlow(Flow flow, HelperStatus status, int exitCode) {
    if (flow != Flow.STATUS_UI && status.coordinates() != null) {
      return false;
    }
    if ("unauthorized_invocation".equals(status.reason())) {
      return exitCode == 5;
    }
    if ("module_unavailable".equals(status.reason())) {
      return exitCode == 3;
    }
    if (flow != Flow.APPLY) {
      return exitCode == 0;
    }
    boolean accepted =
        switch (status.controlState()) {
          case "applied", "saved_pending_upstream", "saved_pending_reboot" -> true;
          default -> false;
        };
    return accepted ? exitCode == 0 : exitCode >= 2 && exitCode <= 5;
  }

  private static Failure classifyUnparsedExit(int exitCode) {
    if (exitCode == 1) {
      return Failure.DENIED;
    }
    if (exitCode == 126 || exitCode == 127) {
      return Failure.MISSING_MODULE;
    }
    return Failure.PROTOCOL;
  }

  private static ReadResult readBounded(InputStream stream) throws IOException {
    byte[] output = new byte[MAXIMUM_OUTPUT_BYTES];
    byte[] buffer = new byte[1024];
    int size = 0;
    boolean exceeded = false;
    byte[] result;
    try {
      int count;
      while ((count = stream.read(buffer)) >= 0) {
        if (count == 0) {
          continue;
        }
        if (!exceeded && size + count <= MAXIMUM_OUTPUT_BYTES) {
          System.arraycopy(buffer, 0, output, size, count);
          size += count;
        } else {
          exceeded = true;
        }
        Arrays.fill(buffer, 0, count, (byte) 0);
      }
      result = Arrays.copyOf(output, size);
    } finally {
      Arrays.fill(buffer, (byte) 0);
      Arrays.fill(output, (byte) 0);
    }
    return new ReadResult(result, exceeded);
  }

  private static void destroy(Process process) {
    process.destroy();
    try {
      if (!process.waitFor(250, TimeUnit.MILLISECONDS)) {
        process.destroyForcibly();
        process.waitFor(250, TimeUnit.MILLISECONDS);
      }
    } catch (InterruptedException error) {
      Thread.currentThread().interrupt();
      process.destroyForcibly();
    }
  }

  private static void closeQuietly(AutoCloseable resource) {
    try {
      resource.close();
    } catch (Exception ignored) {
      // Process cleanup is best-effort after the result has already been classified.
    }
  }

  private record ReadResult(byte[] bytes, boolean exceededLimit) {}
}
