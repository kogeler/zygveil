// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.servervpn.policy;

public final class SnapshotProjection {
  private SnapshotProjection() {}

  public static <T> Result<T> project(
      boolean authorized,
      boolean rawVpn,
      T origin,
      DonorSelection.Selection<?> donor,
      BackupResult<T> donorBackup) {
    if (!authorized || !rawVpn || origin == null) {
      return Result.origin(origin);
    }
    if (donor == null
        || donor.outcome() != DonorSelection.Outcome.UNIQUE
        || donorBackup == null
        || !donorBackup.detached()
        || donorBackup.value() == null
        || donorBackup.value() == origin) {
      return Result.origin(origin);
    }
    return Result.substituted(donorBackup.value());
  }

  public record BackupResult<T>(T value, boolean detached) {}

  public enum Action {
    ORIGIN,
    SUBSTITUTE
  }

  public record Result<T>(Action action, T value) {
    private static <T> Result<T> origin(T value) {
      return new Result<>(Action.ORIGIN, value);
    }

    private static <T> Result<T> substituted(T value) {
      return new Result<>(Action.SUBSTITUTE, value);
    }
  }
}
