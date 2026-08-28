// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.servervpn.policy;

public final class EgressDecision {
  private EgressDecision() {}

  public static <T> Result<T> decide(
      TargetAuthorization.Decision owner,
      boolean registrationCurrent,
      T source,
      boolean sourceVpn,
      DonorSelection.Selection<T> donor) {
    if (owner == null
        || !owner.authorized()
        || !registrationCurrent
        || source == null
        || !sourceVpn
        || donor == null
        || donor.outcome() != DonorSelection.Outcome.UNIQUE
        || donor.value() == null
        || donor.value() == source) {
      return Result.origin(source);
    }
    return Result.substitute(donor.value());
  }

  public enum Action {
    ORIGIN,
    SUBSTITUTE
  }

  public record Result<T>(Action action, T source) {
    private static <T> Result<T> origin(T source) {
      return new Result<>(Action.ORIGIN, source);
    }

    private static <T> Result<T> substitute(T source) {
      return new Result<>(Action.SUBSTITUTE, source);
    }
  }
}
