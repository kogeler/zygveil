// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.servervpn.policy;

import java.util.List;

public final class DonorSelection {
  private DonorSelection() {}

  public static <T> Selection<T> select(
      List<Candidate<T>> declaredUnderlying, List<Candidate<T>> stableEnumeration) {
    if (declaredUnderlying != null && !declaredUnderlying.isEmpty()) {
      Selection<T> declared = selectUnique(declaredUnderlying, Source.DECLARED_UNDERLYING);
      return declared.outcome() == Outcome.UNIQUE
          ? declared
          : Selection.ambiguous(Source.DECLARED_UNDERLYING);
    }
    return selectUnique(stableEnumeration, Source.STABLE_ENUMERATION);
  }

  private static <T> Selection<T> selectUnique(List<Candidate<T>> candidates, Source source) {
    if (candidates == null) {
      return Selection.none(source);
    }
    T selected = null;
    for (Candidate<T> candidate : candidates) {
      if (candidate == null || !candidate.eligible()) {
        continue;
      }
      if (selected != null) {
        return Selection.ambiguous(source);
      }
      selected = candidate.value();
    }
    return selected == null ? Selection.none(source) : Selection.unique(source, selected);
  }

  public record Candidate<T>(
      T value,
      boolean sameNetwork,
      boolean current,
      boolean connected,
      boolean vpn,
      boolean notVpn,
      boolean internet,
      boolean validated) {
    private boolean eligible() {
      return value != null
          && !sameNetwork
          && current
          && connected
          && !vpn
          && notVpn
          && internet
          && validated;
    }
  }

  public enum Outcome {
    NONE,
    UNIQUE,
    AMBIGUOUS
  }

  public enum Source {
    DECLARED_UNDERLYING,
    STABLE_ENUMERATION
  }

  public record Selection<T>(Outcome outcome, Source source, T value) {
    private static <T> Selection<T> none(Source source) {
      return new Selection<>(Outcome.NONE, source, null);
    }

    private static <T> Selection<T> unique(Source source, T value) {
      return new Selection<>(Outcome.UNIQUE, source, value);
    }

    private static <T> Selection<T> ambiguous(Source source) {
      return new Selection<>(Outcome.AMBIGUOUS, source, null);
    }
  }
}
