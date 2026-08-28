// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.policy;

import java.util.List;

public final class DonorPolicy {
  private DonorPolicy() {}

  public static <T> Selection<T> select(List<Candidate<T>> candidates) {
    T selected = null;
    if (candidates == null) {
      return Selection.none();
    }
    for (Candidate<T> candidate : candidates) {
      if (candidate == null || !candidate.eligible()) {
        continue;
      }
      if (selected != null) {
        return Selection.ambiguous();
      }
      selected = candidate.value;
    }
    return selected == null ? Selection.none() : Selection.unique(selected);
  }

  public static final class Candidate<T> {
    private final T value;
    private final boolean sameNetwork;
    private final boolean vpn;
    private final boolean notVpn;
    private final boolean internet;
    private final boolean validated;

    public Candidate(
        T value,
        boolean sameNetwork,
        boolean vpn,
        boolean notVpn,
        boolean internet,
        boolean validated) {
      this.value = value;
      this.sameNetwork = sameNetwork;
      this.vpn = vpn;
      this.notVpn = notVpn;
      this.internet = internet;
      this.validated = validated;
    }

    private boolean eligible() {
      return value != null && !sameNetwork && !vpn && notVpn && internet && validated;
    }
  }

  public static final class Selection<T> {
    public enum Outcome {
      NONE,
      UNIQUE,
      AMBIGUOUS
    }

    private final Outcome outcome;
    private final T value;

    private Selection(Outcome outcome, T value) {
      this.outcome = outcome;
      this.value = value;
    }

    public Outcome outcome() {
      return outcome;
    }

    public T value() {
      return value;
    }

    private static <T> Selection<T> none() {
      return new Selection<>(Outcome.NONE, null);
    }

    private static <T> Selection<T> unique(T value) {
      return new Selection<>(Outcome.UNIQUE, value);
    }

    private static <T> Selection<T> ambiguous() {
      return new Selection<>(Outcome.AMBIGUOUS, null);
    }
  }
}
