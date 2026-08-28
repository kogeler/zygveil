// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.policy;

public final class MatcherPolicy {
  private MatcherPolicy() {}

  public static Plan plan(
      boolean capabilitiesPresent,
      boolean rawVpn,
      boolean requestHasNotVpn,
      boolean requestHasVpn,
      int requestTransportCount) {
    if (!capabilitiesPresent || !rawVpn) {
      return Plan.origin();
    }
    if (requestHasVpn && requestTransportCount <= 0) {
      throw new IllegalArgumentException("VPN request has no transport values");
    }
    if (requestHasVpn && requestTransportCount == 1) {
      return Plan.noMatch();
    }
    return Plan.transform(requestHasNotVpn, requestHasVpn);
  }

  public enum Action {
    ORIGIN,
    NO_MATCH,
    TRANSFORM
  }

  public static final class Plan {
    private final Action action;
    private final boolean removeNotVpn;
    private final boolean removeVpn;

    private Plan(Action action, boolean removeNotVpn, boolean removeVpn) {
      this.action = action;
      this.removeNotVpn = removeNotVpn;
      this.removeVpn = removeVpn;
    }

    public static Plan origin() {
      return new Plan(Action.ORIGIN, false, false);
    }

    public static Plan noMatch() {
      return new Plan(Action.NO_MATCH, false, false);
    }

    public static Plan transform(boolean removeNotVpn, boolean removeVpn) {
      return new Plan(Action.TRANSFORM, removeNotVpn, removeVpn);
    }

    public Action action() {
      return action;
    }

    public boolean removeNotVpn() {
      return removeNotVpn;
    }

    public boolean removeVpn() {
      return removeVpn;
    }
  }
}
