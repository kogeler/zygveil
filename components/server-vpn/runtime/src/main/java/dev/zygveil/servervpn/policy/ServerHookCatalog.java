// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.servervpn.policy;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class ServerHookCatalog {
  public static final List<Hook> HOOKS =
      List.of(
          hook("sync.network_capabilities", Boundary.SYNCHRONOUS, Phase.AFTER),
          hook("sync.link_properties", Boundary.SYNCHRONOUS, Phase.AFTER),
          hook("sync.legacy_active", Boundary.SYNCHRONOUS, Phase.AFTER),
          hook("sync.legacy_type", Boundary.SYNCHRONOUS, Phase.AFTER),
          hook("sync.legacy_network", Boundary.SYNCHRONOUS, Phase.AFTER),
          hook("sync.legacy_all", Boundary.SYNCHRONOUS, Phase.AFTER),
          hook("sync.default_proxy", Boundary.SYNCHRONOUS, Phase.AFTER),
          hook("ingress.listen", Boundary.INGRESS, Phase.BEFORE),
          hook("ingress.pending_listen", Boundary.INGRESS, Phase.BEFORE),
          hook("ingress.pending_request", Boundary.INGRESS, Phase.BEFORE),
          hook("ingress.request", Boundary.INGRESS, Phase.BEFORE),
          hook("ingress.connectivity_diagnostics", Boundary.INGRESS, Phase.BEFORE),
          hook("egress.callback", Boundary.EGRESS, Phase.BEFORE),
          hook("egress.pending_intent", Boundary.EGRESS, Phase.BEFORE));

  static {
    validate();
  }

  private ServerHookCatalog() {}

  private static Hook hook(String id, Boundary boundary, Phase phase) {
    return new Hook(id, boundary, phase);
  }

  private static void validate() {
    if (HOOKS.size() != 14) {
      throw new IllegalStateException("server hook catalog size is not 14");
    }
    Set<String> identifiers = new HashSet<>();
    int synchronous = 0;
    int ingress = 0;
    int egress = 0;
    for (Hook hook : HOOKS) {
      if (!identifiers.add(hook.id())) {
        throw new IllegalStateException("duplicate server hook ID: " + hook.id());
      }
      switch (hook.boundary()) {
        case SYNCHRONOUS -> synchronous++;
        case INGRESS -> ingress++;
        case EGRESS -> egress++;
      }
    }
    if (synchronous != 7 || ingress != 5 || egress != 2) {
      throw new IllegalStateException("server hook boundary counts are invalid");
    }
  }

  public enum Boundary {
    SYNCHRONOUS,
    INGRESS,
    EGRESS
  }

  public enum Phase {
    BEFORE,
    AFTER
  }

  public record Hook(String id, Boundary boundary, Phase phase) {}
}
