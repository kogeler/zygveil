// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.location.controller;

import java.util.Locale;

public record ControllerState(Tone tone, String reason) {
  public enum Tone {
    IDLE,
    LOADING,
    APPLIED,
    PENDING_UPSTREAM,
    PENDING_REBOOT,
    RECOVERY_REQUIRED,
    REJECTED,
    WAITING,
    INACTIVE,
    DENIED,
    MISSING,
    TIMEOUT,
    CANCELLED,
    PROTOCOL,
    IO
  }

  public static ControllerState fromStatus(HelperStatus status) {
    if ("rejected".equals(status.controlState()) && !"runtime_inactive".equals(status.reason())) {
      return new ControllerState(Tone.REJECTED, status.reason());
    }
    if ("waiting".equals(status.moduleState())
        && "waiting".equals(status.runtimeState())
        && "awaiting_first_coordinates".equals(status.controlState())) {
      return new ControllerState(Tone.WAITING, status.reason());
    }
    if ("waiting".equals(status.moduleState()) && "waiting".equals(status.runtimeState())) {
      return switch (status.controlState()) {
        case "saved_pending_upstream" ->
            new ControllerState(Tone.PENDING_UPSTREAM, status.reason());
        case "saved_pending_reboot" -> new ControllerState(Tone.PENDING_REBOOT, status.reason());
        case "recovery_required" -> new ControllerState(Tone.RECOVERY_REQUIRED, status.reason());
        case "rejected" -> new ControllerState(Tone.REJECTED, status.reason());
        default -> new ControllerState(Tone.INACTIVE, status.reason());
      };
    }
    if (!"active".equals(status.moduleState()) || !"active".equals(status.runtimeState())) {
      return new ControllerState(Tone.INACTIVE, status.reason());
    }
    return switch (status.controlState()) {
      case "applied" -> new ControllerState(Tone.APPLIED, status.reason());
      case "saved_pending_upstream" -> new ControllerState(Tone.PENDING_UPSTREAM, status.reason());
      case "saved_pending_reboot" -> new ControllerState(Tone.PENDING_REBOOT, status.reason());
      case "recovery_required" -> new ControllerState(Tone.RECOVERY_REQUIRED, status.reason());
      case "rejected" -> new ControllerState(Tone.REJECTED, status.reason());
      case "unavailable" -> new ControllerState(Tone.INACTIVE, status.reason());
      default -> new ControllerState(Tone.PROTOCOL, "invalid_control_state");
    };
  }

  public static ControllerState fromFailure(RootHelper.Failure failure) {
    Tone tone =
        switch (failure) {
          case NONE -> Tone.PROTOCOL;
          case DENIED -> Tone.DENIED;
          case MISSING_MODULE -> Tone.MISSING;
          case TIMEOUT -> Tone.TIMEOUT;
          case CANCELLED -> Tone.CANCELLED;
          case OUTPUT_LIMIT, PROTOCOL -> Tone.PROTOCOL;
          case IO -> Tone.IO;
        };
    return new ControllerState(tone, failure.name().toLowerCase(Locale.ROOT));
  }
}
