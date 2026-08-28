// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe;

public final class SecondaryLocationProbeService extends BaseLocationProbeService {
  @Override
  protected int notificationId() {
    return 2302;
  }
}
