// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.location.controller;

final class OperationGuard {
  private long generation;

  synchronized long begin() {
    generation++;
    return generation;
  }

  synchronized void invalidate() {
    generation++;
  }

  synchronized boolean isCurrent(long candidate) {
    return candidate == generation;
  }
}
