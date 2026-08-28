// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe.detector;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;

public final class PendingIntentSignal {
  private static final ConcurrentMap<String, Slot> SLOTS = new ConcurrentHashMap<>();

  private PendingIntentSignal() {}

  public static void prepare(String runId, String testId) {
    if (SLOTS.putIfAbsent(key(runId, testId), new Slot()) != null) {
      throw new IllegalStateException("PendingIntent signal already exists");
    }
  }

  public static void complete(String runId, String testId, JSONObject raw, boolean vpn) {
    Slot slot = SLOTS.get(key(runId, testId));
    if (slot != null) {
      slot.raw = raw;
      slot.vpn = vpn;
      slot.latch.countDown();
    }
  }

  public static Observation await(String runId, String testId, long timeoutMs)
      throws InterruptedException {
    Slot slot = SLOTS.get(key(runId, testId));
    if (slot == null) {
      throw new IllegalStateException("PendingIntent signal was not prepared");
    }
    if (!slot.latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
      return null;
    }
    return new Observation(slot.raw, slot.vpn);
  }

  public static void clear(String runId, String testId) {
    SLOTS.remove(key(runId, testId));
  }

  private static String key(String runId, String testId) {
    return runId + "\n" + testId;
  }

  public static final class Observation {
    public final JSONObject raw;
    public final boolean vpn;

    private Observation(JSONObject raw, boolean vpn) {
      this.raw = raw;
      this.vpn = vpn;
    }
  }

  private static final class Slot {
    private final CountDownLatch latch = new CountDownLatch(1);
    private volatile JSONObject raw = new JSONObject();
    private volatile boolean vpn;
  }
}
