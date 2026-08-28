// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.policy;

public final class RequestObservationContext {
  private static final ThreadLocal<State> STATE = new ThreadLocal<>();

  private RequestObservationContext() {}

  public static Scope enter() {
    State state = STATE.get();
    if (state == null) {
      state = new State();
      STATE.set(state);
    }
    state.depth++;
    return new Scope(Thread.currentThread(), state, state.depth);
  }

  public static boolean isActive() {
    State state = STATE.get();
    return state != null && state.depth > 0;
  }

  public static int depth() {
    State state = STATE.get();
    return state == null ? 0 : state.depth;
  }

  private static final class State {
    private int depth;
  }

  public static final class Scope implements AutoCloseable {
    private final Thread owner;
    private final State state;
    private final int expectedDepth;
    private boolean closed;

    private Scope(Thread owner, State state, int expectedDepth) {
      this.owner = owner;
      this.state = state;
      this.expectedDepth = expectedDepth;
    }

    @Override
    public void close() {
      if (closed) {
        return;
      }
      if (Thread.currentThread() != owner) {
        throw new IllegalStateException("request observation scope closed on another thread");
      }
      State current = STATE.get();
      if (current != state || current.depth != expectedDepth) {
        throw new IllegalStateException("request observation scopes closed out of order");
      }
      current.depth--;
      if (current.depth == 0) {
        STATE.remove();
      }
      closed = true;
    }
  }
}
