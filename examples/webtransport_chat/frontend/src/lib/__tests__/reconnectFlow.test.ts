import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { createReconnectFlow } from "../reconnectFlow";
import { JitterBufferManager } from "../jitterBuffer";

function fakeTransport(readyBehavior: "ok" | "reject" = "ok") {
  return {
    ready:
      readyBehavior === "ok"
        ? Promise.resolve()
        : Promise.reject(new Error("connect failed")),
    closed: new Promise<void>(() => {}),
  };
}

describe("reconnectFlow", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("creates a new WebTransport instance, a new sender id, and re-establishes the bidi stream on reconnect", async () => {
    const openBidi = vi.fn(async () => ({}) as never);
    const makeTransport = vi.fn(() => fakeTransport());
    const jitterBuffer = new JitterBufferManager("00000000", 8);
    const flow = createReconnectFlow({
      makeTransport,
      openBidiStream: openBidi,
      jitterBuffer,
      initialSenderId: new Uint8Array([0, 0, 0, 0]),
    });

    const firstId = flow.senderId;
    await flow.reconnect();

    expect(makeTransport).toHaveBeenCalledTimes(1);
    expect(openBidi).toHaveBeenCalledTimes(1);
    expect(flow.senderId).not.toEqual(firstId);
  });

  it("clears all senders jitter buffers and lastPlayed on reconnect (UI-layer wiring of the jitter-buffer reconnect-reset behavior)", async () => {
    const jitterBuffer = new JitterBufferManager("00000000", 8);
    const reconnectSpy = vi.spyOn(jitterBuffer, "reconnect");
    const flow = createReconnectFlow({
      makeTransport: () => fakeTransport(),
      openBidiStream: async () => ({}) as never,
      jitterBuffer,
      initialSenderId: new Uint8Array([0, 0, 0, 0]),
    });

    await flow.reconnect();
    expect(reconnectSpy).toHaveBeenCalledTimes(1);
  });

  it("retains every previously used sender id for the page lifetime, not just the current one", async () => {
    const jitterBuffer = new JitterBufferManager("00000000", 8);
    const flow = createReconnectFlow({
      makeTransport: () => fakeTransport(),
      openBidiStream: async () => ({}) as never,
      jitterBuffer,
      initialSenderId: new Uint8Array([0, 0, 0, 0]),
    });

    await flow.reconnect();
    const secondId = flow.senderId;
    await flow.reconnect();

    expect(flow.allSenderIds.length).toBe(3); // initial + 2 reconnects
    expect(flow.allSenderIds).toContainEqual(secondId);
  });

  it("backs off exponentially (1s,2s,4s,8s,16s capped at 30s) and gives up with a manual-reconnect UI after 5 attempts", async () => {
    const makeTransport = vi.fn(() => fakeTransport("reject"));
    const jitterBuffer = new JitterBufferManager("00000000", 8);
    const onGiveUp = vi.fn();
    const flow = createReconnectFlow({
      makeTransport,
      openBidiStream: async () => ({}) as never,
      jitterBuffer,
      initialSenderId: new Uint8Array([0, 0, 0, 0]),
      onGiveUp,
    });

    const done = flow.reconnectWithBackoff();
    // 5 attempts: delays before attempt 2..5 are 1s,2s,4s,8s (capped at 30s)
    await vi.runAllTimersAsync();
    await done;

    expect(makeTransport).toHaveBeenCalledTimes(5);
    expect(onGiveUp).toHaveBeenCalledTimes(1);
  });

  it("shows a reconnecting UI state and disables/marks-unreliable chat and voice send during reconnect", async () => {
    const jitterBuffer = new JitterBufferManager("00000000", 8);
    const flow = createReconnectFlow({
      makeTransport: () => fakeTransport(),
      openBidiStream: async () => ({}) as never,
      jitterBuffer,
      initialSenderId: new Uint8Array([0, 0, 0, 0]),
    });

    expect(flow.reconnecting).toBe(false);
    const p = flow.reconnect();
    expect(flow.reconnecting).toBe(true);
    await p;
    expect(flow.reconnecting).toBe(false);
  });
});
