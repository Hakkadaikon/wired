import { describe, expect, it, vi } from "vitest";
import { openChatChannel } from "../chatChannel";

// A bidi stream pair backed by an in-memory queue: writes on one side
// become reads on the other, close/error propagate through .closed.
function fakeBidiStream() {
  const queue: Uint8Array[] = [];
  let notify: (() => void) | null = null;
  let closedResolve: (() => void) | null = null;
  let closedReject: ((e: unknown) => void) | null = null;
  const closed = new Promise<void>((res, rej) => {
    closedResolve = res;
    closedReject = rej;
  });

  const writable = {
    getWriter: () => ({
      write: async (chunk: Uint8Array) => {
        queue.push(chunk);
        notify?.();
      },
      close: async () => {},
    }),
  };

  const readable = {
    getReader: () => ({
      read: async () => {
        if (queue.length > 0) return { value: queue.shift(), done: false };
        await new Promise<void>((resolve) => (notify = resolve));
        if (queue.length > 0) return { value: queue.shift(), done: false };
        return { value: undefined, done: true };
      },
    }),
  };

  return {
    writable,
    readable,
    closed,
    fail: (err: unknown) => closedReject?.(err),
    finish: () => closedResolve?.(),
  };
}

describe("chatChannel", () => {
  it("delivers a JSON message written to the bidi stream writer to the reader", async () => {
    const stream = fakeBidiStream();
    const received: unknown[] = [];
    const channel = openChatChannel(stream as never, {
      onMessage: (msg) => received.push(msg),
      onError: () => {},
    });
    await channel.send({ text: "hello" });
    // allow the reader loop's microtask to run
    await new Promise((r) => setTimeout(r, 0));
    expect(received).toEqual([{ text: "hello" }]);
  });

  it("handles malformed JSON from the bidi stream reader without crashing the app", async () => {
    const stream = fakeBidiStream();
    const onError = vi.fn();
    const received: unknown[] = [];
    openChatChannel(stream as never, {
      onMessage: (msg) => received.push(msg),
      onError,
    });
    const writer = stream.writable.getWriter();
    await writer.write(new TextEncoder().encode("{not json"));
    await new Promise((r) => setTimeout(r, 0));
    expect(received).toEqual([]);
    expect(onError).toHaveBeenCalled();
  });

  it("transitions to send-unavailable and reflects it in UI when the bidi stream rejects", async () => {
    const stream = fakeBidiStream();
    const onSendUnavailable = vi.fn();
    const channel = openChatChannel(stream as never, {
      onMessage: () => {},
      onError: () => {},
      onSendUnavailable,
    });
    stream.fail(new Error("stream reset"));
    await new Promise((r) => setTimeout(r, 0));
    await expect(channel.send({ text: "x" })).rejects.toThrow();
    expect(onSendUnavailable).toHaveBeenCalledTimes(1);
  });
});
