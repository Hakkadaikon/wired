import { describe, expect, it, vi } from "vitest";
import { createSendGate } from "../sendGate";

describe("createSendGate", () => {
  it("sends immediately when nothing is in flight", async () => {
    const send = vi.fn().mockResolvedValue(undefined);
    const gate = createSendGate(send);
    await gate(new Uint8Array([1]));
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("never calls send twice concurrently (no overlapping in-flight sends)", async () => {
    let concurrent = 0;
    let maxConcurrent = 0;
    const send = vi.fn(async () => {
      concurrent++;
      maxConcurrent = Math.max(maxConcurrent, concurrent);
      await new Promise((r) => setTimeout(r, 10));
      concurrent--;
    });
    const gate = createSendGate(send);
    await Promise.all([
      gate(new Uint8Array([1])),
      gate(new Uint8Array([2])),
      gate(new Uint8Array([3])),
    ]);
    expect(maxConcurrent).toBe(1);
  });

  it("coalesces bursts down to latest-wins while one send is in flight (voice-burst shape)", async () => {
    const seen: number[] = [];
    let release: (() => void) | null = null;
    const send = vi.fn(async (bytes: Uint8Array) => {
      seen.push(bytes[0]);
      await new Promise<void>((r) => (release = r));
    });
    const gate = createSendGate(send);
    void gate(new Uint8Array([1]));
    await new Promise((r) => setTimeout(r, 0));
    void gate(new Uint8Array([2]));
    void gate(new Uint8Array([3])); // 2 gets coalesced away by 3
    release!();
    await new Promise((r) => setTimeout(r, 0));
    release!();
    await new Promise((r) => setTimeout(r, 0));
    expect(seen).toEqual([1, 3]);
  });

  it("a rejected send does not wedge the gate for later sends", async () => {
    const send = vi
      .fn()
      .mockRejectedValueOnce(new Error("stream locked"))
      .mockResolvedValue(undefined);
    const gate = createSendGate(send);
    await gate(new Uint8Array([1]));
    await gate(new Uint8Array([2]));
    expect(send).toHaveBeenCalledTimes(2);
  });

  it("mixed callers (chat + presence + voice) never race the underlying writer", async () => {
    let locked = false;
    const send = vi.fn(async () => {
      if (locked) throw new Error("Cannot create writer when WritableStream is locked");
      locked = true;
      await new Promise((r) => setTimeout(r, 5));
      locked = false;
    });
    const gate = createSendGate(send);
    const chat = gate(new Uint8Array([1]));
    const presence = gate(new Uint8Array([2]));
    const voice = gate(new Uint8Array([3]));
    await Promise.all([chat, presence, voice]);
    expect(send.mock.results.every((r) => r.type !== "throw")).toBe(true);
  });
});
