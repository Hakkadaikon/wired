import { describe, expect, it, vi } from "vitest";
import { createAudioContextGate } from "../audioContextGate";

function fakeAudioContext(resumeBehavior: "ok" | "reject" | "pending" = "ok") {
  return {
    state: "suspended" as "suspended" | "running",
    resume: vi.fn(async function (this: { state: string }) {
      if (resumeBehavior === "reject") {
        throw new Error("resume blocked by browser policy");
      }
      if (resumeBehavior === "pending") {
        return new Promise(() => {}); // never resolves
      }
      this.state = "running";
    }),
  };
}

describe("audioContextGate", () => {
  it("stays suspended until resume() is called from a trusted-event handler", () => {
    const ctx = fakeAudioContext();
    const gate = createAudioContextGate(() => ctx as never);
    expect(gate.state).toBe("suspended");
  });

  it("resumes to running when the join button click handler calls resume()", async () => {
    const ctx = fakeAudioContext();
    const gate = createAudioContextGate(() => ctx as never);
    await gate.resumeFromUserGesture();
    expect(ctx.resume).toHaveBeenCalledTimes(1);
    expect(gate.state).toBe("running");
  });

  it("retains buffered/decoded voice data instead of dropping it before resume", () => {
    const ctx = fakeAudioContext();
    const gate = createAudioContextGate(() => ctx as never);
    gate.enqueue({ frame: 1 });
    gate.enqueue({ frame: 2 });
    expect(gate.pendingCount()).toBe(2);
  });

  it("plays queued frames in arrival order once resume() succeeds", async () => {
    const ctx = fakeAudioContext();
    const play = vi.fn();
    const gate = createAudioContextGate(() => ctx as never, { play });
    gate.enqueue({ frame: 1 });
    gate.enqueue({ frame: 2 });
    expect(play).not.toHaveBeenCalled();
    await gate.resumeFromUserGesture();
    expect(play.mock.calls.map(([f]) => f)).toEqual([{ frame: 1 }, { frame: 2 }]);
    expect(gate.pendingCount()).toBe(0);
  });

  it("plays frames immediately while the context is running", async () => {
    const ctx = fakeAudioContext();
    const play = vi.fn();
    const gate = createAudioContextGate(() => ctx as never, { play });
    await gate.resumeFromUserGesture();
    gate.enqueue({ frame: 3 });
    expect(play).toHaveBeenCalledWith({ frame: 3 });
    expect(gate.pendingCount()).toBe(0);
  });

  it("shows a not-playing indicator instead of silently succeeding when resume() fails or stays pending", async () => {
    const ctx = fakeAudioContext("reject");
    const onResumeFailed = vi.fn();
    const gate = createAudioContextGate(() => ctx as never, {
      onResumeFailed,
    });
    await gate.resumeFromUserGesture();
    expect(gate.state).not.toBe("running");
    expect(onResumeFailed).toHaveBeenCalledTimes(1);
  });

  it("shows a not-playing indicator when resume() stays pending instead of waiting forever", async () => {
    vi.useFakeTimers();
    try {
      const ctx = fakeAudioContext("pending");
      const onResumeFailed = vi.fn();
      const gate = createAudioContextGate(() => ctx as never, {
        onResumeFailed,
      });
      const done = gate.resumeFromUserGesture();
      await vi.runAllTimersAsync();
      await done;
      expect(gate.state).not.toBe("running");
      expect(onResumeFailed).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});
