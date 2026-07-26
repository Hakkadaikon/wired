import { describe, expect, it, vi } from "vitest";
import { createPlaybackSink } from "../playbackSink";

function fakeAudioData(duration: number) {
  return {
    numberOfChannels: 1,
    numberOfFrames: 960,
    sampleRate: 48000,
    copyTo: vi.fn(),
    close: vi.fn(),
    duration, // seconds, fake-only convenience so the buffer stub can report it
  };
}

function fakeCtx() {
  const sources: { buffer: unknown; startedAt: number[] }[] = [];
  let currentTime = 0;
  const ctx = {
    get currentTime() {
      return currentTime;
    },
    setCurrentTime: (t: number) => {
      currentTime = t;
    },
    createBuffer: () => ({
      duration: 0.02,
      copyToChannel: vi.fn(),
    }),
    createBufferSource: () => {
      const src = {
        buffer: null as unknown,
        connect: vi.fn(),
        start: vi.fn((when: number) => {
          sources.push({ buffer: src.buffer, startedAt: [when] });
        }),
      };
      return src;
    },
    destination: {},
  };
  return { ctx, sources };
}

describe("createPlaybackSink", () => {
  it("schedules the first frame from a sender at (or after) the current time", () => {
    const { ctx, sources } = fakeCtx();
    const sink = createPlaybackSink(ctx as never);
    sink("peerA", fakeAudioData(0.02) as never);
    expect(sources[0].startedAt[0]).toBeGreaterThanOrEqual(0);
  });

  it("schedules a second frame from the SAME sender right after the first (back-to-back, no gap)", () => {
    const { ctx, sources } = fakeCtx();
    const sink = createPlaybackSink(ctx as never);
    sink("peerA", fakeAudioData(0.02) as never);
    sink("peerA", fakeAudioData(0.02) as never);
    expect(sources[1].startedAt[0]).toBeCloseTo(sources[0].startedAt[0] + 0.02, 5);
  });

  it("schedules concurrent speakers independently -- one sender's playhead never delays another's", () => {
    const { ctx, sources } = fakeCtx();
    const sink = createPlaybackSink(ctx as never);
    // peerA has been talking for a while (playhead advanced)...
    sink("peerA", fakeAudioData(0.02) as never);
    sink("peerA", fakeAudioData(0.02) as never);
    sink("peerA", fakeAudioData(0.02) as never);
    // ...peerB starts talking now, for the first time. peerB's first frame
    // must play at "now", not after peerA's entire backlog.
    sink("peerB", fakeAudioData(0.02) as never);
    const peerBStart = sources[3].startedAt[0];
    expect(peerBStart).toBeLessThan(sources[2].startedAt[0]);
  });

  it("advancing real time lets a sender's playhead catch back up instead of drifting forever", () => {
    const { ctx, sources } = fakeCtx();
    const sink = createPlaybackSink(ctx as never);
    sink("peerA", fakeAudioData(0.02) as never);
    ctx.setCurrentTime(5); // 5 real seconds pass with no more frames
    sink("peerA", fakeAudioData(0.02) as never);
    expect(sources[1].startedAt[0]).toBeCloseTo(5, 5);
  });

  it("closes the AudioData frame after copying it out", () => {
    const { ctx } = fakeCtx();
    const sink = createPlaybackSink(ctx as never);
    const frame = fakeAudioData(0.02);
    sink("peerA", frame as never);
    expect(frame.close).toHaveBeenCalledTimes(1);
  });
});
