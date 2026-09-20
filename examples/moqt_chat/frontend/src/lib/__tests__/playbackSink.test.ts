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
  const gains: { gain: { value: number }; connect: ReturnType<typeof vi.fn> }[] = [];
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
    createGain: () => {
      const node = { gain: { value: 1 }, connect: vi.fn() };
      gains.push(node);
      return node;
    },
    destination: {},
  };
  return { ctx, sources, gains };
}

describe("createPlaybackSink", () => {
  it("schedules the first frame from a sender at (or after) the current time", () => {
    const { ctx, sources } = fakeCtx();
    const sink = createPlaybackSink(ctx as never);
    sink.play("peerA", fakeAudioData(0.02) as never);
    expect(sources[0].startedAt[0]).toBeGreaterThanOrEqual(0);
  });

  it("schedules a second frame from the SAME sender right after the first (back-to-back, no gap)", () => {
    const { ctx, sources } = fakeCtx();
    const sink = createPlaybackSink(ctx as never);
    sink.play("peerA", fakeAudioData(0.02) as never);
    sink.play("peerA", fakeAudioData(0.02) as never);
    expect(sources[1].startedAt[0]).toBeCloseTo(sources[0].startedAt[0] + 0.02, 5);
  });

  it("schedules concurrent speakers independently -- one sender's playhead never delays another's", () => {
    const { ctx, sources } = fakeCtx();
    const sink = createPlaybackSink(ctx as never);
    // peerA has been talking for a while (playhead advanced)...
    sink.play("peerA", fakeAudioData(0.02) as never);
    sink.play("peerA", fakeAudioData(0.02) as never);
    sink.play("peerA", fakeAudioData(0.02) as never);
    // ...peerB starts talking now, for the first time. peerB's first frame
    // must play at "now", not after peerA's entire backlog.
    sink.play("peerB", fakeAudioData(0.02) as never);
    const peerBStart = sources[3].startedAt[0];
    expect(peerBStart).toBeLessThan(sources[2].startedAt[0]);
  });

  it("advancing real time lets a sender's playhead catch back up instead of drifting forever", () => {
    const { ctx, sources } = fakeCtx();
    const sink = createPlaybackSink(ctx as never);
    sink.play("peerA", fakeAudioData(0.02) as never);
    ctx.setCurrentTime(5); // 5 real seconds pass with no more frames
    sink.play("peerA", fakeAudioData(0.02) as never);
    expect(sources[1].startedAt[0]).toBeCloseTo(5, 5);
  });

  it("closes the AudioData frame after copying it out", () => {
    const { ctx } = fakeCtx();
    const sink = createPlaybackSink(ctx as never);
    const frame = fakeAudioData(0.02);
    sink.play("peerA", frame as never);
    expect(frame.close).toHaveBeenCalledTimes(1);
  });

  it("connects each source through a per-sender gain node into the master gain node into destination", () => {
    const { ctx, sources, gains } = fakeCtx();
    const sink = createPlaybackSink(ctx as never);
    sink.play("peerA", fakeAudioData(0.02) as never);
    // one master + one per-sender gain node
    expect(gains).toHaveLength(2);
    const [peerGain, masterGain] = gains;
    expect(sources).toHaveLength(1);
    expect(peerGain.connect).toHaveBeenCalledWith(masterGain);
    expect(masterGain.connect).toHaveBeenCalledWith(ctx.destination);
  });

  it("reuses the same per-sender gain node across frames from the same sender", () => {
    const { ctx, gains } = fakeCtx();
    const sink = createPlaybackSink(ctx as never);
    sink.play("peerA", fakeAudioData(0.02) as never);
    sink.play("peerA", fakeAudioData(0.02) as never);
    // still one master + one per-sender gain node
    expect(gains).toHaveLength(2);
  });

  it("gives different senders different gain nodes", () => {
    const { ctx, gains } = fakeCtx();
    const sink = createPlaybackSink(ctx as never);
    sink.play("peerA", fakeAudioData(0.02) as never);
    sink.play("peerB", fakeAudioData(0.02) as never);
    // one master + two per-sender gain nodes
    expect(gains).toHaveLength(3);
  });

  it("setPeerGain updates only that sender's gain value", () => {
    const { ctx, gains } = fakeCtx();
    const sink = createPlaybackSink(ctx as never);
    sink.play("peerA", fakeAudioData(0.02) as never);
    sink.play("peerB", fakeAudioData(0.02) as never);
    sink.setPeerGain("peerA", 0.25);
    const [peerAGain, peerBGain] = gains;
    expect(peerAGain.gain.value).toBe(0.25);
    expect(peerBGain.gain.value).toBe(1);
  });

  it("setMasterGain updates the master node, affecting every sender", () => {
    const { ctx, gains } = fakeCtx();
    const sink = createPlaybackSink(ctx as never);
    sink.play("peerA", fakeAudioData(0.02) as never);
    sink.setMasterGain(0.5);
    const masterGain = gains[gains.length - 1];
    expect(masterGain.gain.value).toBe(0.5);
  });
});
