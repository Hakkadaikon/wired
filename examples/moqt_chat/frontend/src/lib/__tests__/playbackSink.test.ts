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

describe("createPlaybackSink lag cap", () => {
  // Each frame is 0.02s; MAX_LAG_S is 0.2s, so the playhead sits exactly at
  // the cap after 10 back-to-back frames (10 * 0.02 = 0.20, not > 0.20) and
  // crosses it on the 11th (0.22 > 0.20).
  it("does not skip the 10th back-to-back frame (playhead exactly at the cap)", () => {
    const { ctx, sources } = fakeCtx();
    const sink = createPlaybackSink(ctx as never);
    for (let i = 0; i < 10; i++) sink.play("peerA", fakeAudioData(0.02) as never);
    expect(sources).toHaveLength(10);
  });

  it("skips the 11th back-to-back frame (playhead lag exceeds the cap)", () => {
    const { ctx, sources } = fakeCtx();
    const sink = createPlaybackSink(ctx as never);
    let skippedFrame: ReturnType<typeof fakeAudioData> | undefined;
    for (let i = 0; i < 11; i++) {
      const frame = fakeAudioData(0.02);
      if (i === 10) skippedFrame = frame;
      sink.play("peerA", frame as never);
    }
    expect(sources).toHaveLength(10); // the 11th never scheduled a source
    expect(skippedFrame?.close).toHaveBeenCalledTimes(1);
  });

  it("taps {skipped:true} for a frame dropped by the lag cap", () => {
    const { ctx } = fakeCtx();
    const tapped: unknown[] = [];
    (globalThis as { __wiredVoiceTap?: (e: unknown) => void }).__wiredVoiceTap = (e) =>
      tapped.push(e);
    try {
      const sink = createPlaybackSink(ctx as never);
      for (let i = 0; i < 11; i++) sink.play("peerA", fakeAudioData(0.02) as never);
      expect(tapped.some((e) => (e as { skipped?: boolean }).skipped === true)).toBe(true);
    } finally {
      delete (globalThis as { __wiredVoiceTap?: unknown }).__wiredVoiceTap;
    }
  });

  it("tags both the skipped and the lag tap with the sender key", () => {
    const { ctx } = fakeCtx();
    const tapped: { src?: string }[] = [];
    (globalThis as { __wiredVoiceTap?: (e: unknown) => void }).__wiredVoiceTap = (e) =>
      tapped.push(e as { src?: string });
    try {
      const sink = createPlaybackSink(ctx as never);
      for (let i = 0; i < 11; i++) sink.play("peerA", fakeAudioData(0.02) as never);
      expect(tapped.every((e) => e.src === "peerA")).toBe(true);
    } finally {
      delete (globalThis as { __wiredVoiceTap?: unknown }).__wiredVoiceTap;
    }
  });

  it("resumes scheduling once currentTime advances the lag back under the cap", () => {
    const { ctx, sources } = fakeCtx();
    const sink = createPlaybackSink(ctx as never);
    for (let i = 0; i < 11; i++) sink.play("peerA", fakeAudioData(0.02) as never); // 11th skipped
    ctx.setCurrentTime(0.1); // lag now 0.10s, back under the 0.2s cap
    sink.play("peerA", fakeAudioData(0.02) as never);
    expect(sources).toHaveLength(11); // the resumed frame scheduled a source
  });

  it("does not reset the playhead when a frame is skipped", () => {
    const { ctx, sources } = fakeCtx();
    const sink = createPlaybackSink(ctx as never);
    for (let i = 0; i < 10; i++) sink.play("peerA", fakeAudioData(0.02) as never);
    const playheadBeforeSkip = sources[9].startedAt[0] + 0.02;
    sink.play("peerA", fakeAudioData(0.02) as never); // 11th: skipped
    ctx.setCurrentTime(playheadBeforeSkip); // catch currentTime up to the unmoved playhead
    sink.play("peerA", fakeAudioData(0.02) as never);
    expect(sources[10].startedAt[0]).toBeCloseTo(playheadBeforeSkip, 5);
  });
});
