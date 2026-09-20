import { describe, expect, it, vi } from "vitest";
import {
  createFrameAccumulator,
  createVadThrottle,
  pcmToWasm,
  pickAudioConstraints,
  startNoiseSuppressor,
  stripEsmExport,
  type AudioContextLike,
  type AudioWorkletNodeLike,
} from "../noiseSuppressor";

describe("createFrameAccumulator(480)", () => {
  it("returns no frame after fewer than 480 samples", () => {
    const acc = createFrameAccumulator(480);
    expect(acc.push(new Float32Array(128))).toBeNull();
  });

  it("returns no frame at 3x128=384 samples", () => {
    const acc = createFrameAccumulator(480);
    acc.push(new Float32Array(128));
    acc.push(new Float32Array(128));
    expect(acc.push(new Float32Array(128))).toBeNull();
  });

  it("returns exactly one 480-sample frame with 32 samples carried over at 4x128=512", () => {
    const acc = createFrameAccumulator(480);
    acc.push(new Float32Array(128));
    acc.push(new Float32Array(128));
    acc.push(new Float32Array(128));
    const frame = acc.push(new Float32Array(128));
    expect(frame).not.toBeNull();
    expect(frame).toHaveLength(480);
    // the 32-sample carry-over means the next push needs only 3 more blocks
    // (32 + 3*128 = 416, still short) then a 4th completes the next frame.
    acc.push(new Float32Array(128));
    acc.push(new Float32Array(128));
    acc.push(new Float32Array(128));
    expect(acc.push(new Float32Array(128))).not.toBeNull();
  });

  it("returns a frame at exactly 480 samples with zero carry-over", () => {
    const acc = createFrameAccumulator(480);
    // 3*128 + 96 = 480
    acc.push(new Float32Array(128));
    acc.push(new Float32Array(128));
    acc.push(new Float32Array(128));
    const frame = acc.push(new Float32Array(96));
    expect(frame).toHaveLength(480);
    // no carry-over: the next 128-sample push alone must not complete a frame
    expect(acc.push(new Float32Array(128))).toBeNull();
  });

  it("preserves sample values across the accumulated frame", () => {
    const acc = createFrameAccumulator(480);
    const block = new Float32Array(128).fill(0.5);
    let frame: Float32Array | null = null;
    for (let i = 0; i < 4; i++) frame = acc.push(block);
    expect(frame![0]).toBe(0.5);
    expect(frame![479]).toBe(0.5);
  });
});

describe("pcmToWasm", () => {
  it("scales a normal sample by 32768", () => {
    expect(pcmToWasm(0.5)).toBe(0.5 * 32768);
  });

  it("clamps above +1 to +32768", () => {
    expect(pcmToWasm(2)).toBe(32768);
  });

  it("clamps below -1 to -32768", () => {
    expect(pcmToWasm(-2)).toBe(-32768);
  });

  it("maps NaN to 0", () => {
    expect(pcmToWasm(NaN)).toBe(0);
  });
});

describe("createVadThrottle(100ms)", () => {
  it("lets the first event through", () => {
    const throttle = createVadThrottle(100);
    expect(throttle.shouldEmit(0)).toBe(true);
  });

  it("drops an event within 100ms of the last emitted one", () => {
    const throttle = createVadThrottle(100);
    throttle.shouldEmit(0);
    expect(throttle.shouldEmit(99)).toBe(false);
  });

  it("lets an event through again once 100ms have passed", () => {
    const throttle = createVadThrottle(100);
    throttle.shouldEmit(0);
    expect(throttle.shouldEmit(100)).toBe(true);
  });
});

describe("pickAudioConstraints", () => {
  it("disables the built-in noiseSuppression when RNNoise is on", () => {
    expect(pickAudioConstraints(true)).toEqual({
      echoCancellation: true,
      noiseSuppression: false,
      autoGainControl: true,
    });
  });

  it("keeps the built-in noiseSuppression when RNNoise is off", () => {
    expect(pickAudioConstraints(false)).toEqual({
      echoCancellation: true,
      noiseSuppression: true,
      autoGainControl: true,
    });
  });
});

describe("stripEsmExport", () => {
  it("removes a trailing `export default <name>;` statement", () => {
    expect(stripEsmExport("var x = 1;\nexport default x;")).toBe("var x = 1;\n");
  });

  it("leaves source with no export statement unchanged", () => {
    expect(stripEsmExport("var x = 1;")).toBe("var x = 1;");
  });

  it("replaces import.meta.url with an empty string literal (new Function cannot use import.meta)", () => {
    expect(stripEsmExport("var _scriptDir = import.meta.url;")).toBe('var _scriptDir = "";');
  });

  it("replaces every import.meta.url occurrence, not just the first", () => {
    expect(stripEsmExport("a(import.meta.url); b(import.meta.url);")).toBe('a(""); b("");');
  });
});

describe("startNoiseSuppressor", () => {
  function fakeContext(): AudioContextLike {
    return {
      audioWorklet: { addModule: vi.fn(async () => {}) },
      createMediaStreamSource: vi.fn(() => ({
        connect: vi.fn((node) => node),
        disconnect: vi.fn(),
      })),
      createMediaStreamDestination: vi.fn(() => ({
        channelCount: 2,
        stream: { getAudioTracks: () => [{ id: "denoised-track" } as unknown as MediaStreamTrack] },
      })),
      close: vi.fn(async () => {}),
    };
  }

  function fakeNode(): AudioWorkletNodeLike {
    return {
      port: { onmessage: null },
      onprocessorerror: null,
      connect: vi.fn((dest) => dest),
      disconnect: vi.fn(),
    };
  }

  function baseDeps(ctx: AudioContextLike, node: AudioWorkletNodeLike) {
    return {
      makeContext: () => ctx,
      makeNode: () => node,
      fetchText: vi.fn(async () => "var x = 1;\nexport default x;"),
      makeMediaStream: vi.fn(() => ({}) as MediaStream),
    };
  }

  const micTrack = {} as MediaStreamTrack;

  // startNoiseSuppressor awaits fetchText then addModule before wiring
  // node.port.onmessage/onprocessorerror -- flush those microtasks first so
  // the handlers are actually attached before a test fires them.
  async function flushSetup() {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  }

  it("forces the destination to mono (encoder downstream is numberOfChannels:1)", async () => {
    const ctx = fakeContext();
    const node = fakeNode();
    const deps = baseDeps(ctx, node);

    const pending = startNoiseSuppressor(micTrack, () => {}, "", deps);
    await flushSetup();
    node.port.onmessage?.({ data: { type: "ready" } } as MessageEvent);
    await pending;

    const destination = (ctx.createMediaStreamDestination as ReturnType<typeof vi.fn>).mock.results[0].value;
    expect(destination.channelCount).toBe(1);
  });

  it("resolves with the denoised track once the processor posts {type:\"ready\"}", async () => {
    const ctx = fakeContext();
    const node = fakeNode();
    const deps = baseDeps(ctx, node);

    const pending = startNoiseSuppressor(micTrack, () => {}, "", deps);
    await flushSetup();
    node.port.onmessage?.({ data: { type: "ready" } } as MessageEvent);
    const handle = await pending;

    expect(handle.outputTrack).toEqual({ id: "denoised-track" });
  });

  it("rejects when the processor fires processorerror instead of posting ready", async () => {
    const ctx = fakeContext();
    const node = fakeNode();
    const deps = baseDeps(ctx, node);

    const pending = startNoiseSuppressor(micTrack, () => {}, "", deps);
    await flushSetup();
    node.onprocessorerror?.(new Event("error"));

    await expect(pending).rejects.toThrow();
    expect(ctx.close).toHaveBeenCalledTimes(1);
  });

  it("rejects on timeout when neither ready nor processorerror ever fires", async () => {
    vi.useFakeTimers();
    try {
      const ctx = fakeContext();
      const node = fakeNode();
      const deps = baseDeps(ctx, node);

      const pending = startNoiseSuppressor(micTrack, () => {}, "", deps);
      const assertion = expect(pending).rejects.toThrow();
      await vi.runAllTimersAsync();
      await assertion;
      expect(ctx.close).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("routes {type:\"vad\"} messages to onVad after becoming ready", async () => {
    const ctx = fakeContext();
    const node = fakeNode();
    const deps = baseDeps(ctx, node);
    const onVad = vi.fn();

    const pending = startNoiseSuppressor(micTrack, onVad, "", deps);
    await flushSetup();
    node.port.onmessage?.({ data: { type: "ready" } } as MessageEvent);
    await pending;
    node.port.onmessage?.({ data: { type: "vad", isSpeaking: true } } as MessageEvent);

    expect(onVad).toHaveBeenCalledWith(true);
  });
});
