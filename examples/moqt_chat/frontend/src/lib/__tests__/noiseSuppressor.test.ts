import { describe, expect, it } from "vitest";
import {
  createFrameAccumulator,
  createVadThrottle,
  pcmToWasm,
  pickAudioConstraints,
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
