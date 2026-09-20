// RNNoise-based noise suppression, wired as an AudioWorklet between the mic
// source and a MediaStreamDestination whose track feeds micPipeline.ts.
//
// The worklet (public/worklets/rnnoise-processor.js) cannot import ES
// modules or this file, so it duplicates ONLY the accumulator logic below
// (see the comment there pointing back here) -- everything else stays in
// one place, tested here under jsdom.

// -- frame accumulator ------------------------------------------------
// RNNoise processes fixed 480-sample frames; the Web Audio render quantum
// delivers 128-sample blocks, so blocks must be accumulated with carry-over.
export type FrameAccumulator = {
  push: (block: Float32Array) => Float32Array | null;
};

export function createFrameAccumulator(frameSize: number): FrameAccumulator {
  let buf = new Float32Array(0);
  return {
    push(block) {
      const merged = new Float32Array(buf.length + block.length);
      merged.set(buf);
      merged.set(block, buf.length);
      if (merged.length < frameSize) {
        buf = merged;
        return null;
      }
      const frame = merged.slice(0, frameSize);
      buf = merged.slice(frameSize);
      return frame;
    },
  };
}

// -- PCM <-> wasm scaling -----------------------------------------------
// RNNoise's C API expects 16-bit-range floats ([-32768, 32768]); Web Audio
// samples are [-1, 1]. NaN (e.g. from a denormal glitch) maps to silence
// rather than corrupting the wasm heap.
export function pcmToWasm(sample: number): number {
  if (Number.isNaN(sample)) return 0;
  const clamped = Math.max(-1, Math.min(1, sample));
  return clamped * 32768;
}

// -- VAD throttle ---------------------------------------------------------
export type VadThrottle = {
  shouldEmit: (nowMs: number) => boolean;
};

export function createVadThrottle(intervalMs: number): VadThrottle {
  let lastEmit: number | null = null;
  return {
    shouldEmit(nowMs) {
      if (lastEmit !== null && nowMs - lastEmit < intervalMs) return false;
      lastEmit = nowMs;
      return true;
    },
  };
}

// -- gUM constraints --------------------------------------------------
export type AudioConstraints = {
  echoCancellation: boolean;
  noiseSuppression: boolean;
  autoGainControl: boolean;
};

// When RNNoise is enabled, the browser's own noiseSuppression is turned off
// to avoid double-processing the signal.
export function pickAudioConstraints(rnnoiseOn: boolean): AudioConstraints {
  return {
    echoCancellation: true,
    noiseSuppression: !rnnoiseOn,
    autoGainControl: true,
  };
}
