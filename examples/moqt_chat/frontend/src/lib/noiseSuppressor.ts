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

// -- worklet graph setup ------------------------------------------------
// Not unit-tested (thin glue over live browser APIs -- MediaStream,
// AudioWorkletNode -- that jsdom does not implement); covered by the
// e2e-voice clean-audio gate instead, per the brief.

export type NoiseSuppressorHandle = {
  // The processed track to hand to micPipeline.ts in place of the raw mic
  // track.
  outputTrack: MediaStreamTrack;
  stop: () => void;
};

const WORKLET_URL = "/worklets/rnnoise-processor.js";
// Served alongside the worklet; the worklet cannot `import`, so the module
// source is fetched here and handed to it as text via processorOptions.
const RNNOISE_SYNC_URL = "/worklets/rnnoise-sync.js";

// Copied verbatim from node_modules/@jitsi/rnnoise-wasm/dist/rnnoise-sync.js
// at build time (see brief: "Copy that JS file into public/worklets/").
// That file ends in `export default createRNNWasmModuleSync;`, which is
// invalid inside `new Function` (worklets cannot use ES module syntax) --
// this strips just that trailing statement.
export function stripEsmExport(source: string): string {
  return source.replace(/export\s+default\s+[^;]+;?\s*$/, "");
}

// Sets up mic -> AudioWorkletNode("rnnoise-processor") -> destination and
// returns the denoised track. Throws if the worklet/wasm fails to load;
// callers fall back to the browser's built-in noiseSuppression
// (pickAudioConstraints(false)) and keep the call working, per the brief.
export async function startNoiseSuppressor(
  micTrack: MediaStreamTrack,
  onVad: (isSpeaking: boolean) => void,
  basePath = "",
): Promise<NoiseSuppressorHandle> {
  const ctx = new AudioContext({ sampleRate: 48000 });
  const wasmModuleSource = await fetch(`${basePath}${RNNOISE_SYNC_URL}`).then((r) => r.text());
  await ctx.audioWorklet.addModule(`${basePath}${WORKLET_URL}`);

  const source = ctx.createMediaStreamSource(new MediaStream([micTrack]));
  const node = new AudioWorkletNode(ctx, "rnnoise-processor", {
    processorOptions: { wasmModuleSource: stripEsmExport(wasmModuleSource) },
  });
  node.port.onmessage = (ev: MessageEvent<{ type: string; isSpeaking: boolean }>) => {
    if (ev.data?.type === "vad") onVad(ev.data.isSpeaking);
  };
  const destination = ctx.createMediaStreamDestination();
  source.connect(node).connect(destination);

  return {
    outputTrack: destination.stream.getAudioTracks()[0],
    stop: () => {
      node.port.onmessage = null;
      node.disconnect();
      source.disconnect();
      void ctx.close();
    },
  };
}
