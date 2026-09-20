// AudioWorkletProcessor for RNNoise-based noise suppression.
//
// Worklets run in their own global scope and cannot `import` ES modules, so
// this file cannot import src/lib/noiseSuppressor.ts. It duplicates ONLY the
// frame-accumulator logic (see createFrameAccumulator there, tested under
// jsdom) -- everything else (constraints, VAD throttle, PCM scaling) is a
// direct inline use of the same math, kept here because it touches the wasm
// heap directly.
//
// The wasm module's JS glue (dist/rnnoise-sync.js, copied to
// public/worklets/rnnoise-sync.js) is fetched by the main thread and handed
// to this processor as text via processorOptions, since AudioWorkletGlobalScope
// has no `fetch`-then-`import` path for a same-origin ES module in all
// browsers this app targets; `new Function` evaluates it to obtain
// createRNNWasmModuleSync.

const FRAME_SIZE = 480;
const VAD_THRESHOLD = 0.5;
const VAD_THROTTLE_MS = 100;

class RNNoiseProcessor extends AudioWorkletProcessor {
  constructor(options) {
    super();
    this._buf = new Float32Array(0);
    // Denoised samples ready to be handed out to `process()`'s 128-sample
    // output blocks; frames come out 480 at a time but must be drained 128
    // at a time, so the leftover is queued here (independent of _buf, which
    // queues raw INPUT samples not yet forming a full frame).
    this._outQueue = new Float32Array(0);
    this._lastVadEmitMs = null;
    this._ready = false;

    const src = options.processorOptions.wasmModuleSource;
    // See noiseSuppressor.ts's stripEsmExport: the fetched source already
    // has its trailing `export default ...;` removed by the main thread.
    const createRNNWasmModuleSync = new Function(`${src}\nreturn createRNNWasmModuleSync;`)();
    this._module = createRNNWasmModuleSync();
    this._state = this._module._rnnoise_create();
    // 480 floats each for input and output, in the wasm heap.
    this._inPtr = this._module._malloc(FRAME_SIZE * 4);
    this._outPtr = this._module._malloc(FRAME_SIZE * 4);
    this._ready = true;
  }

  // Mirrors createFrameAccumulator(480) in noiseSuppressor.ts.
  _pushBlock(block) {
    const merged = new Float32Array(this._buf.length + block.length);
    merged.set(this._buf);
    merged.set(block, this._buf.length);
    if (merged.length < FRAME_SIZE) {
      this._buf = merged;
      return null;
    }
    const frame = merged.slice(0, FRAME_SIZE);
    this._buf = merged.slice(FRAME_SIZE);
    return frame;
  }

  _processFrame(frame) {
    const heap = this._module.HEAPF32;
    const inBase = this._inPtr / 4;
    const outBase = this._outPtr / 4;
    for (let i = 0; i < FRAME_SIZE; i++) {
      const s = frame[i];
      const clamped = Number.isNaN(s) ? 0 : Math.max(-1, Math.min(1, s));
      heap[inBase + i] = clamped * 32768;
    }
    const vadScore = this._module._rnnoise_process_frame(this._state, this._outPtr, this._inPtr);
    const out = new Float32Array(FRAME_SIZE);
    for (let i = 0; i < FRAME_SIZE; i++) {
      out[i] = heap[outBase + i] / 32768;
    }
    this._maybeEmitVad(vadScore);
    return out;
  }

  _maybeEmitVad(vadScore) {
    const now = currentTime * 1000;
    if (this._lastVadEmitMs !== null && now - this._lastVadEmitMs < VAD_THROTTLE_MS) return;
    this._lastVadEmitMs = now;
    this.port.postMessage({ type: "vad", isSpeaking: vadScore > VAD_THRESHOLD });
  }

  process(inputs, outputs) {
    if (!this._ready) return true;
    const input = inputs[0][0];
    const output = outputs[0][0];
    if (!input || !output) return true;

    const frame = this._pushBlock(input);
    if (frame) {
      const denoised = this._processFrame(frame);
      const combined = new Float32Array(this._outQueue.length + denoised.length);
      combined.set(this._outQueue);
      combined.set(denoised, this._outQueue.length);
      this._outQueue = combined;
    }

    // Drain up to one output block from whatever denoised audio is queued;
    // silence (zero-fill) covers startup latency before the first frame
    // completes, same as a comfort-noise-free gap.
    const n = Math.min(output.length, this._outQueue.length);
    output.set(this._outQueue.subarray(0, n));
    if (n < output.length) output.fill(0, n);
    this._outQueue = this._outQueue.slice(n);
    return true;
  }
}

registerProcessor("rnnoise-processor", RNNoiseProcessor);
