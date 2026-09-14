// Screen-share capture -> VP8 encode -> chunk -> send pipeline. Mirrors
// micPipeline.ts's shape exactly: getDisplayMedia and VideoEncoder are both
// injected so tests can supply fakes instead of real browser APIs, and
// sendGate.ts (not a new gate) serializes sends against the one long-lived
// stream moqtScreenClient.ts's sendVideoChunk writes to.
//
// createSendGate's declared signature carries Uint8Array, but its body
// (sendGate.ts) never touches the payload's type -- it only forwards
// whatever `send` returns. sendVideoChunk takes a structured ScreenChunk
// (not raw bytes, unlike sendVoiceFrame), so the gate is instantiated over
// ScreenChunk via an `as` cast at this one call site rather than widening
// sendGate.ts's own type for every other caller.

import { createSendGate } from "./sendGate";
import type { ScreenChunk } from "./moqtScreenWire";

const WIDTH = 1280;
const HEIGHT = 720;
const FRAME_RATE = 10;
const CODEC = "vp8";
const MAX_CHUNK_BYTES = 480;
// A keyframe lets a late-joining/reassembling receiver resync; 2s is the
// brief's cadence, not derived from anything finer-grained.
const KEYFRAME_INTERVAL_MS = 2000;

type EncodedChunk = {
  byteLength: number;
  type: string;
  copyTo: (dst: Uint8Array) => void;
};

type MediaStreamTrackLike = {
  stop: () => void;
  addEventListener: (type: "ended", cb: () => void) => void;
};

export type ScreenSharePipelineDeps = {
  getDisplayMedia: (constraints: {
    video: { width: number; height: number; frameRate: number };
    audio: boolean;
  }) => Promise<{ getVideoTracks: () => MediaStreamTrackLike[] }>;
  VideoEncoderCtor: new (init: {
    output: (chunk: EncodedChunk, metadata: unknown) => void;
    error: (err: unknown) => void;
  }) => {
    configure: (config: unknown) => void;
    encode: (frame: unknown, opts?: { keyFrame: boolean }) => void;
    close: () => void;
  };
  sendVideoChunk: (chunk: ScreenChunk) => void | Promise<void>;
  onError?: (err: unknown) => void;
  onEncodeError?: (err: unknown) => void;
};

export type ScreenSharePipeline = {
  stop: () => void;
  stopped: boolean;
  /** Feeds one captured video frame to the encoder. Exposed so tests can
   * drive frames without a real MediaStreamTrackProcessor; production
   * wiring (Task 7) reads frames off the track the same way micPipeline.ts
   * reads audio frames off its processor. */
  pushFrame: (frame: { close?: () => void }) => void;
};

function splitIntoChunks(bytes: Uint8Array): Uint8Array[] {
  const pieces: Uint8Array[] = [];
  for (let off = 0; off < bytes.length; off += MAX_CHUNK_BYTES) {
    pieces.push(bytes.slice(off, off + MAX_CHUNK_BYTES));
  }
  return pieces.length > 0 ? pieces : [bytes];
}

function toScreenChunks(seq: number, isKeyframe: boolean, buffer: Uint8Array): ScreenChunk[] {
  const pieces = splitIntoChunks(buffer);
  return pieces.map((data, idx) => ({
    seq,
    idx,
    count: pieces.length,
    keyframe: isKeyframe,
    timestampUs: 0,
    data,
    ...(isKeyframe && idx === 0 ? { width: WIDTH, height: HEIGHT, codec: CODEC } : {}),
  }));
}

export async function startScreenSharePipeline(
  deps: ScreenSharePipelineDeps,
): Promise<ScreenSharePipeline> {
  let media: { getVideoTracks: () => MediaStreamTrackLike[] };
  try {
    media = await deps.getDisplayMedia({
      video: { width: WIDTH, height: HEIGHT, frameRate: FRAME_RATE },
      audio: false,
    });
  } catch (err) {
    deps.onError?.(err);
    throw err;
  }
  const track = media.getVideoTracks()[0];

  const gatedSend = createSendGate(deps.sendVideoChunk as unknown as (
    bytes: Uint8Array,
  ) => void | Promise<void>) as unknown as (chunk: ScreenChunk) => Promise<void>;

  let seq = 0;
  let lastKeyframeAt = -Infinity;

  const pipeline: ScreenSharePipeline = {
    stopped: false,
    stop: () => {
      pipeline.stopped = true;
      track?.stop();
      encoder.close();
    },
    pushFrame: (frame) => {
      if (pipeline.stopped) return;
      const now = Date.now();
      const forceKeyframe = now - lastKeyframeAt >= KEYFRAME_INTERVAL_MS;
      if (forceKeyframe) lastKeyframeAt = now;
      encoder.encode(frame, { keyFrame: forceKeyframe });
      frame.close?.();
    },
  };

  const encoder = new deps.VideoEncoderCtor({
    output: (chunk) => {
      if (pipeline.stopped) return;
      const buffer = new Uint8Array(chunk.byteLength);
      chunk.copyTo(buffer);
      const pieces = toScreenChunks(seq++, chunk.type === "key", buffer);
      // Sequential, awaited sends -- NOT fire-and-forget. sendGate's
      // latest-wins coalescing (right for standalone voice frames) would
      // drop pieces of the SAME frame if fired concurrently, and
      // moqtScreenWire.ts's reassembler discards a frame missing any one
      // chunk. Awaiting each call keeps the gate never "inFlight" when the
      // next piece of this frame arrives, so none of them get coalesced
      // away.
      void (async () => {
        for (const screenChunk of pieces) {
          await gatedSend(screenChunk);
        }
      })();
    },
    error: (err) => {
      deps.onEncodeError?.(err);
    },
  });
  encoder.configure({
    codec: CODEC,
    width: WIDTH,
    height: HEIGHT,
    bitrate: 1_000_000,
    latencyMode: "realtime",
  });

  track?.addEventListener("ended", () => {
    pipeline.stop();
  });

  return pipeline;
}
