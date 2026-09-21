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

// getDisplayMedia's width/height are IDEAL constraints, not a promise: a
// portrait window or a non-16:9 monitor is captured at its own size (a 4K
// screen is scaled down to fit 1080p, a 1080p one comes through as is).
// The encoder is configured to whatever size the frames actually have --
// configuring it to a fixed size would make VideoEncoder scale the frames
// into that shape without keeping their aspect, and the bitstream itself
// would then be the distorted one.
const CAPTURE_WIDTH = 1920;
const CAPTURE_HEIGHT = 1080;
// Encoder size until the first frame reports its own.
const DEFAULT_WIDTH = 1280;
const DEFAULT_HEIGHT = 720;
const FRAME_RATE = 10;
const CODEC = "vp8";
const MAX_CHUNK_BYTES = 480;
// A keyframe lets a late-joining/reassembling receiver resync; 2s is the
// brief's cadence, not derived from anything finer-grained.
const KEYFRAME_INTERVAL_MS = 2000;
// Latest wins: once this many frames sit unencoded (encoder or send path
// not keeping up), a new frame is dropped instead of queued -- a queued
// backlog only adds delay the viewer can never get back.
const MAX_ENCODE_QUEUE = 2;
// Bitrate scales with the pixel rate so 1080p text stays legible instead of
// being squeezed into 720p's budget: 0.12 bit per pixel per frame is
// 1.1 Mbps at 720p10 and 2.5 Mbps at 1080p10, clamped to [1, 4] Mbps.
const BITS_PER_PIXEL_FRAME = 0.12;
const MIN_BITRATE = 1_000_000;
const MAX_BITRATE = 4_000_000;

export function screenBitrate(width: number, height: number, fps = FRAME_RATE): number {
  const wanted = Math.round(width * height * fps * BITS_PER_PIXEL_FRAME);
  return Math.min(MAX_BITRATE, Math.max(MIN_BITRATE, wanted));
}

type EncodedChunk = {
  byteLength: number;
  type: string;
  copyTo: (dst: Uint8Array) => void;
};

type MediaStreamTrackLike = {
  stop: () => void;
  addEventListener: (type: "ended", cb: () => void) => void;
  // "detail" tells the browser's encoder this is text/UI, not motion video
  // (MediaStreamTrack.contentHint).
  contentHint?: string;
  getSettings?: () => { width?: number; height?: number };
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
    encodeQueueSize?: number;
  };
  sendVideoChunk: (chunk: ScreenChunk) => void | Promise<void>;
  onError?: (err: unknown) => void;
  onEncodeError?: (err: unknown) => void;
};

export type ScreenFrameLike = { close?: () => void; codedWidth?: number; codedHeight?: number };

export type ScreenSharePipeline = {
  stop: () => void;
  stopped: boolean;
  /** Feeds one captured video frame to the encoder. Exposed so tests can
   * drive frames without a real MediaStreamTrackProcessor; production
   * wiring (Task 7) reads frames off the track the same way micPipeline.ts
   * reads audio frames off its processor. */
  pushFrame: (frame: ScreenFrameLike) => void;
  /** Makes the next pushed frame a keyframe regardless of the cadence --
   * for when the send stream was reopened and the receiver needs to
   * resync (moqtScreenClient.ts's onStreamReset). */
  requestKeyframe: () => void;
};

function splitIntoChunks(bytes: Uint8Array): Uint8Array[] {
  const pieces: Uint8Array[] = [];
  for (let off = 0; off < bytes.length; off += MAX_CHUNK_BYTES) {
    pieces.push(bytes.slice(off, off + MAX_CHUNK_BYTES));
  }
  return pieces.length > 0 ? pieces : [bytes];
}

function toScreenChunks(
  seq: number,
  isKeyframe: boolean,
  buffer: Uint8Array,
  width: number,
  height: number,
): ScreenChunk[] {
  const pieces = splitIntoChunks(buffer);
  return pieces.map((data, idx) => ({
    seq,
    idx,
    count: pieces.length,
    keyframe: isKeyframe,
    timestampUs: 0,
    data,
    ...(isKeyframe && idx === 0 ? { width, height, codec: CODEC } : {}),
  }));
}

async function sendPieces(
  pieces: ScreenChunk[],
  gatedSend: (chunk: ScreenChunk) => Promise<void>,
): Promise<void> {
  for (const screenChunk of pieces) {
    await gatedSend(screenChunk);
  }
}

export async function startScreenSharePipeline(
  deps: ScreenSharePipelineDeps,
): Promise<ScreenSharePipeline> {
  let media: { getVideoTracks: () => MediaStreamTrackLike[] };
  try {
    media = await deps.getDisplayMedia({
      video: { width: CAPTURE_WIDTH, height: CAPTURE_HEIGHT, frameRate: FRAME_RATE },
      audio: false,
    });
  } catch (err) {
    deps.onError?.(err);
    throw err;
  }
  const track = media.getVideoTracks()[0];
  if (track) track.contentHint = "detail";
  const settings = track?.getSettings?.() ?? {};
  let width = settings.width ?? DEFAULT_WIDTH;
  let height = settings.height ?? DEFAULT_HEIGHT;

  const gatedSend = createSendGate(deps.sendVideoChunk as unknown as (
    bytes: Uint8Array,
  ) => void | Promise<void>) as unknown as (chunk: ScreenChunk) => Promise<void>;

  let seq = 0;
  let lastKeyframeAt = -Infinity;
  // Chains each output() call's send-loop off the previous one's, so frame
  // N's pieces fully drain through gatedSend before frame N+1's pieces
  // start -- output() itself can fire again before a prior frame's loop
  // has finished (real encode() is async), which a per-frame detached
  // async IIFE does not serialize against. .catch keeps one frame's
  // rejection from wedging the chain for later frames.
  let sendChain: Promise<void> = Promise.resolve();

  const configure = () => {
    encoder.configure({
      codec: CODEC,
      width,
      height,
      bitrate: screenBitrate(width, height),
      latencyMode: "realtime",
    });
  };

  // A frame of a new size (the shared window was resized, or the first
  // frame differs from the track's advertised settings) re-configures the
  // encoder and forces a keyframe, since only a keyframe carries the size
  // the receiver decodes against.
  const followFrameSize = (frame: ScreenFrameLike) => {
    const fw = frame.codedWidth;
    const fh = frame.codedHeight;
    if (!fw || !fh || (fw === width && fh === height)) return;
    width = fw;
    height = fh;
    configure();
    lastKeyframeAt = -Infinity;
  };

  const pipeline: ScreenSharePipeline = {
    stopped: false,
    stop: () => {
      pipeline.stopped = true;
      track?.stop();
      encoder.close();
    },
    requestKeyframe: () => {
      lastKeyframeAt = -Infinity;
    },
    pushFrame: (frame) => {
      if (pipeline.stopped) return;
      if ((encoder.encodeQueueSize ?? 0) > MAX_ENCODE_QUEUE) {
        frame.close?.();
        return;
      }
      followFrameSize(frame);
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
      // ponytail: the size stamped here is the CURRENT encoder size; a
      // resize between encode() and this output() would stamp the new size
      // on the old frame. The keyframe forced by the resize follows right
      // behind, so the receiver resyncs within one frame either way.
      const pieces = toScreenChunks(seq++, chunk.type === "key", buffer, width, height);
      // Sequential, awaited sends within a frame -- NOT fire-and-forget.
      // sendGate's latest-wins coalescing (right for standalone voice
      // frames) would drop pieces of the SAME frame if fired concurrently,
      // and moqtScreenWire.ts's reassembler discards a frame missing any
      // one chunk. Awaiting each call keeps the gate never "inFlight" when
      // the next piece of this frame arrives, so none of them get
      // coalesced away. Chained onto sendChain (not a detached IIFE) so
      // this guarantee also holds ACROSS frames -- see sendChain's
      // declaration above.
      sendChain = sendChain.then(() => sendPieces(pieces, gatedSend)).catch(() => {});
    },
    error: (err) => {
      deps.onEncodeError?.(err);
    },
  });
  configure();

  track?.addEventListener("ended", () => {
    pipeline.stop();
  });

  return pipeline;
}
