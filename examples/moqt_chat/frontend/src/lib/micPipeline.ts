// Mic capture -> Opus encode -> voice frame pipeline.
// getUserMedia -> MediaStreamTrackProcessor -> AudioEncoder are all injected
// so tests can supply fakes instead of real browser APIs.
//
// Unlike webtransport_chat's own (datagram-based, senderId embedded in each
// frame's wire bytes), this pipeline hands the caller raw Opus bytes only:
// the MOQT Track Alias already identifies the sender on the wire
// (moqtVoiceWire.ts), and sequencing/MOQT Object framing is
// MoqtVoiceClient's job, not this pipeline's.

import { createSendGate } from "./sendGate";

export type MicPipelineDeps = {
  getUserMedia: (constraints: {
    audio: boolean | { echoCancellation: boolean; noiseSuppression: boolean; autoGainControl: boolean };
  }) => Promise<{ getAudioTracks: () => { stop: () => void }[] }>;
  makeProcessor: (track: unknown) => {
    readable: {
      getReader: () => {
        read: () => Promise<{ value: unknown; done: boolean }>;
      };
    };
  };
  AudioEncoderCtor: new (init: {
    output: (chunk: { byteLength: number; copyTo: (dst: Uint8Array) => void }) => void;
    error: (err: unknown) => void;
  }) => { configure: (config: unknown) => void; encode: (frame: unknown) => void };
  sendVoiceFrame: (opusPayload: Uint8Array) => void | Promise<void>;
  isMuted: () => boolean;
  // AudioEncoder.isConfigSupported. Optional: absent, a rejection, or a
  // false verdict all fall back to BASE_CONFIG.
  isConfigSupported?: (config: unknown) => Promise<{ supported: boolean }>;
  onError?: (err: unknown) => void;
  onEncodeError?: (err: unknown) => void;
  // Fires once sendVoiceFrame has failed CONSECUTIVE_SEND_FAILURE_LIMIT
  // times in a row with no successful send in between -- a single dropped
  // frame is normal (sendGate.ts's own doc: "a rejected send does not
  // wedge the gate"), but a run this long means voice isn't reaching the
  // peer at all (e.g. the server-side uni-stream slot cap, srvloop.h's
  // WIRED_SRVLOOP_MAX_WT_UNI_STREAMS, staying saturated) and the silence
  // deserves surfacing instead of vanishing into sendGate's own catch.
  onSendFailing?: (err: unknown) => void;
};

// ~2s of continuous failure at one Opus frame per 20ms -- long enough that
// it is not just an unlucky single dropped frame mid-burst.
const CONSECUTIVE_SEND_FAILURE_LIMIT = 100;

export type MicPipeline = {
  stop: () => void;
  stopped: boolean;
  // The captured mic track(s), so a caller (page-unload cleanup) can stop
  // the device independently of the full pipeline teardown.
  tracks: { stop: () => void }[];
};

// sampleRate/numberOfChannels are required AudioEncoderConfig members; Opus
// is defined at 48 kHz, mono keeps the frames small.
const BASE_CONFIG = { codec: "opus", sampleRate: 48000, numberOfChannels: 1 };
// application: "voip" tunes Opus for speech (vs. music/audio) and 20ms
// frames are the VoIP-standard packetization interval.
const VOIP_CONFIG = {
  ...BASE_CONFIG,
  bitrate: 24000,
  opus: { application: "voip", frameDuration: 20000 },
};

export async function pickEncoderConfig(
  isConfigSupported?: (config: unknown) => Promise<{ supported: boolean }>,
): Promise<typeof BASE_CONFIG | typeof VOIP_CONFIG> {
  if (!isConfigSupported) return BASE_CONFIG;
  try {
    const { supported } = await isConfigSupported(VOIP_CONFIG);
    return supported ? VOIP_CONFIG : BASE_CONFIG;
  } catch {
    return BASE_CONFIG;
  }
}

const ORIGINAL_CONSTRAINTS = {
  audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
};
// Bare constraints: a peer/OS that rejected the detailed constraints (or
// handed back a dead/muted track for them) still usually grants plain audio.
const BARE_CONSTRAINTS = { audio: true };

type CapturedTrack = { stop: () => void; readyState?: string; muted?: boolean };

function isBadTrack(track?: CapturedTrack): boolean {
  return track?.readyState === "ended" || track?.muted === true;
}

function isOverconstrained(err: unknown): boolean {
  return (err as { name?: string } | undefined)?.name === "OverconstrainedError";
}

async function captureTrack(
  getUserMedia: MicPipelineDeps["getUserMedia"],
): Promise<{ getAudioTracks: () => { stop: () => void }[] }> {
  try {
    const media = await getUserMedia(ORIGINAL_CONSTRAINTS);
    if (!isBadTrack(media.getAudioTracks()[0] as CapturedTrack)) {
      return media;
    }
    media.getAudioTracks()[0]?.stop();
  } catch (err) {
    if (!isOverconstrained(err)) throw err;
  }
  return getUserMedia(BARE_CONSTRAINTS);
}

async function readLoop(
  reader: { read: () => Promise<{ value: unknown; done: boolean }> },
  onFrame: (frame: unknown) => void,
): Promise<void> {
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    onFrame(value);
  }
}

export async function startMicPipeline(
  deps: MicPipelineDeps,
): Promise<MicPipeline> {
  let media: { getAudioTracks: () => { stop: () => void }[] };
  try {
    // Explicit processing constraints: acoustic feedback (speaker -> mic)
    // is the default failure mode when two participants share one room.
    // If the browser hands back a dead/muted track for these, or rejects
    // them as OverconstrainedError, captureTrack retries once with bare
    // { audio: true } before giving up.
    media = await captureTrack(deps.getUserMedia);
    const badTrack = media.getAudioTracks()[0] as CapturedTrack | undefined;
    if (isBadTrack(badTrack)) {
      badTrack?.stop();
      throw new Error("mic track unavailable after retry");
    }
  } catch (err) {
    deps.onError?.(err);
    throw err;
  }
  const track = media.getAudioTracks()[0];
  const processor = deps.makeProcessor(track);
  const config = await pickEncoderConfig(deps.isConfigSupported);
  // This gate serializes voice frames among themselves (latest-wins under
  // backpressure, see createSendGate). deps.sendVoiceFrame is expected to
  // additionally be gated by the caller against the shared MOQT stream
  // (see moqtVoiceClient.ts) -- voice Objects share that one writer, and
  // only the outer gate prevents a race on the underlying stream.
  let consecutiveFailures = 0;
  const gatedSend = createSendGate(
    async (bytes) => {
      await deps.sendVoiceFrame(bytes);
      consecutiveFailures = 0; // a later success clears an earlier bad run
    },
    (err) => {
      consecutiveFailures++;
      if (consecutiveFailures === CONSECUTIVE_SEND_FAILURE_LIMIT) {
        deps.onSendFailing?.(err);
      }
    },
  );

  const encoder = new deps.AudioEncoderCtor({
    output: (chunk) => {
      if (deps.isMuted()) return;
      const payload = new Uint8Array(chunk.byteLength);
      chunk.copyTo(payload);
      gatedSend(payload);
    },
    error: (err) => {
      deps.onEncodeError?.(err);
    },
  });
  encoder.configure(config);

  const pipeline: MicPipeline = {
    stopped: false,
    tracks: track ? [track] : [],
    stop: () => {
      pipeline.stopped = true;
      track?.stop();
    },
  };

  readLoop(processor.readable.getReader(), (frame) => {
    if (pipeline.stopped) return;
    encoder.encode(frame);
    // AudioData frames come from a finite browser-owned pool; capture stalls
    // if they are not released after use.
    (frame as { close?: () => void }).close?.();
  });

  return pipeline;
}
