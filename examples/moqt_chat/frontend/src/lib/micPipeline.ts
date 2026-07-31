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
};

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
    media = await deps.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
    });
  } catch (err) {
    deps.onError?.(err);
    throw err;
  }
  const track = media.getAudioTracks()[0];
  const processor = deps.makeProcessor(track);
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
  // sampleRate/numberOfChannels are required members of AudioEncoderConfig;
  // Opus is defined at 48 kHz, mono keeps the frames small.
  encoder.configure({ codec: "opus", sampleRate: 48000, numberOfChannels: 1 });

  const pipeline: MicPipeline = {
    stopped: false,
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
