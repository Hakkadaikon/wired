// Mic capture -> Opus encode -> voice datagram pipeline.
// getUserMedia -> MediaStreamTrackProcessor -> AudioEncoder are all injected
// so tests can supply fakes instead of real browser APIs.

import { encodeVoiceFrame } from "./voiceProtocol";
import { nextSeq } from "./jitterBuffer";

export type MicPipelineDeps = {
  getUserMedia: (constraints: {
    audio: boolean;
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
  sendDatagram: (bytes: Uint8Array) => void | Promise<void>;
  isMuted: () => boolean;
  senderId?: Uint8Array;
  onError?: (err: unknown) => void;
  onEncodeError?: (err: unknown) => void;
};

export type MicPipeline = {
  stop: () => void;
  stopped: boolean;
};

// A send in flight blocks the writer; while it is in flight, only the most
// recently encoded frame is kept for the next send -- never a growing queue
// of stale ones (backpressure -> latest-wins, not buffering).
function makeSendGate(send: (bytes: Uint8Array) => void | Promise<void>) {
  let inFlight = false;
  let pending: Uint8Array | null = null;
  const pump = async (bytes: Uint8Array) => {
    inFlight = true;
    await send(bytes);
    inFlight = false;
    if (pending) {
      const next = pending;
      pending = null;
      await pump(next);
    }
  };
  return (bytes: Uint8Array) => {
    if (inFlight) {
      pending = bytes;
      return;
    }
    void pump(bytes);
  };
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
    media = await deps.getUserMedia({ audio: true });
  } catch (err) {
    deps.onError?.(err);
    throw err;
  }
  const track = media.getAudioTracks()[0];
  const processor = deps.makeProcessor(track);
  const senderId = deps.senderId ?? new Uint8Array(4);
  let seq = 0;
  const gatedSend = makeSendGate((bytes) => deps.sendDatagram(bytes));

  const encoder = new deps.AudioEncoderCtor({
    output: (chunk) => {
      if (deps.isMuted()) return;
      const payload = new Uint8Array(chunk.byteLength);
      chunk.copyTo(payload);
      seq = nextSeq(seq);
      const encoded = encodeVoiceFrame(senderId, seq, payload);
      if (encoded.ok) gatedSend(encoded.bytes);
    },
    error: (err) => {
      deps.onEncodeError?.(err);
    },
  });
  encoder.configure({ codec: "opus" });

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
  });

  return pipeline;
}
