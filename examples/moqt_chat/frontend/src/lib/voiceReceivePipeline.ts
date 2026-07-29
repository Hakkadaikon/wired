// Receive-side voice pipeline: decoded MOQT voice Object -> jitter buffer ->
// playback-order drain -> AudioDecoder -> caller-supplied playback queue.
//
// Unlike webtransport_chat's own (datagram bytes decoded here, sender key
// hex-derived from embedded senderId bytes), the caller has already decoded
// the MOQT Object into a VoiceObjectPayload and resolved its sender: the
// MOQT Track Alias identifies the publisher (moqtVoiceClient.ts), so
// senderKey here is simply the participant id.

import type { JitterBufferManager } from "./jitterBuffer";
import type { VoiceObjectPayload } from "./moqtVoiceWire";

type Decoder = { configure: (config: unknown) => void; decode: (chunk: unknown) => void };

export type VoiceReceivePipelineDeps = {
  jitterBuffer: JitterBufferManager;
  AudioDecoderCtor: new (init: {
    output: (frame: unknown) => void;
    error: (err: unknown) => void;
  }) => Decoder;
  // senderKey is passed through so the playback sink can schedule each
  // speaker on their own timeline instead of one shared across the room.
  enqueuePlayback: (senderKey: string, frame: unknown) => void;
  onDecodeError?: (err: unknown) => void;
};

export type VoiceReceivePipeline = {
  handleObjectPayload: (payload: VoiceObjectPayload, senderKey: string) => void;
  drainAndDecode: (senderKey: string) => void;
};

export function createVoiceReceivePipeline(
  deps: VoiceReceivePipelineDeps,
): VoiceReceivePipeline {
  const payloadBySeq = new Map<string, Map<number, Uint8Array>>();
  // One AudioDecoder per sender, not one shared across the room: a decoder
  // owns a single running timestamp used to schedule playback, so feeding
  // frames from several concurrent speakers through it interleaves their
  // timestamps and desyncs every speaker's playback timing the moment two
  // people talk at once.
  const decoders = new Map<string, Decoder>();

  const decoderFor = (senderKey: string): Decoder => {
    let decoder = decoders.get(senderKey);
    if (!decoder) {
      decoder = new deps.AudioDecoderCtor({
        output: (frame) => deps.enqueuePlayback(senderKey, frame),
        error: (err) => deps.onDecodeError?.(err),
      });
      // sampleRate/numberOfChannels are required members of
      // AudioDecoderConfig; Opus is defined at 48 kHz and the mic pipeline
      // encodes mono.
      decoder.configure({ codec: "opus", sampleRate: 48000, numberOfChannels: 1 });
      decoders.set(senderKey, decoder);
    }
    return decoder;
  };

  return {
    handleObjectPayload: (payload, senderKey) => {
      deps.jitterBuffer.push(senderKey, payload.seq);
      let bySeq = payloadBySeq.get(senderKey);
      if (!bySeq) {
        bySeq = new Map();
        payloadBySeq.set(senderKey, bySeq);
      }
      bySeq.set(payload.seq, payload.opus);
    },
    drainAndDecode: (senderKey) => {
      const seqs = deps.jitterBuffer.drain(senderKey);
      if (seqs.length === 0) return;
      const decoder = decoderFor(senderKey);
      const bySeq = payloadBySeq.get(senderKey);
      for (const seq of seqs) {
        const payload = bySeq?.get(seq);
        bySeq?.delete(seq);
        if (payload) decoder.decode(payload);
      }
    },
  };
}
