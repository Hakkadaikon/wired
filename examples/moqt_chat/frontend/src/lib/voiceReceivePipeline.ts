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
import { voiceTap } from "./voiceTap";

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

  // A decoder that hit a fatal error is CLOSED for good (WebCodecs: every
  // later decode() throws InvalidStateError) -- drop it so the next drain
  // builds a fresh one instead of throwing on every frame forever.
  const dropDecoder = (senderKey: string) => {
    decoders.delete(senderKey);
  };

  const decoderFor = (senderKey: string): Decoder => {
    let decoder = decoders.get(senderKey);
    if (!decoder) {
      decoder = new deps.AudioDecoderCtor({
        output: (frame) => deps.enqueuePlayback(senderKey, frame),
        error: (err) => {
          dropDecoder(senderKey);
          deps.onDecodeError?.(err);
        },
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
      voiceTap({ dir: "recv", seq: payload.seq, src: senderKey, t: performance.now() });
      deps.jitterBuffer.push(senderKey, payload.seq);
      let bySeq = payloadBySeq.get(senderKey);
      if (!bySeq) {
        bySeq = new Map();
        payloadBySeq.set(senderKey, bySeq);
      }
      bySeq.set(payload.seq, payload.opus);
    },
    drainAndDecode: (senderKey) => {
      // One 20ms tick == one pull() call (useMoqtChat.ts's drain loop).
      // frame -> decode + tap depth; lost -> tap plc only, no concealment
      // here (that is the next task's job); wait -> nothing this tick.
      const bySeq = payloadBySeq.get(senderKey);
      for (const item of deps.jitterBuffer.pull(senderKey)) {
        if (item.type === "wait") continue;
        if (item.type === "lost") {
          voiceTap({ dir: "drain", seq: item.seq, src: senderKey, t: performance.now(), plc: true });
          continue;
        }
        const payload = bySeq?.get(item.seq);
        bySeq?.delete(item.seq);
        if (!payload) continue;
        const decoder = decoderFor(senderKey);
        voiceTap({
          dir: "drain",
          seq: item.seq,
          src: senderKey,
          t: performance.now(),
          depth: deps.jitterBuffer.bufferedSeqs(senderKey).length,
        });
        try {
          decoder.decode(payload);
        } catch (err) {
          // decode() on an already-closed codec throws synchronously (the
          // error callback races this batch); drop the decoder so the next
          // tick recreates it, and abandon the rest of this tick's items --
          // every remaining frame would throw the same way.
          dropDecoder(senderKey);
          deps.onDecodeError?.(err);
          return;
        }
      }
    },
  };
}
