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

// ponytail: WebCodecs has no PLC/FEC API, so concealment is "replay the last
// Opus payload verbatim" -- cheap and good enough for short gaps. Upgrade to
// a PCM cross-fade or true in-band Opus PLC once WebCodecs exposes one.
const PLC_MAX_REPEATS = 2;

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
  // Last successfully decoded Opus payload per sender, for PLC repeats, plus
  // how many consecutive lost pulls have already been concealed from it.
  const lastPayload = new Map<string, Uint8Array>();
  const plcRepeats = new Map<string, number>();
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

  // Shared by a real decode and a PLC repeat: decode() on an already-closed
  // codec throws synchronously (the error callback races this batch); drop
  // the decoder so the next tick recreates it. Returns false to tell the
  // caller to abandon the rest of this tick's items -- every remaining
  // frame would throw the same way.
  const decodeOrDrop = (senderKey: string, decoder: Decoder, opus: Uint8Array): boolean => {
    try {
      decoder.decode(opus);
      return true;
    } catch (err) {
      dropDecoder(senderKey);
      deps.onDecodeError?.(err);
      return false;
    }
  };

  const concealLost = (senderKey: string, seq: number): boolean => {
    voiceTap({ dir: "drain", seq, src: senderKey, t: performance.now(), plc: true });
    const opus = lastPayload.get(senderKey);
    if (!opus) return true; // no frame ever decoded yet: nothing to repeat
    const repeats = plcRepeats.get(senderKey) ?? 0;
    if (repeats >= PLC_MAX_REPEATS) return true; // budget spent: silence
    plcRepeats.set(senderKey, repeats + 1);
    return decodeOrDrop(senderKey, decoderFor(senderKey), opus);
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
      // frame -> decode + tap depth, remember it for PLC, reset the repeat
      // counter; lost -> tap plc + conceal (see concealLost); wait ->
      // nothing this tick.
      const bySeq = payloadBySeq.get(senderKey);
      for (const item of deps.jitterBuffer.pull(senderKey)) {
        if (item.type === "wait") continue;
        if (item.type === "lost") {
          if (!concealLost(senderKey, item.seq)) return;
          continue;
        }
        const payload = bySeq?.get(item.seq);
        bySeq?.delete(item.seq);
        if (!payload) continue;
        voiceTap({
          dir: "drain",
          seq: item.seq,
          src: senderKey,
          t: performance.now(),
          depth: deps.jitterBuffer.bufferedSeqs(senderKey).length,
        });
        if (!decodeOrDrop(senderKey, decoderFor(senderKey), payload)) return;
        lastPayload.set(senderKey, payload);
        plcRepeats.set(senderKey, 0);
      }
    },
  };
}
