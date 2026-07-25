// Receive-side voice pipeline: decoded voice datagram -> jitter buffer ->
// playback-order drain -> AudioDecoder -> caller-supplied playback queue.
// jitterBuffer.ts keys senders by string id, so raw sender-id bytes are
// hex-encoded to build that key consistently on both push and drain.

import type { JitterBufferManager } from "./jitterBuffer";
import { decodeFrame } from "./voiceProtocol";

export function senderIdKey(senderId: Uint8Array): string {
  return Array.from(senderId, (b) => b.toString(16).padStart(2, "0")).join(
    "",
  );
}

export type VoiceReceivePipelineDeps = {
  jitterBuffer: JitterBufferManager;
  AudioDecoderCtor: new (init: {
    output: (frame: unknown) => void;
    error: (err: unknown) => void;
  }) => { configure: (config: unknown) => void; decode: (chunk: unknown) => void };
  enqueuePlayback: (frame: unknown) => void;
  onDecodeError?: (err: unknown) => void;
};

export type VoiceReceivePipeline = {
  handleDatagram: (bytes: Uint8Array) => void;
  drainAndDecode: (senderKey: string) => void;
};

export function createVoiceReceivePipeline(
  deps: VoiceReceivePipelineDeps,
): VoiceReceivePipeline {
  const payloadBySeq = new Map<string, Map<number, Uint8Array>>();
  const decoder = new deps.AudioDecoderCtor({
    output: (frame) => deps.enqueuePlayback(frame),
    error: (err) => deps.onDecodeError?.(err),
  });
  // sampleRate/numberOfChannels are required members of AudioDecoderConfig;
  // Opus is defined at 48 kHz and the mic pipeline encodes mono.
  decoder.configure({ codec: "opus", sampleRate: 48000, numberOfChannels: 1 });

  return {
    handleDatagram: (bytes) => {
      const result = decodeFrame(bytes);
      if (!result.ok || result.frame.channel !== "voice") return;
      const { senderId, seq, payload } = result.frame;
      const key = senderIdKey(senderId);
      deps.jitterBuffer.push(key, seq);
      let bySeq = payloadBySeq.get(key);
      if (!bySeq) {
        bySeq = new Map();
        payloadBySeq.set(key, bySeq);
      }
      bySeq.set(seq, payload);
    },
    drainAndDecode: (senderKey) => {
      const seqs = deps.jitterBuffer.drain(senderKey);
      const bySeq = payloadBySeq.get(senderKey);
      for (const seq of seqs) {
        const payload = bySeq?.get(seq);
        bySeq?.delete(seq);
        if (payload) decoder.decode(payload);
      }
    },
  };
}
