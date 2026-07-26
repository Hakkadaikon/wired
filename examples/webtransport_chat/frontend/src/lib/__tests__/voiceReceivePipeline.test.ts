import { describe, expect, it, vi } from "vitest";
import {
  createVoiceReceivePipeline,
  senderIdKey,
} from "../voiceReceivePipeline";
import { JitterBufferManager } from "../jitterBuffer";
import { encodeVoiceFrame } from "../voiceProtocol";

const OWN = new Uint8Array([9, 9, 9, 9]);
const PEER = new Uint8Array([1, 2, 3, 4]);
const PEER2 = new Uint8Array([5, 6, 7, 8]);

function fakeDecoder(behavior: "ok" | "error" = "ok") {
  let outputCb: ((frame: unknown) => void) | null = null;
  let errorCb: ((err: unknown) => void) | null = null;
  const configureCalls: unknown[] = [];
  const decodeCalls: unknown[] = [];
  const ctor = vi.fn(function (this: unknown, init: {
    output: (f: unknown) => void;
    error: (e: unknown) => void;
  }) {
    outputCb = init.output;
    errorCb = init.error;
    return {
      configure: vi.fn((config: unknown) => {
        configureCalls.push(config);
      }),
      decode: vi.fn((chunk: unknown) => {
        decodeCalls.push(chunk);
        if (behavior === "error") errorCb?.(new Error("bad opus"));
        else outputCb?.({ decoded: true });
      }),
    };
  });
  return { ctor, configureCalls, decodeCalls };
}

describe("voiceReceivePipeline", () => {
  it("configures each sender's decoder with the Opus parameters the browser requires", () => {
    const jb = new JitterBufferManager(senderIdKey(OWN), 8);
    const decoder = fakeDecoder();
    const pipeline = createVoiceReceivePipeline({
      jitterBuffer: jb,
      AudioDecoderCtor: decoder.ctor as never,
      enqueuePlayback: vi.fn(),
    });
    const encoded = encodeVoiceFrame(PEER, 1, new Uint8Array([1]));
    if (!encoded.ok) throw new Error("encode failed");
    pipeline.handleDatagram(encoded.bytes);
    pipeline.drainAndDecode(senderIdKey(PEER));
    expect(decoder.configureCalls[0]).toEqual({
      codec: "opus",
      sampleRate: 48000,
      numberOfChannels: 1,
    });
  });

  it("decodes a received voice datagram through jitter buffer, AudioDecoder and the Web Audio playback queue", () => {
    const jb = new JitterBufferManager(senderIdKey(OWN), 8);
    const decoder = fakeDecoder();
    const enqueue = vi.fn();
    const pipeline = createVoiceReceivePipeline({
      jitterBuffer: jb,
      AudioDecoderCtor: decoder.ctor as never,
      enqueuePlayback: enqueue,
    });

    const encoded = encodeVoiceFrame(PEER, 1, new Uint8Array([1, 2, 3]));
    if (!encoded.ok) throw new Error("encode failed");
    pipeline.handleDatagram(encoded.bytes);
    pipeline.drainAndDecode(senderIdKey(PEER));

    expect(enqueue).toHaveBeenCalledTimes(1);
    expect(enqueue).toHaveBeenCalledWith(senderIdKey(PEER), { decoded: true });
  });

  it("skips a frame and continues playback when AudioDecoder reports a decode error", () => {
    const jb = new JitterBufferManager(senderIdKey(OWN), 8);
    const decoder = fakeDecoder("error");
    const enqueue = vi.fn();
    const onDecodeError = vi.fn();
    const pipeline = createVoiceReceivePipeline({
      jitterBuffer: jb,
      AudioDecoderCtor: decoder.ctor as never,
      enqueuePlayback: enqueue,
      onDecodeError,
    });

    const encoded = encodeVoiceFrame(PEER, 1, new Uint8Array([1, 2, 3]));
    if (!encoded.ok) throw new Error("encode failed");
    pipeline.handleDatagram(encoded.bytes);
    expect(() =>
      pipeline.drainAndDecode(senderIdKey(PEER)),
    ).not.toThrow();

    expect(enqueue).not.toHaveBeenCalled();
    expect(onDecodeError).toHaveBeenCalledTimes(1);
  });

  it("gives each sender its own decoder instance (concurrent speakers don't share decode state)", () => {
    const jb = new JitterBufferManager(senderIdKey(OWN), 8);
    const decoder = fakeDecoder();
    const pipeline = createVoiceReceivePipeline({
      jitterBuffer: jb,
      AudioDecoderCtor: decoder.ctor as never,
      enqueuePlayback: vi.fn(),
    });

    const framePeer1 = encodeVoiceFrame(PEER, 1, new Uint8Array([1]));
    const framePeer2 = encodeVoiceFrame(PEER2, 1, new Uint8Array([2]));
    if (!framePeer1.ok || !framePeer2.ok) throw new Error("encode failed");
    pipeline.handleDatagram(framePeer1.bytes);
    pipeline.handleDatagram(framePeer2.bytes);
    pipeline.drainAndDecode(senderIdKey(PEER));
    pipeline.drainAndDecode(senderIdKey(PEER2));

    // One AudioDecoder per distinct sender, not one shared across everyone
    // -- a shared decoder's single running timestamp counter advances once
    // per decoded frame regardless of which sender it came from, which
    // desyncs playback timing once two people talk at once.
    expect(decoder.ctor).toHaveBeenCalledTimes(2);
  });

  it("treats jitter buffer exhaustion as silence/wait without throwing", () => {
    const jb = new JitterBufferManager(senderIdKey(OWN), 8);
    const decoder = fakeDecoder();
    const enqueue = vi.fn();
    const pipeline = createVoiceReceivePipeline({
      jitterBuffer: jb,
      AudioDecoderCtor: decoder.ctor as never,
      enqueuePlayback: enqueue,
    });

    expect(() =>
      pipeline.drainAndDecode(senderIdKey(PEER)),
    ).not.toThrow();
    expect(enqueue).not.toHaveBeenCalled();
  });
});
