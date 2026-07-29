import { describe, expect, it, vi } from "vitest";
import { createVoiceReceivePipeline } from "../voiceReceivePipeline";
import { JitterBufferManager } from "../jitterBuffer";
import type { VoiceObjectPayload } from "../moqtVoiceWire";

const OWN = "user1";
const PEER = "user2";
const PEER2 = "user3";

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

function payload(seq: number, opus: number[]): VoiceObjectPayload {
  return { seq, opus: new Uint8Array(opus) };
}

describe("voiceReceivePipeline", () => {
  it("configures each sender's decoder with the Opus parameters the browser requires", () => {
    const jb = new JitterBufferManager(OWN, 8);
    const decoder = fakeDecoder();
    const pipeline = createVoiceReceivePipeline({
      jitterBuffer: jb,
      AudioDecoderCtor: decoder.ctor as never,
      enqueuePlayback: vi.fn(),
    });
    pipeline.handleObjectPayload(payload(1, [1]), PEER);
    pipeline.drainAndDecode(PEER);
    expect(decoder.configureCalls[0]).toEqual({
      codec: "opus",
      sampleRate: 48000,
      numberOfChannels: 1,
    });
  });

  it("decodes a received voice Object through jitter buffer, AudioDecoder and the Web Audio playback queue", () => {
    const jb = new JitterBufferManager(OWN, 8);
    const decoder = fakeDecoder();
    const enqueue = vi.fn();
    const pipeline = createVoiceReceivePipeline({
      jitterBuffer: jb,
      AudioDecoderCtor: decoder.ctor as never,
      enqueuePlayback: enqueue,
    });

    pipeline.handleObjectPayload(payload(1, [1, 2, 3]), PEER);
    pipeline.drainAndDecode(PEER);

    expect(enqueue).toHaveBeenCalledTimes(1);
    expect(enqueue).toHaveBeenCalledWith(PEER, { decoded: true });
  });

  it("skips a frame and continues playback when AudioDecoder reports a decode error", () => {
    const jb = new JitterBufferManager(OWN, 8);
    const decoder = fakeDecoder("error");
    const enqueue = vi.fn();
    const onDecodeError = vi.fn();
    const pipeline = createVoiceReceivePipeline({
      jitterBuffer: jb,
      AudioDecoderCtor: decoder.ctor as never,
      enqueuePlayback: enqueue,
      onDecodeError,
    });

    pipeline.handleObjectPayload(payload(1, [1, 2, 3]), PEER);
    expect(() => pipeline.drainAndDecode(PEER)).not.toThrow();

    expect(enqueue).not.toHaveBeenCalled();
    expect(onDecodeError).toHaveBeenCalledTimes(1);
  });

  it("gives each sender its own decoder instance (concurrent speakers don't share decode state)", () => {
    const jb = new JitterBufferManager(OWN, 8);
    const decoder = fakeDecoder();
    const pipeline = createVoiceReceivePipeline({
      jitterBuffer: jb,
      AudioDecoderCtor: decoder.ctor as never,
      enqueuePlayback: vi.fn(),
    });

    pipeline.handleObjectPayload(payload(1, [1]), PEER);
    pipeline.handleObjectPayload(payload(1, [2]), PEER2);
    pipeline.drainAndDecode(PEER);
    pipeline.drainAndDecode(PEER2);

    // One AudioDecoder per distinct sender, not one shared across everyone
    // -- a shared decoder's single running timestamp counter advances once
    // per decoded frame regardless of which sender it came from, which
    // desyncs playback timing once two people talk at once.
    expect(decoder.ctor).toHaveBeenCalledTimes(2);
  });

  it("treats jitter buffer exhaustion as silence/wait without throwing", () => {
    const jb = new JitterBufferManager(OWN, 8);
    const decoder = fakeDecoder();
    const enqueue = vi.fn();
    const pipeline = createVoiceReceivePipeline({
      jitterBuffer: jb,
      AudioDecoderCtor: decoder.ctor as never,
      enqueuePlayback: enqueue,
    });

    expect(() => pipeline.drainAndDecode(PEER)).not.toThrow();
    expect(enqueue).not.toHaveBeenCalled();
  });
});
