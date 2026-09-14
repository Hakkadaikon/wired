import { describe, expect, it, vi } from "vitest";
import { createScreenReceivePipeline } from "../screenReceivePipeline";

const PEER = "user2";
const PEER2 = "user3";
// jsdom has no WebCodecs; a fake stand-in for the injected
// EncodedVideoChunkCtor keeps this file's own no-DOM-required guarantee.
const FakeEncodedVideoChunk = vi.fn(function (
  this: unknown,
  init: { type: string; timestamp: number; data: Uint8Array },
) {
  return init;
}) as unknown as new (init: { type: "key" | "delta"; timestamp: number; data: Uint8Array }) => unknown;

function frame(keyframe: boolean, extra: Partial<{ width: number; height: number; codec: string }> = {}) {
  return {
    data: new Uint8Array([1, 2, 3]),
    keyframe,
    width: extra.width ?? 1280,
    height: extra.height ?? 720,
    codec: extra.codec ?? "vp8",
  };
}

function fakeDecoder(behavior: "ok" | "error" | "throw" = "ok") {
  let outputCb: ((f: unknown) => void) | null = null;
  let errorCb: ((e: unknown) => void) | null = null;
  const configureCalls: unknown[] = [];
  const decodeCalls: unknown[] = [];
  const ctor = vi.fn(function (this: unknown, init: {
    output: (f: unknown) => void;
    error: (e: unknown) => void;
  }) {
    outputCb = init.output;
    errorCb = init.error;
    return {
      configure: vi.fn((config: unknown) => configureCalls.push(config)),
      decode: vi.fn((chunk: unknown) => {
        decodeCalls.push(chunk);
        if (behavior === "throw") throw new DOMException("closed codec", "InvalidStateError");
        if (behavior === "error") errorCb?.(new Error("bad vp8"));
        else outputCb?.({ decoded: true });
      }),
    };
  });
  return { ctor, configureCalls, decodeCalls };
}

describe("screenReceivePipeline", () => {
  it("drops a delta frame arriving before any keyframe (WaitKey)", () => {
    const decoder = fakeDecoder();
    const onFrame = vi.fn();
    const pipeline = createScreenReceivePipeline({
      VideoDecoderCtor: decoder.ctor as never,
      EncodedVideoChunkCtor: FakeEncodedVideoChunk,
      onFrame,
    });

    pipeline.handleFrame(PEER, frame(false));

    expect(decoder.ctor).not.toHaveBeenCalled();
    expect(decoder.decodeCalls).toHaveLength(0);
    expect(onFrame).not.toHaveBeenCalled();
  });

  it("configures the decoder and transitions to Decoding on a keyframe", () => {
    const decoder = fakeDecoder();
    const onFrame = vi.fn();
    const pipeline = createScreenReceivePipeline({
      VideoDecoderCtor: decoder.ctor as never,
      EncodedVideoChunkCtor: FakeEncodedVideoChunk,
      onFrame,
    });

    pipeline.handleFrame(PEER, frame(true, { width: 1280, height: 720, codec: "vp8" }));

    expect(decoder.configureCalls[0]).toEqual({ codec: "vp8", codedWidth: 1280, codedHeight: 720 });
    expect(pipeline.stateFor(PEER)).toBe("Decoding");
    expect(onFrame).toHaveBeenCalledWith(PEER, { decoded: true });
  });

  it("feeds both keyframe and delta frames to decode() while Decoding", () => {
    const decoder = fakeDecoder();
    const pipeline = createScreenReceivePipeline({
      VideoDecoderCtor: decoder.ctor as never,
      EncodedVideoChunkCtor: FakeEncodedVideoChunk,
      onFrame: vi.fn(),
    });

    pipeline.handleFrame(PEER, frame(true));
    pipeline.handleFrame(PEER, frame(false));
    pipeline.handleFrame(PEER, frame(false));

    expect(decoder.decodeCalls).toHaveLength(3);
    expect(decoder.ctor).toHaveBeenCalledTimes(1); // configured once, not rebuilt per frame
  });

  it("returns to WaitKey when the decoder's error callback fires, dropping subsequent deltas", () => {
    const decoder = fakeDecoder("error");
    const onFrame = vi.fn();
    const pipeline = createScreenReceivePipeline({
      VideoDecoderCtor: decoder.ctor as never,
      EncodedVideoChunkCtor: FakeEncodedVideoChunk,
      onFrame,
    });

    pipeline.handleFrame(PEER, frame(true)); // decode() invokes error callback synchronously here
    expect(pipeline.stateFor(PEER)).toBe("WaitKey");

    pipeline.handleFrame(PEER, frame(false));
    expect(decoder.decodeCalls).toHaveLength(1); // the delta after the error was dropped, not decoded
  });

  it("returns to WaitKey when decoder.decode() throws synchronously", () => {
    const decoder = fakeDecoder("throw");
    const onDecodeError = vi.fn();
    const pipeline = createScreenReceivePipeline({
      VideoDecoderCtor: decoder.ctor as never,
      EncodedVideoChunkCtor: FakeEncodedVideoChunk,
      onFrame: vi.fn(),
      onDecodeError,
    });

    expect(() => pipeline.handleFrame(PEER, frame(true))).not.toThrow();
    expect(pipeline.stateFor(PEER)).toBe("WaitKey");
    expect(onDecodeError).toHaveBeenCalledTimes(1);
  });

  it("re-enters Decoding once a new keyframe arrives after an error (liveness)", () => {
    const decoder = fakeDecoder("throw");
    const pipeline = createScreenReceivePipeline({
      VideoDecoderCtor: decoder.ctor as never,
      EncodedVideoChunkCtor: FakeEncodedVideoChunk,
      onFrame: vi.fn(),
    });

    pipeline.handleFrame(PEER, frame(true)); // throws -> back to WaitKey
    expect(pipeline.stateFor(PEER)).toBe("WaitKey");

    decoder.ctor.mockImplementationOnce(function (this: unknown, init: {
      output: (f: unknown) => void;
      error: (e: unknown) => void;
    }) {
      return {
        configure: vi.fn(),
        decode: vi.fn(() => init.output({ decoded: true })),
      };
    });
    pipeline.handleFrame(PEER, frame(true)); // new keyframe must reach Decoding
    expect(pipeline.stateFor(PEER)).toBe("Decoding");
  });

  it("re-configures the SAME decoder instance (no leak) when a new keyframe arrives while already Decoding", () => {
    const decoder = fakeDecoder();
    const pipeline = createScreenReceivePipeline({
      VideoDecoderCtor: decoder.ctor as never,
      EncodedVideoChunkCtor: FakeEncodedVideoChunk,
      onFrame: vi.fn(),
    });

    pipeline.handleFrame(PEER, frame(true));
    pipeline.handleFrame(PEER, frame(true));

    expect(pipeline.stateFor(PEER)).toBe("Decoding");
    expect(decoder.configureCalls).toHaveLength(2); // configure() called each keyframe...
    expect(decoder.ctor).toHaveBeenCalledTimes(1); // ...but the VideoDecoder instance is reused, not rebuilt
  });

  it("gives each sender its own decoder and state (independent tiles)", () => {
    const decoder = fakeDecoder();
    const pipeline = createScreenReceivePipeline({
      VideoDecoderCtor: decoder.ctor as never,
      EncodedVideoChunkCtor: FakeEncodedVideoChunk,
      onFrame: vi.fn(),
    });

    pipeline.handleFrame(PEER, frame(true));
    pipeline.handleFrame(PEER2, frame(false)); // PEER2 still WaitKey

    expect(pipeline.stateFor(PEER)).toBe("Decoding");
    expect(pipeline.stateFor(PEER2)).toBe("WaitKey");
    expect(decoder.ctor).toHaveBeenCalledTimes(1);
  });

  it("closes and drops a sender's decoder on teardown", () => {
    const decoder = fakeDecoder();
    const closeSpy = vi.fn();
    decoder.ctor.mockImplementationOnce(function (this: unknown, init: {
      output: (f: unknown) => void;
      error: (e: unknown) => void;
    }) {
      return { configure: vi.fn(), decode: vi.fn(() => init.output({ decoded: true })), close: closeSpy };
    });
    const pipeline = createScreenReceivePipeline({
      VideoDecoderCtor: decoder.ctor as never,
      EncodedVideoChunkCtor: FakeEncodedVideoChunk,
      onFrame: vi.fn(),
    });

    pipeline.handleFrame(PEER, frame(true));
    pipeline.closeSender(PEER);

    expect(closeSpy).toHaveBeenCalledTimes(1);
    expect(pipeline.stateFor(PEER)).toBe("WaitKey"); // fresh state if the sender comes back
  });
});
