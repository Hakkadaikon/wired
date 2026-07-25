import { describe, expect, it, vi } from "vitest";
import { startMicPipeline } from "../micPipeline";

type Track = { stop: () => void };

function fakeGetUserMedia(track: Track | Error) {
  return vi.fn(async () => {
    if (track instanceof Error) throw track;
    return { getAudioTracks: () => [track], getTracks: () => [track] };
  });
}

function fakeProcessor() {
  const queue: unknown[] = [];
  let waiting: ((chunk: unknown) => void) | null = null;
  const readable = {
    getReader: () => ({
      read: async () => {
        if (queue.length > 0) {
          return { value: queue.shift(), done: false };
        }
        return new Promise((resolve) => {
          waiting = (chunk: unknown) => resolve({ value: chunk, done: false });
        });
      },
    }),
  };
  return {
    readable,
    emit: (chunk: unknown) => {
      if (waiting) {
        const w = waiting;
        waiting = null;
        w(chunk);
      } else {
        queue.push(chunk);
      }
    },
  };
}

function fakeEncoder(behavior: "ok" | "error" = "ok") {
  let outputCb: ((chunk: unknown) => void) | null = null;
  let errorCb: ((err: unknown) => void) | null = null;
  const encodeCalls: unknown[] = [];
  const configureCalls: unknown[] = [];
  const ctor = vi.fn(function (this: unknown, init: {
    output: (c: unknown) => void;
    error: (e: unknown) => void;
  }) {
    outputCb = init.output;
    errorCb = init.error;
    return {
      configure: vi.fn((config: unknown) => {
        configureCalls.push(config);
      }),
      encode: vi.fn((frame: unknown) => {
        encodeCalls.push(frame);
        if (behavior === "error") {
          errorCb?.(new Error("encode failed"));
        } else {
          outputCb?.({
            byteLength: 5,
            copyTo: (dst: Uint8Array) => dst.set([1, 2, 3, 4, 5]),
          });
        }
      }),
    };
  });
  return { ctor, encodeCalls, configureCalls };
}

describe("micPipeline", () => {
  it("configures the encoder with the Opus parameters the browser requires", async () => {
    const encoder = fakeEncoder();
    await startMicPipeline({
      getUserMedia: fakeGetUserMedia({ stop: vi.fn() }),
      makeProcessor: () => fakeProcessor(),
      AudioEncoderCtor: encoder.ctor as never,
      sendDatagram: vi.fn(),
      isMuted: () => false,
    });
    expect(encoder.configureCalls[0]).toEqual({
      codec: "opus",
      sampleRate: 48000,
      numberOfChannels: 1,
    });
  });

  it("closes each captured frame after handing it to the encoder", async () => {
    const encoder = fakeEncoder();
    const processor = fakeProcessor();
    await startMicPipeline({
      getUserMedia: fakeGetUserMedia({ stop: vi.fn() }),
      makeProcessor: () => processor,
      AudioEncoderCtor: encoder.ctor as never,
      sendDatagram: vi.fn(),
      isMuted: () => false,
    });
    const frame = { close: vi.fn() };
    processor.emit(frame);
    await new Promise((r) => setTimeout(r, 0));
    expect(encoder.encodeCalls).toContain(frame);
    expect(frame.close).toHaveBeenCalledTimes(1);
  });

  it("keeps sending after a datagram send rejects", async () => {
    const encoder = fakeEncoder();
    const processor = fakeProcessor();
    const sent: Uint8Array[] = [];
    let failNext = true;
    await startMicPipeline({
      getUserMedia: fakeGetUserMedia({ stop: vi.fn() }),
      makeProcessor: () => processor,
      AudioEncoderCtor: encoder.ctor as never,
      sendDatagram: async (bytes) => {
        if (failNext) {
          failNext = false;
          throw new Error("transport is closing");
        }
        sent.push(bytes);
      },
      isMuted: () => false,
    });
    processor.emit({ close: vi.fn() }); // this send rejects
    await new Promise((r) => setTimeout(r, 0));
    processor.emit({ close: vi.fn() }); // this one must still go out
    await new Promise((r) => setTimeout(r, 0));
    expect(sent.length).toBe(1);
  });

  it("starts getUserMedia -> MediaStreamTrackProcessor -> AudioEncoder pipeline on mic on", async () => {
    const track: Track = { stop: vi.fn() };
    const getUserMedia = fakeGetUserMedia(track);
    const processor = fakeProcessor();
    const encoder = fakeEncoder();
    const sendDatagram = vi.fn();

    const pipeline = await startMicPipeline({
      getUserMedia,
      makeProcessor: () => processor,
      AudioEncoderCtor: encoder.ctor as never,
      sendDatagram,
      isMuted: () => false,
    });

    expect(getUserMedia).toHaveBeenCalledTimes(1);
    expect(encoder.ctor).toHaveBeenCalledTimes(1);
    pipeline.stop();
  });

  it("stays mic-off and shows an error when getUserMedia rejects", async () => {
    const getUserMedia = fakeGetUserMedia(new Error("permission denied"));
    const onError = vi.fn();

    await expect(
      startMicPipeline({
        getUserMedia,
        makeProcessor: () => fakeProcessor(),
        AudioEncoderCtor: fakeEncoder().ctor as never,
        sendDatagram: vi.fn(),
        isMuted: () => false,
        onError,
      }),
    ).rejects.toThrow();
    expect(onError).toHaveBeenCalledTimes(1);
  });

  it("sends a voice datagram in the voice protocol's wire format for each encoded chunk", async () => {
    const track: Track = { stop: vi.fn() };
    const processor = fakeProcessor();
    const encoder = fakeEncoder();
    const sendDatagram = vi.fn();

    await startMicPipeline({
      getUserMedia: fakeGetUserMedia(track),
      makeProcessor: () => processor,
      AudioEncoderCtor: encoder.ctor as never,
      sendDatagram,
      isMuted: () => false,
    });

    processor.emit({ dummy: "frame" });
    await new Promise((r) => setTimeout(r, 0));

    expect(sendDatagram).toHaveBeenCalledTimes(1);
    const sent = sendDatagram.mock.calls[0][0] as Uint8Array;
    expect(sent[0]).toBe(0x02); // channel byte for voice
  });

  it("does not send datagrams while muted even if encoder output exists", async () => {
    const track: Track = { stop: vi.fn() };
    const processor = fakeProcessor();
    const encoder = fakeEncoder();
    const sendDatagram = vi.fn();

    await startMicPipeline({
      getUserMedia: fakeGetUserMedia(track),
      makeProcessor: () => processor,
      AudioEncoderCtor: encoder.ctor as never,
      sendDatagram,
      isMuted: () => true,
    });

    processor.emit({ dummy: "frame" });
    await new Promise((r) => setTimeout(r, 0));

    expect(sendDatagram).not.toHaveBeenCalled();
  });

  it("skips the frame and keeps the pipeline alive when AudioEncoder reports an error", async () => {
    const track: Track = { stop: vi.fn() };
    const processor = fakeProcessor();
    const encoder = fakeEncoder("error");
    const sendDatagram = vi.fn();
    const onEncodeError = vi.fn();

    const pipeline = await startMicPipeline({
      getUserMedia: fakeGetUserMedia(track),
      makeProcessor: () => processor,
      AudioEncoderCtor: encoder.ctor as never,
      sendDatagram,
      isMuted: () => false,
      onEncodeError,
    });

    processor.emit({ dummy: "frame" });
    await new Promise((r) => setTimeout(r, 0));

    expect(sendDatagram).not.toHaveBeenCalled();
    expect(onEncodeError).toHaveBeenCalledTimes(1);
    expect(pipeline.stopped).toBe(false);
  });

  it("prioritizes the latest frame over queuing stale ones under datagram writer backpressure", async () => {
    const track: Track = { stop: vi.fn() };
    const processor = fakeProcessor();
    const encoder = fakeEncoder();
    let resolveFirstSend: (() => void) | null = null;
    const sendDatagram = vi
      .fn()
      .mockImplementationOnce(
        () =>
          new Promise<void>((resolve) => {
            resolveFirstSend = resolve;
          }),
      )
      .mockImplementation(async () => {});

    await startMicPipeline({
      getUserMedia: fakeGetUserMedia(track),
      makeProcessor: () => processor,
      AudioEncoderCtor: encoder.ctor as never,
      sendDatagram,
      isMuted: () => false,
    });

    processor.emit({ id: 1 });
    await Promise.resolve();
    processor.emit({ id: 2 });
    processor.emit({ id: 3 });
    await new Promise((r) => setTimeout(r, 0));
    resolveFirstSend?.();
    await new Promise((r) => setTimeout(r, 0));

    // frame 1 (in flight) + only the latest queued frame (3), never frame 2
    expect(sendDatagram).toHaveBeenCalledTimes(2);
  });
});
