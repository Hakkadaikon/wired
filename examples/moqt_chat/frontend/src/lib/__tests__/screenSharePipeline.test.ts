import { describe, expect, it, vi } from "vitest";
import { startScreenSharePipeline } from "../screenSharePipeline";
import { decodeScreenObjectMessage, encodeScreenObjectMessage, type ScreenChunk } from "../moqtScreenWire";

type Track = {
  stop: () => void;
  listeners: Record<string, (() => void)[]>;
  addEventListener: (type: string, cb: () => void) => void;
  fireEnded: () => void;
};

function fakeTrack(): Track {
  const listeners: Record<string, (() => void)[]> = {};
  return {
    stop: vi.fn(),
    listeners,
    addEventListener: (type, cb) => {
      (listeners[type] ??= []).push(cb);
    },
    fireEnded: () => listeners["ended"]?.forEach((cb) => cb()),
  };
}

function fakeGetDisplayMedia(track: Track) {
  return vi.fn(async () => ({ getVideoTracks: () => [track] }));
}

// Synchronously invokes `output` with a fixed-size fake chunk on every
// encode() call -- avoids needing a real VideoFrame/decoder round trip
// (task brief: "so you don't need real video frames").
function fakeEncoder(chunkByteLength: number) {
  let outputCb: ((chunk: unknown, metadata: unknown) => void) | null = null;
  const configureCalls: unknown[] = [];
  const encodeCalls: { frame: unknown; opts: unknown }[] = [];
  let closed = false;
  const ctor = vi.fn(function (this: unknown, init: {
    output: (c: unknown, m: unknown) => void;
    error: (e: unknown) => void;
  }) {
    outputCb = init.output;
    return {
      configure: vi.fn((config: unknown) => configureCalls.push(config)),
      encode: vi.fn((frame: unknown, opts: unknown) => {
        encodeCalls.push({ frame, opts });
        const bytes = new Uint8Array(chunkByteLength).fill(0xab);
        outputCb?.(
          {
            byteLength: bytes.length,
            type: (opts as { keyFrame?: boolean } | undefined)?.keyFrame ? "key" : "delta",
            copyTo: (dst: Uint8Array) => dst.set(bytes),
          },
          {},
        );
      }),
      close: vi.fn(() => {
        closed = true;
      }),
    };
  });
  return { ctor, configureCalls, encodeCalls, isClosed: () => closed };
}

function fakeFrame() {
  return { close: vi.fn(), timestamp: 0 };
}

describe("screenSharePipeline", () => {
  it("calls getDisplayMedia with the spec'd constraints", async () => {
    const track = fakeTrack();
    const getDisplayMedia = fakeGetDisplayMedia(track);
    const encoder = fakeEncoder(10);
    await startScreenSharePipeline({
      getDisplayMedia,
      VideoEncoderCtor: encoder.ctor as never,
      sendVideoChunk: vi.fn(),
    });
    expect(getDisplayMedia).toHaveBeenCalledWith({
      video: { width: 1280, height: 720, frameRate: 10 },
      audio: false,
    });
  });

  it("configures the encoder for vp8 realtime at ~1Mbps", async () => {
    const track = fakeTrack();
    const encoder = fakeEncoder(10);
    await startScreenSharePipeline({
      getDisplayMedia: fakeGetDisplayMedia(track),
      VideoEncoderCtor: encoder.ctor as never,
      sendVideoChunk: vi.fn(),
    });
    expect(encoder.configureCalls[0]).toMatchObject({
      codec: "vp8",
      bitrate: 1_000_000,
      latencyMode: "realtime",
    });
  });

  it("splits an encoded chunk into <=480-byte wire chunks and sends each through sendVideoChunk", async () => {
    const track = fakeTrack();
    const encoder = fakeEncoder(1000); // -> ceil(1000/480) = 3 pieces
    const sent: ScreenChunk[] = [];
    const pipeline = await startScreenSharePipeline({
      getDisplayMedia: fakeGetDisplayMedia(track),
      VideoEncoderCtor: encoder.ctor as never,
      sendVideoChunk: async (chunk) => {
        sent.push(chunk);
      },
    });
    pipeline.pushFrame(fakeFrame());
    await new Promise((r) => setTimeout(r, 0));

    expect(sent.length).toBe(3);
    expect(sent.every((c) => c.data.length <= 480)).toBe(true);
    expect(sent.reduce((n, c) => n + c.data.length, 0)).toBe(1000);
  });

  it("round-trips sent chunks through the wire codec with matching seq/idx/count/flags", async () => {
    const track = fakeTrack();
    const encoder = fakeEncoder(500); // -> 2 pieces
    const sent: ScreenChunk[] = [];
    const pipeline = await startScreenSharePipeline({
      getDisplayMedia: fakeGetDisplayMedia(track),
      VideoEncoderCtor: encoder.ctor as never,
      sendVideoChunk: async (chunk) => {
        sent.push(chunk);
      },
    });
    pipeline.pushFrame(fakeFrame());
    await new Promise((r) => setTimeout(r, 0));

    const decoded = sent.map((c) => decodeScreenObjectMessage(encodeScreenObjectMessage(c)).chunk);
    expect(decoded[0]).toMatchObject({ seq: 0, idx: 0, count: 2, keyframe: true });
    expect(decoded[1]).toMatchObject({ seq: 0, idx: 1, count: 2, keyframe: true });
  });

  it("carries width/height/codec only on the idx=0 keyframe chunk", async () => {
    const track = fakeTrack();
    const encoder = fakeEncoder(500); // -> 2 pieces
    const sent: ScreenChunk[] = [];
    const pipeline = await startScreenSharePipeline({
      getDisplayMedia: fakeGetDisplayMedia(track),
      VideoEncoderCtor: encoder.ctor as never,
      sendVideoChunk: async (chunk) => {
        sent.push(chunk);
      },
    });
    pipeline.pushFrame(fakeFrame());
    await new Promise((r) => setTimeout(r, 0));

    expect(sent[0].width).toBe(1280);
    expect(sent[0].height).toBe(720);
    expect(sent[0].codec).toBe("vp8");
    expect(sent[1].width).toBeUndefined();
    expect(sent[1].height).toBeUndefined();
    expect(sent[1].codec).toBeUndefined();
  });

  it("does not attach width/height/codec on a non-keyframe chunk even at idx=0", async () => {
    const track = fakeTrack();
    const encoder = fakeEncoder(10);
    const sent: ScreenChunk[] = [];
    const pipeline = await startScreenSharePipeline({
      getDisplayMedia: fakeGetDisplayMedia(track),
      VideoEncoderCtor: encoder.ctor as never,
      sendVideoChunk: async (chunk) => {
        sent.push(chunk);
      },
    });
    // First pushFrame forces a keyframe (cadence timer just started); a
    // second frame right after should not, since <2s has elapsed.
    pipeline.pushFrame(fakeFrame());
    await new Promise((r) => setTimeout(r, 0));
    sent.length = 0;
    pipeline.pushFrame(fakeFrame());
    await new Promise((r) => setTimeout(r, 0));

    expect(sent[0].keyframe).toBe(false);
    expect(sent[0].codec).toBeUndefined();
  });

  it("serializes cross-frame sends: frame N+1's chunks don't start sending until frame N's are done", async () => {
    // Regression test for cross-frame chunk interleaving: real WebCodecs can
    // fire a second output() before the first frame's pieces have drained
    // through gatedSend (e.g. under backpressure). Here we invoke the
    // captured output callback directly, twice, without awaiting between --
    // simulating that race deterministically instead of relying on a
    // synchronous fake encoder (which structurally cannot exercise it).
    const track = fakeTrack();
    // Typed as `null` on both sides of `:` (not inferred) so TS keeps the
    // full union across the closure below instead of narrowing this `let`
    // to the literal type `null` -- a known TS control-flow-analysis gap
    // when the reassignment happens inside a passed-in callback.
    let outputCb: ((chunk: unknown, metadata: unknown) => void) | null =
      null as ((chunk: unknown, metadata: unknown) => void) | null;
    const ctor = vi.fn(function (this: unknown, init: {
      output: (c: unknown, m: unknown) => void;
      error: (e: unknown) => void;
    }) {
      outputCb = init.output;
      return {
        configure: vi.fn(),
        encode: vi.fn(),
        close: vi.fn(),
      };
    });

    const sendOrder: string[] = [];
    const resolvers: (() => void)[] = [];
    const sendVideoChunk = vi.fn((chunk: ScreenChunk) => {
      sendOrder.push(`${chunk.seq}:${chunk.idx}`);
      return new Promise<void>((resolve) => {
        resolvers.push(resolve);
      });
    });

    await startScreenSharePipeline({
      getDisplayMedia: fakeGetDisplayMedia(track),
      VideoEncoderCtor: ctor as never,
      sendVideoChunk,
    });

    const bytes = new Uint8Array(500).fill(0xab); // -> 2 pieces per frame
    const chunkLike = (keyFrame: boolean) => ({
      byteLength: bytes.length,
      type: keyFrame ? "key" : "delta",
      copyTo: (dst: Uint8Array) => dst.set(bytes),
    });

    // Frame 0's output fires, then frame 1's output fires immediately after
    // -- before frame 0's first gatedSend promise has resolved.
    outputCb?.(chunkLike(true), {});
    outputCb?.(chunkLike(true), {});
    await new Promise((r) => setTimeout(r, 0));

    // Only frame 0's first piece should have started sending so far.
    expect(sendOrder).toEqual(["0:0"]);

    resolvers[0](); // resolve frame 0 piece 0's send
    await new Promise((r) => setTimeout(r, 0));

    expect(sendOrder).toEqual(["0:0", "0:1"]);

    resolvers[1](); // resolve frame 0 piece 1's send
    await new Promise((r) => setTimeout(r, 0));

    // Only now should frame 1's pieces begin.
    expect(sendOrder).toEqual(["0:0", "0:1", "1:0"]);
  });

  it("stops the encoder and sending when the captured track fires 'ended'", async () => {
    const track = fakeTrack();
    const encoder = fakeEncoder(10);
    const sendVideoChunk = vi.fn(async () => {});
    const pipeline = await startScreenSharePipeline({
      getDisplayMedia: fakeGetDisplayMedia(track),
      VideoEncoderCtor: encoder.ctor as never,
      sendVideoChunk,
    });

    track.fireEnded();

    expect(encoder.isClosed()).toBe(true);
    expect(pipeline.stopped).toBe(true);

    pipeline.pushFrame(fakeFrame());
    await new Promise((r) => setTimeout(r, 0));
    expect(sendVideoChunk).not.toHaveBeenCalled();
  });
});
