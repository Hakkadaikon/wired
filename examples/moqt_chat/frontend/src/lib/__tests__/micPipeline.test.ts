import { describe, expect, it, vi } from "vitest";
import { pickEncoderConfig, startMicPipeline } from "../micPipeline";

type Track = { stop: () => void; readyState?: string; muted?: boolean };

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
      read: async (): Promise<{ value: unknown; done: boolean }> => {
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

const BASE_CONFIG = { codec: "opus", sampleRate: 48000, numberOfChannels: 1 };
const VOIP_CONFIG = {
  codec: "opus",
  sampleRate: 48000,
  numberOfChannels: 1,
  bitrate: 24000,
  opus: { application: "voip", frameDuration: 20000 },
};

describe("pickEncoderConfig", () => {
  it.each([
    ["resolves supported -> VOIP", () => Promise.resolve({ supported: true }), VOIP_CONFIG],
    ["resolves unsupported -> BASE", () => Promise.resolve({ supported: false }), BASE_CONFIG],
    ["rejects -> BASE", () => Promise.reject(new Error("nope")), BASE_CONFIG],
    ["dep absent -> BASE", undefined, BASE_CONFIG],
  ])("%s", async (_label, isConfigSupported, expected) => {
    await expect(pickEncoderConfig(isConfigSupported)).resolves.toEqual(expected);
  });
});

describe("micPipeline", () => {
  it("configures the encoder with the Opus parameters the browser requires", async () => {
    const encoder = fakeEncoder();
    await startMicPipeline({
      getUserMedia: fakeGetUserMedia({ stop: vi.fn() }),
      makeProcessor: () => fakeProcessor(),
      AudioEncoderCtor: encoder.ctor as never,
      sendVoiceFrame: vi.fn(),
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
      sendVoiceFrame: vi.fn(),
      isMuted: () => false,
    });
    const frame = { close: vi.fn() };
    processor.emit(frame);
    await new Promise((r) => setTimeout(r, 0));
    expect(encoder.encodeCalls).toContain(frame);
    expect(frame.close).toHaveBeenCalledTimes(1);
  });

  it("keeps sending after a send rejects", async () => {
    const encoder = fakeEncoder();
    const processor = fakeProcessor();
    const sent: Uint8Array[] = [];
    let failNext = true;
    await startMicPipeline({
      getUserMedia: fakeGetUserMedia({ stop: vi.fn() }),
      makeProcessor: () => processor,
      AudioEncoderCtor: encoder.ctor as never,
      sendVoiceFrame: async (bytes) => {
        if (failNext) {
          failNext = false;
          throw new Error("stream is closing");
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
    const sendVoiceFrame = vi.fn();

    const pipeline = await startMicPipeline({
      getUserMedia,
      makeProcessor: () => processor,
      AudioEncoderCtor: encoder.ctor as never,
      sendVoiceFrame,
      isMuted: () => false,
    });

    expect(getUserMedia).toHaveBeenCalledTimes(1);
    expect(encoder.ctor).toHaveBeenCalledTimes(1);
    pipeline.stop();
  });

  it("exposes the captured mic track so a caller can stop it independently of pipeline.stop()", async () => {
    const track: Track = { stop: vi.fn() };
    const pipeline = await startMicPipeline({
      getUserMedia: fakeGetUserMedia(track),
      makeProcessor: () => fakeProcessor(),
      AudioEncoderCtor: fakeEncoder().ctor as never,
      sendVoiceFrame: vi.fn(),
      isMuted: () => false,
    });

    expect(pipeline.tracks).toEqual([track]);
  });

  it("stays mic-off and shows an error when getUserMedia rejects", async () => {
    const getUserMedia = fakeGetUserMedia(new Error("permission denied"));
    const onError = vi.fn();

    await expect(
      startMicPipeline({
        getUserMedia,
        makeProcessor: () => fakeProcessor(),
        AudioEncoderCtor: fakeEncoder().ctor as never,
        sendVoiceFrame: vi.fn(),
        isMuted: () => false,
        onError,
      }),
    ).rejects.toThrow();
    expect(onError).toHaveBeenCalledTimes(1);
  });

  it("sends the raw Opus bytes for each encoded chunk", async () => {
    const track: Track = { stop: vi.fn() };
    const processor = fakeProcessor();
    const encoder = fakeEncoder();
    const sendVoiceFrame = vi.fn();

    await startMicPipeline({
      getUserMedia: fakeGetUserMedia(track),
      makeProcessor: () => processor,
      AudioEncoderCtor: encoder.ctor as never,
      sendVoiceFrame,
      isMuted: () => false,
    });

    processor.emit({ dummy: "frame" });
    await new Promise((r) => setTimeout(r, 0));

    expect(sendVoiceFrame).toHaveBeenCalledTimes(1);
    const sent = sendVoiceFrame.mock.calls[0][0] as Uint8Array;
    expect(Array.from(sent)).toEqual([1, 2, 3, 4, 5]);
  });

  it("does not send frames while muted even if encoder output exists", async () => {
    const track: Track = { stop: vi.fn() };
    const processor = fakeProcessor();
    const encoder = fakeEncoder();
    const sendVoiceFrame = vi.fn();

    await startMicPipeline({
      getUserMedia: fakeGetUserMedia(track),
      makeProcessor: () => processor,
      AudioEncoderCtor: encoder.ctor as never,
      sendVoiceFrame,
      isMuted: () => true,
    });

    processor.emit({ dummy: "frame" });
    await new Promise((r) => setTimeout(r, 0));

    expect(sendVoiceFrame).not.toHaveBeenCalled();
  });

  it("skips the frame and keeps the pipeline alive when AudioEncoder reports an error", async () => {
    const track: Track = { stop: vi.fn() };
    const processor = fakeProcessor();
    const encoder = fakeEncoder("error");
    const sendVoiceFrame = vi.fn();
    const onEncodeError = vi.fn();

    const pipeline = await startMicPipeline({
      getUserMedia: fakeGetUserMedia(track),
      makeProcessor: () => processor,
      AudioEncoderCtor: encoder.ctor as never,
      sendVoiceFrame,
      isMuted: () => false,
      onEncodeError,
    });

    processor.emit({ dummy: "frame" });
    await new Promise((r) => setTimeout(r, 0));

    expect(sendVoiceFrame).not.toHaveBeenCalled();
    expect(onEncodeError).toHaveBeenCalledTimes(1);
    expect(pipeline.stopped).toBe(false);
  });

  it("keeps sendVoiceFrame failures silent below the consecutive-failure threshold", async () => {
    const track: Track = { stop: vi.fn() };
    const processor = fakeProcessor();
    const encoder = fakeEncoder();
    const onSendFailing = vi.fn();

    await startMicPipeline({
      getUserMedia: fakeGetUserMedia(track),
      makeProcessor: () => processor,
      AudioEncoderCtor: encoder.ctor as never,
      sendVoiceFrame: () => {
        throw new Error("stream is closing");
      },
      isMuted: () => false,
      onSendFailing,
    });

    for (let i = 0; i < 10; i++) {
      processor.emit({ dummy: "frame" });
      await new Promise((r) => setTimeout(r, 0));
    }

    expect(onSendFailing).not.toHaveBeenCalled();
  });

  it("surfaces onSendFailing once sendVoiceFrame fails for a long consecutive run", async () => {
    const track: Track = { stop: vi.fn() };
    const processor = fakeProcessor();
    const encoder = fakeEncoder();
    const onSendFailing = vi.fn();

    await startMicPipeline({
      getUserMedia: fakeGetUserMedia(track),
      makeProcessor: () => processor,
      AudioEncoderCtor: encoder.ctor as never,
      sendVoiceFrame: () => {
        throw new Error("stream is closing");
      },
      isMuted: () => false,
      onSendFailing,
    });

    for (let i = 0; i < 100; i++) {
      processor.emit({ dummy: "frame" });
      await new Promise((r) => setTimeout(r, 0));
    }

    expect(onSendFailing).toHaveBeenCalledTimes(1);
  });

  it("resets the consecutive-failure count after a successful send", async () => {
    const track: Track = { stop: vi.fn() };
    const processor = fakeProcessor();
    const encoder = fakeEncoder();
    const onSendFailing = vi.fn();
    let callCount = 0;

    await startMicPipeline({
      getUserMedia: fakeGetUserMedia(track),
      makeProcessor: () => processor,
      AudioEncoderCtor: encoder.ctor as never,
      sendVoiceFrame: () => {
        callCount++;
        // Every 50th call succeeds, so 100 consecutive failures never happen.
        if (callCount % 50 === 0) return;
        throw new Error("stream is closing");
      },
      isMuted: () => false,
      onSendFailing,
    });

    for (let i = 0; i < 149; i++) {
      processor.emit({ dummy: "frame" });
      await new Promise((r) => setTimeout(r, 0));
    }

    expect(onSendFailing).not.toHaveBeenCalled();
  });

  it("prioritizes the latest frame over queuing stale ones under backpressure", async () => {
    const track: Track = { stop: vi.fn() };
    const processor = fakeProcessor();
    const encoder = fakeEncoder();
    let resolveFirstSend: (() => void) | null = null;
    const sendVoiceFrame = vi
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
      sendVoiceFrame,
      isMuted: () => false,
    });

    processor.emit({ id: 1 });
    await Promise.resolve();
    processor.emit({ id: 2 });
    processor.emit({ id: 3 });
    await new Promise((r) => setTimeout(r, 0));
    (resolveFirstSend as (() => void) | null)?.();
    await new Promise((r) => setTimeout(r, 0));

    // frame 1 (in flight) + only the latest queued frame (3), never frame 2
    expect(sendVoiceFrame).toHaveBeenCalledTimes(2);
  });

  describe("bad-track retry", () => {
    const ORIGINAL_CONSTRAINTS = {
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
    };
    const BARE_CONSTRAINTS = { audio: true };

    it("calls getUserMedia once with the original constraints for a healthy track", async () => {
      const track: Track = { stop: vi.fn(), readyState: "live", muted: false };
      const getUserMedia = fakeGetUserMedia(track);

      await startMicPipeline({
        getUserMedia,
        makeProcessor: () => fakeProcessor(),
        AudioEncoderCtor: fakeEncoder().ctor as never,
        sendVoiceFrame: vi.fn(),
        isMuted: () => false,
      });

      expect(getUserMedia).toHaveBeenCalledTimes(1);
      expect(getUserMedia).toHaveBeenCalledWith(ORIGINAL_CONSTRAINTS);
    });

    it("stops an ended track and retries once with bare audio:true constraints", async () => {
      const stop = vi.fn();
      const endedTrack: Track = { stop, readyState: "ended" };
      const healthyTrack: Track = { stop: vi.fn(), readyState: "live", muted: false };
      const getUserMedia = vi
        .fn()
        .mockResolvedValueOnce({ getAudioTracks: () => [endedTrack] })
        .mockResolvedValueOnce({ getAudioTracks: () => [healthyTrack] });

      const pipeline = await startMicPipeline({
        getUserMedia,
        makeProcessor: () => fakeProcessor(),
        AudioEncoderCtor: fakeEncoder().ctor as never,
        sendVoiceFrame: vi.fn(),
        isMuted: () => false,
      });

      expect(getUserMedia).toHaveBeenCalledTimes(2);
      expect(getUserMedia).toHaveBeenNthCalledWith(2, BARE_CONSTRAINTS);
      expect(stop).toHaveBeenCalledTimes(1);
      expect(pipeline.tracks).toEqual([healthyTrack]);
    });

    it("stops a muted track and retries once with bare audio:true constraints", async () => {
      const stop = vi.fn();
      const mutedTrack: Track = { stop, readyState: "live", muted: true };
      const healthyTrack: Track = { stop: vi.fn(), readyState: "live", muted: false };
      const getUserMedia = vi
        .fn()
        .mockResolvedValueOnce({ getAudioTracks: () => [mutedTrack] })
        .mockResolvedValueOnce({ getAudioTracks: () => [healthyTrack] });

      await startMicPipeline({
        getUserMedia,
        makeProcessor: () => fakeProcessor(),
        AudioEncoderCtor: fakeEncoder().ctor as never,
        sendVoiceFrame: vi.fn(),
        isMuted: () => false,
      });

      expect(getUserMedia).toHaveBeenCalledTimes(2);
      expect(getUserMedia).toHaveBeenNthCalledWith(2, BARE_CONSTRAINTS);
      expect(stop).toHaveBeenCalledTimes(1);
    });

    it("calls onError once and rejects when the retry also yields a bad track", async () => {
      const endedTrack1: Track = { stop: vi.fn(), readyState: "ended" };
      const endedTrack2: Track = { stop: vi.fn(), readyState: "ended" };
      const getUserMedia = vi
        .fn()
        .mockResolvedValueOnce({ getAudioTracks: () => [endedTrack1] })
        .mockResolvedValueOnce({ getAudioTracks: () => [endedTrack2] });
      const onError = vi.fn();

      await expect(
        startMicPipeline({
          getUserMedia,
          makeProcessor: () => fakeProcessor(),
          AudioEncoderCtor: fakeEncoder().ctor as never,
          sendVoiceFrame: vi.fn(),
          isMuted: () => false,
          onError,
        }),
      ).rejects.toThrow();

      expect(getUserMedia).toHaveBeenCalledTimes(2);
      expect(onError).toHaveBeenCalledTimes(1);
    });

    it("retries once with bare constraints on OverconstrainedError", async () => {
      const overconstrained = Object.assign(new Error("overconstrained"), {
        name: "OverconstrainedError",
      });
      const healthyTrack: Track = { stop: vi.fn(), readyState: "live", muted: false };
      const getUserMedia = vi
        .fn()
        .mockRejectedValueOnce(overconstrained)
        .mockResolvedValueOnce({ getAudioTracks: () => [healthyTrack] });

      await startMicPipeline({
        getUserMedia,
        makeProcessor: () => fakeProcessor(),
        AudioEncoderCtor: fakeEncoder().ctor as never,
        sendVoiceFrame: vi.fn(),
        isMuted: () => false,
      });

      expect(getUserMedia).toHaveBeenCalledTimes(2);
      expect(getUserMedia).toHaveBeenNthCalledWith(2, BARE_CONSTRAINTS);
    });

    it("does not retry a rejection with a different error name", async () => {
      const permissionError = Object.assign(new Error("denied"), {
        name: "NotAllowedError",
      });
      const getUserMedia = vi.fn().mockRejectedValueOnce(permissionError);
      const onError = vi.fn();

      await expect(
        startMicPipeline({
          getUserMedia,
          makeProcessor: () => fakeProcessor(),
          AudioEncoderCtor: fakeEncoder().ctor as never,
          sendVoiceFrame: vi.fn(),
          isMuted: () => false,
          onError,
        }),
      ).rejects.toThrow();

      expect(getUserMedia).toHaveBeenCalledTimes(1);
      expect(onError).toHaveBeenCalledTimes(1);
    });
  });
});
