import { describe, expect, it, vi } from "vitest";
import { AppendQueue, LiveMovie, MOVIE_MIME } from "../moqtLiveClient";
import { MOVIE_INIT_TRACK_NAME, MOVIE_TRACK_NAME } from "../moqtMovieClient";
import type { MoqtChatClient } from "../moqtClient";
import { concatBytes, encodeVarint, utf8ToBytes } from "../moqtWire";
import { readFileSync } from "node:fs";
import path from "node:path";

function fakeSourceBuffer() {
  const listeners: Record<string, (() => void)[]> = { updateend: [], error: [] };
  const appended: Uint8Array[] = [];
  const removed: [number, number][] = [];
  const sb = {
    updating: false,
    mode: "segments",
    buffered: { length: 0, start: () => 0, end: () => 0 },
    appendBuffer(b: BufferSource) {
      if (sb.updating) throw new Error("busy");
      sb.updating = true;
      appended.push(new Uint8Array(b as ArrayBuffer));
    },
    remove(s: number, e: number) {
      if (sb.updating) throw new Error("busy");
      sb.updating = true;
      removed.push([s, e]);
    },
    addEventListener(t: "updateend" | "error", h: () => void) {
      listeners[t].push(h);
    },
    finish() {
      sb.updating = false;
      for (const h of listeners.updateend) h();
    },
    fireError() {
      for (const h of listeners.error) h();
    },
  };
  return { sb, appended, removed };
}

describe("AppendQueue", () => {
  it("appends one buffer at a time, in order, waiting for updateend", () => {
    const { sb, appended } = fakeSourceBuffer();
    const q = new AppendQueue(sb, vi.fn());
    q.push(new Uint8Array([1]));
    q.push(new Uint8Array([2]));
    q.push(new Uint8Array([3]));
    expect(appended.length).toBe(1);
    sb.finish();
    expect(appended.length).toBe(2);
    sb.finish();
    expect(appended.length).toBe(3);
    expect([...appended[2]]).toEqual([3]);
  });

  it("queues a trim like an append and only when more than 60 s sit behind currentTime", () => {
    const { sb, removed } = fakeSourceBuffer();
    sb.buffered = { length: 1, start: () => 0, end: () => 100 };
    const q = new AppendQueue(sb, vi.fn());
    q.trim(30);
    expect(removed.length).toBe(0);
    q.trim(70);
    expect(removed).toEqual([[0, 40]]);
  });

  it("reports a SourceBuffer error once and stops appending", () => {
    const { sb, appended } = fakeSourceBuffer();
    const onError = vi.fn();
    const q = new AppendQueue(sb, onError);
    sb.fireError();
    expect(onError).toHaveBeenCalledTimes(1);
    expect(typeof onError.mock.calls[0][0]).toBe("string");
    q.push(new Uint8Array([1]));
    expect(appended.length).toBe(0);
  });
});

describe("MOVIE_MIME", () => {
  it("matches the committed asset's avcC profile/compat/level", () => {
    const f = readFileSync(path.resolve(__dirname, "../../../../../../assets/movie-live.mp4"));
    const i = f.indexOf("avcC");
    const hex = [f[i + 5], f[i + 6], f[i + 7]]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    expect(MOVIE_MIME).toContain(`avc1.${hex}`);
  });
});

// One Object per Group stream (header already consumed by the caller):
// Object ID Delta 0, Payload Length, payload bytes.
function fragmentWire(payload: Uint8Array): Uint8Array {
  return concatBytes([encodeVarint(0n), encodeVarint(BigInt(payload.length)), payload]);
}

function fakeReader(chunks: Uint8Array[]): ReadableStreamDefaultReader<Uint8Array> {
  const queue = [...chunks];
  return {
    read: vi.fn(async () =>
      queue.length > 0 ? { value: queue.shift(), done: false } : { value: undefined, done: true },
    ),
  } as unknown as ReadableStreamDefaultReader<Uint8Array>;
}

function fakeVideo() {
  return {
    src: "",
    currentTime: 0,
    addEventListener: vi.fn(),
    removeAttribute: vi.fn(),
    load: vi.fn(),
  } as unknown as HTMLVideoElement;
}

// A LiveMovie already start()ed against a fake MediaSource whose sourceopen
// fires synchronously, so tests drive handleInit/handleFragment directly.
async function startedLiveMovie(opts?: { onFirstGroup?: (g: bigint) => void }) {
  const { sb, appended } = fakeSourceBuffer();
  vi.stubGlobal(
    "MediaSource",
    class {
      static isTypeSupported = () => true;
      addEventListener(_t: string, h: () => void) {
        h();
      }
      addSourceBuffer() {
        return sb;
      }
    },
  );
  const revokeObjectURL = vi.fn();
  vi.stubGlobal("URL", { createObjectURL: () => "blob:fake", revokeObjectURL });
  const subscribeTrack = vi.fn(async () => {});
  const live = new LiveMovie(
    { subscribeTrack } as unknown as MoqtChatClient,
    fakeVideo(),
    { onError: vi.fn(), ...opts },
  );
  await live.start();
  return { live, sb, appended, subscribeTrack, revokeObjectURL };
}

describe("LiveMovie start() failure reporting", () => {
  it("reports an unsupported MSE codec without creating a MediaSource", async () => {
    const constructed = vi.fn();
    vi.stubGlobal(
      "MediaSource",
      class {
        static isTypeSupported = () => false;
        constructor() {
          constructed();
        }
      },
    );
    const onError = vi.fn();
    const video = fakeVideo();
    const live = new LiveMovie({} as unknown as MoqtChatClient, video, { onError });
    await live.start();
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError.mock.calls[0][0]).toContain(MOVIE_MIME);
    expect(constructed).not.toHaveBeenCalled();
    expect(video.src).toBe("");
  });

  it("routes an addSourceBuffer failure to onError as 'live start failed'", async () => {
    vi.stubGlobal(
      "MediaSource",
      class {
        static isTypeSupported = () => true;
        addEventListener(_t: string, h: () => void) {
          h();
        }
        addSourceBuffer(): never {
          throw new DOMException("bad codec", "NotSupportedError");
        }
      },
    );
    vi.stubGlobal("URL", { createObjectURL: () => "blob:fake", revokeObjectURL: vi.fn() });
    const onError = vi.fn();
    const live = new LiveMovie({} as unknown as MoqtChatClient, fakeVideo(), { onError });
    await live.start();
    expect(onError).toHaveBeenCalledExactlyOnceWith(
      "live start failed: NotSupportedError: bad codec",
    );
  });
});

describe("LiveMovie", () => {
  it("appends init before any fragment and buffers fragments that arrive first", async () => {
    const { live, sb, appended, subscribeTrack } = await startedLiveMovie();
    expect(subscribeTrack).toHaveBeenCalledExactlyOnceWith(
      utf8ToBytes(MOVIE_INIT_TRACK_NAME),
      MOVIE_INIT_TRACK_NAME,
    );
    expect(sb.mode).toBe("sequence");

    const frag = new Uint8Array([10, 11, 12]);
    await live.handleFragment(fragmentWire(frag), fakeReader([]), false, 0n);
    expect(appended.length).toBe(0);

    const init = new Uint8Array([1, 2, 3]);
    live.handleInit(init);
    expect([...appended[0]]).toEqual([...init]);
    sb.finish();
    expect([...appended[1]]).toEqual([...frag]);
    expect(subscribeTrack).toHaveBeenLastCalledWith(utf8ToBytes(MOVIE_TRACK_NAME), MOVIE_TRACK_NAME);
  });

  it("records the first Group id it received", async () => {
    const onFirstGroup = vi.fn();
    const { live } = await startedLiveMovie({ onFirstGroup });
    await live.handleFragment(fragmentWire(new Uint8Array([1])), fakeReader([]), false, 7n);
    await live.handleFragment(fragmentWire(new Uint8Array([2])), fakeReader([]), false, 8n);
    expect(live.firstGroup).toBe(7n);
    expect(onFirstGroup).toHaveBeenCalledExactlyOnceWith(7n);
  });

  it("drops a malformed fragment without touching the queue", async () => {
    const { live, sb, appended } = await startedLiveMovie();
    live.handleInit(new Uint8Array([1]));
    sb.finish();
    const wire = fragmentWire(new Uint8Array([10, 11, 12]));
    await live.handleFragment(wire.slice(0, wire.length - 1), fakeReader([]), false, 0n);
    expect(appended.length).toBe(1);
    expect(live.firstGroup).toBeUndefined();
  });

  it("stop() revokes the object URL start() created", async () => {
    const { live, revokeObjectURL } = await startedLiveMovie();
    live.stop();
    expect(revokeObjectURL).toHaveBeenCalledExactlyOnceWith("blob:fake");
  });
});
