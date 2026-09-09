import { describe, expect, it, vi } from "vitest";
import {
  decodeBlobObjects,
  MOVIE_TRACK_ALIAS,
  MOVIE_TRACK_NAME,
  readMovie,
  subscribeMovie,
} from "../moqtMovieClient";
import { CANDIDATE_PARTICIPANT_IDS, type MoqtChatClient } from "../moqtClient";
import { ownAudioTrackAlias } from "../moqtVoiceClient";
import { concatBytes, encodeVarint, MoqtDecodeError, utf8ToBytes } from "../moqtWire";

const MAX_PAYLOAD = 16384;

function fill(len: number, seed: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = (i * 31 + seed) & 0xff;
  return out;
}

// Mirrors the hub's blob framing: Object ID Delta 0, Payload Length, bytes.
function encodeObjects(payloads: Uint8Array[]): Uint8Array {
  return concatBytes(
    payloads.map((p) => concatBytes([encodeVarint(0n), encodeVarint(BigInt(p.length)), p])),
  );
}

function splitEvery(bytes: Uint8Array, n: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < bytes.length; i += n) out.push(bytes.slice(i, i + n));
  return out;
}

describe("MOVIE_TRACK_ALIAS", () => {
  it("is 2 * candidate pool size, distinct from every chat and audio alias", () => {
    expect(MOVIE_TRACK_ALIAS).toBe(2n * BigInt(CANDIDATE_PARTICIPANT_IDS.length));
    for (let i = 0; i < CANDIDATE_PARTICIPANT_IDS.length; i++) {
      expect(MOVIE_TRACK_ALIAS).not.toBe(BigInt(i));
    }
    for (const id of CANDIDATE_PARTICIPANT_IDS) {
      expect(MOVIE_TRACK_ALIAS).not.toBe(ownAudioTrackAlias(id));
    }
  });
});

describe("decodeBlobObjects", () => {
  it("round-trips a single Object", () => {
    const payload = fill(100, 1);
    expect(decodeBlobObjects(encodeObjects([payload]), false)).toEqual(payload);
  });

  it("concatenates N Objects in order, including a full 16384-byte one and a shorter last one", () => {
    const payloads = [fill(MAX_PAYLOAD, 1), fill(MAX_PAYLOAD, 2), fill(777, 3)];
    expect(decodeBlobObjects(encodeObjects(payloads), false)).toEqual(concatBytes(payloads));
  });

  it("rejects a truncated tail with MoqtDecodeError", () => {
    const wire = encodeObjects([fill(50, 1), fill(50, 2)]);
    expect(() => decodeBlobObjects(wire.slice(0, wire.length - 1), false)).toThrow(
      MoqtDecodeError,
    );
    // cut inside the second Object's length prefix
    expect(() => decodeBlobObjects(wire.slice(0, 53), false)).toThrow(MoqtDecodeError);
  });
});

function fakeReader(chunks: Uint8Array[]): ReadableStreamDefaultReader<Uint8Array> {
  const queue = [...chunks];
  return {
    read: vi.fn(async () =>
      queue.length > 0 ? { value: queue.shift(), done: false } : { value: undefined, done: true },
    ),
  } as unknown as ReadableStreamDefaultReader<Uint8Array>;
}

describe("readMovie", () => {
  const payloads = [fill(MAX_PAYLOAD, 5), fill(MAX_PAYLOAD, 6), fill(1000, 7)];
  const movie = concatBytes(payloads);
  const wire = encodeObjects(payloads);

  it("returns the original bytes when the header chunk carried no Object bytes", async () => {
    const got = await readMovie(new Uint8Array(0), fakeReader(splitEvery(wire, 4000)), false);
    expect(got).toEqual(movie);
  });

  it("returns the original bytes when Objects straddle chunk boundaries", async () => {
    const got = await readMovie(wire.slice(0, 7), fakeReader(splitEvery(wire.slice(7), 1234)), false);
    expect(got).toEqual(movie);
  });

  it("returns undefined for a malformed (truncated) stream", async () => {
    expect(await readMovie(wire.slice(0, 10), fakeReader([]), false)).toBeUndefined();
  });

  it("returns undefined when the reader aborts", async () => {
    const reader = { read: vi.fn(async () => { throw new Error("aborted"); }) };
    const got = await readMovie(
      new Uint8Array(0),
      reader as unknown as ReadableStreamDefaultReader<Uint8Array>,
      false,
    );
    expect(got).toBeUndefined();
  });
});

describe("subscribeMovie", () => {
  it("SUBSCRIBEs the hub's \"movie\" track", async () => {
    const subscribeTrack = vi.fn(async () => {});
    await subscribeMovie({ subscribeTrack } as unknown as MoqtChatClient);
    expect(subscribeTrack).toHaveBeenCalledExactlyOnceWith(
      utf8ToBytes(MOVIE_TRACK_NAME),
      "movie",
    );
  });
});
