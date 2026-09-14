import { describe, expect, it, vi } from "vitest";
import { MoqtScreenClient, ownScreenTrackAlias } from "../moqtScreenClient";
import { CANDIDATE_PARTICIPANT_IDS, type MoqtChatClient } from "../moqtClient";
import { MOVIE_INIT_TRACK_ALIAS } from "../moqtMovieClient";
import { concatBytes, decodeSubgroupHeader, decodeSubgroupObject } from "../moqtWire";
import { decodeScreenObjectMessage } from "../moqtScreenWire";

describe("ownScreenTrackAlias", () => {
  it("sits immediately after the movie init alias (SCREEN_ALIAS_OFFSET), not a bare 10", () => {
    for (const id of CANDIDATE_PARTICIPANT_IDS) {
      expect(ownScreenTrackAlias(id)).toBeGreaterThanOrEqual(MOVIE_INIT_TRACK_ALIAS + 1n);
    }
  });

  it("is distinct per participant (no two screen aliases collide)", () => {
    const aliases = CANDIDATE_PARTICIPANT_IDS.map(ownScreenTrackAlias);
    expect(new Set(aliases).size).toBe(aliases.length);
  });

  it("covers exactly [offset, offset+N) for id=0..N-1 (boundary check)", () => {
    const offset = MOVIE_INIT_TRACK_ALIAS + 1n;
    const aliases = CANDIDATE_PARTICIPANT_IDS.map(ownScreenTrackAlias).sort((a, b) =>
      a < b ? -1 : a > b ? 1 : 0,
    );
    expect(aliases[0]).toBe(offset);
    expect(aliases[aliases.length - 1]).toBe(offset + BigInt(CANDIDATE_PARTICIPANT_IDS.length) - 1n);
  });
});

// Minimal fake, same shape as moqtVoiceClient.test.ts's fakeWebTransport:
// only createUnidirectionalStream is exercised by sendVideoChunk.
function fakeWebTransport() {
  const writes: Uint8Array[] = [];
  let closed = false;
  const writer = {
    write: vi.fn(async (chunk: Uint8Array) => {
      writes.push(chunk);
    }),
    close: vi.fn(async () => {
      closed = true;
    }),
  };
  const stream = { getWriter: () => writer };
  const createUnidirectionalStream = vi.fn(async () => stream);
  return {
    webTransport: { createUnidirectionalStream } as unknown as WebTransport,
    createUnidirectionalStream,
    writer,
    writes,
    get closed() {
      return closed;
    },
  };
}

function fakeChatClient(wt: ReturnType<typeof fakeWebTransport>): MoqtChatClient {
  return {
    localId: "user1",
    webTransport: wt.webTransport,
    publishTrack: vi.fn(async () => {}),
    subscribeTrack: vi.fn(async () => {}),
  } as unknown as MoqtChatClient;
}

describe("MoqtScreenClient.sendVideoChunk", () => {
  it("opens exactly one uni stream on the first call, and reuses its writer after", async () => {
    const wt = fakeWebTransport();
    const client = new MoqtScreenClient(fakeChatClient(wt), { onScreenChunk: vi.fn() });
    await client.publishScreenTrack();

    await client.sendVideoChunk({
      seq: 0,
      idx: 0,
      count: 1,
      keyframe: true,
      timestampUs: 0,
      data: new Uint8Array([1, 2, 3]),
    });
    await client.sendVideoChunk({
      seq: 1,
      idx: 0,
      count: 1,
      keyframe: false,
      timestampUs: 1,
      data: new Uint8Array([4, 5, 6]),
    });

    expect(wt.createUnidirectionalStream).toHaveBeenCalledTimes(1);
    expect(wt.writer.write).toHaveBeenCalledTimes(2);
  });

  it("close() FINs the writer", async () => {
    const wt = fakeWebTransport();
    const client = new MoqtScreenClient(fakeChatClient(wt), { onScreenChunk: vi.fn() });
    await client.publishScreenTrack();
    await client.sendVideoChunk({
      seq: 0,
      idx: 0,
      count: 1,
      keyframe: true,
      timestampUs: 0,
      data: new Uint8Array([1]),
    });

    client.close();
    await Promise.resolve();

    expect(wt.writer.close).toHaveBeenCalledTimes(1);
  });

  it("close() before any chunk was sent is a no-op (no writer to close)", () => {
    const wt = fakeWebTransport();
    const client = new MoqtScreenClient(fakeChatClient(wt), { onScreenChunk: vi.fn() });
    expect(() => client.close()).not.toThrow();
    expect(wt.writer.close).not.toHaveBeenCalled();
  });

  it("round-trips a chunk through the wire so the reassembled Object decodes back", async () => {
    const wt = fakeWebTransport();
    const client = new MoqtScreenClient(fakeChatClient(wt), { onScreenChunk: vi.fn() });
    await client.publishScreenTrack();
    await client.sendVideoChunk({
      seq: 7,
      idx: 0,
      count: 1,
      keyframe: true,
      timestampUs: 123,
      width: 1920,
      height: 1080,
      codec: "vp8",
      data: new Uint8Array([9, 8, 7]),
    });

    const wire = concatBytes(wt.writes);
    const { len: headerLen } = decodeSubgroupHeader(wire);
    const { object } = decodeSubgroupObject(wire, headerLen, false, 0n, true);
    const { chunk } = decodeScreenObjectMessage(object.payload);
    expect(chunk.seq).toBe(7);
    expect(chunk.data).toEqual(new Uint8Array([9, 8, 7]));
  });
});

describe("MoqtScreenClient.handleIncomingStream", () => {
  it("cancels the reader for a track alias outside the screen range", () => {
    const wt = fakeWebTransport();
    const client = new MoqtScreenClient(fakeChatClient(wt), { onScreenChunk: vi.fn() });
    const cancel = vi.fn(async () => {});
    const reader = { cancel, read: vi.fn() } as unknown as ReadableStreamDefaultReader<Uint8Array>;
    client.handleIncomingStream(
      { trackAlias: 0n, groupId: 0n, flags: { properties: false } } as never,
      new Uint8Array(),
      reader,
    );
    expect(cancel).toHaveBeenCalledTimes(1);
  });
});
