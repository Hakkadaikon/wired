import { afterEach, describe, expect, it, vi } from "vitest";
import {
  MoqtScreenClient,
  ownScreenTrackAlias,
  SCREEN_ALIAS_OFFSET,
  SCREEN_WRITE_TIMEOUT_MS,
} from "../moqtScreenClient";
import { CANDIDATE_PARTICIPANT_IDS, type MoqtChatClient } from "../moqtClient";
import { concatBytes, decodeSubgroupHeader, decodeSubgroupObject, encodeVarint } from "../moqtWire";
import { decodeScreenObjectMessage, encodeScreenObjectMessage } from "../moqtScreenWire";

describe("ownScreenTrackAlias", () => {
  it("SCREEN_ALIAS_OFFSET is CANDIDATE_PARTICIPANT_IDS.length * 2 + 2 (10 for the current 4-id pool)", () => {
    expect(SCREEN_ALIAS_OFFSET).toBe(BigInt(CANDIDATE_PARTICIPANT_IDS.length * 2 + 2));
    expect(SCREEN_ALIAS_OFFSET).toBe(10n);
  });

  it("is distinct per participant (no two screen aliases collide)", () => {
    const aliases = CANDIDATE_PARTICIPANT_IDS.map(ownScreenTrackAlias);
    expect(new Set(aliases).size).toBe(aliases.length);
  });

  it("covers exactly [offset, offset+N) for id=0..N-1 (boundary check)", () => {
    const offset = SCREEN_ALIAS_OFFSET;
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
  const wt = {
    // While set, write() never settles -- a flow-control window that
    // never opens, from the writer's point of view.
    hang: false,
    writer: {
      write: vi.fn((chunk: Uint8Array) => {
        if (wt.hang) return new Promise<void>(() => {});
        writes.push(chunk);
        return Promise.resolve();
      }),
      close: vi.fn(async () => {
        closed = true;
      }),
      abort: vi.fn(async () => {}),
    },
    createUnidirectionalStream: vi.fn(async () => ({ getWriter: () => wt.writer })),
    webTransport: undefined as unknown as WebTransport,
    writes,
    get closed() {
      return closed;
    },
  };
  wt.webTransport = { createUnidirectionalStream: wt.createUnidirectionalStream } as unknown as WebTransport;
  return wt;
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

const chunkAt = (seq: number) => ({
  seq,
  idx: 0,
  count: 1,
  keyframe: false,
  timestampUs: 0,
  data: new Uint8Array([seq]),
});

describe("MoqtScreenClient.sendVideoChunk write timeout", () => {
  afterEach(() => vi.useRealTimers());

  it("aborts a write that hangs past the timeout, resets, and reopens on the next chunk", async () => {
    vi.useFakeTimers();
    const wt = fakeWebTransport();
    const onStreamReset = vi.fn();
    const client = new MoqtScreenClient(fakeChatClient(wt), { onScreenChunk: vi.fn(), onStreamReset });
    await client.publishScreenTrack();
    await client.sendVideoChunk(chunkAt(0));

    wt.hang = true;
    // Handler attached up front: the rejection lands mid-advance, before
    // an `await expect(...).rejects` could observe it.
    const rejected = client.sendVideoChunk(chunkAt(1)).then(() => false, () => true);
    await vi.advanceTimersByTimeAsync(SCREEN_WRITE_TIMEOUT_MS - 1);
    expect(wt.writer.abort).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(await rejected).toBe(true);
    expect(wt.writer.abort).toHaveBeenCalledTimes(1);
    expect(onStreamReset).toHaveBeenCalledTimes(1);

    wt.hang = false;
    await client.sendVideoChunk(chunkAt(2));
    expect(wt.createUnidirectionalStream).toHaveBeenCalledTimes(2);
    // The reopened stream starts over with a SUBGROUP_HEADER, not a bare Object.
    const last = wt.writes[wt.writes.length - 1];
    expect(decodeSubgroupHeader(last).header.trackAlias).toBe(ownScreenTrackAlias("user1"));
  });

  it("times out a createUnidirectionalStream that never resolves, without a writer to abort", async () => {
    vi.useFakeTimers();
    const wt = fakeWebTransport();
    wt.createUnidirectionalStream.mockImplementation(() => new Promise(() => {}));
    const onStreamReset = vi.fn();
    const client = new MoqtScreenClient(fakeChatClient(wt), { onScreenChunk: vi.fn(), onStreamReset });
    await client.publishScreenTrack();
    const rejected = client.sendVideoChunk(chunkAt(0)).then(() => false, () => true);
    await vi.advanceTimersByTimeAsync(SCREEN_WRITE_TIMEOUT_MS);
    expect(await rejected).toBe(true);
    expect(wt.writer.abort).not.toHaveBeenCalled();
    expect(onStreamReset).toHaveBeenCalledTimes(1);
  });
});

describe("MoqtScreenClient.handleIncomingStream", () => {
  it("routes a second stream from the same sender to the same onScreenChunk", () => {
    const wt = fakeWebTransport();
    const onScreenChunk = vi.fn();
    const client = new MoqtScreenClient(fakeChatClient(wt), { onScreenChunk });
    const header = { trackAlias: ownScreenTrackAlias("user2"), groupId: 0n, flags: { properties: false } };
    const object = (seq: number) => {
      const body = encodeScreenObjectMessage(chunkAt(seq));
      return concatBytes([encodeVarint(0n), encodeVarint(BigInt(body.length)), body]);
    };
    const doneReader = { read: vi.fn(async () => ({ value: undefined, done: true })), cancel: vi.fn() };
    client.handleIncomingStream(header as never, object(0), doneReader as never);
    client.handleIncomingStream(header as never, object(1), doneReader as never);
    expect(onScreenChunk.mock.calls.map((c) => [c[0], c[1].seq])).toEqual([["user2", 0], ["user2", 1]]);
  });

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
