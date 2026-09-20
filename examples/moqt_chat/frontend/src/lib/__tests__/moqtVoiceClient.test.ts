import { describe, expect, it, vi } from "vitest";
import { MoqtVoiceClient, ownAudioTrackAlias } from "../moqtVoiceClient";
import { CANDIDATE_PARTICIPANT_IDS, ownTrackAlias, type MoqtChatClient } from "../moqtClient";
import {
  concatBytes,
  decodeObjectDatagram,
  decodeSubgroupHeader,
  encodeObjectDatagram,
} from "../moqtWire";
import { decodeVoiceObjectStream } from "../moqtVoiceWire";

describe("ownAudioTrackAlias", () => {
  it("never collides with a chat Track Alias (0..N-1)", () => {
    for (const id of CANDIDATE_PARTICIPANT_IDS) {
      expect(ownAudioTrackAlias(id)).toBeGreaterThanOrEqual(
        BigInt(CANDIDATE_PARTICIPANT_IDS.length),
      );
    }
  });

  it("is offset from the same participant's chat alias by the candidate pool size", () => {
    for (const id of CANDIDATE_PARTICIPANT_IDS) {
      expect(ownAudioTrackAlias(id) - ownTrackAlias(id)).toBe(
        BigInt(CANDIDATE_PARTICIPANT_IDS.length),
      );
    }
  });

  it("is distinct per participant (no two audio aliases collide)", () => {
    const aliases = CANDIDATE_PARTICIPANT_IDS.map(ownAudioTrackAlias);
    expect(new Set(aliases).size).toBe(aliases.length);
  });
});

// Minimal fake: createUnidirectionalStream and (when maxDatagramSize is
// given) wt.datagrams are what MoqtVoiceClient.sendOpusFrame exercises; the
// fake writers just record what they were written. No maxDatagramSize
// models a transport without a usable datagram path, so the pre-datagram
// stream-path tests below double as the fallback-path coverage.
function fakeWebTransport(opts: { maxDatagramSize?: number } = {}) {
  const writes: Uint8Array[] = [];
  const datagramWrites: Uint8Array[] = [];
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
  const datagrams =
    opts.maxDatagramSize === undefined
      ? undefined
      : {
          maxDatagramSize: opts.maxDatagramSize,
          writable: {
            getWriter: () => ({
              write: async (chunk: Uint8Array) => {
                datagramWrites.push(chunk);
              },
            }),
          },
        };
  return {
    webTransport: { createUnidirectionalStream, datagrams } as unknown as WebTransport,
    createUnidirectionalStream,
    writer,
    writes,
    datagramWrites,
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
  } as unknown as MoqtChatClient;
}

describe("MoqtVoiceClient.sendOpusFrame", () => {
  it("opens exactly one uni stream on the first call, and reuses its writer after", async () => {
    const wt = fakeWebTransport();
    const client = new MoqtVoiceClient(fakeChatClient(wt), { onOpusFrame: vi.fn() });
    await client.publishAudioTrack();

    await client.sendOpusFrame(new Uint8Array([1, 2, 3]));
    await client.sendOpusFrame(new Uint8Array([4, 5, 6]));
    await client.sendOpusFrame(new Uint8Array([7, 8, 9]));

    expect(wt.createUnidirectionalStream).toHaveBeenCalledTimes(1);
    expect(wt.writer.write).toHaveBeenCalledTimes(3);
  });

  it("close() FINs the writer", async () => {
    const wt = fakeWebTransport();
    const client = new MoqtVoiceClient(fakeChatClient(wt), { onOpusFrame: vi.fn() });
    await client.publishAudioTrack();
    await client.sendOpusFrame(new Uint8Array([1]));

    client.close();
    await Promise.resolve(); // let the fire-and-forget writer.close() settle

    expect(wt.writer.close).toHaveBeenCalledTimes(1);
  });

  it("close() before any frame was sent is a no-op (no writer to close)", () => {
    const wt = fakeWebTransport();
    const client = new MoqtVoiceClient(fakeChatClient(wt), { onOpusFrame: vi.fn() });
    expect(() => client.close()).not.toThrow();
    expect(wt.writer.close).not.toHaveBeenCalled();
  });

  // The receive side keys its jitter buffer on each Object's seq and drops
  // an already-buffered seq as a duplicate (jitterBuffer.ts) -- a constant
  // seq delivered exactly ONE audible frame per call and silently discarded
  // every later one (the original "voice never gets through" symptom).
  it("increments the wire seq on every frame", async () => {
    const wt = fakeWebTransport();
    const client = new MoqtVoiceClient(fakeChatClient(wt), { onOpusFrame: vi.fn() });
    await client.publishAudioTrack();

    await client.sendOpusFrame(new Uint8Array([1]));
    await client.sendOpusFrame(new Uint8Array([2]));
    await client.sendOpusFrame(new Uint8Array([3]));

    const wire = concatBytes(wt.writes);
    const { len: headerLen } = decodeSubgroupHeader(wire);
    const payloads = decodeVoiceObjectStream(wire, headerLen, false);
    expect(payloads.map((p) => p.seq)).toEqual([0, 1, 2]);
  });

  it("sends each frame as one OBJECT_DATAGRAM when it fits maxDatagramSize", async () => {
    const wt = fakeWebTransport({ maxDatagramSize: 1200 });
    const client = new MoqtVoiceClient(fakeChatClient(wt), { onOpusFrame: vi.fn() });
    await client.publishAudioTrack();

    await client.sendOpusFrame(new Uint8Array([1, 2, 3]));
    await client.sendOpusFrame(new Uint8Array([4, 5]));

    expect(wt.createUnidirectionalStream).not.toHaveBeenCalled();
    expect(wt.datagramWrites.length).toBe(2);
    const d = decodeObjectDatagram(wt.datagramWrites[1]);
    expect(d.type).toBe(0x08n);
    expect(d.trackAlias).toBe(ownAudioTrackAlias("user1"));
    expect(d.groupId).toBe(0n);
    expect(d.objectId).toBe(1n);
    // payload keeps the stream path's exact shape: seq u16 BE + opus
    expect(Array.from(d.payload)).toEqual([0, 1, 4, 5]);
  });

  it("falls back to the uni-stream path when the frame exceeds maxDatagramSize", async () => {
    const wt = fakeWebTransport({ maxDatagramSize: 8 });
    const client = new MoqtVoiceClient(fakeChatClient(wt), { onOpusFrame: vi.fn() });
    await client.publishAudioTrack();

    await client.sendOpusFrame(new Uint8Array(100));

    expect(wt.datagramWrites.length).toBe(0);
    expect(wt.createUnidirectionalStream).toHaveBeenCalledTimes(1);
    expect(wt.writer.write).toHaveBeenCalledTimes(1);
  });
});

describe("MoqtVoiceClient.handleIncomingDatagram", () => {
  const datagramFrom = (participant: string, seq: number, opus: number[]) =>
    decodeObjectDatagram(
      encodeObjectDatagram({
        type: 0x08n,
        trackAlias: ownAudioTrackAlias(participant),
        groupId: 0n,
        objectId: BigInt(seq),
        payload: new Uint8Array([(seq >> 8) & 0xff, seq & 0xff, ...opus]),
      }),
    );

  it("routes a known audio alias to onOpusFrame with the decoded payload", () => {
    const onOpusFrame = vi.fn();
    const client = new MoqtVoiceClient(fakeChatClient(fakeWebTransport()), { onOpusFrame });

    client.handleIncomingDatagram(datagramFrom("user2", 7, [9, 8]));

    expect(onOpusFrame).toHaveBeenCalledTimes(1);
    const [participant, payload] = onOpusFrame.mock.calls[0];
    expect(participant).toBe("user2");
    expect(payload.seq).toBe(7);
    expect(Array.from(payload.opus)).toEqual([9, 8]);
  });

  it("ignores a datagram whose alias is not a known audio track", () => {
    const onOpusFrame = vi.fn();
    const client = new MoqtVoiceClient(fakeChatClient(fakeWebTransport()), { onOpusFrame });

    const chatAlias = decodeObjectDatagram(
      encodeObjectDatagram({ type: 0x08n, trackAlias: 0n, groupId: 0n, objectId: 0n }),
    );
    const beyondPool = decodeObjectDatagram(
      encodeObjectDatagram({ type: 0x08n, trackAlias: 99n, groupId: 0n, objectId: 0n }),
    );
    expect(() => client.handleIncomingDatagram(chatAlias)).not.toThrow();
    expect(() => client.handleIncomingDatagram(beyondPool)).not.toThrow();
    expect(onOpusFrame).not.toHaveBeenCalled();
  });

  it("ignores a datagram whose payload is too short to carry the seq header", () => {
    const onOpusFrame = vi.fn();
    const client = new MoqtVoiceClient(fakeChatClient(fakeWebTransport()), { onOpusFrame });

    const short = decodeObjectDatagram(
      encodeObjectDatagram({
        type: 0x08n,
        trackAlias: ownAudioTrackAlias("user2"),
        groupId: 0n,
        objectId: 0n,
        payload: new Uint8Array([1]),
      }),
    );
    expect(() => client.handleIncomingDatagram(short)).not.toThrow();
    expect(onOpusFrame).not.toHaveBeenCalled();
  });
});
