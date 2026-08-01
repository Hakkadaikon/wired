import { describe, expect, it, vi } from "vitest";
import { MoqtVoiceClient, ownAudioTrackAlias } from "../moqtVoiceClient";
import { CANDIDATE_PARTICIPANT_IDS, ownTrackAlias, type MoqtChatClient } from "../moqtClient";
import { concatBytes, decodeSubgroupHeader } from "../moqtWire";
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

// Minimal fake: only createUnidirectionalStream is exercised by
// MoqtVoiceClient.sendOpusFrame, so the fake stream's writer just records
// what it was written and whether it was closed -- no fake reader side is
// needed since these tests only cover the send path.
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
});
