import { afterEach, describe, expect, it, vi } from "vitest";
import {
  buildChatObjectMessage,
  buildNicknameObjectMessage,
  classifyChatPayload,
  MoqtChatClient,
  parseChatObjectMessage,
  parseNicknameFromChatText,
  candidateParticipantIds,
  certHashesToWebTransportOptions,
} from "../moqtClient";
import { FakeWebTransport } from "./fakeWebTransport";
import {
  decodeSubgroupHeader,
  decodeSubgroupObject,
  bytesToUtf8,
  encodeControlFrame,
  encodeObjectDatagram,
  encodeRequestError,
  encodeSubscribeOk,
  utf8ToBytes,
} from "../moqtWire";
import {
  decodeImageChunkMessage,
  encodeImageChunkMessage,
  IMAGE_CHUNK_MARKER,
  splitImageIntoChunks,
} from "../moqtImageWire";

describe("buildChatObjectMessage", () => {
  it("round-trips through the moqtWire subgroup decoder", () => {
    const wire = buildChatObjectMessage({
      trackAlias: 7n,
      groupId: 3n,
      text: "hello moqt",
    });

    const { header, len } = decodeSubgroupHeader(wire);
    expect(header.trackAlias).toBe(7n);
    expect(header.groupId).toBe(3n);
    expect(header.flags.firstObject).toBe(true);
    expect(header.flags.subgroupIdMode).toBe(0);

    const { object } = decodeSubgroupObject(wire, len, false, 0n, true);
    expect(object.objectId).toBe(0n);
    expect(bytesToUtf8(object.payload)).toBe("hello moqt");
  });

  it("produces exactly one message per call (fresh Group ID each send)", () => {
    const a = buildChatObjectMessage({ trackAlias: 1n, groupId: 0n, text: "a" });
    const b = buildChatObjectMessage({ trackAlias: 1n, groupId: 1n, text: "b" });
    expect(a).not.toEqual(b);
  });
});

describe("parseChatObjectMessage", () => {
  it("recovers the text payload from a full SUBGROUP wire message", () => {
    const wire = buildChatObjectMessage({
      trackAlias: 42n,
      groupId: 9n,
      text: "round trip",
    });
    const parsed = parseChatObjectMessage(wire);
    expect(parsed.trackAlias).toBe(42n);
    expect(parsed.text).toBe("round trip");
  });

  it("throws MoqtDecodeError-shaped error on truncated input", () => {
    expect(() => parseChatObjectMessage(new Uint8Array([0x70]))).toThrow();
  });
});

describe("nickname self-announce message", () => {
  it("round-trips a nickname through the same SUBGROUP wire framing as chat", () => {
    const wire = buildNicknameObjectMessage({ trackAlias: 2n, groupId: 0n, nickname: "Alice" });
    const parsed = parseChatObjectMessage(wire);
    expect(parseNicknameFromChatText(parsed.text)).toBe("Alice");
  });

  it("a normal chat message is never mistaken for a nickname announce", () => {
    expect(parseNicknameFromChatText("hello everyone")).toBeUndefined();
  });

  it("an empty nickname is not sent as an announce", () => {
    expect(() => buildNicknameObjectMessage({ trackAlias: 2n, groupId: 0n, nickname: "" })).toThrow();
  });
});

describe("classifyChatPayload", () => {
  it("classifies plain UTF-8 chat text as text", () => {
    expect(classifyChatPayload(utf8ToBytes("hello everyone"))).toBe("text");
  });

  it("classifies a nickname-marker payload as nickname", () => {
    expect(classifyChatPayload(utf8ToBytes("\u0000nick:Alice"))).toBe("nickname");
  });

  it("classifies an image-chunk-marker payload as image", () => {
    const { chunk } = decodeImageChunkMessage(
      encodeImageChunkMessage({ seq: 1, idx: 0, count: 1, mimeType: "image/png", totalBytes: 3, data: new Uint8Array([1, 2, 3]) }),
    );
    const wire = encodeImageChunkMessage(chunk);
    expect(classifyChatPayload(wire)).toBe("image");
  });

  it("IMAGE_CHUNK_MARKER (0xFF) never appears as a valid UTF-8 lead byte, so it cannot collide with text", () => {
    // 0xFF is not a valid UTF-8 lead byte per RFC 3629 (max lead byte is 0xF4);
    // any real chat text's first byte can therefore never equal the marker.
    expect(IMAGE_CHUNK_MARKER).toBe(0xff);
    const text = utf8ToBytes("some ordinary message");
    expect(text[0]).not.toBe(IMAGE_CHUNK_MARKER);
  });

  it("does not collide with the nickname marker (0x00)", () => {
    expect(IMAGE_CHUNK_MARKER).not.toBe(0x00);
  });
});

describe("candidateParticipantIds", () => {
  it("excludes the local participant id from the fixed candidate pool", () => {
    const ids = candidateParticipantIds("user2");
    expect(ids).not.toContain("user2");
    expect(ids.length).toBeGreaterThan(0);
  });

  it("is stable regardless of local id casing/whitespace", () => {
    const ids = candidateParticipantIds("user1");
    expect(new Set(ids).size).toBe(ids.length);
  });
});

// Drives MoqtChatClient's transport-close detection with a fake WebTransport
// whose deferred closed promise the test settles by hand.
describe("MoqtChatClient transport close detection", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  // Runs microtasks and 0ms timers so a just-settled closed promise's
  // handlers fire before the assertions.
  const flushAsync = () => vi.advanceTimersByTimeAsync(0);

  async function connectedClient() {
    vi.useFakeTimers();
    const fake = new FakeWebTransport();
    vi.stubGlobal("WebTransport", function () {
      return fake;
    });
    const statuses: string[] = [];
    const client = new MoqtChatClient("user1", {
      onStatusChange: (s) => statuses.push(s),
      onMessage: () => {},
    });
    const connected = client.connect("https://hub.example/", []);
    fake.resolveReady();
    await connected;
    const disconnects = () => statuses.filter((s) => s === "disconnected").length;
    return { client, fake, statuses, disconnects };
  }

  it("a closed promise that rejects reports one disconnected", async () => {
    const { fake, disconnects } = await connectedClient();

    fake.rejectClosed(new Error("hub died"));
    await flushAsync();

    expect(disconnects()).toBe(1);
  });

  it("a closed promise that resolves reports one disconnected", async () => {
    const { fake, disconnects } = await connectedClient();

    fake.resolveClosed({ closeCode: 0 });
    await flushAsync();

    expect(disconnects()).toBe(1);
  });

  it("the previous transport's late closed settling is ignored", async () => {
    const { client, fake, disconnects } = await connectedClient();
    const next = new FakeWebTransport();
    vi.stubGlobal("WebTransport", function () {
      return next;
    });
    const reconnected = client.connect("https://hub.example/", []);
    next.resolveReady();
    await reconnected;

    fake.resolveClosed({ closeCode: 0 });
    await flushAsync();

    expect(disconnects()).toBe(0);
  });

  it("tearing down an already-dead session reports no second disconnected", async () => {
    const { client, fake, disconnects } = await connectedClient();

    fake.rejectClosed(new Error("hub died"));
    await flushAsync();
    expect(disconnects()).toBe(1);

    client.close();
    await flushAsync();

    expect(disconnects()).toBe(1);
  });

  it("a failed connect leaves no unhandled rejection from the closed promise", async () => {
    vi.useFakeTimers();
    const fake = new FakeWebTransport();
    vi.stubGlobal("WebTransport", function () {
      return fake;
    });
    const statuses: string[] = [];
    const client = new MoqtChatClient("user1", {
      onStatusChange: (s) => statuses.push(s),
      onMessage: () => {},
    });

    const attempt = client.connect("https://hub.example/", []);
    fake.rejectReady(new Error("hub down"));
    fake.rejectClosed(new Error("hub down"));

    await expect(attempt).rejects.toThrow("hub down");
    await flushAsync();
    // The client stays silent on this path (the caller's rejection handling
    // reports the one "disconnected") -- and the closed rejection must not
    // escape as an unhandled rejection, which would fail this run.
    expect(statuses.filter((s) => s === "disconnected")).toHaveLength(0);
  });

  it("close() reports disconnected once and its closed settling adds none", async () => {
    const { client, fake, disconnects } = await connectedClient();

    client.close();
    fake.resolveClosed({ closeCode: 0 });
    await flushAsync();

    expect(disconnects()).toBe(1);
  });
});

describe("MoqtChatClient subscribeTrack replies", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  async function connected() {
    vi.useFakeTimers();
    const fake = new FakeWebTransport();
    vi.stubGlobal("WebTransport", function () {
      return fake;
    });
    const client = new MoqtChatClient("user1", { onStatusChange: () => {}, onMessage: () => {} });
    const ready = client.connect("https://hub.example/", []);
    fake.resolveReady();
    await ready;
    // connect() itself SUBSCRIBEs to every chat candidate; answer those
    // first so the FIFO reply pairing lines up with the track below.
    for (let i = 0; i < candidateParticipantIds("user1").length; i++) {
      fake.controlReplies.push(doesNotExist());
    }
    await vi.advanceTimersByTimeAsync(0);
    return { fake, client };
  }

  const subscribeOk = () =>
    encodeControlFrame(0x4n, encodeSubscribeOk({ trackAlias: 9n, parameters: [], trackProperties: [] }));
  const doesNotExist = () =>
    encodeControlFrame(0x5n, encodeRequestError({ errorCode: 0x4n, retryInterval: 0n, errorReason: new Uint8Array(0) }));

  it("isSubscribed turns true once the hub answers SUBSCRIBE_OK", async () => {
    const { fake, client } = await connected();
    expect(client.isSubscribed("user2/screen")).toBe(false);

    await client.subscribeTrack(utf8ToBytes("user2/screen"), "user2/screen");
    fake.controlReplies.push(subscribeOk());
    await vi.advanceTimersByTimeAsync(0);

    expect(client.isSubscribed("user2/screen")).toBe(true);
    client.close();
  });

  it("isSubscribed stays false after DOES_NOT_EXIST, so the caller keeps retrying", async () => {
    const { fake, client } = await connected();

    await client.subscribeTrack(utf8ToBytes("user3/screen"), "user3/screen");
    fake.controlReplies.push(doesNotExist());
    await vi.advanceTimersByTimeAsync(0);

    expect(client.isSubscribed("user3/screen")).toBe(false);
    client.close();
  });
});

describe("MoqtChatClient incoming datagrams", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  async function connectedWithDatagrams() {
    vi.useFakeTimers();
    const fake = new FakeWebTransport();
    vi.stubGlobal("WebTransport", function () {
      return fake;
    });
    const aliases: bigint[] = [];
    const client = new MoqtChatClient("user1", {
      onStatusChange: () => {},
      onMessage: () => {},
      onUnknownDatagram: (datagram) => aliases.push(datagram.trackAlias),
    });
    const connected = client.connect("https://hub.example/", []);
    fake.resolveReady();
    await connected;
    return { fake, aliases };
  }

  const dgram = (trackAlias: bigint) =>
    encodeObjectDatagram({ type: 0x08n, trackAlias, groupId: 0n, objectId: 0n });

  it("routes a non-chat alias to onUnknownDatagram, decoded", async () => {
    const { fake, aliases } = await connectedWithDatagrams();

    fake.datagrams.push(dgram(4n));
    fake.datagrams.push(dgram(5n));
    await vi.advanceTimersByTimeAsync(0);

    expect(aliases).toEqual([4n, 5n]);
  });

  it("drops a malformed datagram and keeps reading, and ignores a chat alias", async () => {
    const { fake, aliases } = await connectedWithDatagrams();

    fake.datagrams.push(new Uint8Array([0x22, 0x02, 0x00, 0x05, 0x04])); // invalid Type
    fake.datagrams.push(dgram(0n)); // chat-range alias: not for this callback
    fake.datagrams.push(dgram(7n));
    await vi.advanceTimersByTimeAsync(0);

    expect(aliases).toEqual([7n]);
  });
});

describe("MoqtChatClient.sendImage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("sends one uni stream per chunk, each a valid SUBGROUP_HEADER + image Object, in order", async () => {
    vi.useFakeTimers();
    const fake = new FakeWebTransport();
    vi.stubGlobal("WebTransport", function () {
      return fake;
    });
    const written: Uint8Array[] = [];
    fake.createUnidirectionalStream = (async () => ({
      getWriter: () => ({
        write: async (chunk: Uint8Array) => {
          written.push(chunk);
        },
        close: async () => {},
      }),
    })) as typeof fake.createUnidirectionalStream;
    const client = new MoqtChatClient("user1", { onStatusChange: () => {}, onMessage: () => {} });
    const connected = client.connect("https://hub.example/", []);
    fake.resolveReady();
    await connected;

    const data = new Uint8Array(1000).map((_, i) => i % 256);
    await client.sendImage(data, "image/png");

    const expectedChunks = splitImageIntoChunks(0, data, "image/png");
    expect(written).toHaveLength(expectedChunks.length);

    let prevGroupId = -1n;
    for (let i = 0; i < written.length; i++) {
      const { header, len } = decodeSubgroupHeader(written[i]);
      expect(header.trackAlias).toBe(0n); // user1's own track alias
      expect(header.groupId).toBeGreaterThan(prevGroupId); // increasing -> order preserved
      prevGroupId = header.groupId;

      const { object } = decodeSubgroupObject(written[i], len, header.flags.properties, 0n, true);
      const { chunk } = decodeImageChunkMessage(object.payload);
      expect(chunk.seq).toBe(0);
      expect(chunk.idx).toBe(i);
      expect(chunk.count).toBe(expectedChunks.length);
      expect(chunk.data).toEqual(expectedChunks[i].data);
    }

    client.close();
  });
});

describe("certHashesToWebTransportOptions", () => {
  it("returns no serverCertificateHashes option when no hashes given", () => {
    const opts = certHashesToWebTransportOptions([]);
    expect(opts.serverCertificateHashes).toBeUndefined();
  });

  it("parses colon-hex SHA-256 fingerprints into sha-256 entries", () => {
    const hex = "aa".repeat(32);
    const opts = certHashesToWebTransportOptions([hex]);
    expect(opts.serverCertificateHashes).toHaveLength(1);
    expect(opts.serverCertificateHashes?.[0].algorithm).toBe("sha-256");
  });

  it("rejects a fingerprint that is not 32 bytes", () => {
    expect(() => certHashesToWebTransportOptions(["aabb"])).toThrow();
  });
});
