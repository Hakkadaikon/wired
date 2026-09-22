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
  concatBytes,
  decodeSubgroupHeader,
  decodeSubgroupObject,
  bytesToUtf8,
  encodeControlFrame,
  encodeObjectDatagram,
  encodeRequestError,
  encodeSubscribeOk,
  encodeVarint,
  utf8ToBytes,
} from "../moqtWire";
import {
  buildAttachmentSubgroupHeader,
  decodeAttachmentChunkMessage,
  decodeTextPartMessage,
  encodeAttachmentChunkMessage,
  encodeTextPartMessage,
  ATTACHMENT_CHUNK_MARKER,
  splitAttachmentIntoChunks,
} from "../moqtAttachmentWire";

// Wraps an already-encoded Object body (text-part or attachment-chunk) in
// the SUBGROUP_HEADER + Object envelope a real uni stream carries, for
// pushing into FakeWebTransport.incomingUnidirectionalStreams.
function wireObject(trackAlias: bigint, groupId: bigint, body: Uint8Array): Uint8Array {
  return concatBytes([
    buildAttachmentSubgroupHeader(trackAlias, groupId),
    encodeVarint(0n),
    encodeVarint(BigInt(body.length)),
    body,
  ]);
}

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

  it("classifies an attachment-chunk-marker payload as attachment-chunk", () => {
    const wire = encodeAttachmentChunkMessage({
      messageId: 1,
      attachmentIdx: 0,
      seq: 0,
      idx: 0,
      count: 1,
      mimeType: "image/png",
      totalBytes: 3,
      data: new Uint8Array([1, 2, 3]),
    });
    expect(classifyChatPayload(wire)).toBe("attachment-chunk");
  });

  it("classifies a text-part-marker payload as attachment-text", () => {
    const wire = encodeTextPartMessage(1, 2, "hello");
    expect(classifyChatPayload(wire)).toBe("attachment-text");
  });

  it("ATTACHMENT_CHUNK_MARKER (0xFD) never appears as a valid UTF-8 lead byte, so it cannot collide with text", () => {
    // 0xFD is not a valid UTF-8 lead byte per RFC 3629 (max lead byte is 0xF4);
    // any real chat text's first byte can therefore never equal the marker.
    expect(ATTACHMENT_CHUNK_MARKER).toBe(0xfd);
    const text = utf8ToBytes("some ordinary message");
    expect(text[0]).not.toBe(ATTACHMENT_CHUNK_MARKER);
  });

  it("does not collide with the nickname marker (0x00)", () => {
    expect(ATTACHMENT_CHUNK_MARKER).not.toBe(0x00);
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

describe("MoqtChatClient.sendMessage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  async function connectedWithCapture() {
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
    return { client, written };
  }

  it("publishes the text part once, then each attachment as its chunked run, in order", async () => {
    const { client, written } = await connectedWithCapture();

    const dataA = new Uint8Array(1000).map((_, i) => i % 256);
    const dataB = new Uint8Array(10).map((_, i) => i);
    await client.sendMessage("hello", [
      { bytes: dataA, mimeType: "image/png" },
      { bytes: dataB, mimeType: "video/mp4" },
    ]);

    const expectedChunksA = splitAttachmentIntoChunks(1, 0, "image/png", dataA);
    const expectedChunksB = splitAttachmentIntoChunks(1, 1, "video/mp4", dataB);
    // 1 text-part stream + chunked streams for each attachment.
    expect(written).toHaveLength(1 + expectedChunksA.length + expectedChunksB.length);

    const { header: h0, len: l0 } = decodeSubgroupHeader(written[0]);
    expect(h0.trackAlias).toBe(0n); // user1's own track alias
    const { object: o0 } = decodeSubgroupObject(written[0], l0, h0.flags.properties, 0n, true);
    const textPart = decodeTextPartMessage(o0.payload);
    const messageId = textPart.messageId; // seeded from crypto.getRandomValues, not fixed
    expect(textPart.attachmentCount).toBe(2);
    expect(textPart.text).toBe("hello");

    let prevGroupId = h0.groupId;
    for (let i = 0; i < expectedChunksA.length; i++) {
      const wire = written[1 + i];
      const { header, len } = decodeSubgroupHeader(wire);
      expect(header.groupId).toBeGreaterThan(prevGroupId);
      prevGroupId = header.groupId;
      const { object } = decodeSubgroupObject(wire, len, header.flags.properties, 0n, true);
      const chunk = decodeAttachmentChunkMessage(object.payload);
      expect(chunk.messageId).toBe(messageId);
      expect(chunk.attachmentIdx).toBe(0);
      expect(chunk.idx).toBe(i);
      expect(chunk.data).toEqual(expectedChunksA[i].data);
    }

    const offsetB = 1 + expectedChunksA.length;
    for (let i = 0; i < expectedChunksB.length; i++) {
      const wire = written[offsetB + i];
      const { header, len } = decodeSubgroupHeader(wire);
      expect(header.groupId).toBeGreaterThan(prevGroupId);
      prevGroupId = header.groupId;
      const { object } = decodeSubgroupObject(wire, len, header.flags.properties, 0n, true);
      const chunk = decodeAttachmentChunkMessage(object.payload);
      expect(chunk.messageId).toBe(messageId);
      expect(chunk.attachmentIdx).toBe(1);
      expect(chunk.idx).toBe(i);
      expect(chunk.data).toEqual(expectedChunksB[i].data);
    }

    client.close();
  });

  it("sends only the text part when there are no attachments", async () => {
    const { client, written } = await connectedWithCapture();

    await client.sendMessage("just text", []);

    expect(written).toHaveLength(1);
    const { header, len } = decodeSubgroupHeader(written[0]);
    const { object } = decodeSubgroupObject(written[0], len, header.flags.properties, 0n, true);
    const textPart = decodeTextPartMessage(object.payload);
    expect(textPart.attachmentCount).toBe(0);
    expect(textPart.text).toBe("just text");

    client.close();
  });

  // C1 regression: a fixed #nextMessageId = 1 start meant a reloaded sender
  // reused messageIds a previous session's session already used, so a
  // receiver's still-pending (attachment-only) entry for that id could
  // absorb a new, unrelated text-only send. The counter must start from a
  // value seeded by crypto.getRandomValues, not a hardcoded 1.
  it("C1: the first messageId sent is seeded from crypto.getRandomValues, not a hardcoded 1", async () => {
    const getRandomValues = vi.fn((arr: Uint32Array) => {
      arr[0] = 0xdeadbeef;
      return arr;
    });
    vi.stubGlobal("crypto", { getRandomValues });
    const { client, written } = await connectedWithCapture();

    await client.sendMessage("hello", []);

    const { header, len } = decodeSubgroupHeader(written[0]);
    const { object } = decodeSubgroupObject(written[0], len, header.flags.properties, 0n, true);
    const textPart = decodeTextPartMessage(object.payload);
    expect(textPart.messageId).toBe(0xdeadbeef);
    expect(getRandomValues).toHaveBeenCalled();

    client.close();
  });
});

// Drives the receive-side message-aggregation state machine: a text part and
// its attachments can arrive in either order, over separate uni streams, and
// onMessage must fire exactly once per message once everything has arrived.
describe("MoqtChatClient message aggregation", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  async function connectedListening() {
    vi.useFakeTimers();
    const fake = new FakeWebTransport();
    vi.stubGlobal("WebTransport", function () {
      return fake;
    });
    const messages: { participantId: string; text: string; attachments: { bytes: Uint8Array; mimeType: string }[] }[] = [];
    const client = new MoqtChatClient("user1", {
      onStatusChange: () => {},
      onMessage: (participantId, text, attachments) => {
        messages.push({ participantId, text, attachments });
      },
    });
    const connected = client.connect("https://hub.example/", []);
    fake.resolveReady();
    await connected;
    return { fake, client, messages };
  }

  // user2's track alias (CANDIDATE_PARTICIPANT_IDS index 1).
  const SENDER_ALIAS = 1n;

  function pushTextPart(fake: FakeWebTransport, messageId: number, attachmentCount: number, text: string, groupId = 0n) {
    fake.incomingUnidirectionalStreams.push(
      wireObject(SENDER_ALIAS, groupId, encodeTextPartMessage(messageId, attachmentCount, text)),
    );
  }

  function pushAttachment(fake: FakeWebTransport, messageId: number, attachmentIdx: number, mimeType: string, data: Uint8Array, groupIdStart = 1n) {
    const chunks = splitAttachmentIntoChunks(messageId, attachmentIdx, mimeType, data);
    chunks.forEach((chunk, i) => {
      fake.incomingUnidirectionalStreams.push(
        wireObject(SENDER_ALIAS, groupIdStart + BigInt(i), encodeAttachmentChunkMessage(chunk)),
      );
    });
  }

  it("scenario 1: text then all attachments -> onMessage fires exactly once", async () => {
    const { fake, messages } = await connectedListening();

    pushTextPart(fake, 1, 2, "hi", 0n);
    pushAttachment(fake, 1, 0, "image/png", new Uint8Array([1, 2, 3]), 1n);
    pushAttachment(fake, 1, 1, "video/mp4", new Uint8Array([4, 5, 6]), 10n);
    await vi.advanceTimersByTimeAsync(0);

    expect(messages).toHaveLength(1);
    expect(messages[0].text).toBe("hi");
    expect(messages[0].attachments).toHaveLength(2);
    expect(messages[0].attachments[0]).toEqual({ bytes: new Uint8Array([1, 2, 3]), mimeType: "image/png" });
    expect(messages[0].attachments[1]).toEqual({ bytes: new Uint8Array([4, 5, 6]), mimeType: "video/mp4" });
  });

  it("scenario 2: attachments then text (count matches) -> onMessage fires exactly once", async () => {
    const { fake, messages } = await connectedListening();

    pushAttachment(fake, 2, 0, "image/png", new Uint8Array([9]), 0n);
    pushTextPart(fake, 2, 1, "after", 5n);
    await vi.advanceTimersByTimeAsync(0);

    expect(messages).toHaveLength(1);
    expect(messages[0].text).toBe("after");
    expect(messages[0].attachments).toEqual([{ bytes: new Uint8Array([9]), mimeType: "image/png" }]);
  });

  it("scenario 3: a message missing one attachment past the timeout is discarded, not delivered", async () => {
    const { fake, client, messages } = await connectedListening();

    pushTextPart(fake, 3, 2, "incomplete", 0n);
    pushAttachment(fake, 3, 0, "image/png", new Uint8Array([1]), 1n);
    await vi.advanceTimersByTimeAsync(0);
    expect(messages).toHaveLength(0);

    vi.advanceTimersByTime(30_001);
    // Push an unrelated later message to trigger the lazy sweep.
    pushTextPart(fake, 999, 0, "trigger sweep", 100n);
    await vi.advanceTimersByTimeAsync(0);

    expect(messages).toHaveLength(1); // only the sweep-trigger message, never #3
    expect(messages[0].text).toBe("trigger sweep");

    // The stale #pendingMessages entry for messageId 3 must actually be
    // gone (not merely unreachable): re-using messageId 3 now starts a
    // fresh, independent, fully-satisfiable cycle rather than completing
    // the old discarded one with a leftover attachment count/text.
    pushTextPart(fake, 3, 1, "reused id", 200n);
    pushAttachment(fake, 3, 0, "image/png", new Uint8Array([7]), 201n);
    await vi.advanceTimersByTimeAsync(0);

    expect(messages).toHaveLength(2);
    expect(messages[1].text).toBe("reused id");
    expect(messages[1].attachments).toEqual([{ bytes: new Uint8Array([7]), mimeType: "image/png" }]);
    client.close();
  });

  it("scenario 4: messageId re-use starts an independent cycle, the first delivery's args untouched", async () => {
    const { fake, messages } = await connectedListening();

    pushTextPart(fake, 5, 0, "first", 0n);
    await vi.advanceTimersByTimeAsync(0);
    expect(messages).toHaveLength(1);
    const firstArgs = messages[0];

    pushTextPart(fake, 5, 0, "second", 1n);
    await vi.advanceTimersByTimeAsync(0);

    expect(messages).toHaveLength(2);
    expect(firstArgs.text).toBe("first"); // untouched by the second cycle
    expect(messages[1].text).toBe("second");
  });

  it("scenario 5: a text-only message (no attachments) delivers immediately on text arrival", async () => {
    const { fake, messages } = await connectedListening();

    pushTextPart(fake, 6, 0, "no attachments here", 0n);
    await vi.advanceTimersByTimeAsync(0);

    expect(messages).toHaveLength(1);
    expect(messages[0].text).toBe("no attachments here");
    expect(messages[0].attachments).toEqual([]);
  });

  it("scenario 6: an attachment chunk delayed past a timed-out message's discard starts fresh, no misdelivery", async () => {
    const { fake, client, messages } = await connectedListening();

    pushTextPart(fake, 7, 1, "will time out", 0n);
    await vi.advanceTimersByTimeAsync(0);
    expect(messages).toHaveLength(0);

    vi.advanceTimersByTime(30_001);
    // A late attachment-chunk arrival triggers the lazy sweep itself, then
    // starts a brand-new (still-incomplete) cycle for the same messageId --
    // it must NOT revive/deliver the old discarded text.
    pushAttachment(fake, 7, 0, "image/png", new Uint8Array([1]), 100n);
    await vi.advanceTimersByTimeAsync(0);

    expect(messages).toHaveLength(0);
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
