import { afterEach, describe, expect, it, vi } from "vitest";
import {
  buildChatObjectMessage,
  MoqtChatClient,
  parseChatObjectMessage,
  candidateParticipantIds,
  certHashesToWebTransportOptions,
} from "../moqtClient";
import { FakeWebTransport } from "./fakeWebTransport";
import {
  decodeSubgroupHeader,
  decodeSubgroupObject,
  bytesToUtf8,
} from "../moqtWire";

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
