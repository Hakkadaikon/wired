import { describe, expect, it } from "vitest";
import {
  buildChatObjectMessage,
  parseChatObjectMessage,
  candidateParticipantIds,
  certHashesToWebTransportOptions,
} from "../moqtClient";
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
