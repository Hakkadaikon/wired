// Golden-vector tests for the request-stream messages (draft-ietf-moq-
// transport-19 10.2 parameters, 10.12-10.18 FETCH / namespace discovery) and
// the FETCH data stream (11.4.4), pinned to the same JSON the C codec's
// tests read (testvectors/moqt_golden.json).
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  bytesToHex,
  bytesToUtf8,
  decodeControlFrame,
  decodeFetchHeader,
  decodeFetchObject,
  decodeFetchOk,
  decodeNamespaceSuffix,
  decodeRequestOk,
  decodeSubscribeOk,
  encodeControlFrame,
  encodeFetch,
  encodeNamespaceRequest,
  encodeSubscribe,
  hexToBytes,
  largestObjectOf,
  MoqtDecodeError,
  newFetchSeq,
  utf8ToBytes,
} from "../moqtWire";

const golden = JSON.parse(
  readFileSync(path.resolve(import.meta.dirname, "../../../../testvectors/moqt_golden.json"), "utf8"),
);
const ctl = new Map<string, { hex: string; type: string }>(
  golden.ctl.map((v: { name: string }) => [v.name, v]),
);
const body = (name: string) => decodeControlFrame(hexToBytes(ctl.get(name)!.hex)).frame.body;
const frame = (name: string, b: Uint8Array) =>
  bytesToHex(encodeControlFrame(BigInt(ctl.get(name)!.type), b));

describe("message parameters (10.2)", () => {
  it("encode subscribe_params: uint8, Length-prefixed filter, uint8 in ascending Type order", () => {
    const b = encodeSubscribe({
      requestId: 0n,
      trackNamespace: ["chat", "room1"].map(utf8ToBytes),
      trackName: utf8ToBytes("alice"),
      parameters: [
        { type: 0x10n, value: 1n },
        { type: 0x20n, value: 64n },
        { type: 0x21n, value: hexToBytes("04050003") },
        { type: 0x22n, value: 2n },
      ],
    });
    expect(frame("subscribe_params", b)).toBe(ctl.get("subscribe_params")!.hex);
  });

  it("decode subscribe_ok_params: LARGEST_OBJECT is a Location, EXPIRES a varint", () => {
    const msg = decodeSubscribeOk(body("subscribe_ok_params"));
    expect(msg.trackAlias).toBe(1n);
    expect(msg.parameters[0]).toEqual({ type: 0x8n, value: 100n });
    expect(largestObjectOf(msg.parameters)).toEqual({ group: 7n, object: 3n });
  });

  it("largestObjectOf is undefined when SUBSCRIBE_OK carries none", () => {
    expect(largestObjectOf([])).toBeUndefined();
  });

  it("decode request_ok_params", () => {
    const msg = decodeRequestOk(body("request_ok_params"));
    expect(msg.parameters).toEqual([
      { type: 0x10n, value: 0n },
      { type: 0x20n, value: 7n },
    ]);
  });

  it("rejects an unknown parameter Type", () => {
    // SUBSCRIBE_OK alias 1, one parameter of Type 0x3f (unregistered).
    expect(() => decodeSubscribeOk(hexToBytes("01013f00"))).toThrow(MoqtDecodeError);
  });
});

describe("FETCH (10.12) / FETCH_OK (10.13)", () => {
  it("encode fetch_relative_joining", () => {
    const b = encodeFetch({ requestId: 2n, fetchType: 2n, joiningRequestId: 0n, joiningStart: 1n, parameters: [] });
    expect(frame("fetch_relative_joining", b)).toBe(ctl.get("fetch_relative_joining")!.hex);
  });

  it("encode fetch_absolute_joining", () => {
    const b = encodeFetch({
      requestId: 4n,
      fetchType: 3n,
      joiningRequestId: 0n,
      joiningStart: 5n,
      parameters: [{ type: 0x20n, value: 128n }],
    });
    expect(frame("fetch_absolute_joining", b)).toBe(ctl.get("fetch_absolute_joining")!.hex);
  });

  it("decode fetch_ok_basic", () => {
    const msg = decodeFetchOk(body("fetch_ok_basic"));
    expect(msg.endOfTrack).toBe(true);
    expect(msg.endLocation).toEqual({ group: 3n, object: 5n });
  });
});

describe("namespace discovery (10.15-10.18)", () => {
  it("encode subscribe_namespace_basic", () => {
    const b = encodeNamespaceRequest({ requestId: 6n, namespace: [utf8ToBytes("chat")], parameters: [] });
    expect(frame("subscribe_namespace_basic", b)).toBe(ctl.get("subscribe_namespace_basic")!.hex);
  });

  it("encode publish_namespace_basic", () => {
    const b = encodeNamespaceRequest({
      requestId: 8n,
      namespace: ["chat", "room1"].map(utf8ToBytes),
      parameters: [],
    });
    expect(frame("publish_namespace_basic", b)).toBe(ctl.get("publish_namespace_basic")!.hex);
  });

  it("decode namespace_basic / namespace_done_basic suffixes", () => {
    for (const name of ["namespace_basic", "namespace_done_basic"]) {
      expect(decodeNamespaceSuffix(body(name)).map(bytesToUtf8)).toEqual(["room1"]);
    }
  });
});

interface FetchVector {
  kind: string;
  name: string;
  hex: string;
  request_id: string;
  objects: { flags: string; group_id: string; object_id: string; end_of_range?: string; payload_hex?: string; publisher_priority?: string }[];
}

describe("FETCH data stream (11.4.4)", () => {
  const vectors = (golden.data as FetchVector[]).filter((v) => v.kind === "fetch_stream");

  it("covers the golden fetch streams", () => {
    expect(vectors.map((v) => v.name)).toEqual(["fetch_stream_basic", "fetch_stream_end_of_range"]);
  });

  for (const v of vectors) {
    it(`decode ${v.name}`, () => {
      const bytes = hexToBytes(v.hex);
      const head = decodeFetchHeader(bytes);
      expect(head.requestId).toBe(BigInt(v.request_id));
      const seq = newFetchSeq();
      let pos = head.len;
      for (const want of v.objects) {
        const { object, len } = decodeFetchObject(bytes, pos, seq);
        expect(object.group).toBe(BigInt(want.group_id));
        expect(object.object).toBe(BigInt(want.object_id));
        expect(object.endOfRange).toBe(want.end_of_range);
        if (want.payload_hex !== undefined) expect(bytesToHex(object.payload)).toBe(want.payload_hex);
        if (want.publisher_priority !== undefined) expect(object.priority).toBe(Number(want.publisher_priority));
        pos += len;
      }
      expect(pos).toBe(bytes.length);
    });
  }

  it("a truncated Object throws so the reader waits for more bytes", () => {
    const bytes = hexToBytes("1c050080026869"); // payload says 2 bytes, both present
    expect(() => decodeFetchObject(bytes.slice(0, 6), 0, newFetchSeq())).toThrow(MoqtDecodeError);
    expect(decodeFetchObject(bytes, 0, newFetchSeq()).len).toBe(7);
  });

  it("rejects a first Object that references a prior one", () => {
    // flags 0x01: prior Subgroup, no Group/Object delta -- nothing precedes it.
    expect(() => decodeFetchObject(hexToBytes("010178"), 0, newFetchSeq())).toThrow(MoqtDecodeError);
  });

  it("rejects Serialization Flags >= 128 other than End of Range", () => {
    expect(() => decodeFetchObject(hexToBytes("808000"), 0, newFetchSeq())).toThrow(MoqtDecodeError);
  });

  it("a later group's Group ID Delta is relative (prior + delta + 1), its Object ID absolute", () => {
    // first: G5/O0 "a"; then flags 0x0c: G = 5+0+1 = 6, O = 2 (absolute), prior prio.
    const bytes = hexToBytes("1c05008001610c00020162");
    const seq = newFetchSeq();
    const a = decodeFetchObject(bytes, 0, seq);
    const b = decodeFetchObject(bytes, a.len, seq);
    expect([b.object.group, b.object.object]).toEqual([6n, 2n]);
    expect(b.object.priority).toBe(0x80);
    expect(bytesToUtf8(b.object.payload)).toBe("b");
  });
});
