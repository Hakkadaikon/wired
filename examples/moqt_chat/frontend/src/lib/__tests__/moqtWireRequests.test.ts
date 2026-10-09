// Golden-vector tests for the request-stream messages (draft-19 legacy
// session: draft-ietf-moq-transport-19 10.2 parameters, 10.12-10.18 FETCH /
// namespace discovery) and the FETCH data stream (11.4.4), pinned to the
// same JSON the C codec's tests read (testvectors/moqt_golden.json). The
// draft-22 forms that differ are tested at the end of this file.
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
  decodeLocationFilter22,
  decodeNamespaceSuffix,
  decodeParams,
  decodeRequestOk,
  decodeSubscribe,
  decodeSubscribeOk,
  encodeControlFrame,
  encodeFetch,
  encodeFillParameters,
  encodeLocationFilter22,
  encodeNamespaceRequest,
  encodeParams,
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
interface CtlVersion {
  hex: string;
  msg_len: number;
}
const ctl = new Map<string, { hex: string; type: string; versions?: Record<string, CtlVersion> }>(
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

interface FetchStreamWire {
  hex: string;
  request_id: string;
  objects: { flags: string; group_id: string; object_id: string; end_of_range?: string; payload_hex?: string; publisher_priority?: string }[];
}

interface FetchVector extends FetchStreamWire {
  kind: string;
  name: string;
  versions?: Record<string, FetchStreamWire>;
}

function checkFetchStream(v: FetchStreamWire, draft: 19 | 22) {
  const bytes = hexToBytes(v.hex);
  const head = decodeFetchHeader(bytes);
  expect(head.requestId).toBe(BigInt(v.request_id));
  const seq = newFetchSeq();
  let pos = head.len;
  for (const want of v.objects) {
    const { object, len } = decodeFetchObject(bytes, pos, seq, draft);
    expect(object.group).toBe(BigInt(want.group_id));
    expect(object.object).toBe(BigInt(want.object_id));
    expect(object.endOfRange).toBe(want.end_of_range);
    if (want.payload_hex !== undefined) expect(bytesToHex(object.payload)).toBe(want.payload_hex);
    if (want.publisher_priority !== undefined) expect(object.priority).toBe(Number(want.publisher_priority));
    pos += len;
  }
  expect(pos).toBe(bytes.length);
}

describe("FETCH data stream (11.4.4)", () => {
  const vectors = (golden.data as FetchVector[]).filter((v) => v.kind === "fetch_stream");

  it("covers the golden fetch streams", () => {
    expect(vectors.map((v) => v.name)).toEqual(["fetch_stream_basic", "fetch_stream_end_of_range"]);
  });

  for (const v of vectors) {
    it(`decode ${v.name}`, () => checkFetchStream(v, 19));
    for (const [ver, vv] of Object.entries(v.versions ?? {})) {
      it(`decode ${v.name} (draft-${ver})`, () => checkFetchStream(vv, Number(ver) as 19 | 22));
    }
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

// draft-ietf-moq-transport-22: the wire forms that differ from draft-19 --
// LOCATION_FILTER without a Length (9.20.9), FILL_PARAMETERS (9.20.15) and
// End of Timed-Out Range (11.4.1.2). Pinned to the "versions" entries of the
// same golden JSON the C codec reads.
describe("draft-22 LOCATION_FILTER (9.20.9)", () => {
  const forms: [string, bigint, bigint[], string][] = [
    ["None", 0x0n, [], "00"],
    ["Relative Start", 0x1n, [3n], "0103"],
    ["Absolute Start", 0x2n, [5n, 1n], "020501"],
    ["Absolute Start, Group End", 0x3n, [5n, 0n, 3n], "03050003"],
    ["Absolute Range", 0x4n, [5n, 0n, 3n, 7n], "0405000307"],
    ["Next Object", 0x5n, [], "05"],
  ];

  for (const [name, type, fields, hex] of forms) {
    it(`encode/decode 0x0${type} ${name}`, () => {
      expect(bytesToHex(encodeLocationFilter22({ type, fields }))).toBe(hex);
      const bytes = hexToBytes(hex + "ff"); // trailing byte: the filter's own length ends it
      expect(decodeLocationFilter22(bytes, 0)).toEqual({ filter: { type, fields }, len: hex.length / 2 });
    });
  }

  it("rejects an unknown Location Filter Type and a truncated filter", () => {
    expect(() => decodeLocationFilter22(hexToBytes("06"), 0)).toThrow(MoqtDecodeError);
    expect(() => decodeLocationFilter22(hexToBytes("0205"), 0)).toThrow(MoqtDecodeError);
    expect(() => encodeLocationFilter22({ type: 0x2n, fields: [5n] })).toThrow(MoqtDecodeError);
  });

  it("a d22 parameter list carries the filter with no Length; d19 keeps the Length", () => {
    const next22 = { type: 0x21n, value: Uint8Array.of(0x05) };
    expect(bytesToHex(encodeParams([next22], 22))).toBe("012105");
    expect(decodeParams(hexToBytes("012105"), 0, 22)).toEqual({ params: [next22], len: 3 });
    const largest19 = { type: 0x21n, value: Uint8Array.of(0x02) };
    expect(bytesToHex(encodeParams([largest19]))).toBe("01210102");
    expect(decodeParams(hexToBytes("01210102"), 0)).toEqual({ params: [largest19], len: 4 });
  });

  it("encode subscribe_params (draft-22 version): filter type 0x03 without a Length", () => {
    const b = encodeSubscribe(
      {
        requestId: 0n,
        trackNamespace: ["chat", "room1"].map(utf8ToBytes),
        trackName: utf8ToBytes("alice"),
        parameters: [
          { type: 0x10n, value: 1n },
          { type: 0x20n, value: 64n },
          { type: 0x21n, value: hexToBytes("03050003") },
          { type: 0x22n, value: 2n },
        ],
      },
      22,
    );
    expect(frame("subscribe_params", b)).toBe(ctl.get("subscribe_params")!.versions!["22"].hex);
  });
});

describe("SUBSCRIBE for live-from-now (subscribe_next_object)", () => {
  const msg = (filter: Uint8Array) => ({
    requestId: 0n,
    trackNamespace: ["chat", "room1"].map(utf8ToBytes),
    trackName: utf8ToBytes("alice"),
    parameters: [{ type: 0x21n, value: filter }],
  });

  it("draft-19: LOCATION_FILTER Largest Object (Length 1, type 0x2)", () => {
    expect(frame("subscribe_next_object", encodeSubscribe(msg(Uint8Array.of(0x2))))).toBe(
      ctl.get("subscribe_next_object")!.hex,
    );
  });

  it("draft-22: LOCATION_FILTER Next Object (type 0x05, no Length)", () => {
    const v = ctl.get("subscribe_next_object")!.versions!["22"];
    expect(frame("subscribe_next_object", encodeSubscribe(msg(Uint8Array.of(0x5)), 22))).toBe(v.hex);
    const decoded = decodeSubscribe(decodeControlFrame(hexToBytes(v.hex)).frame.body, 22);
    expect(decoded.parameters).toEqual([{ type: 0x21n, value: Uint8Array.of(0x5) }]);
  });
});

describe("draft-22 FILL_PARAMETERS (9.20.15)", () => {
  it("the value is an inner parameter list: count + type-delta parameters", () => {
    const relStart = encodeLocationFilter22({ type: 0x1n, fields: [65n] });
    expect(bytesToHex(encodeFillParameters([{ type: 0x21n, value: relStart }]))).toBe("01210141");
  });

  it("encode/decode subscribe_fill (draft-22 version): Next Object + fill of Relative Start 65", () => {
    const v = ctl.get("subscribe_fill")!.versions!["22"];
    const fill = encodeFillParameters([{ type: 0x21n, value: encodeLocationFilter22({ type: 0x1n, fields: [65n] }) }]);
    const b = encodeSubscribe(
      {
        requestId: 0n,
        trackNamespace: ["chat", "room1"].map(utf8ToBytes),
        trackName: utf8ToBytes("alice"),
        parameters: [
          { type: 0x21n, value: Uint8Array.of(0x5) },
          { type: 0x23n, value: fill },
        ],
      },
      22,
    );
    expect(frame("subscribe_fill", b)).toBe(v.hex);
    const decoded = decodeSubscribe(decodeControlFrame(hexToBytes(v.hex)).frame.body, 22);
    expect(decoded.parameters.map((p) => p.type)).toEqual([0x21n, 0x23n]);
    expect(bytesToHex(decoded.parameters[1].value as Uint8Array)).toBe("01210141");
  });

  it("FILL_PARAMETERS is not a draft-19 parameter", () => {
    expect(() => decodeParams(hexToBytes("01230401210141"), 0)).toThrow(MoqtDecodeError);
  });
});

describe("End of Timed-Out Range 0x20C (11.4.1.2)", () => {
  it("is an End of Range on a draft-22 session", () => {
    const { object, len } = decodeFetchObject(hexToBytes("820c0402"), 0, newFetchSeq(), 22);
    expect(object).toEqual({ group: 4n, object: 2n, payload: new Uint8Array(0), endOfRange: "timed_out" });
    expect(len).toBe(4);
  });

  it("is still a PROTOCOL_VIOLATION on a draft-19 session", () => {
    expect(() => decodeFetchObject(hexToBytes("820c0402"), 0, newFetchSeq())).toThrow(MoqtDecodeError);
    expect(() => decodeFetchObject(hexToBytes("820c0402"), 0, newFetchSeq(), 19)).toThrow(MoqtDecodeError);
  });

  it("the golden fetch stream carries a draft-22 version with the marker", () => {
    const v = (golden.data as FetchVector[]).find((x) => x.name === "fetch_stream_end_of_range")!;
    expect(v.versions?.["22"].objects.map((o) => o.flags)).toContain("0x20c");
  });
});
