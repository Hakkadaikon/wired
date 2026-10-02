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
