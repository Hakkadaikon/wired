// Golden-vector tests for the request-stream messages (draft-ietf-moq-
// transport-19 10.2 parameters, 10.12-10.18 FETCH / namespace discovery) and
// the FETCH data stream (11.4.4), pinned to the same JSON the C codec's
// tests read (testvectors/moqt_golden.json).
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  bytesToHex,
  decodeControlFrame,
  decodeRequestOk,
  decodeSubscribeOk,
  encodeControlFrame,
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
