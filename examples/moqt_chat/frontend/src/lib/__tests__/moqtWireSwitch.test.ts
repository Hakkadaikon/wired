// Track switching wire forms (draft-22 sessions only; experimental
// extension values shared with moqtail, tasks/moqt-trackswitch-plan.md 1):
// SWITCH_FROM (message parameter 0x24), SWITCHING_SET_ASSIGNMENT (0x41) and
// the SSTS_ALGORITHMS Setup Option (0x09). Goldens are hand-derived from the
// wire contract with MOQT's leading-ones varint (d22 8.1): 10xxxxxx is a
// 2-byte form (300 = 0x12c -> 81 2c, 2000 = 0x7d0 -> 87 d0), 110xxxxx a
// 3-byte one (0xff01 = 65281 > 16383 -> c0 ff 01).
import { describe, expect, it } from "vitest";
import {
  bytesToHex,
  decodeParams,
  decodeSetup,
  decodeSstsAlgorithms,
  decodeSwitchFrom,
  decodeSwitchingSetAssignment,
  encodeParams,
  encodeSetup,
  encodeSstsAlgorithms,
  encodeSwitchFrom,
  encodeSwitchingSetAssignment,
  hexToBytes,
  MoqtDecodeError,
  PARAM_SWITCH_FROM,
  PARAM_SWITCHING_SET_ASSIGNMENT,
  SETUP_OPTION_SSTS_ALGORITHMS,
  SSTS_ALGORITHM_BACKPRESSURE,
  SSTS_ALGORITHM_DEFAULT,
  sstsAlgorithmsOf,
  switchFromParam,
  switchingSetAssignmentParam,
  SWITCH_MODE_HARD,
  SWITCH_MODE_SOFT,
} from "../moqtWire";

describe("SWITCH_FROM (0x24)", () => {
  it("golden: rid 7, Hard, Publish Done is 24 03 07 00 80", () => {
    const p = switchFromParam({ requestId: 7n, mode: SWITCH_MODE_HARD, publishDone: true });
    // Number of Parameters 1, then the parameter itself.
    expect(bytesToHex(encodeParams([p], 22))).toBe("012403070080");
  });

  it("golden: rid 300 (2-byte varint), Soft, no Publish Done", () => {
    expect(bytesToHex(encodeSwitchFrom({ requestId: 300n, mode: SWITCH_MODE_SOFT, publishDone: false }))).toBe(
      "812c0100",
    );
  });

  it("round-trips through decodeParams on a draft-22 session", () => {
    const sf = { requestId: 12n, mode: SWITCH_MODE_SOFT, publishDone: true };
    const { params } = decodeParams(encodeParams([switchFromParam(sf)], 22), 0, 22);
    expect(params).toHaveLength(1);
    expect(params[0].type).toBe(PARAM_SWITCH_FROM);
    expect(decodeSwitchFrom(params[0].value as Uint8Array)).toEqual(sf);
  });

  it("is an unknown parameter (PROTOCOL_VIOLATION) on a draft-19 session", () => {
    expect(() => decodeParams(hexToBytes("012403070080"), 0, 19)).toThrow(MoqtDecodeError);
  });

  it("rejects trailing bytes after Flags", () => {
    expect(() => decodeSwitchFrom(hexToBytes("07008000"))).toThrow(/PROTOCOL_VIOLATION/);
    expect(() => decodeParams(hexToBytes("01240407008000"), 0, 22)).toThrow(MoqtDecodeError);
  });

  it("rejects a truncated value (no Flags byte)", () => {
    expect(() => decodeSwitchFrom(hexToBytes("0700"))).toThrow(MoqtDecodeError);
  });

  it("rejects Flags bits other than 0x80 (must be 0)", () => {
    expect(() => decodeSwitchFrom(hexToBytes("070001"))).toThrow(/PROTOCOL_VIOLATION/);
    expect(() => decodeSwitchFrom(hexToBytes("070040"))).toThrow(/PROTOCOL_VIOLATION/);
  });

  it("rejects a Mode other than 0 Hard / 1 Soft", () => {
    expect(() => decodeSwitchFrom(hexToBytes("070280"))).toThrow(/PROTOCOL_VIOLATION/);
    expect(() => encodeSwitchFrom({ requestId: 7n, mode: 2n, publishDone: false })).toThrow(MoqtDecodeError);
  });
});

describe("SWITCHING_SET_ASSIGNMENT (0x41)", () => {
  const base = {
    setId: 2n,
    algorithmId: SSTS_ALGORITHM_BACKPRESSURE,
    thresholdKbps: 2000n,
    weight: 1n,
    activate: 2n,
  };

  it("golden: set 2, backpressure, 2000 kbps, weight 1, activate 2, no Rank", () => {
    const p = switchingSetAssignmentParam(base);
    expect(bytesToHex(encodeParams([p], 22))).toBe("0141" + "08" + "02" + "c0ff01" + "87d0" + "01" + "02");
  });

  it("golden: the optional Rank is one trailing u8", () => {
    expect(bytesToHex(encodeSwitchingSetAssignment({ ...base, rank: 3 }))).toBe("02c0ff0187d0010203");
  });

  it("round-trips with and without Rank", () => {
    for (const a of [base, { ...base, rank: 0 }, { ...base, rank: 255, algorithmId: SSTS_ALGORITHM_DEFAULT }]) {
      const { params } = decodeParams(encodeParams([switchingSetAssignmentParam(a)], 22), 0, 22);
      expect(params[0].type).toBe(PARAM_SWITCHING_SET_ASSIGNMENT);
      expect(decodeSwitchingSetAssignment(params[0].value as Uint8Array)).toEqual(a);
    }
  });

  it("Weight is bounded 1..10 (boundaries accepted, 0 and 11 rejected)", () => {
    for (const weight of [1n, 10n]) {
      expect(decodeSwitchingSetAssignment(encodeSwitchingSetAssignment({ ...base, weight })).weight).toBe(weight);
    }
    expect(() => decodeSwitchingSetAssignment(hexToBytes("0200000000"))).toThrow(/PROTOCOL_VIOLATION/);
    expect(() => decodeSwitchingSetAssignment(hexToBytes("0200000b00"))).toThrow(/PROTOCOL_VIOLATION/);
    expect(() => encodeSwitchingSetAssignment({ ...base, weight: 0n })).toThrow(MoqtDecodeError);
    expect(() => encodeSwitchingSetAssignment({ ...base, weight: 11n })).toThrow(MoqtDecodeError);
  });

  it("encode rejects a Rank that is not one byte (0..255 integer)", () => {
    for (const rank of [-1, 256, 1.5]) {
      expect(() => encodeSwitchingSetAssignment({ ...base, rank })).toThrow(MoqtDecodeError);
    }
    expect(() => encodeSwitchingSetAssignment({ ...base, rank: 255 })).not.toThrow();
  });

  it("rejects more than one byte after the required fields", () => {
    expect(() => decodeSwitchingSetAssignment(hexToBytes("02000001000102"))).toThrow(/PROTOCOL_VIOLATION/);
  });

  it("rejects a truncated value", () => {
    expect(() => decodeSwitchingSetAssignment(hexToBytes("02000001"))).toThrow(MoqtDecodeError);
  });

  it("is an unknown parameter on a draft-19 session", () => {
    expect(() => decodeParams(encodeParams([switchingSetAssignmentParam(base)], 22), 0, 19)).toThrow(
      MoqtDecodeError,
    );
  });

  it("orders after SWITCH_FROM in one parameter list (ascending Type deltas)", () => {
    const bytes = encodeParams(
      [
        switchFromParam({ requestId: 1n, mode: SWITCH_MODE_SOFT, publishDone: false }),
        switchingSetAssignmentParam(base),
      ],
      22,
    );
    // 0x24, then delta 0x1d -> 0x41.
    expect(bytesToHex(bytes)).toBe("02" + "2403010100" + "1d0802c0ff0187d00102");
    expect(decodeParams(bytes, 0, 22).params.map((p) => p.type)).toEqual([0x24n, 0x41n]);
  });
});

describe("SSTS_ALGORITHMS Setup Option (0x09)", () => {
  it("golden: [0xff01, 0] is 3+1 bytes of varints, no count", () => {
    expect(bytesToHex(encodeSstsAlgorithms([SSTS_ALGORITHM_BACKPRESSURE, SSTS_ALGORITHM_DEFAULT]))).toBe("c0ff0100");
  });

  it("golden: a SETUP carrying it is 09 04 c0ff01 00 (odd Type: Length + bytes)", () => {
    const body = encodeSetup({
      setupOptions: [{ type: SETUP_OPTION_SSTS_ALGORITHMS, raw: encodeSstsAlgorithms([0xff01n, 0n]) }],
    });
    expect(bytesToHex(body)).toBe("0904c0ff0100");
    expect(sstsAlgorithmsOf(decodeSetup(body).setupOptions)).toEqual([0xff01n, 0n]);
  });

  it("round-trips the empty list and a single id", () => {
    expect(decodeSstsAlgorithms(encodeSstsAlgorithms([]))).toEqual([]);
    expect(decodeSstsAlgorithms(encodeSstsAlgorithms([0n]))).toEqual([0n]);
  });

  it("rejects a truncated varint", () => {
    expect(() => decodeSstsAlgorithms(hexToBytes("c0ff"))).toThrow(MoqtDecodeError);
  });

  it("sstsAlgorithmsOf: undefined when the option is absent (an extension-less hub)", () => {
    expect(sstsAlgorithmsOf(decodeSetup(new Uint8Array(0)).setupOptions)).toBeUndefined();
    // another option (MOQT_IMPLEMENTATION 0x07) only
    expect(sstsAlgorithmsOf(decodeSetup(hexToBytes("070161")).setupOptions)).toBeUndefined();
  });

  it("sstsAlgorithmsOf: a malformed option value reads as not advertised", () => {
    expect(sstsAlgorithmsOf([{ type: SETUP_OPTION_SSTS_ALGORITHMS, raw: hexToBytes("80") }])).toBeUndefined();
  });
});
