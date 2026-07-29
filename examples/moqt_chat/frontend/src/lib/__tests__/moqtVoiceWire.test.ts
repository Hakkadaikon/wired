import { describe, expect, it } from "vitest";
import { concatBytes, decodeSubgroupHeader, MoqtDecodeError } from "../moqtWire";
import {
  buildVoiceSubgroupHeader,
  decodeVoiceObjectPayload,
  decodeVoiceObjectStream,
  encodeVoiceObjectMessage,
  encodeVoiceObjectPayload,
  type VoiceObjectPayload,
} from "../moqtVoiceWire";

function opus(...bytes: number[]): Uint8Array {
  return new Uint8Array(bytes);
}

describe("encodeVoiceObjectPayload / decodeVoiceObjectPayload", () => {
  it("round-trips seq + opus bytes", () => {
    const cases: VoiceObjectPayload[] = [
      { seq: 0, opus: opus() },
      { seq: 1, opus: opus(1, 2, 3) },
      { seq: 65535, opus: opus(0xff, 0x00, 0xab) },
      { seq: 300, opus: new Uint8Array(120).fill(7) },
    ];
    for (const input of cases) {
      const decoded = decodeVoiceObjectPayload(encodeVoiceObjectPayload(input));
      expect(decoded.seq).toBe(input.seq);
      expect(decoded.opus).toEqual(input.opus);
    }
  });

  it("throws on input shorter than the 2-byte seq header", () => {
    expect(() => decodeVoiceObjectPayload(new Uint8Array([0x01]))).toThrow(
      MoqtDecodeError,
    );
    expect(() => decodeVoiceObjectPayload(new Uint8Array([]))).toThrow(
      MoqtDecodeError,
    );
  });
});

describe("buildVoiceSubgroupHeader", () => {
  it("round-trips through decodeSubgroupHeader", () => {
    const wire = buildVoiceSubgroupHeader(5n, 42n);
    const { header } = decodeSubgroupHeader(wire);
    expect(header.trackAlias).toBe(5n);
    expect(header.groupId).toBe(42n);
    expect(header.flags.firstObject).toBe(true);
    expect(header.flags.defaultPriority).toBe(true);
    expect(header.flags.properties).toBe(false);
  });
});

describe("encodeVoiceObjectMessage + decodeVoiceObjectStream", () => {
  it("round-trips a single Object appended after the header", () => {
    const header = buildVoiceSubgroupHeader(1n, 0n);
    const payload: VoiceObjectPayload = { seq: 7, opus: opus(9, 9, 9) };
    const wire = concatBytes([header, encodeVoiceObjectMessage(0n, payload)]);

    const decoded = decodeVoiceObjectStream(wire, header.length, false);
    expect(decoded).toEqual([payload]);
  });

  it.each([1, 3, 20])("restores N=%i concatenated Objects in order", (n) => {
    const header = buildVoiceSubgroupHeader(2n, 0n);
    const payloads: VoiceObjectPayload[] = Array.from({ length: n }, (_, i) => ({
      seq: i,
      opus: opus(i % 256),
    }));
    const objectFrames = payloads.map((p, i) =>
      encodeVoiceObjectMessage(i === 0 ? 0n : 1n, p),
    );
    const wire = concatBytes([header, ...objectFrames]);

    const decoded = decodeVoiceObjectStream(wire, header.length, false);
    expect(decoded).toEqual(payloads);
  });

  it("returns only the complete Objects when the stream is truncated mid-Object", () => {
    const header = buildVoiceSubgroupHeader(3n, 0n);
    const payloads: VoiceObjectPayload[] = [
      { seq: 0, opus: opus(1, 2) },
      { seq: 1, opus: opus(3, 4) },
      { seq: 2, opus: opus(5, 6) },
    ];
    const objectFrames = payloads.map((p, i) =>
      encodeVoiceObjectMessage(i === 0 ? 0n : 1n, p),
    );
    const full = concatBytes([header, ...objectFrames]);
    const truncated = full.slice(0, full.length - 1); // cut into the 3rd Object

    const decoded = decodeVoiceObjectStream(truncated, header.length, false);
    expect(decoded).toEqual(payloads.slice(0, 2));
  });

  it("end-to-end: header + N encodeVoiceObjectMessage calls all restore via decodeVoiceObjectStream", () => {
    const trackAlias = 9n;
    const groupId = 1n;
    const header = buildVoiceSubgroupHeader(trackAlias, groupId);
    const payloads: VoiceObjectPayload[] = Array.from({ length: 8 }, (_, i) => ({
      seq: (1000 + i) % 65536,
      opus: opus(...Array.from({ length: 5 }, (_, j) => (i + j) % 256)),
    }));
    const parts = [header];
    for (let i = 0; i < payloads.length; i++) {
      parts.push(encodeVoiceObjectMessage(i === 0 ? 0n : 1n, payloads[i]));
    }
    const wire = concatBytes(parts);

    const { header: decodedHeader, len: headerLen } = decodeSubgroupHeader(wire);
    expect(decodedHeader.trackAlias).toBe(trackAlias);
    expect(decodedHeader.groupId).toBe(groupId);
    const decoded = decodeVoiceObjectStream(wire, headerLen, decodedHeader.flags.properties);
    expect(decoded).toEqual(payloads);
  });
});
