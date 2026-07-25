import { describe, expect, it } from "vitest";
import { parseCertHash } from "../certHash";

describe("parseCertHash", () => {
  it("parses a colon-separated sha-256 fingerprint into 32 bytes", () => {
    const hex =
      "b4:6d:57:7b:de:f6:70:d6:f1:f9:e9:91:c3:a3:6a:db:" +
      "15:e8:7d:39:34:24:a4:54:89:ed:de:43:22:39:70:88";
    const bytes = parseCertHash(hex);
    expect(bytes).not.toBeNull();
    expect(bytes!.length).toBe(32);
    expect(bytes![0]).toBe(0xb4);
    expect(bytes![31]).toBe(0x88);
  });

  it("accepts bare hex without separators, case-insensitive", () => {
    const bytes = parseCertHash("AbCd");
    expect(Array.from(bytes!)).toEqual([0xab, 0xcd]);
  });

  it("ignores surrounding whitespace", () => {
    const bytes = parseCertHash("  ab cd\n");
    expect(Array.from(bytes!)).toEqual([0xab, 0xcd]);
  });

  it("returns null for empty input", () => {
    expect(parseCertHash("")).toBeNull();
    expect(parseCertHash("  ")).toBeNull();
  });

  it("returns null for non-hex or odd-length input", () => {
    expect(parseCertHash("zz")).toBeNull();
    expect(parseCertHash("abc")).toBeNull();
  });
});
