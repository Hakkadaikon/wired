import { describe, expect, it } from "vitest";
import { canPickOutput, effectiveGain } from "../outputMixer";

describe("effectiveGain", () => {
  it("multiplies peer and master volume", () => {
    expect(effectiveGain(0.5, 0.5)).toBeCloseTo(0.25, 10);
  });

  it("clamps to 0 at the low boundary", () => {
    expect(effectiveGain(0, 1)).toBe(0);
  });

  it("clamps to 1 at the high boundary", () => {
    expect(effectiveGain(1, 1)).toBe(1);
  });

  it("clamps a peer volume above 1 to 1", () => {
    expect(effectiveGain(1.5, 1)).toBe(1);
  });

  it("clamps a negative peer volume to 0", () => {
    expect(effectiveGain(-0.5, 1)).toBe(0);
  });

  it("clamps a master volume above 1 to 1", () => {
    expect(effectiveGain(1, 1.5)).toBe(1);
  });

  it("clamps a negative master volume to 0", () => {
    expect(effectiveGain(1, -0.5)).toBe(0);
  });
});

describe("canPickOutput", () => {
  it("is true when the context exposes setSinkId", () => {
    expect(canPickOutput({ setSinkId: () => Promise.resolve() })).toBe(true);
  });

  it("is false when the context has no setSinkId", () => {
    expect(canPickOutput({})).toBe(false);
  });
});
