import { describe, expect, it } from "vitest";
import { createStallDetector, SCREEN_STALL_MS } from "../stallDetector";

describe("createStallDetector", () => {
  it("is not stalled before any frame, nor just under the threshold after one", () => {
    const d = createStallDetector(SCREEN_STALL_MS);
    expect(d.isStalled(10_000)).toBe(false);
    d.frame(1000);
    expect(d.isStalled(1000 + SCREEN_STALL_MS - 1)).toBe(false);
  });

  it("is stalled once the threshold has elapsed since the last frame, and clears on a frame", () => {
    const d = createStallDetector(SCREEN_STALL_MS);
    d.frame(1000);
    expect(d.isStalled(1000 + SCREEN_STALL_MS)).toBe(true);
    d.frame(5000);
    expect(d.isStalled(5001)).toBe(false);
  });

  it("keeps instances independent", () => {
    const a = createStallDetector(100);
    const b = createStallDetector(100);
    a.frame(0);
    expect(a.isStalled(100)).toBe(true);
    expect(b.isStalled(100)).toBe(false);
  });
});
