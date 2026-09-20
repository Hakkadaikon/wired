import { describe, expect, it } from "vitest";
import { createQualityWindow, qualityLevel } from "../voiceQuality";

describe("qualityLevel", () => {
  it("is none for an empty sample (nothing received)", () => {
    expect(qualityLevel({ received: 0, lost: 0, lagMs: undefined })).toBe("none");
  });

  it("is good at exactly 2% loss (boundary)", () => {
    expect(qualityLevel({ received: 98, lost: 2, lagMs: undefined })).toBe("good");
  });

  it("is degraded just above 2% loss", () => {
    expect(qualityLevel({ received: 9799, lost: 201, lagMs: undefined })).toBe("degraded");
  });

  it("is good at exactly 150ms lag (boundary)", () => {
    expect(qualityLevel({ received: 10, lost: 0, lagMs: 150 })).toBe("good");
  });

  it("is degraded just above 150ms lag", () => {
    expect(qualityLevel({ received: 10, lost: 0, lagMs: 151 })).toBe("degraded");
  });

  it("is good with frames received, no loss, and no lag reported", () => {
    expect(qualityLevel({ received: 10, lost: 0, lagMs: undefined })).toBe("good");
  });
});

describe("createQualityWindow", () => {
  it("snapshot of an untouched sender reports none", () => {
    const w = createQualityWindow();
    expect(qualityLevel(w.snapshot("user1"))).toBe("none");
  });

  it("onFrame contributes a received frame", () => {
    const w = createQualityWindow();
    w.onFrame("user1");
    expect(qualityLevel(w.snapshot("user1"))).toBe("good");
  });

  it("onLost contributes a lost frame toward the loss ratio", () => {
    const w = createQualityWindow();
    for (let i = 0; i < 98; i++) w.onFrame("user1");
    for (let i = 0; i < 2; i++) w.onLost("user1");
    expect(qualityLevel(w.snapshot("user1"))).toBe("good");
    const w2 = createQualityWindow();
    for (let i = 0; i < 9799; i++) w2.onFrame("user1");
    for (let i = 0; i < 201; i++) w2.onLost("user1");
    expect(qualityLevel(w2.snapshot("user1"))).toBe("degraded");
  });

  it("onPlay records the latest playhead lag", () => {
    const w = createQualityWindow();
    w.onFrame("user1");
    w.onPlay("user1", 151);
    expect(qualityLevel(w.snapshot("user1"))).toBe("degraded");
  });

  it("onDepth alone does not count as a received frame", () => {
    const w = createQualityWindow();
    w.onDepth("user1", 3);
    expect(qualityLevel(w.snapshot("user1"))).toBe("none");
  });

  it("snapshot resets the window for that sender", () => {
    const w = createQualityWindow();
    w.onFrame("user1");
    w.onPlay("user1", 200);
    expect(qualityLevel(w.snapshot("user1"))).toBe("degraded");
    expect(qualityLevel(w.snapshot("user1"))).toBe("none");
  });

  it("isolates senders: one sender's loss does not affect another's", () => {
    const w = createQualityWindow();
    w.onFrame("user1");
    for (let i = 0; i < 9799; i++) w.onFrame("user2");
    for (let i = 0; i < 201; i++) w.onLost("user2");
    expect(qualityLevel(w.snapshot("user1"))).toBe("good");
    expect(qualityLevel(w.snapshot("user2"))).toBe("degraded");
  });
});
