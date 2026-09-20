import { describe, expect, it } from "vitest";
import { createQualityWindow, qualityLevel, rmsLevel, isSpeaking } from "../voiceQuality";

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

describe("rmsLevel", () => {
  it("is 0 for an empty sample", () => {
    expect(rmsLevel(new Float32Array(0))).toBe(0);
  });

  it("is 0 for all-zero samples", () => {
    expect(rmsLevel(new Float32Array(16))).toBe(0);
  });

  it("is 100 (clamped) for a full-scale +-1 square wave", () => {
    const samples = new Float32Array([1, -1, 1, -1]);
    expect(rmsLevel(samples)).toBe(100);
  });

  it("is approximately 7 for a 0.1-amplitude sine", () => {
    const n = 480;
    const samples = new Float32Array(n);
    for (let i = 0; i < n; i++) samples[i] = 0.1 * Math.sin((2 * Math.PI * i) / n);
    // RMS of a sine of amplitude A is A/sqrt(2) ~= 0.0707 -> *100 ~= 7.07
    expect(rmsLevel(samples)).toBeCloseTo(7.07, 1);
  });
});

describe("isSpeaking", () => {
  it("is false just under the threshold", () => {
    expect(isSpeaking(9.99)).toBe(false);
  });

  it("is true at the threshold", () => {
    expect(isSpeaking(10)).toBe(true);
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

  it("snapshot of an untouched sender reports not speaking", () => {
    const w = createQualityWindow();
    expect(w.snapshot("user1").speaking).toBe(false);
  });

  it("reports speaking when any onLevel in the window is >= 10", () => {
    const w = createQualityWindow();
    w.onLevel("user1", 3);
    w.onLevel("user1", 42);
    expect(w.snapshot("user1").speaking).toBe(true);
  });

  it("reports not speaking when every onLevel in the window is < 10", () => {
    const w = createQualityWindow();
    w.onLevel("user1", 3);
    w.onLevel("user1", 9.99);
    expect(w.snapshot("user1").speaking).toBe(false);
  });

  it("snapshotSpeaking (not snapshot) resets speaking for that sender", () => {
    const w = createQualityWindow();
    w.onLevel("user1", 50);
    expect(w.snapshot("user1").speaking).toBe(true);
    expect(w.snapshotSpeaking("user1")).toBe(true);
    expect(w.snapshot("user1").speaking).toBe(false);
  });

  it("isolates senders' speaking independently", () => {
    const w = createQualityWindow();
    w.onLevel("user1", 50);
    w.onLevel("user2", 1);
    expect(w.snapshot("user1").speaking).toBe(true);
    expect(w.snapshot("user2").speaking).toBe(false);
  });

  it("snapshotSpeaking reads and resets only the speaking flag, leaving received/lost/lagMs alone", () => {
    const w = createQualityWindow();
    w.onFrame("user1");
    w.onLevel("user1", 50);
    expect(w.snapshotSpeaking("user1")).toBe(true);
    expect(w.snapshotSpeaking("user1")).toBe(false);
    expect(qualityLevel(w.snapshot("user1"))).toBe("good"); // received:1 survived
  });

  it("snapshot() (the 1s quality poll) does not discard speaking evidence the 100ms speaking poll hasn't consumed yet", () => {
    const w = createQualityWindow();
    w.onLevel("user1", 50);
    w.snapshot("user1"); // a 1s quality tick lands before the next speaking poll
    expect(w.snapshotSpeaking("user1")).toBe(true);
  });
});
