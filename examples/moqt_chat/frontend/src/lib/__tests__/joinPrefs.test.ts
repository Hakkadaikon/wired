import { beforeEach, describe, expect, it, vi } from "vitest";
import { clearJoinPrefs, loadJoinPrefs, noiseSuppressionDefault, saveJoinPrefs } from "../joinPrefs";

// The vitest jsdom global does not provide a full Storage; stub a minimal
// in-memory one so these tests exercise our logic deterministically.
const mem = new Map<string, string>();
vi.stubGlobal("localStorage", {
  getItem: (k: string) => mem.get(k) ?? null,
  setItem: (k: string, v: string) => void mem.set(k, String(v)),
  removeItem: (k: string) => void mem.delete(k),
});

describe("joinPrefs", () => {
  beforeEach(() => {
    mem.clear();
  });

  it("round-trips the join form fields", () => {
    saveJoinPrefs({ url: "https://x:4433/", certHash: "ab:cd", name: "user1", nickname: "Alice" });
    expect(loadJoinPrefs()).toEqual({
      url: "https://x:4433/",
      certHash: "ab:cd",
      name: "user1",
      nickname: "Alice",
    });
  });

  it("returns null when nothing was saved", () => {
    expect(loadJoinPrefs()).toBeNull();
  });

  it("returns null on corrupted storage", () => {
    localStorage.setItem("moqt-chat.join", "{not json");
    expect(loadJoinPrefs()).toBeNull();
    localStorage.setItem("moqt-chat.join", JSON.stringify({ url: 1 }));
    expect(loadJoinPrefs()).toBeNull();
  });

  it("reads old saved prefs that predate the nickname field", () => {
    localStorage.setItem("moqt-chat.join", JSON.stringify({ url: "u", certHash: "c", name: "user1" }));
    expect(loadJoinPrefs()).toEqual({ url: "u", certHash: "c", name: "user1" });
  });

  it("rejects a non-string nickname", () => {
    localStorage.setItem(
      "moqt-chat.join",
      JSON.stringify({ url: "u", certHash: "c", name: "user1", nickname: 5 }),
    );
    expect(loadJoinPrefs()).toBeNull();
  });

  it("clears saved fields", () => {
    saveJoinPrefs({ url: "u", certHash: "c", name: "user2" });
    clearJoinPrefs();
    expect(loadJoinPrefs()).toBeNull();
  });
});

describe("noiseSuppressionDefault", () => {
  it("is false when the page URL has ns=0", () => {
    expect(noiseSuppressionDefault("?ns=0")).toBe(false);
  });

  it("is true when ns is absent", () => {
    expect(noiseSuppressionDefault("")).toBe(true);
  });

  it("is false when ns=0 is mixed with other query params", () => {
    expect(noiseSuppressionDefault("?foo=bar&ns=0")).toBe(false);
  });
});
