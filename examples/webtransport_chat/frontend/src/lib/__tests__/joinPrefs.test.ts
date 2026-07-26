import { beforeEach, describe, expect, it, vi } from "vitest";
import { clearJoinPrefs, loadJoinPrefs, saveJoinPrefs } from "../joinPrefs";

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
    saveJoinPrefs({ url: "https://x:4433/", certHash: "ab:cd", name: "alice", micOff: true });
    expect(loadJoinPrefs()).toEqual({
      url: "https://x:4433/",
      certHash: "ab:cd",
      name: "alice",
      micOff: true,
    });
  });

  it("returns null when nothing was saved", () => {
    expect(loadJoinPrefs()).toBeNull();
  });

  it("returns null on corrupted storage", () => {
    localStorage.setItem("webtransport-chat.join", "{not json");
    expect(loadJoinPrefs()).toBeNull();
    localStorage.setItem("webtransport-chat.join", JSON.stringify({ url: 1 }));
    expect(loadJoinPrefs()).toBeNull();
  });

  it("clears saved fields", () => {
    saveJoinPrefs({ url: "u", certHash: "c", name: "n", micOff: false });
    clearJoinPrefs();
    expect(loadJoinPrefs()).toBeNull();
  });
});
