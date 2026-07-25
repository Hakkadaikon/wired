import { describe, expect, it, beforeEach } from "vitest";
import { useVoiceChatStore } from "../voiceChatStore";

describe("voiceChatStore", () => {
  beforeEach(() => {
    useVoiceChatStore.setState(useVoiceChatStore.getInitialState());
  });

  it("starts disconnected, unmuted, with no messages, peers, or names", () => {
    const s = useVoiceChatStore.getState();
    expect(s.connectionState).toBe("disconnected");
    expect(s.muted).toBe(false);
    expect(s.messages).toEqual([]);
    expect(s.peers).toEqual([]);
    expect(s.reconnecting).toBe(false);
    expect(s.displayName).toBe("");
    expect(s.peerNames).toEqual({});
  });

  it("assigns monotonically increasing ids and returns them", () => {
    const id1 = useVoiceChatStore
      .getState()
      .addMessage({ senderId: "ab", name: "", text: "hi", at: 1, own: true });
    const id2 = useVoiceChatStore
      .getState()
      .addMessage({ senderId: "cd", name: "", text: "yo", at: 2, own: false });
    expect(id2).toBeGreaterThan(id1);
    const ids = useVoiceChatStore.getState().messages.map((m) => m.id);
    expect(ids).toEqual([id1, id2]);
  });

  it("appends a chat message preserving name, at, own, and failed", () => {
    const id = useVoiceChatStore.getState().addMessage({
      senderId: "ab",
      name: "alice",
      text: "hi",
      at: 1234,
      own: true,
      failed: true,
    });
    expect(useVoiceChatStore.getState().messages).toEqual([
      {
        id,
        senderId: "ab",
        name: "alice",
        text: "hi",
        at: 1234,
        own: true,
        failed: true,
      },
    ]);
  });

  it("removes a message by id, leaving others intact", () => {
    const id1 = useVoiceChatStore
      .getState()
      .addMessage({ senderId: "ab", name: "", text: "a", at: 1, own: true });
    const id2 = useVoiceChatStore
      .getState()
      .addMessage({ senderId: "ab", name: "", text: "b", at: 2, own: true });
    useVoiceChatStore.getState().removeMessage(id1);
    expect(useVoiceChatStore.getState().messages.map((m) => m.id)).toEqual([
      id2,
    ]);
  });

  it("ignores removeMessage for an unknown id", () => {
    const id = useVoiceChatStore
      .getState()
      .addMessage({ senderId: "ab", name: "", text: "a", at: 1, own: true });
    useVoiceChatStore.getState().removeMessage(id + 999);
    expect(useVoiceChatStore.getState().messages).toHaveLength(1);
  });

  it("sets the display name", () => {
    useVoiceChatStore.getState().setDisplayName("alice");
    expect(useVoiceChatStore.getState().displayName).toBe("alice");
  });

  it("sets and overwrites a peer name", () => {
    useVoiceChatStore.getState().setPeerName("aa", "bob");
    useVoiceChatStore.getState().setPeerName("aa", "bobby");
    expect(useVoiceChatStore.getState().peerNames).toEqual({ aa: "bobby" });
  });

  it("ignores an empty peer name", () => {
    useVoiceChatStore.getState().setPeerName("aa", "bob");
    useVoiceChatStore.getState().setPeerName("aa", "");
    expect(useVoiceChatStore.getState().peerNames).toEqual({ aa: "bob" });
  });

  it("adds peers uniquely in observation order", () => {
    useVoiceChatStore.getState().addPeer("aa");
    useVoiceChatStore.getState().addPeer("bb");
    useVoiceChatStore.getState().addPeer("aa");
    expect(useVoiceChatStore.getState().peers).toEqual(["aa", "bb"]);
  });

  it("clears peers", () => {
    useVoiceChatStore.getState().addPeer("aa");
    useVoiceChatStore.getState().clearPeers();
    expect(useVoiceChatStore.getState().peers).toEqual([]);
  });

  it("toggles mute state", () => {
    useVoiceChatStore.getState().setMuted(true);
    expect(useVoiceChatStore.getState().muted).toBe(true);
  });

  it("updates connection state", () => {
    useVoiceChatStore.getState().setConnectionState("established");
    expect(useVoiceChatStore.getState().connectionState).toBe("established");
  });

  it("updates reconnecting flag", () => {
    useVoiceChatStore.getState().setReconnecting(true);
    expect(useVoiceChatStore.getState().reconnecting).toBe(true);
  });
});
