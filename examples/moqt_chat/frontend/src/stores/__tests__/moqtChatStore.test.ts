import { describe, expect, it, beforeEach } from "vitest";
import { useMoqtChatStore } from "../moqtChatStore";

describe("moqtChatStore", () => {
  beforeEach(() => {
    useMoqtChatStore.setState(useMoqtChatStore.getInitialState());
  });

  it("starts disconnected, unmuted, with no messages or peers", () => {
    const s = useMoqtChatStore.getState();
    expect(s.connectionState).toBe("disconnected");
    expect(s.muted).toBe(false);
    expect(s.messages).toEqual([]);
    expect(s.peers).toEqual([]);
    expect(s.displayName).toBe("");
  });

  it("assigns monotonically increasing message ids and returns them", () => {
    const id1 = useMoqtChatStore
      .getState()
      .addMessage({ senderId: "user1", text: "hi", at: 1, own: true });
    const id2 = useMoqtChatStore
      .getState()
      .addMessage({ senderId: "user2", text: "yo", at: 2, own: false });
    expect(id2).toBeGreaterThan(id1);
    const ids = useMoqtChatStore.getState().messages.map((m) => m.id);
    expect(ids).toEqual([id1, id2]);
  });

  it("appends a chat message preserving text, at, own, and failed", () => {
    const id = useMoqtChatStore.getState().addMessage({
      senderId: "user1",
      text: "hi",
      at: 1234,
      own: true,
      failed: true,
    });
    expect(useMoqtChatStore.getState().messages).toEqual([
      { id, senderId: "user1", text: "hi", at: 1234, own: true, failed: true },
    ]);
  });

  it("removes a message by id, leaving others intact", () => {
    const id1 = useMoqtChatStore
      .getState()
      .addMessage({ senderId: "user1", text: "a", at: 1, own: true });
    const id2 = useMoqtChatStore
      .getState()
      .addMessage({ senderId: "user1", text: "b", at: 2, own: true });
    useMoqtChatStore.getState().removeMessage(id1);
    expect(useMoqtChatStore.getState().messages.map((m) => m.id)).toEqual([id2]);
  });

  it("ignores removeMessage for an unknown id", () => {
    const id = useMoqtChatStore
      .getState()
      .addMessage({ senderId: "user1", text: "a", at: 1, own: true });
    useMoqtChatStore.getState().removeMessage(id + 999);
    expect(useMoqtChatStore.getState().messages).toHaveLength(1);
  });

  it("sets the display name", () => {
    useMoqtChatStore.getState().setDisplayName("user1");
    expect(useMoqtChatStore.getState().displayName).toBe("user1");
  });

  it("adds peers uniquely (dedupes) in observation order", () => {
    useMoqtChatStore.getState().addPeer("user2");
    useMoqtChatStore.getState().addPeer("user3");
    useMoqtChatStore.getState().addPeer("user2");
    expect(useMoqtChatStore.getState().peers).toEqual(["user2", "user3"]);
  });

  it("removes a peer", () => {
    useMoqtChatStore.getState().addPeer("user2");
    useMoqtChatStore.getState().addPeer("user3");
    useMoqtChatStore.getState().removePeer("user2");
    expect(useMoqtChatStore.getState().peers).toEqual(["user3"]);
    useMoqtChatStore.getState().removePeer("unknown"); // no-op
    expect(useMoqtChatStore.getState().peers).toEqual(["user3"]);
  });

  it("clears peers", () => {
    useMoqtChatStore.getState().addPeer("user2");
    useMoqtChatStore.getState().clearPeers();
    expect(useMoqtChatStore.getState().peers).toEqual([]);
  });

  it("clears messages", () => {
    useMoqtChatStore
      .getState()
      .addMessage({ senderId: "user1", text: "hi", at: 1, own: true });
    useMoqtChatStore.getState().clearMessages();
    expect(useMoqtChatStore.getState().messages).toEqual([]);
  });

  it("toggles mute state", () => {
    useMoqtChatStore.getState().setMuted(true);
    expect(useMoqtChatStore.getState().muted).toBe(true);
  });

  it("updates connection state", () => {
    useMoqtChatStore.getState().setConnectionState("connected");
    expect(useMoqtChatStore.getState().connectionState).toBe("connected");
  });
});
