import { describe, expect, it, beforeEach } from "vitest";
import { resolveDisplayName, useMoqtChatStore } from "../moqtChatStore";

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
    expect(s.nicknames).toEqual({});
    expect(s.liveError).toBeNull();
    expect(s.liveFirstGroup).toBeNull();
    expect(s.screenSharing).toBe(false);
    expect(s.screenTiles).toEqual([]);
    expect(s.screenShareError).toBeNull();
    expect(s.masterVolume).toBe(1);
    expect(s.peerVolumes).toEqual({});
    expect(s.voiceQuality).toEqual({});
  });

  it("holds the remote screen tile width (320 px by default) and which tile is maximized", () => {
    const s = useMoqtChatStore.getState();
    expect(s.screenTileWidth).toBe(320);
    expect(s.maximizedScreenTile).toBeNull();
    s.setScreenTileWidth(640);
    s.setMaximizedScreenTile("user2");
    expect(useMoqtChatStore.getState().screenTileWidth).toBe(640);
    expect(useMoqtChatStore.getState().maximizedScreenTile).toBe("user2");
  });

  it("un-maximizes a tile when it is removed", () => {
    const s = useMoqtChatStore.getState();
    s.addScreenTile("user2");
    s.setMaximizedScreenTile("user2");
    s.removeScreenTile("user3");
    expect(useMoqtChatStore.getState().maximizedScreenTile).toBe("user2");
    s.removeScreenTile("user2");
    expect(useMoqtChatStore.getState().maximizedScreenTile).toBeNull();
  });

  it("clearScreenTiles drops every tile, its stalled flag and the maximized one", () => {
    const s = useMoqtChatStore.getState();
    s.addScreenTile("user2");
    s.addScreenTile("user3");
    s.setScreenTileStalled("user2", true);
    s.setMaximizedScreenTile("user3");
    s.clearScreenTiles();
    const after = useMoqtChatStore.getState();
    expect(after.screenTiles).toEqual([]);
    expect(after.stalledScreenTiles).toEqual({});
    expect(after.maximizedScreenTile).toBeNull();
  });

  it("flags a screen tile as stalled and clears it again", () => {
    const s = useMoqtChatStore.getState();
    expect(s.stalledScreenTiles).toEqual({});
    s.setScreenTileStalled("user2", true);
    expect(useMoqtChatStore.getState().stalledScreenTiles).toEqual({ user2: true });
    s.setScreenTileStalled("user2", false);
    expect(useMoqtChatStore.getState().stalledScreenTiles).toEqual({ user2: false });
  });

  it("setScreenTileStalled leaves state untouched when the flag is unchanged", () => {
    const s = useMoqtChatStore.getState();
    s.setScreenTileStalled("user2", true);
    const before = useMoqtChatStore.getState().stalledScreenTiles;
    s.setScreenTileStalled("user2", true);
    expect(useMoqtChatStore.getState().stalledScreenTiles).toBe(before);
  });

  it("sets and clears the live movie error and first group", () => {
    useMoqtChatStore.getState().setLiveError("video buffer error");
    useMoqtChatStore.getState().setLiveFirstGroup("7");
    expect(useMoqtChatStore.getState().liveError).toBe("video buffer error");
    expect(useMoqtChatStore.getState().liveFirstGroup).toBe("7");
    useMoqtChatStore.getState().setLiveError(null);
    useMoqtChatStore.getState().setLiveFirstGroup(null);
    expect(useMoqtChatStore.getState().liveError).toBeNull();
    expect(useMoqtChatStore.getState().liveFirstGroup).toBeNull();
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

  it("sets a participant's nickname without affecting others", () => {
    useMoqtChatStore.getState().setNickname("user1", "Alice");
    useMoqtChatStore.getState().setNickname("user2", "Bob");
    expect(useMoqtChatStore.getState().nicknames).toEqual({ user1: "Alice", user2: "Bob" });
  });
});

describe("resolveDisplayName", () => {
  it("returns the nickname when one is known", () => {
    expect(resolveDisplayName("user1", { user1: "Alice" })).toBe("Alice");
  });

  it("falls back to the id when no nickname is known", () => {
    expect(resolveDisplayName("user1", {})).toBe("user1");
  });

  it("falls back to the id when the nickname is an empty string", () => {
    expect(resolveDisplayName("user1", { user1: "" })).toBe("user1");
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

  it("toggles screen sharing state", () => {
    useMoqtChatStore.getState().setScreenSharing(true);
    expect(useMoqtChatStore.getState().screenSharing).toBe(true);
  });

  it("adds screen tiles uniquely (dedupes) in observation order", () => {
    useMoqtChatStore.getState().addScreenTile("user2");
    useMoqtChatStore.getState().addScreenTile("user3");
    useMoqtChatStore.getState().addScreenTile("user2");
    expect(useMoqtChatStore.getState().screenTiles).toEqual(["user2", "user3"]);
  });

  it("removes a screen tile", () => {
    useMoqtChatStore.getState().addScreenTile("user2");
    useMoqtChatStore.getState().addScreenTile("user3");
    useMoqtChatStore.getState().removeScreenTile("user2");
    expect(useMoqtChatStore.getState().screenTiles).toEqual(["user3"]);
    useMoqtChatStore.getState().removeScreenTile("unknown"); // no-op
    expect(useMoqtChatStore.getState().screenTiles).toEqual(["user3"]);
  });

  it("sets and clears the screen-share error independently of other error state", () => {
    useMoqtChatStore.getState().setScreenShareError("getDisplayMedia was denied");
    expect(useMoqtChatStore.getState().screenShareError).toBe("getDisplayMedia was denied");
    expect(useMoqtChatStore.getState().liveError).toBeNull();
    useMoqtChatStore.getState().setScreenShareError(null);
    expect(useMoqtChatStore.getState().screenShareError).toBeNull();
  });

  it("starts at full master volume with no per-peer overrides", () => {
    expect(useMoqtChatStore.getState().masterVolume).toBe(1);
    expect(useMoqtChatStore.getState().peerVolumes).toEqual({});
  });

  it("sets the master volume", () => {
    useMoqtChatStore.getState().setMasterVolume(0.4);
    expect(useMoqtChatStore.getState().masterVolume).toBe(0.4);
  });

  it("sets a peer's volume without affecting other peers", () => {
    useMoqtChatStore.getState().setPeerVolume("user2", 0.3);
    useMoqtChatStore.getState().setPeerVolume("user3", 0.7);
    expect(useMoqtChatStore.getState().peerVolumes).toEqual({ user2: 0.3, user3: 0.7 });
  });

  it("starts with no voice quality recorded", () => {
    expect(useMoqtChatStore.getState().voiceQuality).toEqual({});
  });

  it("sets a peer's voice quality without affecting other peers", () => {
    useMoqtChatStore.getState().setVoiceQuality("user2", "degraded");
    useMoqtChatStore.getState().setVoiceQuality("user3", "good");
    expect(useMoqtChatStore.getState().voiceQuality).toEqual({
      user2: "degraded",
      user3: "good",
    });
  });

  it("clears voice quality when peers are cleared", () => {
    useMoqtChatStore.getState().setVoiceQuality("user2", "degraded");
    useMoqtChatStore.getState().clearPeers();
    expect(useMoqtChatStore.getState().voiceQuality).toEqual({});
  });

  it("starts with no one speaking, local or remote", () => {
    expect(useMoqtChatStore.getState().speaking).toEqual({});
    expect(useMoqtChatStore.getState().localSpeaking).toBe(false);
  });

  it("sets a peer's speaking state without affecting other peers", () => {
    useMoqtChatStore.getState().setSpeaking("user2", true);
    useMoqtChatStore.getState().setSpeaking("user3", false);
    expect(useMoqtChatStore.getState().speaking).toEqual({ user2: true, user3: false });
  });

  it("clears speaking when peers are cleared", () => {
    useMoqtChatStore.getState().setSpeaking("user2", true);
    useMoqtChatStore.getState().clearPeers();
    expect(useMoqtChatStore.getState().speaking).toEqual({});
  });

  it("sets local speaking state", () => {
    useMoqtChatStore.getState().setLocalSpeaking(true);
    expect(useMoqtChatStore.getState().localSpeaking).toBe(true);
    useMoqtChatStore.getState().setLocalSpeaking(false);
    expect(useMoqtChatStore.getState().localSpeaking).toBe(false);
  });
});
