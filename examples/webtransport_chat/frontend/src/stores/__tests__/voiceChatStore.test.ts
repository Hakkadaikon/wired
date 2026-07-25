import { describe, expect, it, beforeEach } from "vitest";
import { useVoiceChatStore } from "../voiceChatStore";

describe("voiceChatStore", () => {
  beforeEach(() => {
    useVoiceChatStore.setState(useVoiceChatStore.getInitialState());
  });

  it("starts disconnected, unmuted, with no messages or peers", () => {
    const s = useVoiceChatStore.getState();
    expect(s.connectionState).toBe("connecting");
    expect(s.muted).toBe(false);
    expect(s.messages).toEqual([]);
    expect(s.peers).toEqual([]);
    expect(s.reconnecting).toBe(false);
  });

  it("appends a chat message preserving at and own", () => {
    useVoiceChatStore
      .getState()
      .addMessage({ senderId: "ab", text: "hi", at: 1234, own: true });
    expect(useVoiceChatStore.getState().messages).toEqual([
      { senderId: "ab", text: "hi", at: 1234, own: true },
    ]);
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
    useVoiceChatStore.getState().setMuted(false);
    expect(useVoiceChatStore.getState().muted).toBe(false);
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
