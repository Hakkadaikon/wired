import { describe, expect, it, beforeEach } from "vitest";
import { useVoiceChatStore } from "../voiceChatStore";

describe("voiceChatStore", () => {
  beforeEach(() => {
    useVoiceChatStore.setState(useVoiceChatStore.getInitialState());
  });

  it("starts disconnected, unmuted, with no messages", () => {
    const s = useVoiceChatStore.getState();
    expect(s.connectionState).toBe("connecting");
    expect(s.muted).toBe(true);
    expect(s.messages).toEqual([]);
    expect(s.reconnecting).toBe(false);
  });

  it("appends a chat message", () => {
    useVoiceChatStore.getState().addMessage({ senderId: "ab", text: "hi" });
    expect(useVoiceChatStore.getState().messages).toEqual([
      { senderId: "ab", text: "hi" },
    ]);
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
