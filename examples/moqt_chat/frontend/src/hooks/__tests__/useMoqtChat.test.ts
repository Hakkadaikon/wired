import { describe, expect, it, vi } from "vitest";
import {
  captureThenPublishScreen,
  connectChatThenVoice,
  moqtChatCallbacks,
  shouldStartLive,
} from "../useMoqtChat";

// Exercises the pure callback -> store-action translation without
// WebTransport: a MoqtChatClient-shaped fake calls onStatusChange/onMessage
// directly, and we assert the store mock recorded the right actions.
describe("moqtChatCallbacks", () => {
  it("onStatusChange forwards the status to setConnectionState", () => {
    const setConnectionState = vi.fn();
    const callbacks = moqtChatCallbacks({
      setConnectionState,
      addPeer: vi.fn(),
      addMessage: vi.fn(),
    });
    callbacks.onStatusChange("connecting");
    callbacks.onStatusChange("connected");
    expect(setConnectionState).toHaveBeenNthCalledWith(1, "connecting");
    expect(setConnectionState).toHaveBeenNthCalledWith(2, "connected");
  });

  it("onMessage adds the sender as a peer and appends a not-own message", () => {
    const addPeer = vi.fn();
    const addMessage = vi.fn();
    const callbacks = moqtChatCallbacks({
      setConnectionState: vi.fn(),
      addPeer,
      addMessage,
    });
    callbacks.onMessage("user2", "hello");
    expect(addPeer).toHaveBeenCalledWith("user2");
    expect(addMessage).toHaveBeenCalledTimes(1);
    const arg = addMessage.mock.calls[0][0];
    expect(arg.senderId).toBe("user2");
    expect(arg.text).toBe("hello");
    expect(arg.own).toBe(false);
    expect(typeof arg.at).toBe("number");
  });

  it("routes multiple onMessage calls from different senders independently", () => {
    const addPeer = vi.fn();
    const addMessage = vi.fn();
    const callbacks = moqtChatCallbacks({
      setConnectionState: vi.fn(),
      addPeer,
      addMessage,
    });
    callbacks.onMessage("user2", "hi");
    callbacks.onMessage("user3", "yo");
    expect(addPeer.mock.calls).toEqual([["user2"], ["user3"]]);
    expect(addMessage.mock.calls.map((c) => c[0].senderId)).toEqual([
      "user2",
      "user3",
    ]);
  });
});

describe("connectChatThenVoice", () => {
  it("never attempts startVoice when connectChat rejects, and reports onChatFailed", async () => {
    const connectChat = vi.fn().mockRejectedValue(new Error("cert hash mismatch"));
    const startVoice = vi.fn().mockResolvedValue(undefined);
    const onChatFailed = vi.fn();
    const onVoiceFailed = vi.fn();

    await connectChatThenVoice(connectChat, startVoice, onChatFailed, onVoiceFailed);

    expect(startVoice).not.toHaveBeenCalled();
    expect(onChatFailed).toHaveBeenCalledTimes(1);
    expect(onVoiceFailed).not.toHaveBeenCalled();
  });

  it("does NOT call onChatFailed when startVoice rejects after connectChat succeeded -- chat stays connected", async () => {
    const connectChat = vi.fn().mockResolvedValue(undefined);
    const voiceErr = new Error("audio track PUBLISH failed");
    const startVoice = vi.fn().mockRejectedValue(voiceErr);
    const onChatFailed = vi.fn();
    const onVoiceFailed = vi.fn();

    await connectChatThenVoice(connectChat, startVoice, onChatFailed, onVoiceFailed);

    expect(onChatFailed).not.toHaveBeenCalled();
    expect(onVoiceFailed).toHaveBeenCalledExactlyOnceWith(voiceErr);
  });

  it("calls neither failure callback when both connectChat and startVoice succeed", async () => {
    const connectChat = vi.fn().mockResolvedValue(undefined);
    const startVoice = vi.fn().mockResolvedValue(undefined);
    const onChatFailed = vi.fn();
    const onVoiceFailed = vi.fn();

    await connectChatThenVoice(connectChat, startVoice, onChatFailed, onVoiceFailed);

    expect(onChatFailed).not.toHaveBeenCalled();
    expect(onVoiceFailed).not.toHaveBeenCalled();
  });
});

describe("captureThenPublishScreen", () => {
  // Regression coverage for a real bug: startScreenShare used to await a
  // network write (publishScreenTrack) BEFORE calling getDisplayMedia,
  // which can let a click's transient activation expire before the
  // picker ever opens on a real browser -- invisible to the e2e harness,
  // which fakes getDisplayMedia entirely and so cannot exercise ordering
  // against real activation timing. This test pins the ordering contract
  // itself: startCapture must complete before publish is ever called.
  it("calls startCapture before publish, in that order", async () => {
    const calls: string[] = [];
    const startCapture = vi.fn().mockImplementation(async () => {
      calls.push("startCapture");
      return "pipeline";
    });
    const publish = vi.fn().mockImplementation(async () => {
      calls.push("publish");
    });

    const result = await captureThenPublishScreen(startCapture, publish);

    expect(calls).toEqual(["startCapture", "publish"]);
    expect(result).toBe("pipeline");
  });

  it("never calls publish when startCapture rejects (e.g. user cancelled the picker)", async () => {
    const startCapture = vi.fn().mockRejectedValue(new Error("permission denied"));
    const publish = vi.fn().mockResolvedValue(undefined);

    await expect(captureThenPublishScreen(startCapture, publish)).rejects.toThrow(
      "permission denied",
    );
    expect(publish).not.toHaveBeenCalled();
  });

  it("propagates a publish rejection after startCapture already succeeded", async () => {
    const startCapture = vi.fn().mockResolvedValue("pipeline");
    const publish = vi.fn().mockRejectedValue(new Error("PUBLISH write failed"));

    await expect(captureThenPublishScreen(startCapture, publish)).rejects.toThrow(
      "PUBLISH write failed",
    );
    expect(startCapture).toHaveBeenCalledTimes(1);
  });
});

describe("shouldStartLive", () => {
  it("starts only when connected with a mounted <video> and no live movie yet", () => {
    expect(shouldStartLive("connected", true, false)).toBe(true);
  });

  it("never starts while disconnected/connecting, without a video, or twice", () => {
    expect(shouldStartLive("disconnected", true, false)).toBe(false);
    expect(shouldStartLive("connecting", true, false)).toBe(false);
    expect(shouldStartLive("connected", false, false)).toBe(false);
    expect(shouldStartLive("connected", true, true)).toBe(false);
  });
});

