import { describe, expect, it, vi } from "vitest";
import { moqtChatCallbacks } from "../useMoqtChat";

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
