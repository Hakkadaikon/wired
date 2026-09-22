import { afterEach, describe, expect, it, vi } from "vitest";
import {
  applyVoiceTapEvent,
  cancelReconnect,
  chainVoiceTap,
  captureThenPublishScreen,
  clearOwnScreenStall,
  connectChatThenVoice,
  handleSessionStatus,
  micPipelineIsConfigSupported,
  micTracksFrom,
  moqtChatCallbacks,
  OWN_SCREEN_KEY,
  reconnectDelayMs,
  sampleLocalLevel,
  shouldAutoStopOwnScreen,
  shouldStartLive,
  teardownSession,
  type ReconnectRefs,
  type SessionRefs,
} from "../useMoqtChat";
import { createQualityWindow, qualityLevel } from "@/lib/voiceQuality";
import { MoqtChatClient } from "@/lib/moqtClient";
import { FakeWebTransport } from "@/lib/__tests__/fakeWebTransport";

// Builds a SessionRefs where every ref/resource starts populated with a
// spy-able fake, so a single teardownSession() call can assert every
// resource it is responsible for releasing.
function fakeSessionRefs(): SessionRefs {
  return {
    drainTimer: { current: setTimeout(() => {}, 1000) },
    voiceRetryTimer: { current: setInterval(() => {}, 1000) },
    screenRetryTimer: { current: setInterval(() => {}, 1000) },
    qualityTimer: { current: setInterval(() => {}, 1000) },
    speakingTimer: { current: setInterval(() => {}, 1000) },
    previousVoiceTap: { current: undefined },
    mic: { current: { stop: vi.fn() } },
    voice: { current: { close: vi.fn() } },
    receivePipeline: { current: {} },
    knownSenders: { current: new Set(["peerA"]) },
    screenKnownSenders: { current: new Set(["peerA"]) },
    screenShare: { current: { stop: vi.fn() } },
    screen: { current: { close: vi.fn() } },
    screenReceive: { current: {} },
    screenReassemblers: { current: new Map([["peerA", {}]]) },
    screenKeyframeMeta: { current: new Map([["peerA", {}]]) },
    screenStall: { current: new Map([["peerA", {}]]) },
    client: { current: { close: vi.fn() } },
    live: { current: { stop: vi.fn() } },
    unregisterLifecycle: { current: vi.fn() },
    audioCtx: { current: { close: vi.fn().mockResolvedValue(undefined) } },
  };
}

function fakeScreenStore() {
  return { setScreenSharing: vi.fn(), setScreenShareError: vi.fn(), setScreenTileStalled: vi.fn() };
}

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

describe("teardownSession", () => {
  it("stops the drain loop, both retry timers, the mic, and unregisters the lifecycle handler", () => {
    const refs = fakeSessionRefs();
    const mic = refs.mic.current as { stop: ReturnType<typeof vi.fn> };
    const unregister = refs.unregisterLifecycle.current as ReturnType<typeof vi.fn>;

    teardownSession(refs, fakeScreenStore());

    expect(refs.drainTimer.current).toBeNull();
    expect(refs.voiceRetryTimer.current).toBeNull();
    expect(refs.screenRetryTimer.current).toBeNull();
    expect(refs.qualityTimer.current).toBeNull();
    expect(refs.speakingTimer.current).toBeNull();
    expect(mic.stop).toHaveBeenCalledTimes(1);
    expect(refs.mic.current).toBeNull();
    expect(unregister).toHaveBeenCalledTimes(1);
    expect(refs.unregisterLifecycle.current).toBeNull();
  });

  it("drops every sender's stall detector and clears its stalled flag", () => {
    const refs = fakeSessionRefs();
    const store = fakeScreenStore();
    teardownSession(refs, store);
    expect(refs.screenStall.current.size).toBe(0);
    expect(store.setScreenTileStalled).toHaveBeenCalledExactlyOnceWith("peerA", false);
  });

  it("restores whatever __wiredVoiceTap was before this session installed its own", () => {
    const priorTap = vi.fn();
    const g = globalThis as { __wiredVoiceTap?: unknown };
    g.__wiredVoiceTap = "installed-by-this-session";
    try {
      const refs = fakeSessionRefs();
      refs.previousVoiceTap.current = priorTap;

      teardownSession(refs, fakeScreenStore());

      expect(g.__wiredVoiceTap).toBe(priorTap);
      expect(refs.previousVoiceTap.current).toBeUndefined();
    } finally {
      delete g.__wiredVoiceTap;
    }
  });

  it("does not touch __wiredVoiceTap when this session never reached startVoice (qualityTimer never set)", () => {
    const harnessTap = vi.fn();
    const g = globalThis as { __wiredVoiceTap?: unknown };
    g.__wiredVoiceTap = harnessTap;
    try {
      const refs = fakeSessionRefs();
      refs.qualityTimer.current = null; // chat-only failure: startVoice never ran

      teardownSession(refs, fakeScreenStore());

      expect(g.__wiredVoiceTap).toBe(harnessTap);
    } finally {
      delete g.__wiredVoiceTap;
    }
  });

  it("closes voice/screen/client, clears sender sets and reassembler maps, and resets screen-share store state", () => {
    const refs = fakeSessionRefs();
    const voice = refs.voice.current as { close: ReturnType<typeof vi.fn> };
    const screen = refs.screen.current as { close: ReturnType<typeof vi.fn> };
    const client = refs.client.current as { close: ReturnType<typeof vi.fn> };
    const live = refs.live.current as { stop: ReturnType<typeof vi.fn> };
    const store = fakeScreenStore();

    teardownSession(refs, store);

    expect(voice.close).toHaveBeenCalledTimes(1);
    expect(screen.close).toHaveBeenCalledTimes(1);
    expect(client.close).toHaveBeenCalledTimes(1);
    expect(live.stop).toHaveBeenCalledTimes(1);
    expect(refs.knownSenders.current.size).toBe(0);
    expect(refs.screenKnownSenders.current.size).toBe(0);
    expect(refs.screenReassemblers.current.size).toBe(0);
    expect(refs.screenKeyframeMeta.current.size).toBe(0);
    expect(store.setScreenSharing).toHaveBeenCalledWith(false);
    expect(store.setScreenShareError).toHaveBeenCalledWith(null);
  });

  it("is idempotent -- a second call touches nothing already torn down", () => {
    const refs = fakeSessionRefs();
    const mic = refs.mic.current as { stop: ReturnType<typeof vi.fn> };
    const store = fakeScreenStore();

    teardownSession(refs, store);
    teardownSession(refs, store);

    expect(mic.stop).toHaveBeenCalledTimes(1);
  });

  it("closes the AudioContext exactly once, and a second teardown does not close it again", () => {
    const refs = fakeSessionRefs();
    const audioCtx = refs.audioCtx.current as { close: ReturnType<typeof vi.fn> };
    const store = fakeScreenStore();

    teardownSession(refs, store);
    teardownSession(refs, store);

    expect(audioCtx.close).toHaveBeenCalledTimes(1);
    expect(refs.audioCtx.current).toBeNull();
  });

  it("survives a screenShare.stop() throw without skipping the rest of teardown", () => {
    const refs = fakeSessionRefs();
    refs.screenShare.current = {
      stop: () => {
        throw new Error("already stopped");
      },
    };
    const client = refs.client.current as { close: ReturnType<typeof vi.fn> };

    expect(() => teardownSession(refs, fakeScreenStore())).not.toThrow();
    expect(client.close).toHaveBeenCalledTimes(1);
  });
});

describe("clearOwnScreenStall", () => {
  it("drops only the own-tile detector, leaving remote senders' alone", () => {
    const screenStall = new Map<string, unknown>([
      [OWN_SCREEN_KEY, {}],
      ["peerA", {}],
    ]);
    const store = { setScreenTileStalled: vi.fn() };

    clearOwnScreenStall(screenStall, store);

    expect(screenStall.has(OWN_SCREEN_KEY)).toBe(false);
    expect(screenStall.has("peerA")).toBe(true);
    expect(store.setScreenTileStalled).toHaveBeenCalledExactlyOnceWith(OWN_SCREEN_KEY, false);
  });

  it("is a no-op when there was no own-tile detector (never shared, or already stopped)", () => {
    const screenStall = new Map<string, unknown>([["peerA", {}]]);
    const store = { setScreenTileStalled: vi.fn() };

    clearOwnScreenStall(screenStall, store);

    expect(store.setScreenTileStalled).not.toHaveBeenCalled();
  });
});

describe("shouldAutoStopOwnScreen", () => {
  it("fires on the rising edge: own just became stalled while armed", () => {
    expect(shouldAutoStopOwnScreen(OWN_SCREEN_KEY, true, true)).toBe(true);
  });

  it("does not fire once disarmed, even while still stalled (edge-triggered, once)", () => {
    expect(shouldAutoStopOwnScreen(OWN_SCREEN_KEY, true, false)).toBe(false);
  });

  it("does not fire when own is not stalled", () => {
    expect(shouldAutoStopOwnScreen(OWN_SCREEN_KEY, false, true)).toBe(false);
  });

  it("never fires for a remote sender's key, armed or not", () => {
    expect(shouldAutoStopOwnScreen("peerA", true, true)).toBe(false);
  });
});

describe("reconnectDelayMs", () => {
  it("reconnect delay grows exponentially, capped, then null", () => {
    expect(reconnectDelayMs(0)).toBe(1000);
    expect(reconnectDelayMs(1)).toBe(2000);
    expect(reconnectDelayMs(2)).toBe(4000);
    expect(reconnectDelayMs(3)).toBe(8000);
    expect(reconnectDelayMs(4)).toBe(10000);
    expect(reconnectDelayMs(5)).toBeNull();
  });
});

describe("auto-rejoin back-off", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  const freshRefs = (): ReconnectRefs => ({
    timer: { current: null },
    attempt: { current: 0 },
  });

  it("consecutive failures schedule 1000 then 2000 ms delays", () => {
    vi.useFakeTimers();
    const refs = freshRefs();
    const reconnect = vi.fn();

    handleSessionStatus(refs, "disconnected", true, reconnect);
    vi.advanceTimersByTime(999);
    expect(reconnect).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(reconnect).toHaveBeenCalledTimes(1);

    handleSessionStatus(refs, "disconnected", true, reconnect);
    vi.advanceTimersByTime(1999);
    expect(reconnect).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(1);
    expect(reconnect).toHaveBeenCalledTimes(2);
  });

  it("reaching connected resets the back-off to 1000 ms", () => {
    vi.useFakeTimers();
    const refs = freshRefs();
    refs.attempt.current = 2; // dropped twice already
    const reconnect = vi.fn();

    handleSessionStatus(refs, "connected", true, reconnect);
    handleSessionStatus(refs, "disconnected", true, reconnect);

    vi.advanceTimersByTime(1000);
    expect(reconnect).toHaveBeenCalledTimes(1);
  });

  it("after five failed reconnects no further timer is scheduled", () => {
    vi.useFakeTimers();
    const refs = freshRefs();
    refs.attempt.current = 5;
    const reconnect = vi.fn();

    handleSessionStatus(refs, "disconnected", true, reconnect);

    expect(refs.timer.current).toBeNull();
    vi.advanceTimersByTime(60000);
    expect(reconnect).not.toHaveBeenCalled(); // stays down until the user acts
  });

  it("manual rejoin still works after giving up", () => {
    vi.useFakeTimers();
    const refs = freshRefs();
    refs.attempt.current = 5;
    const connectAttempt = vi.fn();
    handleSessionStatus(refs, "disconnected", true, connectAttempt); // gave up

    // The Rejoin click's path: cancel any pending timer, connect once.
    cancelReconnect(refs);
    connectAttempt();

    vi.advanceTimersByTime(60000);
    expect(connectAttempt).toHaveBeenCalledTimes(1);
  });

  it("leaving during back-off cancels the reconnect timer", () => {
    vi.useFakeTimers();
    const refs = freshRefs();
    const reconnect = vi.fn();
    handleSessionStatus(refs, "disconnected", true, reconnect);
    expect(refs.timer.current).not.toBeNull();

    cancelReconnect(refs);

    expect(refs.timer.current).toBeNull();
    vi.advanceTimersByTime(60000);
    expect(reconnect).not.toHaveBeenCalled();
  });

  it("manual rejoin during back-off cancels the timer and connects once", () => {
    vi.useFakeTimers();
    const refs = freshRefs();
    const connectAttempt = vi.fn();
    handleSessionStatus(refs, "disconnected", true, connectAttempt);

    cancelReconnect(refs);
    connectAttempt(); // the Rejoin click's own connect

    vi.advanceTimersByTime(1000); // the original timer's deadline passes
    expect(connectAttempt).toHaveBeenCalledTimes(1);
  });

  it("never schedules once the user no longer wants the session", () => {
    vi.useFakeTimers();
    const refs = freshRefs();
    const reconnect = vi.fn();

    handleSessionStatus(refs, "disconnected", false, reconnect);

    expect(refs.timer.current).toBeNull();
    vi.advanceTimersByTime(60000);
    expect(reconnect).not.toHaveBeenCalled();
  });
});

// End-to-end over the real MoqtChatClient with fake transports: the failed
// session's single "disconnected" and the timer chain that recovers once the
// hub is back.
describe("session drop and automatic rejoin", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  const flushAsync = () => vi.advanceTimersByTimeAsync(0);

  // The hook's own glue in miniature: one client, statuses recorded, every
  // "disconnected" (transport-level or a failed connect()) drives the
  // back-off scheduler.
  function makeSession(nextTransport: () => FakeWebTransport) {
    vi.useFakeTimers();
    vi.stubGlobal("WebTransport", function () {
      return nextTransport();
    });
    const refs: ReconnectRefs = { timer: { current: null }, attempt: { current: 0 } };
    const statuses: string[] = [];
    const attemptSession = () =>
      connectChatThenVoice(
        () => client.connect("https://hub.example/", []),
        async () => {},
        () => report("disconnected"),
        () => {},
      );
    const report = (status: "connecting" | "connected" | "disconnected") => {
      statuses.push(status);
      handleSessionStatus(refs, status, true, () => void attemptSession());
    };
    const client = new MoqtChatClient("user1", {
      onStatusChange: report,
      onMessage: () => {},
    });
    const disconnects = () => statuses.filter((s) => s === "disconnected").length;
    return { refs, statuses, attemptSession, disconnects, client };
  }

  it("a failed connect attempt reports exactly one disconnected", async () => {
    const fake = new FakeWebTransport();
    const { attemptSession, disconnects, refs, client } = makeSession(() => fake);

    const attempt = attemptSession();
    fake.rejectReady(new Error("transport failed"));
    fake.rejectClosed(new Error("transport failed"));
    await attempt;
    await flushAsync();

    expect(disconnects()).toBe(1);
    expect(refs.attempt.current).toBe(1); // exactly one reconnect scheduled
    expect(refs.timer.current).not.toBeNull();
    cancelReconnect(refs);
    client.close();
  });

  it("a failed connect attempt reports exactly one disconnected even when closed settles before ready", async () => {
    const fake = new FakeWebTransport();
    const { attemptSession, disconnects, refs, client } = makeSession(() => fake);

    const attempt = attemptSession();
    // The browser does not promise an order between the two rejections.
    fake.rejectClosed(new Error("transport failed"));
    fake.rejectReady(new Error("transport failed"));
    await attempt;
    await flushAsync();

    expect(disconnects()).toBe(1);
    expect(refs.attempt.current).toBe(1); // exactly one reconnect scheduled
    cancelReconnect(refs);
    client.close();
  });

  it("the session reconnects on its own once the hub returns", async () => {
    const first = new FakeWebTransport();
    const whileDown = new FakeWebTransport();
    const hubBack = new FakeWebTransport();
    const fakes = [first, whileDown, hubBack];
    const { attemptSession, statuses, refs, disconnects, client } = makeSession(
      () => fakes.shift() ?? new FakeWebTransport(),
    );

    const joined = attemptSession();
    first.resolveReady();
    await joined;
    expect(statuses.at(-1)).toBe("connected");

    first.rejectClosed(new Error("hub went down"));
    await flushAsync();
    expect(disconnects()).toBe(1);

    // First back-off attempt (1000 ms) still finds the hub down.
    await vi.advanceTimersByTimeAsync(1000);
    whileDown.rejectReady(new Error("still down"));
    whileDown.rejectClosed(new Error("still down"));
    await flushAsync();
    expect(disconnects()).toBe(2);

    // Second back-off attempt (2000 ms) finds the hub back.
    await vi.advanceTimersByTimeAsync(2000);
    hubBack.resolveReady();
    await flushAsync();

    expect(statuses.at(-1)).toBe("connected"); // without any user action
    expect(refs.attempt.current).toBe(0);
    client.close();
  });
});

describe("micTracksFrom", () => {
  it("returns [] when no mic pipeline has been started (before connect, or after leave)", () => {
    expect(micTracksFrom(null)).toEqual([]);
  });

  it("returns the started mic pipeline's tracks", () => {
    const track = { stop: vi.fn() };
    expect(micTracksFrom({ tracks: [track] })).toEqual([track]);
  });
});

describe("micPipelineIsConfigSupported", () => {
  const original = (globalThis as { AudioEncoder?: unknown }).AudioEncoder;

  afterEach(() => {
    (globalThis as { AudioEncoder?: unknown }).AudioEncoder = original;
  });

  it("is absent when the AudioEncoder global does not exist", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    delete (globalThis as any).AudioEncoder;
    expect(micPipelineIsConfigSupported()).toBeUndefined();
  });

  it("delegates to AudioEncoder.isConfigSupported when the global exists", async () => {
    const isConfigSupported = vi.fn().mockResolvedValue({ supported: true });
    (globalThis as { AudioEncoder?: unknown }).AudioEncoder = { isConfigSupported };

    const dep = micPipelineIsConfigSupported();
    expect(dep).toBeTypeOf("function");
    await expect(dep?.({ codec: "opus" })).resolves.toEqual({ supported: true });
    expect(isConfigSupported).toHaveBeenCalledWith({ codec: "opus" });
  });
});

describe("applyVoiceTapEvent", () => {
  it("routes a recv event to onFrame", () => {
    const w = createQualityWindow();
    applyVoiceTapEvent(w, { dir: "recv", seq: 1, src: "user1", t: 0 });
    expect(qualityLevel(w.snapshot("user1"))).toBe("good");
  });

  it("routes a drain event with plc to onLost, and with depth to onDepth", () => {
    const w = createQualityWindow();
    for (let i = 0; i < 98; i++) applyVoiceTapEvent(w, { dir: "recv", seq: i, src: "user1", t: 0 });
    applyVoiceTapEvent(w, { dir: "drain", seq: 0, src: "user1", t: 0, depth: 3 });
    for (let i = 0; i < 2; i++)
      applyVoiceTapEvent(w, { dir: "drain", seq: 100 + i, src: "user1", t: 0, plc: true });
    // 98 received, 2 lost == exactly 2% (good boundary); the depth-only
    // drain event above must not itself count as a lost or received frame.
    expect(qualityLevel(w.snapshot("user1"))).toBe("good");
  });

  it("routes a play event's lag to onPlay", () => {
    const w = createQualityWindow();
    applyVoiceTapEvent(w, { dir: "recv", seq: 1, src: "user1", t: 0 });
    applyVoiceTapEvent(w, { dir: "play", seq: -1, src: "user1", t: 0, lag: 200 });
    expect(qualityLevel(w.snapshot("user1"))).toBe("degraded");
  });

  it("ignores send events and events with no sender key", () => {
    const w = createQualityWindow();
    applyVoiceTapEvent(w, { dir: "send", seq: 1, t: 0 });
    applyVoiceTapEvent(w, { dir: "drain", seq: 1, t: 0, plc: true });
    expect(qualityLevel(w.snapshot("user1"))).toBe("none");
  });
});

describe("chainVoiceTap", () => {
  it("feeds the quality window without dropping a pre-existing tap (e2e harness)", () => {
    const w = createQualityWindow();
    const priorCalls: unknown[] = [];
    const prior = (e: unknown) => priorCalls.push(e);
    const combined = chainVoiceTap(w, prior);
    combined({ dir: "recv", seq: 1, src: "user1", t: 0 });
    expect(qualityLevel(w.snapshot("user1"))).toBe("good");
    expect(priorCalls).toEqual([{ dir: "recv", seq: 1, src: "user1", t: 0 }]);
  });

  it("works with no pre-existing tap", () => {
    const w = createQualityWindow();
    const combined = chainVoiceTap(w, undefined);
    expect(() => combined({ dir: "recv", seq: 1, src: "user1", t: 0 })).not.toThrow();
    expect(qualityLevel(w.snapshot("user1"))).toBe("good");
  });
});

describe("sampleLocalLevel", () => {
  it("reads the analyser's buffer into scratch and returns its rms level", () => {
    const scratch = new Float32Array(4);
    const analyser = {
      getFloatTimeDomainData: (buf: Float32Array) => buf.fill(1),
    };
    expect(sampleLocalLevel(analyser, scratch)).toBe(100);
  });

  it("returns 0 for silence", () => {
    const scratch = new Float32Array(4);
    const analyser = { getFloatTimeDomainData: (buf: Float32Array) => buf.fill(0) };
    expect(sampleLocalLevel(analyser, scratch)).toBe(0);
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

