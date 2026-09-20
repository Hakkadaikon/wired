"use client";

// Glue layer: wraps MoqtChatClient/MoqtVoiceClient and mirrors their
// callbacks into moqtChatStore. UI components read/write only the store;
// the client/pipeline instances themselves live in refs here, never in
// component state.
//
// Voice wiring mirrors webtransport_chat's useVoiceChat.ts (same jitter
// buffer -> AudioDecoder -> audioGate -> playbackSink pipeline), adapted to
// MOQT Objects instead of WebTransport DATAGRAMs: sendOpusFrame/
// handleIncomingStream replace sendDatagram/handleDatagram, and the
// participant id itself is the sender key (no senderId bytes to hex-encode).

import { useCallback, useEffect, useRef, useState } from "react";
import {
  candidateParticipantIds,
  MoqtChatClient,
  type MoqtChatCallbacks,
} from "@/lib/moqtClient";
import { MoqtVoiceClient } from "@/lib/moqtVoiceClient";
import { isScreenTrackAlias, MoqtScreenClient } from "@/lib/moqtScreenClient";
import { MOVIE_INIT_TRACK_ALIAS, MOVIE_TRACK_ALIAS, readMovie } from "@/lib/moqtMovieClient";
import { LiveMovie } from "@/lib/moqtLiveClient";
import { startMicPipeline, type MicPipeline } from "@/lib/micPipeline";
import { startNoiseSuppressor, type NoiseSuppressorHandle } from "@/lib/noiseSuppressor";
import { startScreenSharePipeline, type ScreenSharePipeline } from "@/lib/screenSharePipeline";
import {
  createScreenReceivePipeline,
  type ScreenReceivePipeline,
} from "@/lib/screenReceivePipeline";
import { screenFrameReassemblerInit, screenFrameReassemblerPush } from "@/lib/moqtScreenWire";
import { screenTap } from "@/lib/screenTap";
import {
  createVoiceReceivePipeline,
  type VoiceReceivePipeline,
} from "@/lib/voiceReceivePipeline";
import { createAudioContextGate, type AudioContextGate } from "@/lib/audioContextGate";
import { createPlaybackSink, type PlaybackSink } from "@/lib/playbackSink";
import { effectiveGain } from "@/lib/outputMixer";
import { JitterBufferManager } from "@/lib/jitterBuffer";
import { createQualityWindow, qualityLevel, type QualityWindow } from "@/lib/voiceQuality";
import type { VoiceTapEvent } from "@/lib/voiceTap";
import { registerPageLifecycleCleanup } from "@/lib/pageLifecycle";
import {
  useMoqtChatStore,
  type ConnectionState,
  type MoqtChatState,
} from "@/stores/moqtChatStore";

const JITTER_BUFFER_CAPACITY = 8;
const DRAIN_INTERVAL_MS = 20;
// How often to retry SUBSCRIBE for a candidate's audio track that hasn't
// PUBLISHed yet -- mirrors moqtClient.ts's own #retrySubscribes (SS10.7:
// no namespace discovery in this subset, so a SUBSCRIBE for a peer who
// joins later is retried on an interval rather than notified). A
// subscribeToAudioTrack() sent before the peer's own PUBLISH gets
// DOES_NOT_EXIST and is never retried unless something resends it.
const VOICE_SUBSCRIBE_RETRY_MS = 1000;
// Same gap, same fix, for screen tracks: publishScreenTrack() only ever
// fires when a peer manually calls startScreenShare(), typically long
// after everyone has joined, so a one-shot SUBSCRIBE sweep at connect time
// would miss almost every peer's share for the rest of the session.
const SCREEN_SUBSCRIBE_RETRY_MS = 1000;
// How often the quality window is snapshotted into the store (task brief:
// "every 1s"); independent of DRAIN_INTERVAL_MS, which paces jitter-buffer
// pulls, not quality reporting.
const QUALITY_SNAPSHOT_INTERVAL_MS = 1000;

// voiceReceivePipeline hands the decoder raw Opus payloads; the real
// AudioDecoder wants EncodedAudioChunk, so wrap each payload here with a
// running timestamp (one 20 ms Opus frame per chunk) -- same shape as
// webtransport_chat's useVoiceChat.ts.
const OPUS_FRAME_US = 20_000;
class OpusChunkDecoder {
  private dec: AudioDecoder;
  private ts = 0;
  constructor(init: { output: (frame: unknown) => void; error: (err: unknown) => void }) {
    this.dec = new AudioDecoder(init as never);
  }
  configure(config: unknown) {
    this.dec.configure(config as never);
  }
  decode(payload: Uint8Array) {
    this.dec.decode(
      new EncodedAudioChunk({
        type: "key",
        timestamp: this.ts,
        data: payload as BufferSource,
      }),
    );
    this.ts += OPUS_FRAME_US;
  }
}

type ProcessorLike = {
  readable: { getReader: () => { read: () => Promise<{ value: unknown; done: boolean }> } };
};

function makeProcessor(track: unknown): ProcessorLike {
  const Ctor = (
    window as unknown as {
      MediaStreamTrackProcessor: new (init: { track: unknown }) => ProcessorLike;
    }
  ).MediaStreamTrackProcessor;
  return new Ctor({ track });
}

// Pure translation from MoqtChatClient's callbacks to store actions --
// exported so a test can exercise it against a store instance and a fake
// client shaped like MoqtChatClient, without touching WebTransport.
export function moqtChatCallbacks(
  store: Pick<MoqtChatState, "setConnectionState" | "addPeer" | "addMessage">,
): Pick<MoqtChatCallbacks, "onStatusChange" | "onMessage"> {
  return {
    onStatusChange: (status) => store.setConnectionState(status),
    onMessage: (participantId, text) => {
      store.addPeer(participantId);
      store.addMessage({
        senderId: participantId,
        text,
        at: Date.now(),
        own: false,
      });
    },
  };
}

// The two-stage connect/startVoice sequencing pulled out of connect()'s own
// closure so it's testable without a real WebTransport: chat and voice fail
// independently on purpose. connectChat failing (e.g. cert hash mismatch)
// never even attempts startVoice and reports "disconnected". connectChat
// succeeding but startVoice failing (audio track PUBLISH/SUBSCRIBE, mic
// permission, AudioContext setup) must NOT undo that success -- an earlier
// version awaited both under one try/catch, so a voice failure alone sent
// the join screen back to "Connecting..." even though chat was already
// working (see moqtClient.ts's connect(): onStatusChange("connected") has
// already fired by the time connectChat resolves).
export async function connectChatThenVoice(
  connectChat: () => Promise<void>,
  startVoice: () => Promise<void>,
  onChatFailed: () => void,
  onVoiceFailed: (err: unknown) => void,
): Promise<void> {
  try {
    await connectChat();
  } catch {
    onChatFailed();
    return;
  }
  try {
    await startVoice();
  } catch (err) {
    onVoiceFailed(err);
  }
}

// The capture-before-publish ordering pulled out of startScreenShare's own
// closure so the contract is directly testable: getDisplayMedia() requires
// transient user activation (a real-browser constraint the e2e harness's
// faked getDisplayMedia cannot exercise, per its own doc comment), so
// startCapture must be the first thing awaited after a click -- publish
// only needs to complete before the first sendVideoChunk, which happens
// later once frames start flowing. If startCapture rejects (permission
// denied, user cancelled the picker), publish is never called -- no track
// gets PUBLISHed for a share that never started.
export async function captureThenPublishScreen<T>(
  startCapture: () => Promise<T>,
  publish: () => Promise<void>,
): Promise<T> {
  const pipeline = await startCapture();
  await publish();
  return pipeline;
}

// getMicTracks for registerPageLifecycleCleanup: [] when no mic pipeline is
// running (before connect, or after it has been torn down), otherwise the
// started pipeline's own tracks -- so beforeunload can actually stop the
// device instead of a hardcoded empty list. Pure so it's testable without
// rendering the hook.
export function micTracksFrom(mic: { tracks: { stop: () => void }[] } | null): { stop: () => void }[] {
  return mic?.tracks ?? [];
}

// When to open the live movie's MediaSource: only in the connected room
// view (the <video> ref is mounted there), and never a second time while
// one is already live. Pure so it's testable without rendering the hook.
// Routes one voiceTap event (moqtVoiceClient/voiceReceivePipeline/
// playbackSink's shared trace point, voiceTap.ts) into the quality window.
// "send" carries no sender key from the receiver's own perspective and is
// ignored, same as any event missing src. Pure so it's testable without
// installing globalThis.__wiredVoiceTap.
export function applyVoiceTapEvent(window: QualityWindow, e: VoiceTapEvent): void {
  if (!e.src) return;
  if (e.dir === "recv") window.onFrame(e.src);
  else if (e.dir === "drain") {
    if (e.plc) window.onLost(e.src);
    else if (e.depth !== undefined) window.onDepth(e.src, e.depth);
  } else if (e.dir === "play" && e.lag !== undefined) window.onPlay(e.src, e.lag);
}

// Wraps a possibly-preexisting globalThis.__wiredVoiceTap (the e2e load
// harness installs its own before navigation, voiceTap.ts's own doc) so
// installing the quality feed never drops the harness's trace collection.
export function chainVoiceTap(
  window: QualityWindow,
  previous: ((e: VoiceTapEvent) => void) | undefined,
): (e: VoiceTapEvent) => void {
  return (e) => {
    applyVoiceTapEvent(window, e);
    previous?.(e);
  };
}

export function shouldStartLive(
  connectionState: ConnectionState,
  hasVideo: boolean,
  alreadyStarted: boolean,
): boolean {
  return connectionState === "connected" && hasVideo && !alreadyStarted;
}

// The current session's live resources -- everything a manual Rejoin
// (connect() called while a previous session is still up) would otherwise
// duplicate: the drain loop, both SUBSCRIBE retry timers, the mic, and the
// page-unload handler. Pulled out of leave()'s own teardown so connect() can
// call the identical logic before starting a new session, instead of only
// leave() ever stopping the previous one. Plain ref-shaped params (not React
// refs) so it's testable without rendering the hook -- same pattern as
// registerPageLifecycleCleanup's own deps/target split.
export type SessionRefs = {
  drainTimer: { current: ReturnType<typeof setTimeout> | null };
  voiceRetryTimer: { current: ReturnType<typeof setInterval> | null };
  screenRetryTimer: { current: ReturnType<typeof setInterval> | null };
  qualityTimer: { current: ReturnType<typeof setInterval> | null };
  // Whatever globalThis.__wiredVoiceTap held immediately before this session
  // chained its own quality tap onto it (chainVoiceTap's own doc) -- restored
  // verbatim on teardown so repeated connect/leave/rejoin cycles don't nest
  // one more closure onto the global every time.
  previousVoiceTap: { current: ((e: VoiceTapEvent) => void) | undefined };
  mic: { current: { stop: () => void } | null };
  voice: { current: { close: () => void } | null };
  receivePipeline: { current: unknown };
  knownSenders: { current: Set<string> };
  screenKnownSenders: { current: Set<string> };
  screenShare: { current: { stop: () => void } | null };
  screen: { current: { close: () => void } | null };
  screenReceive: { current: unknown };
  screenReassemblers: { current: Map<string, unknown> };
  screenKeyframeMeta: { current: Map<string, unknown> };
  client: { current: { close: () => void } | null };
  live: { current: { stop: () => void } | null };
  unregisterLifecycle: { current: (() => void) | null };
};

export function teardownSession(
  refs: SessionRefs,
  store: Pick<MoqtChatState, "setScreenSharing" | "setScreenShareError">,
): void {
  if (refs.drainTimer.current !== null) {
    clearTimeout(refs.drainTimer.current);
    refs.drainTimer.current = null;
  }
  if (refs.voiceRetryTimer.current !== null) {
    clearInterval(refs.voiceRetryTimer.current);
    refs.voiceRetryTimer.current = null;
  }
  if (refs.screenRetryTimer.current !== null) {
    clearInterval(refs.screenRetryTimer.current);
    refs.screenRetryTimer.current = null;
  }
  if (refs.qualityTimer.current !== null) {
    clearInterval(refs.qualityTimer.current);
    refs.qualityTimer.current = null;
    // Only restore if THIS session actually chained a tap on (guarded by
    // the same startVoice step that starts qualityTimer) -- an unconditional
    // overwrite here would stomp an e2e harness tap installed before a
    // chat-only connect failure that never reached startVoice at all.
    (globalThis as { __wiredVoiceTap?: unknown }).__wiredVoiceTap = refs.previousVoiceTap.current;
    refs.previousVoiceTap.current = undefined;
  }
  refs.mic.current?.stop();
  refs.mic.current = null;
  refs.voice.current?.close();
  refs.voice.current = null;
  refs.receivePipeline.current = null;
  refs.knownSenders.current.clear();
  refs.screenKnownSenders.current.clear();
  try {
    refs.screenShare.current?.stop();
  } catch {
    // torn down regardless; see stopScreenShare's own doc
  }
  refs.screenShare.current = null;
  refs.screen.current?.close();
  refs.screen.current = null;
  refs.screenReceive.current = null;
  refs.screenReassemblers.current.clear();
  refs.screenKeyframeMeta.current.clear();
  store.setScreenSharing(false);
  store.setScreenShareError(null);
  refs.client.current?.close();
  refs.client.current = null;
  refs.live.current?.stop();
  refs.live.current = null;
  refs.unregisterLifecycle.current?.();
  refs.unregisterLifecycle.current = null;
}

// Back-off schedule for the automatic rejoin after a transport-level
// disconnect: 1 s, 2 s, 4 s, 8 s, then capped at 10 s. null after five
// failed attempts means "give up until the user acts" (the Rejoin button
// keeps working either way).
// AudioEncoder.isConfigSupported, when the global exists -- pickEncoderConfig
// (micPipeline.ts) uses it to probe VOIP_CONFIG before falling back to
// BASE_CONFIG. Environments without AudioEncoder (older browsers, tests)
// omit the dep entirely rather than reference the missing global.
export function micPipelineIsConfigSupported():
  | ((config: unknown) => Promise<{ supported: boolean }>)
  | undefined {
  if (typeof AudioEncoder === "undefined") return undefined;
  return async (config) => ({
    supported: (await AudioEncoder.isConfigSupported(config as AudioEncoderConfig)).supported ?? false,
  });
}

export function reconnectDelayMs(attempt: number): number | null {
  return attempt >= 5 ? null : Math.min(10000, 1000 * 2 ** attempt);
}

export type ReconnectRefs = {
  timer: { current: ReturnType<typeof setTimeout> | null };
  attempt: { current: number };
};

// Drives the auto-rejoin back-off from session status changes: reaching
// "connected" resets the counter; a "disconnected" while the user still
// wants the session schedules the next attempt (or gives up once the
// schedule is exhausted). Plain ref-shaped params, same testability pattern
// as teardownSession above.
export function handleSessionStatus(
  refs: ReconnectRefs,
  status: ConnectionState,
  wantsSession: boolean,
  reconnect: () => void,
): void {
  if (status === "connected") {
    refs.attempt.current = 0;
    return;
  }
  if (status !== "disconnected" || !wantsSession) return;
  const delay = reconnectDelayMs(refs.attempt.current);
  if (delay === null) return;
  refs.attempt.current += 1;
  refs.timer.current = setTimeout(() => {
    refs.timer.current = null;
    reconnect();
  }, delay);
}

export function cancelReconnect(refs: ReconnectRefs): void {
  if (refs.timer.current !== null) {
    clearTimeout(refs.timer.current);
    refs.timer.current = null;
  }
}

export function useMoqtChat() {
  const store = useMoqtChatStore();
  const [micError, setMicError] = useState<string | null>(null);

  const clientRef = useRef<MoqtChatClient | null>(null);
  const voiceRef = useRef<MoqtVoiceClient | null>(null);
  const screenRef = useRef<MoqtScreenClient | null>(null);
  // One frame reassembler per remote sender: moqtScreenWire.ts's
  // reassembler is single-stream state (a `pending` frame keyed by seq), so
  // sharing one across senders would corrupt whichever sender's frame
  // wasn't currently being assembled the moment two people share at once.
  const screenReassemblersRef = useRef<Map<string, ReturnType<typeof screenFrameReassemblerInit>>>(
    new Map(),
  );
  // width/height/codec ride only on a keyframe's idx===0 chunk (wire
  // format, moqtScreenWire.ts), but a frame reassembles on its LAST
  // arriving chunk, whose own fields are undefined -- so the keyframe's
  // metadata has to be remembered per-sender and reapplied at reassembly.
  const screenKeyframeMetaRef = useRef<Map<string, { width?: number; height?: number; codec?: string }>>(
    new Map(),
  );
  const screenReceiveRef = useRef<ScreenReceivePipeline | null>(null);
  const screenShareRef = useRef<ScreenSharePipeline | null>(null);
  const micRef = useRef<MicPipeline | null>(null);
  // The RNNoise AudioWorklet graph, when the noiseSuppressor dep above
  // actually ran (rnnoiseOn was true and it didn't throw) -- stopped
  // alongside the mic in teardownCurrentSession so its AudioContext doesn't
  // leak across a manual Rejoin.
  const noiseSuppressorRef = useRef<NoiseSuppressorHandle | null>(null);
  const receivePipelineRef = useRef<VoiceReceivePipeline | null>(null);
  const jitterBufferRef = useRef<JitterBufferManager | null>(null);
  // Per-peer voice quality: fed by chainVoiceTap (installed in startVoice)
  // and snapshotted into the store every QUALITY_SNAPSHOT_INTERVAL_MS by
  // qualityTimerRef, same shape as the drain loop's own timer ref.
  const qualityWindowRef = useRef<QualityWindow>(createQualityWindow());
  const qualityTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const previousVoiceTapRef = useRef<((e: VoiceTapEvent) => void) | undefined>(undefined);
  const audioGateRef = useRef<AudioContextGate | null>(null);
  // The playback sink and the AudioContext it owns: page.tsx's volume
  // sliders apply through sinkRef (see the store-subscription effect
  // below), and its output-device select calls audioCtxRef's setSinkId.
  const sinkRef = useRef<PlaybackSink | null>(null);
  const audioCtxRef = useRef<AudioContext | null>(null);
  const knownSendersRef = useRef<Set<string>>(new Set());
  // Screen-share counterpart to knownSendersRef: a candidate is added once
  // its first screen chunk arrives (onScreenChunk below), so the retry
  // loop stops resending SUBSCRIBE for peers who are already streaming.
  const screenKnownSendersRef = useRef<Set<string>>(new Set());
  const localIdRef = useRef<string>("");
  const drainTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const voiceRetryTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const screenRetryTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  // registerPageLifecycleCleanup's own unregister, so teardownSession can
  // remove the beforeunload handler instead of piling up a new one on
  // every connect() (a manual Rejoin would otherwise leave the previous
  // session's handler still attached).
  const unregisterLifecycleRef = useRef<(() => void) | null>(null);
  // Auto-rejoin state: the back-off timer/attempt pair handleSessionStatus
  // drives, the last connect()'s arguments (non-null while the user wants
  // the session, i.e. between connect() and leave()), and the latest
  // connect() itself -- the timer outlives the render that scheduled it,
  // and connect's identity changes with the store.
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttemptRef = useRef(0);
  const sessionArgsRef = useRef<{ url: string; localId: string; certHashesHex: string[] } | null>(
    null,
  );
  const connectRef = useRef<((url: string, localId: string, certHashesHex: string[]) => Promise<void>) | null>(
    null,
  );
  // The live <video> element page.tsx renders; LiveMovie drives it directly.
  const videoRef = useRef<HTMLVideoElement>(null);
  const liveRef = useRef<LiveMovie | null>(null);
  // One <canvas> per screen-share tile (remote senders keyed by participant
  // id, own outgoing preview keyed by "own"). page.tsx registers/unregisters
  // as tiles mount/unmount; the decode pipeline's onFrame draws into
  // whichever canvas is currently registered for that sender, or drops the
  // frame if the tile isn't mounted (e.g. between store update and render).
  const screenCanvasRefs = useRef<Map<string, HTMLCanvasElement>>(new Map());
  const registerScreenCanvas = useCallback((id: string, el: HTMLCanvasElement | null) => {
    if (el) screenCanvasRefs.current.set(id, el);
    else screenCanvasRefs.current.delete(id);
  }, []);

  // Draws one decoded/captured frame into whichever tile canvas is
  // currently registered for `key` ("own" for the local outgoing preview,
  // a participant id for a remote sender) -- shared by the receive-side
  // onFrame callback below and startScreenShare's own-preview draw, so both
  // tiles use the identical draw-then-close contract.
  const drawScreenFrame = useCallback((key: string, frame: CanvasImageSource & { close?: () => void }) => {
    const canvas = screenCanvasRefs.current.get(key);
    const ctx = canvas?.getContext("2d");
    if (ctx && canvas) ctx.drawImage(frame, 0, 0, canvas.width, canvas.height);
  }, []);

  const clearLive = useCallback(() => {
    store.setLiveError(null);
    store.setLiveFirstGroup(null);
  }, [store]);

  // Start the live movie only once the room view is on screen: the <video>
  // mounts in the same render that flips connectionState to "connected", so
  // this effect (which runs after the DOM commit) is the first moment
  // videoRef.current is reliably non-null. The cleanup stops playback
  // whenever connectionState leaves "connected" (leave() or a drop).
  const connectionState = store.connectionState;
  useEffect(() => {
    const client = clientRef.current;
    const video = videoRef.current;
    if (!shouldStartLive(connectionState, video !== null, liveRef.current !== null)) return;
    if (!client || !video) return;
    const live = new LiveMovie(client, video, {
      onError: (m) => useMoqtChatStore.getState().setLiveError(m),
      onFirstGroup: (g) => useMoqtChatStore.getState().setLiveFirstGroup(g.toString()),
    });
    liveRef.current = live;
    // start() reports its own failures through onError, but if anything
    // still escapes, surface it -- a swallowed rejection here is exactly
    // the silent forever-spinner this pipeline must never show.
    live.start().catch((err) => useMoqtChatStore.getState().setLiveError(String(err)));
    return () => {
      liveRef.current?.stop();
      liveRef.current = null;
    };
  }, [connectionState]);

  const startDrainLoop = useCallback(() => {
    const tick = () => {
      const pipeline = receivePipelineRef.current;
      if (pipeline) {
        for (const key of knownSendersRef.current) pipeline.drainAndDecode(key);
      }
      drainTimerRef.current = setTimeout(tick, DRAIN_INTERVAL_MS);
    };
    tick();
  }, []);

  const teardownCurrentSession = useCallback(() => {
    teardownSession(
      {
        drainTimer: drainTimerRef,
        voiceRetryTimer: voiceRetryTimerRef,
        screenRetryTimer: screenRetryTimerRef,
        qualityTimer: qualityTimerRef,
        previousVoiceTap: previousVoiceTapRef,
        mic: micRef,
        voice: voiceRef,
        receivePipeline: receivePipelineRef,
        knownSenders: knownSendersRef,
        screenKnownSenders: screenKnownSendersRef,
        screenShare: screenShareRef,
        screen: screenRef,
        screenReceive: screenReceiveRef,
        screenReassemblers: screenReassemblersRef,
        screenKeyframeMeta: screenKeyframeMetaRef,
        client: clientRef,
        live: liveRef,
        unregisterLifecycle: unregisterLifecycleRef,
      },
      store,
    );
    sinkRef.current = null;
    audioCtxRef.current = null;
    noiseSuppressorRef.current?.stop();
    noiseSuppressorRef.current = null;
  }, [store]);

  const startVoice = useCallback(
    async (localId: string, chat: MoqtChatClient) => {
      const audioCtx = new AudioContext();
      audioCtxRef.current = audioCtx;
      const sink = createPlaybackSink(audioCtx);
      sinkRef.current = sink;
      // Pick up whatever the rail's sliders were already set to (e.g. a
      // manual Rejoin after tuning volumes) -- the effect below only fires
      // on a later slider change, not on sink creation itself.
      const state = useMoqtChatStore.getState();
      sink.setMasterGain(effectiveGain(state.masterVolume, 1));
      for (const [id, v] of Object.entries(state.peerVolumes)) {
        sink.setPeerGain(id, effectiveGain(v, 1));
      }
      const audioGate = createAudioContextGate(
        () => audioCtx as unknown as { state: "suspended" | "running" | "closed"; resume: () => Promise<void> },
        {
          onResumeFailed: () => setMicError("audio playback permission was blocked by the browser"),
          play: sink.play,
        },
      );
      audioGateRef.current = audioGate;
      await audioGate.resumeFromUserGesture();

      jitterBufferRef.current = new JitterBufferManager(localId, JITTER_BUFFER_CAPACITY);
      receivePipelineRef.current = createVoiceReceivePipeline({
        jitterBuffer: jitterBufferRef.current,
        AudioDecoderCtor: OpusChunkDecoder as never,
        enqueuePlayback: (senderKey, frame) => audioGate.enqueue(senderKey, frame),
      });
      startDrainLoop();

      // Feed the quality window from the same tap point the load harness
      // uses, chained so an already-installed harness tap keeps working
      // (chainVoiceTap's own doc), then snapshot it into the store once a
      // second per the task brief. previousVoiceTapRef remembers exactly
      // what was installed before THIS session's own chain, so teardown can
      // restore it verbatim instead of nesting one more closure per
      // connect/rejoin cycle.
      const globalTap = globalThis as { __wiredVoiceTap?: (e: VoiceTapEvent) => void };
      previousVoiceTapRef.current = globalTap.__wiredVoiceTap;
      globalTap.__wiredVoiceTap = chainVoiceTap(qualityWindowRef.current, previousVoiceTapRef.current);
      qualityTimerRef.current = setInterval(() => {
        for (const key of knownSendersRef.current) {
          const level = qualityLevel(qualityWindowRef.current.snapshot(key));
          useMoqtChatStore.getState().setVoiceQuality(key, level);
        }
      }, QUALITY_SNAPSHOT_INTERVAL_MS);

      const voice = new MoqtVoiceClient(chat, {
        onOpusFrame: (participantId, payload) => {
          knownSendersRef.current.add(participantId);
          receivePipelineRef.current?.handleObjectPayload(payload, participantId);
        },
      });
      voiceRef.current = voice;
      await voice.publishAudioTrack();
      for (const candidate of candidateParticipantIds(localId)) {
        await voice.subscribeToAudioTrack(candidate);
      }
      voiceRetryTimerRef.current = setInterval(() => {
        for (const candidate of candidateParticipantIds(localId)) {
          if (knownSendersRef.current.has(candidate)) continue;
          void voiceRef.current?.subscribeToAudioTrack(candidate);
        }
      }, VOICE_SUBSCRIBE_RETRY_MS);

      // SUBSCRIBE to every candidate's screen track too, same shape as the
      // voice loop above -- a subscribe sent before that peer ever
      // PUBLISHes just gets DOES_NOT_EXIST and is harmless
      // (moqtScreenClient.ts's own doc); once they call startScreenShare,
      // handleIncomingStream routes their Objects to onScreenChunk above.
      // Screen sharing is opt-in and typically starts well after everyone
      // has joined, so this ALSO needs the retry timer, same mechanism as
      // voice: without it, a peer who starts sharing after this one-shot
      // sweep would never get subscribed to. Wrapped so a screen SUBSCRIBE
      // failure can never fail startVoice itself (which would surface as a
      // voice error for an unrelated feature).
      try {
        for (const candidate of candidateParticipantIds(localId)) {
          await screenRef.current?.subscribeToScreenTrack(candidate);
        }
      } catch {
        // isolation: a screen SUBSCRIBE failure must not block/fail voice
      }
      screenRetryTimerRef.current = setInterval(() => {
        for (const candidate of candidateParticipantIds(localId)) {
          if (screenKnownSendersRef.current.has(candidate)) continue;
          void screenRef.current?.subscribeToScreenTrack(candidate);
        }
      }, SCREEN_SUBSCRIBE_RETRY_MS);

      startMicPipeline({
        getUserMedia: (c) => navigator.mediaDevices.getUserMedia(c),
        makeProcessor,
        AudioEncoderCtor: AudioEncoder as never,
        sendVoiceFrame: (bytes) => voice.sendOpusFrame(bytes),
        isMuted: () => useMoqtChatStore.getState().muted,
        isConfigSupported: micPipelineIsConfigSupported(),
        rnnoiseOn: useMoqtChatStore.getState().noiseSuppressionEnabled,
        noiseSuppressor: async (track) => {
          // VAD consumption is a later task's job (brief); onVad is wired
          // here only so the worklet has somewhere to post to.
          const handle = await startNoiseSuppressor(
            track as unknown as MediaStreamTrack,
            () => {},
          );
          noiseSuppressorRef.current = handle;
          return handle.outputTrack as unknown as { stop: () => void };
        },
        onError: () => setMicError("microphone permission was denied"),
        onEncodeError: () => setMicError("microphone audio could not be encoded"),
        onSendFailing: () =>
          setMicError("voice isn't reaching other participants (connection trouble)"),
      })
        .then((mic) => {
          micRef.current = mic;
        })
        .catch(() => {});
    },
    [startDrainLoop],
  );

  const connect = useCallback(
    async (url: string, localId: string, certHashesHex: string[]) => {
      const reconnectRefs = { timer: reconnectTimerRef, attempt: reconnectAttemptRef };
      // A manual Rejoin (connect() called while a previous session is
      // still up) must not stack a second drain loop / retry timer / mic /
      // lifecycle handler on top of the first -- tear the old session down
      // before starting the new one. leave() itself calls the same
      // teardown for the "give up on the room" path. It also cancels any
      // pending automatic rejoin, and drops the session args across the
      // teardown so the old session's own close cannot schedule one.
      cancelReconnect(reconnectRefs);
      sessionArgsRef.current = null;
      teardownCurrentSession();
      sessionArgsRef.current = { url, localId, certHashesHex };
      localIdRef.current = localId;
      setMicError(null);
      store.clearPeers();
      store.clearMessages();
      store.setDisplayName(localId);
      clearLive();

      // The movie aliases must be checked BEFORE voice: MoqtVoiceClient
      // cancels any stream whose alias it doesn't own. Both movie branches
      // no-op while liveRef is still null (the effect above hasn't started
      // playback yet -- defensive, since LiveMovie itself issues the movie
      // SUBSCRIBEs after liveRef is set): a stray init/fragment is simply
      // dropped, and the hub paces the next Group within ~2 s.
      // Every status report for this session -- the client's own
      // onStatusChange and a failed connect()'s rejection below -- funnels
      // through here, so the store and the auto-rejoin back-off see one
      // consistent stream. A torn-down session's late report is dropped.
      const reportStatus = (status: ConnectionState) => {
        if (clientRef.current !== client) return;
        store.setConnectionState(status);
        handleSessionStatus(reconnectRefs, status, sessionArgsRef.current !== null, () => {
          const args = sessionArgsRef.current;
          if (args) void connectRef.current?.(args.url, args.localId, args.certHashesHex);
        });
      };
      const client: MoqtChatClient = new MoqtChatClient(localId, {
        ...moqtChatCallbacks(store),
        onStatusChange: reportStatus,
        onUnknownUniStream: (header, firstChunkTail, reader) => {
          if (header.trackAlias === MOVIE_INIT_TRACK_ALIAS) {
            void readMovie(firstChunkTail, reader, header.flags.properties).then(
              (bytes) => bytes && liveRef.current?.handleInit(bytes),
            );
            return;
          }
          if (header.trackAlias === MOVIE_TRACK_ALIAS) {
            void liveRef.current?.handleFragment(
              firstChunkTail,
              reader,
              header.flags.properties,
              header.groupId,
            );
            return;
          }
          // Screen alias range must be checked before the voice fallback
          // below: MoqtVoiceClient cancels any stream whose alias it
          // doesn't own, so a screen stream routed there first is eaten.
          if (isScreenTrackAlias(header.trackAlias)) {
            screenRef.current?.handleIncomingStream(header, firstChunkTail, reader);
            return;
          }
          voiceRef.current?.handleIncomingStream(header, firstChunkTail, reader);
        },
        // Only voice sends OBJECT_DATAGRAMs (moqtVoiceClient.ts's
        // sendOpusFrame); movie/screen are stream-borne, so no alias
        // dispatch is needed here yet.
        onUnknownDatagram: (datagram) => {
          voiceRef.current?.handleIncomingDatagram(datagram);
        },
      });
      clientRef.current = client;

      // Screen-share receive side. Wrapped so a decode-pipeline throw can
      // never propagate into onUnknownUniStream's routing (which chat/voice
      // streams also flow through) -- see startScreenShare's own doc for
      // the send-side half of this isolation guarantee.
      screenReceiveRef.current = createScreenReceivePipeline({
        VideoDecoderCtor: VideoDecoder as never,
        EncodedVideoChunkCtor: EncodedVideoChunk,
        onFrame: (senderKey, frame) => {
          const vf = frame as CanvasImageSource & {
            close?: () => void;
            codedWidth?: number;
            codedHeight?: number;
          };
          try {
            drawScreenFrame(senderKey, vf);
            screenTap({
              senderId: senderKey,
              width: vf.codedWidth ?? 0,
              height: vf.codedHeight ?? 0,
              t: performance.now(),
            });
          } finally {
            vf.close?.();
          }
        },
        onDecodeError: () =>
          useMoqtChatStore.getState().setScreenShareError("a peer's screen share could not be decoded"),
      });
      screenRef.current = new MoqtScreenClient(client, {
        onScreenChunk: (participantId, chunk) => {
          screenKnownSendersRef.current.add(participantId);
          try {
            let reassembler = screenReassemblersRef.current.get(participantId);
            if (!reassembler) {
              reassembler = screenFrameReassemblerInit();
              screenReassemblersRef.current.set(participantId, reassembler);
            }
            if (chunk.keyframe && chunk.idx === 0) {
              screenKeyframeMetaRef.current.set(participantId, {
                width: chunk.width,
                height: chunk.height,
                codec: chunk.codec,
              });
            }
            const frameBytes = screenFrameReassemblerPush(reassembler, chunk);
            if (!frameBytes) return;
            useMoqtChatStore.getState().addScreenTile(participantId);
            const meta = screenKeyframeMetaRef.current.get(participantId);
            screenReceiveRef.current?.handleFrame(participantId, {
              data: frameBytes,
              keyframe: chunk.keyframe,
              width: meta?.width,
              height: meta?.height,
              codec: meta?.codec,
            });
          } catch (err) {
            // A malformed/incoming screen stream must never break chat or
            // voice, which share this same onUnknownUniStream callback.
            useMoqtChatStore
              .getState()
              .setScreenShareError(err instanceof Error ? err.message : "screen share receive failed");
          }
        },
      });

      unregisterLifecycleRef.current = registerPageLifecycleCleanup({
        closeTransport: () => client.close(),
        getMicTracks: () => micTracksFrom(micRef.current),
      });

      // The live movie is NOT started here: the effect above starts it once
      // the connected room view (and its <video>) has actually mounted, so
      // it is fire-and-forget and never affects chat/voice failure handling
      // (connectChatThenVoice's own doc).
      await connectChatThenVoice(
        () => client.connect(url, certHashesHex),
        () => startVoice(localId, client),
        // Connection failed (e.g. cert hash mismatch): fall back to
        // disconnected instead of leaving the join screen stuck on
        // "Connecting..." forever. The client itself stays silent on this
        // path, so this is the session's one "disconnected" -- and it
        // schedules the automatic rejoin.
        () => reportStatus("disconnected"),
        (err) => setMicError(err instanceof Error ? err.message : "voice setup failed"),
      );
    },
    [store, startVoice, clearLive, drawScreenFrame, teardownCurrentSession],
  );

  const sendChat = useCallback(
    async (text: string) => {
      const client = clientRef.current;
      const senderId = localIdRef.current;
      if (!client) return;
      const message = { senderId, text, at: Date.now(), own: true };
      try {
        await client.send(text);
        store.addMessage(message);
      } catch {
        store.addMessage({ ...message, failed: true });
      }
    },
    [store],
  );

  const toggleMute = useCallback(() => {
    store.setMuted(!store.muted);
  }, [store]);

  // Screen-share start/stop, modeled on startVoice/mic's shape but kept
  // fully independent: any failure here (getDisplayMedia rejection,
  // encoder error, decode error, publish/send failure) is caught and
  // surfaced ONLY through screenShareError, never through micError or the
  // chat connection state -- a screen-share failure must never break or
  // block chat/voice (task brief's isolation requirement). Verified by
  // reading every await/callback below: each is inside its own try/catch
  // or an error-only callback (onError/onEncodeError), and none of those
  // paths touch clientRef, voiceRef, or store.setConnectionState.
  const startScreenShare = useCallback(async () => {
    const client = clientRef.current;
    const screen = screenRef.current;
    if (!client || !screen) return;
    try {
      let capturedTrack: MediaStreamTrack | undefined;
      const pipeline = await captureThenPublishScreen(
        () =>
          startScreenSharePipeline({
            getDisplayMedia: async (c) => {
              const stream = await navigator.mediaDevices.getDisplayMedia(c);
              capturedTrack = stream.getVideoTracks()[0];
              return stream;
            },
            VideoEncoderCtor: VideoEncoder as never,
            sendVideoChunk: (chunk) => screen.sendVideoChunk(chunk),
            onError: () => store.setScreenShareError("screen share permission was denied"),
            onEncodeError: () => store.setScreenShareError("screen share could not be encoded"),
          }),
        () => screen.publishScreenTrack(),
      );
      screenShareRef.current = pipeline;
      store.setScreenSharing(true);
      store.setScreenShareError(null);
      store.addScreenTile("own");

      // Pump captured frames into the pipeline the same way micPipeline's
      // caller pumps audio frames -- read off a MediaStreamTrackProcessor
      // until the pipeline is stopped or the track ends.
      if (capturedTrack) {
        const processor = makeProcessor(capturedTrack);
        const reader = processor.readable.getReader();
        void (async () => {
          for (;;) {
            const { value, done } = await reader.read();
            if (done || pipeline.stopped) return;
            if (value) {
              // Draw the local preview BEFORE handing the frame to
              // pushFrame, which closes it once encode() has copied what it
              // needs -- drawing after would read a closed VideoFrame. A
              // draw failure (e.g. a transient canvas error) must not kill
              // the encode/send path -- the preview is cosmetic, the share
              // itself is not.
              try {
                drawScreenFrame("own", value as CanvasImageSource & { close?: () => void });
              } catch {
                // preview draw is best-effort; the network path continues below
              }
              pipeline.pushFrame(value as { close?: () => void });
            }
          }
        })().catch((err) => store.setScreenShareError(err instanceof Error ? err.message : "screen share capture failed"));
      }
    } catch (err) {
      store.setScreenShareError(err instanceof Error ? err.message : "screen share failed to start");
    }
  }, [store, drawScreenFrame]);

  const stopScreenShare = useCallback(() => {
    try {
      screenShareRef.current?.stop();
    } catch {
      // stop() failing is not actionable -- the pipeline is being torn down
      // regardless, so surfacing an error here would only be noise.
    }
    screenShareRef.current = null;
    store.setScreenSharing(false);
    store.removeScreenTile("own");
  }, [store]);

  // Keep the auto-rejoin timer retrying through the CURRENT connect() --
  // connect's identity changes with the store, and a timer scheduled by an
  // older render must not resurrect a stale closure's session.
  useEffect(() => {
    connectRef.current = connect;
  }, [connect]);

  // Apply the rail's master/per-peer volume controls to the live gain
  // nodes: the peer GainNode carries that peer's own slider (clamped by
  // outputMixer.ts's effectiveGain against unity), the master GainNode
  // carries the master slider -- the two multiply acoustically once
  // connected in series (playbackSink.ts), so neither setter folds the
  // other's value in.
  const masterVolume = store.masterVolume;
  const peerVolumes = store.peerVolumes;
  useEffect(() => {
    const sink = sinkRef.current;
    if (!sink) return;
    sink.setMasterGain(effectiveGain(masterVolume, 1));
    for (const [id, v] of Object.entries(peerVolumes)) {
      sink.setPeerGain(id, effectiveGain(v, 1));
    }
  }, [masterVolume, peerVolumes]);

  const leave = useCallback(() => {
    // The user no longer wants the session: cancel any pending automatic
    // rejoin, and drop the args first so the teardown below cannot
    // schedule a new one.
    cancelReconnect({ timer: reconnectTimerRef, attempt: reconnectAttemptRef });
    sessionArgsRef.current = null;
    teardownCurrentSession();
    setMicError(null);
    store.setConnectionState("disconnected");
    store.clearPeers();
    store.clearMessages();
    clearLive();
  }, [teardownCurrentSession, store, clearLive]);

  // Routes voice output to a chosen audiooutput device (AudioContext.setSinkId,
  // not yet in TS's DOM lib -- same as makeProcessor's MediaStreamTrackProcessor
  // cast above). No-ops before startVoice has created a context, or in a
  // browser without setSinkId (page.tsx's select isn't rendered there anyway,
  // via outputMixer.ts's canPickOutput).
  const setOutputDevice = useCallback((deviceId: string) => {
    const ctx = audioCtxRef.current as unknown as { setSinkId?: (id: string) => Promise<void> } | null;
    void ctx?.setSinkId?.(deviceId);
  }, []);

  return {
    connect,
    sendChat,
    toggleMute,
    leave,
    micError,
    videoRef,
    startScreenShare,
    stopScreenShare,
    registerScreenCanvas,
    setOutputDevice,
  };
}
