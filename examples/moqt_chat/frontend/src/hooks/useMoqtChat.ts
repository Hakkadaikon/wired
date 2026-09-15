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
import { createPlaybackSink } from "@/lib/playbackSink";
import { JitterBufferManager } from "@/lib/jitterBuffer";
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

// When to open the live movie's MediaSource: only in the connected room
// view (the <video> ref is mounted there), and never a second time while
// one is already live. Pure so it's testable without rendering the hook.
export function shouldStartLive(
  connectionState: ConnectionState,
  hasVideo: boolean,
  alreadyStarted: boolean,
): boolean {
  return connectionState === "connected" && hasVideo && !alreadyStarted;
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
  const receivePipelineRef = useRef<VoiceReceivePipeline | null>(null);
  const jitterBufferRef = useRef<JitterBufferManager | null>(null);
  const audioGateRef = useRef<AudioContextGate | null>(null);
  const knownSendersRef = useRef<Set<string>>(new Set());
  // Screen-share counterpart to knownSendersRef: a candidate is added once
  // its first screen chunk arrives (onScreenChunk below), so the retry
  // loop stops resending SUBSCRIBE for peers who are already streaming.
  const screenKnownSendersRef = useRef<Set<string>>(new Set());
  const localIdRef = useRef<string>("");
  const drainTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const voiceRetryTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const screenRetryTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
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

  const startVoice = useCallback(
    async (localId: string, chat: MoqtChatClient) => {
      const audioCtx = new AudioContext();
      const audioGate = createAudioContextGate(
        () => audioCtx as unknown as { state: "suspended" | "running" | "closed"; resume: () => Promise<void> },
        {
          onResumeFailed: () => setMicError("audio playback permission was blocked by the browser"),
          play: createPlaybackSink(audioCtx),
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
      const client = new MoqtChatClient(localId, {
        ...moqtChatCallbacks(store),
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

      registerPageLifecycleCleanup({
        closeTransport: () => client.close(),
        getMicTracks: () => [],
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
        // "Connecting..." forever.
        () => store.setConnectionState("disconnected"),
        (err) => setMicError(err instanceof Error ? err.message : "voice setup failed"),
      );
    },
    [store, startVoice, clearLive, drawScreenFrame],
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

  const leave = useCallback(() => {
    if (drainTimerRef.current !== null) {
      clearTimeout(drainTimerRef.current);
      drainTimerRef.current = null;
    }
    if (voiceRetryTimerRef.current !== null) {
      clearInterval(voiceRetryTimerRef.current);
      voiceRetryTimerRef.current = null;
    }
    if (screenRetryTimerRef.current !== null) {
      clearInterval(screenRetryTimerRef.current);
      screenRetryTimerRef.current = null;
    }
    micRef.current?.stop();
    micRef.current = null;
    voiceRef.current?.close();
    voiceRef.current = null;
    receivePipelineRef.current = null;
    knownSendersRef.current.clear();
    screenKnownSendersRef.current.clear();
    try {
      screenShareRef.current?.stop();
    } catch {
      // torn down regardless; see stopScreenShare's own doc
    }
    screenShareRef.current = null;
    screenRef.current?.close();
    screenRef.current = null;
    screenReceiveRef.current = null;
    screenReassemblersRef.current.clear();
    screenKeyframeMetaRef.current.clear();
    store.setScreenSharing(false);
    store.setScreenShareError(null);
    clientRef.current?.close();
    clientRef.current = null;
    liveRef.current?.stop();
    liveRef.current = null;
    setMicError(null);
    store.setConnectionState("disconnected");
    store.clearPeers();
    store.clearMessages();
    clearLive();
  }, [store, clearLive]);

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
  };
}
