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

import { useCallback, useRef, useState } from "react";
import {
  candidateParticipantIds,
  MoqtChatClient,
  type MoqtChatCallbacks,
} from "@/lib/moqtClient";
import { MoqtVoiceClient } from "@/lib/moqtVoiceClient";
import { startMicPipeline, type MicPipeline } from "@/lib/micPipeline";
import {
  createVoiceReceivePipeline,
  type VoiceReceivePipeline,
} from "@/lib/voiceReceivePipeline";
import { createAudioContextGate, type AudioContextGate } from "@/lib/audioContextGate";
import { createPlaybackSink } from "@/lib/playbackSink";
import { JitterBufferManager } from "@/lib/jitterBuffer";
import { registerPageLifecycleCleanup } from "@/lib/pageLifecycle";
import { useMoqtChatStore, type MoqtChatState } from "@/stores/moqtChatStore";

const JITTER_BUFFER_CAPACITY = 8;
const DRAIN_INTERVAL_MS = 20;
// How often to retry SUBSCRIBE for a candidate's audio track that hasn't
// PUBLISHed yet -- mirrors moqtClient.ts's own #retrySubscribes (SS10.7:
// no namespace discovery in this subset, so a SUBSCRIBE for a peer who
// joins later is retried on an interval rather than notified). A
// subscribeToAudioTrack() sent before the peer's own PUBLISH gets
// DOES_NOT_EXIST and is never retried unless something resends it.
const VOICE_SUBSCRIBE_RETRY_MS = 1000;

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

export function useMoqtChat() {
  const store = useMoqtChatStore();
  const [micError, setMicError] = useState<string | null>(null);

  const clientRef = useRef<MoqtChatClient | null>(null);
  const voiceRef = useRef<MoqtVoiceClient | null>(null);
  const micRef = useRef<MicPipeline | null>(null);
  const receivePipelineRef = useRef<VoiceReceivePipeline | null>(null);
  const jitterBufferRef = useRef<JitterBufferManager | null>(null);
  const audioGateRef = useRef<AudioContextGate | null>(null);
  const knownSendersRef = useRef<Set<string>>(new Set());
  const localIdRef = useRef<string>("");
  const drainTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const voiceRetryTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

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

      startMicPipeline({
        getUserMedia: (c) => navigator.mediaDevices.getUserMedia(c),
        makeProcessor,
        AudioEncoderCtor: AudioEncoder as never,
        sendVoiceFrame: (bytes) => voice.sendOpusFrame(bytes),
        isMuted: () => useMoqtChatStore.getState().muted,
        onError: () => setMicError("microphone permission was denied"),
        onEncodeError: () => setMicError("microphone audio could not be encoded"),
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

      const client = new MoqtChatClient(localId, {
        ...moqtChatCallbacks(store),
        onUnknownUniStream: (header, firstChunkTail, reader) =>
          voiceRef.current?.handleIncomingStream(header, firstChunkTail, reader),
      });
      clientRef.current = client;

      registerPageLifecycleCleanup({
        closeTransport: () => client.close(),
        getMicTracks: () => [],
      });

      try {
        await client.connect(url, certHashesHex);
        await startVoice(localId, client);
      } catch {
        // Connection failed (e.g. cert hash mismatch): fall back to
        // disconnected instead of leaving the join screen stuck on
        // "Connecting..." forever.
        store.setConnectionState("disconnected");
      }
    },
    [store, startVoice],
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

  const leave = useCallback(() => {
    if (drainTimerRef.current !== null) {
      clearTimeout(drainTimerRef.current);
      drainTimerRef.current = null;
    }
    if (voiceRetryTimerRef.current !== null) {
      clearInterval(voiceRetryTimerRef.current);
      voiceRetryTimerRef.current = null;
    }
    micRef.current?.stop();
    micRef.current = null;
    voiceRef.current?.close();
    voiceRef.current = null;
    receivePipelineRef.current = null;
    knownSendersRef.current.clear();
    clientRef.current?.close();
    clientRef.current = null;
    setMicError(null);
    store.setConnectionState("disconnected");
    store.clearPeers();
    store.clearMessages();
  }, [store]);

  return { connect, sendChat, toggleMute, leave, micError };
}
