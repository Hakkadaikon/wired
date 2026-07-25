"use client";

// Glue layer: wires the browser WebTransport/WebCodecs/getUserMedia APIs to
// the lib-layer pipelines and mirrors their outcomes into voiceChatStore.
// UI components read/write only the store; all transport/pipeline objects
// live in refs here, never in component state.
//
// Chat and voice share the one DATAGRAM channel, multiplexed by the leading
// byte (voiceProtocol.ts) — the server relays datagrams only and accepts no
// bidirectional streams, so chat rides datagrams too.

import { useCallback, useRef, useState } from "react";
import { WebTransportClient } from "@/lib/webtransportClient";
import { startMicPipeline, type MicPipeline } from "@/lib/micPipeline";
import { createVoiceReceivePipeline } from "@/lib/voiceReceivePipeline";
import { createAudioContextGate } from "@/lib/audioContextGate";
import { createReconnectFlow, type ReconnectFlow } from "@/lib/reconnectFlow";
import { registerPageLifecycleCleanup } from "@/lib/pageLifecycle";
import { decodeFrame, encodeChatFrame, generateSenderId } from "@/lib/voiceProtocol";
import { parseCertHash } from "@/lib/certHash";
import { JitterBufferManager } from "@/lib/jitterBuffer";
import { senderIdKey } from "@/lib/voiceReceivePipeline";
import { useVoiceChatStore } from "@/stores/voiceChatStore";

const JITTER_BUFFER_CAPACITY = 8;
const DRAIN_INTERVAL_MS = 20;

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

// WebTransportClient's TransportLike wants `closed: Promise<void>`, but the
// real API resolves it with a WebTransportCloseInfo -- adapt the shape here
// while keeping the real WebTransport reachable via `.raw` for datagram
// access.
type TransportHandle = {
  raw: WebTransport;
  ready: Promise<void>;
  closed: Promise<void>;
  close: () => void;
};

function makeTransportHandle(url: string, certHash: Uint8Array | null): TransportHandle {
  // The server's self-signed certificate fails normal CA validation, so pin
  // it via serverCertificateHashes when a fingerprint was provided.
  const raw = certHash
    ? new WebTransport(url, {
        serverCertificateHashes: [{ algorithm: "sha-256", value: certHash as BufferSource }],
      })
    : new WebTransport(url);
  return {
    raw,
    ready: raw.ready,
    closed: raw.closed.then(() => undefined),
    close: () => raw.close(),
  };
}

// voiceReceivePipeline hands the decoder raw Opus payloads; the real
// AudioDecoder wants EncodedAudioChunk, so wrap each payload here with a
// running timestamp (one 20 ms Opus frame per chunk).
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

// Renders decoded AudioData seamlessly: each frame becomes an AudioBuffer
// scheduled right after the previous one on a running playhead.
function makePlaybackSink(ctx: AudioContext): (frame: unknown) => void {
  let playhead = 0;
  return (frame) => {
    const audio = frame as AudioData;
    const buf = ctx.createBuffer(audio.numberOfChannels, audio.numberOfFrames, audio.sampleRate);
    for (let ch = 0; ch < audio.numberOfChannels; ch++) {
      const data = new Float32Array(audio.numberOfFrames);
      audio.copyTo(data, { planeIndex: ch, format: "f32-planar" });
      buf.copyToChannel(data, ch);
    }
    audio.close();
    const src = ctx.createBufferSource();
    src.buffer = buf;
    src.connect(ctx.destination);
    playhead = Math.max(playhead, ctx.currentTime);
    src.start(playhead);
    playhead += buf.duration;
  };
}

async function sendDatagram(transport: WebTransport, bytes: Uint8Array): Promise<void> {
  const writer = transport.datagrams.writable.getWriter();
  try {
    await writer.write(bytes);
  } finally {
    writer.releaseLock();
  }
}

async function readDatagrams(
  transport: WebTransport,
  onDatagram: (bytes: Uint8Array) => void,
): Promise<void> {
  const reader = transport.datagrams.readable.getReader();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    if (value) onDatagram(value);
  }
}

export function useVoiceChat() {
  const store = useVoiceChatStore();
  const [fatalError, setFatalError] = useState<string | null>(null);
  const [micError, setMicError] = useState<string | null>(null);

  const transportRef = useRef<WebTransport | null>(null);
  const micRef = useRef<MicPipeline | null>(null);
  const receivePipelineRef = useRef<ReturnType<typeof createVoiceReceivePipeline> | null>(null);
  const jitterBufferRef = useRef<JitterBufferManager | null>(null);
  const audioGateRef = useRef<ReturnType<typeof createAudioContextGate> | null>(null);
  const knownSendersRef = useRef<Set<string>>(new Set());
  const ownSenderKeysRef = useRef<Set<string>>(new Set());
  const senderIdRef = useRef<Uint8Array | null>(null);
  const drainStartedRef = useRef(false);

  const startDrainLoop = useCallback(() => {
    if (drainStartedRef.current) return;
    drainStartedRef.current = true;
    const tick = () => {
      const pipeline = receivePipelineRef.current;
      if (pipeline) {
        for (const key of knownSendersRef.current) pipeline.drainAndDecode(key);
      }
      window.setTimeout(tick, DRAIN_INTERVAL_MS);
    };
    tick();
  }, []);

  const handleDatagram = useCallback(
    (bytes: Uint8Array) => {
      const decoded = decodeFrame(bytes);
      if (!decoded.ok) return;
      if (decoded.frame.channel === "chat") {
        const key = senderIdKey(decoded.frame.senderId);
        // The server broadcast echoes our own datagrams back; the local copy
        // was already added on send.
        if (!ownSenderKeysRef.current.has(key)) {
          store.addMessage({ senderId: key, text: decoded.frame.text, at: Date.now(), own: false });
          store.addPeer(key);
        }
        return;
      }
      // Voice self-echo is filtered inside the jitter buffer, which remembers
      // every own sender id across reconnects.
      const voiceKey = senderIdKey(decoded.frame.senderId);
      if (!ownSenderKeysRef.current.has(voiceKey)) store.addPeer(voiceKey);
      knownSendersRef.current.add(voiceKey);
      receivePipelineRef.current?.handleDatagram(bytes);
    },
    [store],
  );

  // (Re)binds every pipeline to a live transport: called on the first connect
  // and again on each successful reconnect, where transport and sender id are
  // both new.
  const attachTransport = useCallback(
    (transport: WebTransport, senderId: Uint8Array) => {
      transportRef.current = transport;
      senderIdRef.current = senderId;
      ownSenderKeysRef.current.add(senderIdKey(senderId));

      const audioGate = audioGateRef.current;
      const jitterBuffer = jitterBufferRef.current;
      if (!audioGate || !jitterBuffer) return;

      receivePipelineRef.current = createVoiceReceivePipeline({
        jitterBuffer,
        AudioDecoderCtor: OpusChunkDecoder as never,
        enqueuePlayback: (frame) => audioGate.enqueue(frame),
      });
      readDatagrams(transport, handleDatagram).catch(() => {});
      startDrainLoop();

      micRef.current?.stop();
      startMicPipeline({
        getUserMedia: (c) => navigator.mediaDevices.getUserMedia(c),
        makeProcessor,
        AudioEncoderCtor: AudioEncoder as never,
        sendDatagram: (bytes) => sendDatagram(transport, bytes),
        isMuted: () => useVoiceChatStore.getState().muted,
        senderId,
        onError: () => setMicError("microphone permission was denied"),
        onEncodeError: () => setMicError("microphone audio could not be encoded"),
      })
        .then((mic) => {
          micRef.current = mic;
        })
        .catch(() => {});
    },
    [handleDatagram, startDrainLoop],
  );

  const connect = useCallback(
    async (url: string, certHashHex: string) => {
      const certHash = parseCertHash(certHashHex);
      setFatalError(null);
      setMicError(null);
      store.clearPeers();
      store.setConnectionState("connecting");

      const audioCtx = new AudioContext();
      const audioGate = createAudioContextGate(
        () => audioCtx as unknown as { state: "suspended" | "running" | "closed"; resume: () => Promise<void> },
        {
          onResumeFailed: () => setMicError("audio playback permission was blocked by the browser"),
          play: makePlaybackSink(audioCtx),
        },
      );
      audioGateRef.current = audioGate;
      await audioGate.resumeFromUserGesture();

      const senderId = generateSenderId();
      jitterBufferRef.current = new JitterBufferManager(
        senderIdKey(senderId),
        JITTER_BUFFER_CAPACITY,
      );

      let flow: ReconnectFlow | null = null;
      const onDisconnected = () => {
        store.setConnectionState("disconnected");
        store.setReconnecting(true);
        void flow
          ?.reconnectWithBackoff()
          .finally(() => store.setReconnecting(false));
      };

      flow = createReconnectFlow<TransportHandle, void>({
        makeTransport: () => makeTransportHandle(url, certHash),
        openBidiStream: async (handle) => {
          if (!flow) return;
          attachTransport(handle.raw, flow.senderId);
          store.setConnectionState("established");
          handle.closed.then(onDisconnected, onDisconnected);
        },
        jitterBuffer: jitterBufferRef.current,
        initialSenderId: senderId,
        onGiveUp: () => setFatalError("reconnection failed after 5 attempts; please rejoin manually"),
      });

      const client = new WebTransportClient<TransportHandle>(
        () => makeTransportHandle(url, certHash),
        {
          onError: () => setFatalError("could not establish the connection"),
          onDisconnect: onDisconnected,
        },
      );

      await client.connect();
      if (client.state !== "established" || !client.transport) return;
      store.setConnectionState("established");
      attachTransport(client.transport.raw, senderId);

      registerPageLifecycleCleanup({
        closeTransport: () => {
          transportRef.current?.close();
          micRef.current?.stop();
        },
        getMicTracks: () => [],
      });
    },
    [store, attachTransport],
  );

  const sendChat = useCallback(
    async (text: string) => {
      const senderId = senderIdRef.current;
      const transport = transportRef.current;
      if (!senderId || !transport) return;
      const encoded = encodeChatFrame(senderId, text);
      if (!encoded.ok) {
        setFatalError("message could not be sent");
        return;
      }
      try {
        await sendDatagram(transport, encoded.bytes);
        store.addMessage({ senderId: senderIdKey(senderId), text, at: Date.now(), own: true });
      } catch {
        setFatalError("message could not be sent");
      }
    },
    [store],
  );

  const toggleMute = useCallback(() => {
    store.setMuted(!store.muted);
  }, [store]);

  return { connect, sendChat, toggleMute, fatalError, micError };
}
