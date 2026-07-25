"use client";

// Glue layer: wires the browser WebTransport/WebCodecs/getUserMedia APIs to
// the lib-layer pipelines and mirrors their outcomes into voiceChatStore.
// UI components read/write only the store; all transport/pipeline objects
// live in refs here, never in component state.

import { useCallback, useRef, useState } from "react";
import { WebTransportClient } from "@/lib/webtransportClient";
import { openChatChannel, type ChatChannel } from "@/lib/chatChannel";
import { startMicPipeline, type MicPipeline } from "@/lib/micPipeline";
import { createVoiceReceivePipeline } from "@/lib/voiceReceivePipeline";
import { createAudioContextGate } from "@/lib/audioContextGate";
import { createReconnectFlow } from "@/lib/reconnectFlow";
import { registerPageLifecycleCleanup } from "@/lib/pageLifecycle";
import { decodeFrame, generateSenderId } from "@/lib/voiceProtocol";
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
// while keeping the real WebTransport reachable via `.raw` for datagram/bidi
// stream access.
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
  onVoiceDatagram: (bytes: Uint8Array) => void,
): Promise<void> {
  const reader = transport.datagrams.readable.getReader();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    if (value) onVoiceDatagram(value);
  }
}

async function openBidiChat(
  transport: WebTransport,
  onMessage: (msg: { senderId: string; text: string }) => void,
  onSendUnavailable: () => void,
): Promise<ChatChannel> {
  const stream = await transport.createBidirectionalStream();
  return openChatChannel(stream as never, {
    onMessage: (msg) => onMessage(msg as { senderId: string; text: string }),
    onError: () => {},
    onSendUnavailable,
  });
}

export function useVoiceChat() {
  const store = useVoiceChatStore();
  const [fatalError, setFatalError] = useState<string | null>(null);
  const [micError, setMicError] = useState<string | null>(null);

  const chatChannelRef = useRef<ChatChannel | null>(null);
  const micRef = useRef<MicPipeline | null>(null);
  const receivePipelineRef = useRef<ReturnType<typeof createVoiceReceivePipeline> | null>(null);
  const knownSendersRef = useRef<Set<string>>(new Set());
  const senderIdRef = useRef<string>("");

  const startDrainLoop = useCallback(() => {
    const tick = () => {
      const pipeline = receivePipelineRef.current;
      if (pipeline) {
        for (const key of knownSendersRef.current) pipeline.drainAndDecode(key);
      }
      window.setTimeout(tick, DRAIN_INTERVAL_MS);
    };
    tick();
  }, []);

  const startVoice = useCallback(
    (
      transport: WebTransport,
      senderId: Uint8Array,
      audioGate: ReturnType<typeof createAudioContextGate>,
    ) => {
      const jitterBuffer = new JitterBufferManager(senderIdKey(senderId), JITTER_BUFFER_CAPACITY);
      const receivePipeline = createVoiceReceivePipeline({
        jitterBuffer,
        AudioDecoderCtor: AudioDecoder as never,
        enqueuePlayback: (frame) => audioGate.enqueue(frame),
      });
      receivePipelineRef.current = receivePipeline;

      void readDatagrams(transport, (bytes) => {
        const decoded = decodeFrame(bytes);
        if (decoded.ok && decoded.frame.channel === "voice") {
          knownSendersRef.current.add(senderIdKey(decoded.frame.senderId));
        }
        receivePipeline.handleDatagram(bytes);
      });
      startDrainLoop();

      startMicPipeline({
        getUserMedia: (c) => navigator.mediaDevices.getUserMedia(c),
        makeProcessor,
        AudioEncoderCtor: AudioEncoder as never,
        sendDatagram: (bytes) => sendDatagram(transport, bytes),
        isMuted: () => useVoiceChatStore.getState().muted,
        senderId,
        onError: () => setMicError("microphone permission was denied"),
      })
        .then((mic) => {
          micRef.current = mic;
        })
        .catch(() => {});
    },
    [startDrainLoop],
  );

  const connect = useCallback(
    async (url: string, certHashHex: string) => {
      const certHash = parseCertHash(certHashHex);
      setFatalError(null);
      setMicError(null);
      store.setConnectionState("connecting");

      const audioGate = createAudioContextGate(
        () => new AudioContext() as unknown as { state: "suspended" | "running" | "closed"; resume: () => Promise<void> },
        { onResumeFailed: () => setMicError("audio playback permission was blocked by the browser") },
      );
      await audioGate.resumeFromUserGesture();

      const senderId = generateSenderId();
      senderIdRef.current = senderIdKey(senderId);

      const client = new WebTransportClient<TransportHandle>(() => makeTransportHandle(url, certHash), {
        onError: () => setFatalError("could not establish the connection"),
        onDisconnect: () => {
          store.setConnectionState("disconnected");
          store.setReconnecting(true);
          void reconnectFlow.reconnectWithBackoff().finally(() => store.setReconnecting(false));
        },
      });

      const reconnectFlow = createReconnectFlow<TransportHandle, void>({
        makeTransport: () => makeTransportHandle(url, certHash),
        openBidiStream: async () => {
          const handle = client.transport;
          if (!handle) return;
          chatChannelRef.current = await openBidiChat(
            handle.raw,
            (msg) => store.addMessage(msg),
            () => setFatalError("chat is unavailable on this connection"),
          );
        },
        jitterBuffer: new JitterBufferManager(senderIdKey(senderId), JITTER_BUFFER_CAPACITY),
        initialSenderId: senderId,
        onGiveUp: () => setFatalError("reconnection failed after 5 attempts; please rejoin manually"),
      });

      await client.connect();
      if (client.state !== "established" || !client.transport) return;
      store.setConnectionState("established");

      const transport = client.transport.raw;
      chatChannelRef.current = await openBidiChat(
        transport,
        (msg) => store.addMessage(msg),
        () => setFatalError("chat is unavailable on this connection"),
      );
      startVoice(transport, senderId, audioGate);

      registerPageLifecycleCleanup({
        closeTransport: () => {
          client.transport?.close();
          micRef.current?.stop();
        },
        getMicTracks: () => [],
      });
    },
    [store, startVoice],
  );

  const sendChat = useCallback(
    async (text: string) => {
      const message = { senderId: senderIdRef.current, text };
      try {
        await chatChannelRef.current?.send(message);
        store.addMessage(message);
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
