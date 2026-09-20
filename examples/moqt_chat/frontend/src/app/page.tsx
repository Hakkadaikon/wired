"use client";

import { useEffect, useRef, useState } from "react";
import { useMoqtChat } from "@/hooks/useMoqtChat";
import { clearJoinPrefs, loadJoinPrefs, saveJoinPrefs } from "@/lib/joinPrefs";
import { CANDIDATE_PARTICIPANT_IDS } from "@/lib/moqtClient";
import { useMoqtChatStore, type ChatMessage } from "@/stores/moqtChatStore";
import { canPickOutput } from "@/lib/outputMixer";
import { Wordmark } from "./wordmark";

const DEFAULT_URL = "https://localhost:4433/";
const DEFAULT_PARTICIPANT_ID = CANDIDATE_PARTICIPANT_IDS[0];

const STATUS_LABEL: Record<string, string> = {
  connecting: "Connecting",
  connected: "Connected",
  disconnected: "Disconnected",
};

function Status() {
  const connectionState = useMoqtChatStore((s) => s.connectionState);
  return (
    <div className="status">
      <span className="status__block" data-testid="status" data-status={connectionState} />
      <span>{STATUS_LABEL[connectionState]}</span>
    </div>
  );
}

function MicToggle({ onToggleMute }: { onToggleMute: () => void }) {
  const muted = useMoqtChatStore((s) => s.muted);
  return (
    <button
      type="button"
      className={muted ? "sign sign--outline" : "sign"}
      data-testid="mic-toggle"
      onClick={onToggleMute}
    >
      {muted ? "Mic off" : "Mic on"}
    </button>
  );
}

function NoiseSuppressionToggle() {
  const enabled = useMoqtChatStore((s) => s.noiseSuppressionEnabled);
  const setNoiseSuppressionEnabled = useMoqtChatStore((s) => s.setNoiseSuppressionEnabled);
  return (
    <button
      type="button"
      className={enabled ? "sign" : "sign sign--outline"}
      data-testid="ns-toggle"
      onClick={() => setNoiseSuppressionEnabled(!enabled)}
    >
      {enabled ? "NS on" : "NS off"}
    </button>
  );
}

function ScreenShareToggle({
  sharing,
  onStart,
  onStop,
}: {
  sharing: boolean;
  onStart: () => void;
  onStop: () => void;
}) {
  return (
    <button
      type="button"
      className={sharing ? "sign sign--outline" : "sign"}
      data-testid="screen-toggle"
      onClick={sharing ? onStop : onStart}
    >
      {sharing ? "Stop sharing" : "Share screen"}
    </button>
  );
}

function ScreenTiles({
  registerScreenCanvas,
}: {
  registerScreenCanvas: (id: string, el: HTMLCanvasElement | null) => void;
}) {
  const screenTiles = useMoqtChatStore((s) => s.screenTiles);
  const screenSharing = useMoqtChatStore((s) => s.screenSharing);
  const screenShareError = useMoqtChatStore((s) => s.screenShareError);
  if (screenTiles.length === 0 && !screenSharing) return null;
  return (
    <div className="screens">
      {screenSharing && (
        <canvas
          ref={(el) => registerScreenCanvas("own", el)}
          data-testid="screen-tile-own"
          width={160}
          height={90}
        />
      )}
      {screenTiles
        .filter((id) => id !== "own")
        .map((id) => (
          <canvas
            key={id}
            ref={(el) => registerScreenCanvas(id, el)}
            data-testid={`screen-tile-${id}`}
            width={320}
            height={180}
          />
        ))}
      <Notice message={screenShareError} />
    </div>
  );
}

/** Warning-sign panel: black panel, optional bold heading, light body. */
function Notice({
  title,
  message,
  children,
}: {
  title?: string;
  message: string | null;
  children?: React.ReactNode;
}) {
  if (!message) return null;
  return (
    <div className="notice" role="alert">
      <p>
        {title && <strong>{title}</strong>}
        {message}
      </p>
      {children}
    </div>
  );
}

function Peers() {
  const peers = useMoqtChatStore((s) => s.peers);
  const voiceQuality = useMoqtChatStore((s) => s.voiceQuality);
  const speaking = useMoqtChatStore((s) => s.speaking);
  const localSpeaking = useMoqtChatStore((s) => s.localSpeaking);
  return (
    <section>
      <h2>Room</h2>
      <p className="caption">{peers.length + 1} in room</p>
      <ul className="peers">
        <li className="you">
          You
          <span
            className="status__block"
            data-testid="speaking-you"
            data-speaking={localSpeaking || undefined}
          />
        </li>
        {peers.map((p) => (
          <li key={p}>
            {p}
            <span
              className="status__block"
              data-testid={`quality-${p}`}
              data-quality={voiceQuality[p] === "none" ? undefined : voiceQuality[p]}
              data-speaking={speaking[p] || undefined}
            />
          </li>
        ))}
      </ul>
      {peers.length === 0 && <p className="caption">Waiting for others…</p>}
    </section>
  );
}

function Volume() {
  const peers = useMoqtChatStore((s) => s.peers);
  const masterVolume = useMoqtChatStore((s) => s.masterVolume);
  const peerVolumes = useMoqtChatStore((s) => s.peerVolumes);
  const setMasterVolume = useMoqtChatStore((s) => s.setMasterVolume);
  const setPeerVolume = useMoqtChatStore((s) => s.setPeerVolume);
  return (
    <section>
      <h2>Volume</h2>
      <label className="volume">
        <span className="volume__label">Master</span>
        <input
          type="range"
          min={0}
          max={1}
          step={0.01}
          value={masterVolume}
          data-testid="master-volume"
          onChange={(e) => setMasterVolume(Number(e.target.value))}
        />
      </label>
      {peers.map((p) => (
        <label key={p} className="volume volume--peer">
          <span className="volume__label">{p}</span>
          <input
            type="range"
            min={0}
            max={1}
            step={0.01}
            value={peerVolumes[p] ?? 1}
            data-testid={`peer-volume-${p}`}
            onChange={(e) => setPeerVolume(p, Number(e.target.value))}
          />
        </label>
      ))}
    </section>
  );
}

function OutputDevice({ onSelect }: { onSelect: (deviceId: string) => void }) {
  const [devices, setDevices] = useState<MediaDeviceInfo[]>([]);
  useEffect(() => {
    const AudioContextCtor = window.AudioContext as unknown as {
      prototype: { setSinkId?: unknown };
    };
    if (!canPickOutput(AudioContextCtor.prototype)) return;
    navigator.mediaDevices
      .enumerateDevices()
      .then((all) => setDevices(all.filter((d) => d.kind === "audiooutput")))
      .catch(() => {});
  }, []);
  if (devices.length === 0) return null;
  return (
    <section>
      <h2>Output</h2>
      <select
        data-testid="output-device"
        onChange={(e) => onSelect(e.target.value)}
        defaultValue=""
      >
        <option value="" disabled>
          Default
        </option>
        {devices.map((d) => (
          <option key={d.deviceId} value={d.deviceId}>
            {d.label || d.deviceId}
          </option>
        ))}
      </select>
    </section>
  );
}

function Message({ m }: { m: ChatMessage }) {
  const time = new Date(m.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  // DOM order is sender, time, text (the grid puts the time last): the e2e
  // load harness matches "msg:<tag>:<seq>" in textContent, and a time
  // directly after the text would extend the digits.
  return (
    <div className="message" data-testid="message" data-sender={m.senderId}>
      <span className={m.own ? "message__sender you" : "message__sender"}>
        {m.own ? "You" : m.senderId}
      </span>
      <span className="message__time caption">{time}</span>
      <span className="message__text">{m.text}</span>
      {m.failed && <span className="message__failed caption">Not sent</span>}
    </div>
  );
}

function LivePlayer({ videoRef }: { videoRef: React.RefObject<HTMLVideoElement | null> }) {
  const liveError = useMoqtChatStore((s) => s.liveError);
  const liveFirstGroup = useMoqtChatStore((s) => s.liveFirstGroup);
  // Distinguishes "not playing yet" (caption) from "playing" (no caption)
  // and from a real failure (liveError banner). LiveMovie holds play() back
  // until enough is buffered, so wait for actual playback, not readiness.
  const [waiting, setWaiting] = useState(true);
  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;
    const ready = () => setWaiting(false);
    video.addEventListener("playing", ready);
    return () => video.removeEventListener("playing", ready);
  }, [videoRef]);
  return (
    <>
      <video
        ref={videoRef}
        className="live"
        data-testid="live"
        data-first-group={liveFirstGroup ?? undefined}
        muted
        playsInline
        controls
      />
      <Notice message={liveError} />
      {!liveError && waiting && <p className="caption">Waiting for the movie stream…</p>}
    </>
  );
}

function MessageList() {
  const messages = useMoqtChatStore((s) => s.messages);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = listRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages.length]);

  return (
    <div ref={listRef} className="messages" data-testid="messages">
      {messages.length === 0 && <span className="caption">No messages yet</span>}
      {messages.map((m) => (
        <Message key={m.id} m={m} />
      ))}
    </div>
  );
}

function Compose({ onSend, disabled }: { onSend: (text: string) => void; disabled: boolean }) {
  const [draft, setDraft] = useState("");
  const submit = () => {
    const text = draft.trim();
    if (!text) return;
    onSend(text);
    setDraft("");
  };
  // Enter is handled on keydown rather than via a <form>: the e2e load
  // harness dispatches a synthetic keydown, which never submits a form.
  return (
    <div className="compose" data-testid="chat-form">
      <input
        name="chat-message"
        placeholder="Type a message"
        value={draft}
        disabled={disabled}
        data-testid="text"
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") submit();
        }}
      />
      <button type="button" className="sign" disabled={disabled} onClick={submit}>
        Send →
      </button>
    </div>
  );
}

function JoinScreen({
  url,
  setUrl,
  certHash,
  setCertHash,
  participantId,
  setParticipantId,
  connecting,
  onJoin,
  onClearSaved,
}: {
  url: string;
  setUrl: (v: string) => void;
  certHash: string;
  setCertHash: (v: string) => void;
  participantId: string;
  setParticipantId: (v: string) => void;
  connecting: boolean;
  onJoin: () => void;
  onClearSaved: () => void;
}) {
  return (
    <div className="cover">
      <div>
        <h1>Join the room</h1>
        <p className="cover__lede">
          Voice, a live movie track, screen sharing and text over one MOQT session. Pick a participant
          id and connect to the hub.
        </p>
      </div>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          if (!connecting) onJoin();
        }}
      >
        <label className="field">
          <span className="field__label">Server URL</span>
          <input
            placeholder={DEFAULT_URL}
            value={url}
            data-testid="url"
            onChange={(e) => setUrl(e.target.value)}
          />
        </label>
        <label className="field">
          <span className="field__label">Certificate hash (SHA-256)</span>
          <input
            placeholder="hex fingerprint"
            value={certHash}
            data-testid="certHash"
            onChange={(e) => setCertHash(e.target.value)}
          />
          <span className="field__hint caption">
            Copy it from the server&apos;s startup log. Leave empty for a CA-signed certificate.
          </span>
        </label>
        <div className="field">
          <span className="field__label">Participant ID</span>
          <div className="tiles" data-testid="author">
            {CANDIDATE_PARTICIPANT_IDS.map((id) => (
              <button
                key={id}
                type="button"
                className="tile"
                aria-pressed={id === participantId}
                data-testid={`participant-${id}`}
                onClick={() => setParticipantId(id)}
              >
                {id}
              </button>
            ))}
          </div>
        </div>
        <button type="submit" className="sign sign--red" disabled={connecting} data-testid="connect">
          {connecting ? "Connecting…" : "→ Join"}
        </button>
        <button type="button" className="link" onClick={onClearSaved}>
          Clear saved info
        </button>
      </form>
      <div className="cover__mark">
        <Wordmark height="6em" />
      </div>
    </div>
  );
}

export default function Home() {
  const [url, setUrl] = useState(DEFAULT_URL);
  const [certHash, setCertHash] = useState("");
  const [participantId, setParticipantId] = useState(DEFAULT_PARTICIPANT_ID);
  const [joined, setJoined] = useState(false);
  const {
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
  } = useMoqtChat();
  const connectionState = useMoqtChatStore((s) => s.connectionState);
  const screenSharing = useMoqtChatStore((s) => s.screenSharing);

  // Switch to the chat screen once the connection is established.
  useEffect(
    () =>
      useMoqtChatStore.subscribe((s) => {
        if (s.connectionState === "connected") setJoined(true);
      }),
    [],
  );

  // Restore the join form from the last visit. Deferred a tick, not in the
  // initial state: the page is statically prerendered (no localStorage until
  // hydration), and a synchronous setState inside the effect would both
  // trip the react-hooks rule and risk a hydration mismatch.
  useEffect(() => {
    const t = window.setTimeout(() => {
      const saved = loadJoinPrefs();
      if (!saved) return;
      setUrl(saved.url);
      setCertHash(saved.certHash);
      if (saved.name) setParticipantId(saved.name);
    }, 0);
    return () => window.clearTimeout(t);
  }, []);

  const clearSaved = () => {
    clearJoinPrefs();
    setUrl(DEFAULT_URL);
    setCertHash("");
    setParticipantId(DEFAULT_PARTICIPANT_ID);
  };

  const connecting = connectionState === "connecting";
  const lost = joined && connectionState === "disconnected";

  return (
    <main className={joined ? "page page--room" : "page"}>
      <header className="masthead">
        <div className="masthead__brand">
          <Wordmark height="1.6em" />
          <span className="masthead__stem">Chat</span>
        </div>
        {joined ? (
          <div className="masthead__tools">
            <MicToggle onToggleMute={toggleMute} />
            <NoiseSuppressionToggle />
            <ScreenShareToggle
              sharing={screenSharing}
              onStart={() => void startScreenShare()}
              onStop={stopScreenShare}
            />
            <button
              type="button"
              className="sign sign--outline"
              onClick={() => {
                leave();
                setJoined(false);
              }}
            >
              ← Leave
            </button>
          </div>
        ) : (
          <p className="masthead__id">
            Media over QUIC Transport
            <br />
            draft-ietf-moq-transport-19
          </p>
        )}
      </header>
      <hr className="rule" />

      <Notice title="Connection lost" message={lost ? "The session to the hub was closed." : null}>
        <button
          type="button"
          className="sign sign--outline"
          onClick={() => void connect(url, participantId, certHash ? [certHash] : [])}
        >
          → Rejoin
        </button>
      </Notice>
      <Notice message={micError} />

      {joined ? (
        <div className="room">
          <aside className="rail">
            <Peers />
            <Volume />
            <OutputDevice onSelect={setOutputDevice} />
            <section>
              <h2>Status</h2>
              <Status />
            </section>
          </aside>
          <section className="body">
            <LivePlayer videoRef={videoRef} />
            <ScreenTiles registerScreenCanvas={registerScreenCanvas} />
            <MessageList />
            <Compose onSend={sendChat} disabled={connectionState !== "connected"} />
          </section>
        </div>
      ) : (
        <JoinScreen
          url={url}
          setUrl={setUrl}
          certHash={certHash}
          setCertHash={setCertHash}
          participantId={participantId}
          setParticipantId={setParticipantId}
          connecting={connecting}
          onJoin={() => {
            saveJoinPrefs({ url, certHash, name: participantId });
            void connect(url, participantId, certHash ? [certHash] : []);
          }}
          onClearSaved={clearSaved}
        />
      )}
      <footer className="folio">MOQT Chat · wired</footer>
    </main>
  );
}
