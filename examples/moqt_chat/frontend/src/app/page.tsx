"use client";

import { useEffect, useRef, useState } from "react";
import { useMoqtChat } from "@/hooks/useMoqtChat";
import { clearJoinPrefs, loadJoinPrefs, saveJoinPrefs } from "@/lib/joinPrefs";
import { CANDIDATE_PARTICIPANT_IDS } from "@/lib/moqtClient";
import { resolveDisplayName, useMoqtChatStore, type ChatMessage } from "@/stores/moqtChatStore";
import { canPickOutput } from "@/lib/outputMixer";
import { SCREEN_TILE_MAX_PX, SCREEN_TILE_MIN_PX, SCREEN_TILE_STEP_PX } from "@/lib/screenTileSize";
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
  const stalledScreenTiles = useMoqtChatStore((s) => s.stalledScreenTiles);
  const screenTileWidth = useMoqtChatStore((s) => s.screenTileWidth);
  const nicknames = useMoqtChatStore((s) => s.nicknames);
  const maximized = useMoqtChatStore((s) => s.maximizedScreenTile);
  const setMaximized = useMoqtChatStore((s) => s.setMaximizedScreenTile);
  // Esc (or the browser's own exit) leaves fullscreen without going
  // through the button, so follow the document's state, not the click.
  useEffect(() => {
    const onChange = () => {
      if (!document.fullscreenElement) setMaximized(null);
    };
    document.addEventListener("fullscreenchange", onChange);
    return () => document.removeEventListener("fullscreenchange", onChange);
  }, [setMaximized]);
  const toggleMaximize = (id: string, canvas: HTMLCanvasElement | null) => {
    if (maximized === id) {
      if (document.fullscreenElement) void document.exitFullscreen().catch(() => {});
      setMaximized(null);
      return;
    }
    setMaximized(id);
    // Without the Fullscreen API the .screen-tile--max class (full width)
    // stands in.
    if (canvas?.requestFullscreen) void canvas.requestFullscreen().catch(() => {});
  };
  if (screenTiles.length === 0 && !screenSharing) return null;
  return (
    <div className="screens" style={{ "--tile-w": `${screenTileWidth}px` } as React.CSSProperties}>
      {screenSharing && (
        <div className="screen-own-wrap">
          <canvas
            ref={(el) => registerScreenCanvas("own", el)}
            className="screen-own"
            data-testid="screen-tile-own"
            width={160}
            height={90}
          />
          {stalledScreenTiles.own && (
            <span className="caption" data-testid="screen-stalled-own">
              画面共有が停止しているようです。一度停止してから再度共有してください
            </span>
          )}
        </div>
      )}
      {screenTiles
        .filter((id) => id !== "own")
        .map((id) => (
          <div key={id} className={maximized === id ? "screen-tile screen-tile--max" : "screen-tile"}>
            <canvas
              ref={(el) => registerScreenCanvas(id, el)}
              data-testid={`screen-tile-${id}`}
              width={320}
              height={180}
            />
            <div className="screen-tile__bar">
              <span className="caption">{resolveDisplayName(id, nicknames)}</span>
              {stalledScreenTiles[id] && (
                <span className="caption" data-testid={`screen-stalled-${id}`}>
                  Stalled
                </span>
              )}
              <button
                type="button"
                className="sign sign--outline sign--small"
                data-testid={`screen-maximize-${id}`}
                onClick={(e) =>
                  toggleMaximize(id, e.currentTarget.closest(".screen-tile")?.querySelector("canvas") ?? null)
                }
              >
                {maximized === id ? "Restore ↙" : "Maximize ↗"}
              </button>
            </div>
          </div>
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
  const nicknames = useMoqtChatStore((s) => s.nicknames);
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
            {resolveDisplayName(p, nicknames)}
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
  const nicknames = useMoqtChatStore((s) => s.nicknames);
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
          <span className="volume__label">{resolveDisplayName(p, nicknames)}</span>
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

function ScreenTileWidth() {
  const width = useMoqtChatStore((s) => s.screenTileWidth);
  const setWidth = useMoqtChatStore((s) => s.setScreenTileWidth);
  return (
    <section>
      <h2>Screens</h2>
      <label className="volume">
        <span className="volume__label">Tile width</span>
        <input
          type="range"
          min={SCREEN_TILE_MIN_PX}
          max={SCREEN_TILE_MAX_PX}
          step={SCREEN_TILE_STEP_PX}
          value={width}
          data-testid="screen-tile-width"
          onChange={(e) => setWidth(Number(e.target.value))}
        />
      </label>
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
  const nicknames = useMoqtChatStore((s) => s.nicknames);
  const time = new Date(m.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  // The Blob URL is created once in onImage (useMoqtChat.ts) and belongs to
  // this message instance for its whole lifetime, so revoke it on unmount
  // only -- capture the value the effect closed over, not a fresh read of m.
  useEffect(() => {
    const url = m.imageDataUrl;
    if (!url) return;
    return () => URL.revokeObjectURL(url);
  }, [m.imageDataUrl]);
  // DOM order is sender, time, text (the grid puts the time last): the e2e
  // load harness matches "msg:<tag>:<seq>" in textContent, and a time
  // directly after the text would extend the digits.
  return (
    <div className="message" data-testid="message" data-sender={m.senderId}>
      <span className={m.own ? "message__sender you" : "message__sender"}>
        {m.own ? "You" : resolveDisplayName(m.senderId, nicknames)}
      </span>
      <span className="message__time caption">{time}</span>
      {m.imageDataUrl ? (
        <img src={m.imageDataUrl} data-testid="message-image" alt="" />
      ) : (
        <span className="message__text">{m.text}</span>
      )}
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

const IMAGE_MAX_BYTES = 5 * 1024 * 1024;

function Compose({
  onSend,
  onSendImage,
  onImageTooLarge,
  disabled,
}: {
  onSend: (text: string) => void;
  onSendImage: (bytes: Uint8Array, mimeType: string) => void;
  onImageTooLarge: () => void;
  disabled: boolean;
}) {
  const [draft, setDraft] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const submit = () => {
    const text = draft.trim();
    if (!text) return;
    onSend(text);
    setDraft("");
  };
  const pickImage = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (bytes.byteLength > IMAGE_MAX_BYTES) {
      onImageTooLarge();
      return;
    }
    onSendImage(bytes, file.type);
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
      <input
        type="file"
        accept="image/*"
        data-testid="image-file"
        hidden
        ref={fileInputRef}
        onChange={(e) => void pickImage(e)}
      />
      <button
        type="button"
        className="sign sign--outline"
        disabled={disabled}
        onClick={() => fileInputRef.current?.click()}
      >
        📎
      </button>
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
  nickname,
  setNickname,
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
  nickname: string;
  setNickname: (v: string) => void;
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
        <label className="field">
          <span className="field__label">Nickname (optional)</span>
          <input
            placeholder="Shown instead of your participant id"
            value={nickname}
            data-testid="nickname"
            onChange={(e) => setNickname(e.target.value)}
          />
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
  const [nickname, setNickname] = useState("");
  const [participantId, setParticipantId] = useState(DEFAULT_PARTICIPANT_ID);
  const [joined, setJoined] = useState(false);
  const {
    connect,
    sendChat,
    sendImage,
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
  const screenShareError = useMoqtChatStore((s) => s.screenShareError);
  const imageSendError = useMoqtChatStore((s) => s.imageSendError);

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
      if (saved.nickname) setNickname(saved.nickname);
    }, 0);
    return () => window.clearTimeout(t);
  }, []);

  const clearSaved = () => {
    clearJoinPrefs();
    setUrl(DEFAULT_URL);
    setCertHash("");
    setNickname("");
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
          onClick={() => void connect(url, participantId, certHash ? [certHash] : [], nickname)}
        >
          → Rejoin
        </button>
      </Notice>
      <Notice message={micError} />
      {/* Also shown inside ScreenTiles while a tile is on screen; repeated
          here so the message survives an auto-stop that removed the last
          tile (own's auto-stop clears screenSharing and its own tile,
          which can make ScreenTiles render nothing at all). */}
      <Notice message={screenShareError} />
      <Notice message={imageSendError} />

      {joined ? (
        <div className="room">
          <aside className="rail">
            <Peers />
            <Volume />
            <ScreenTileWidth />
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
            <Compose
              onSend={sendChat}
              onSendImage={sendImage}
              onImageTooLarge={() =>
                useMoqtChatStore.getState().setImageSendError("image too large (max 5MB)")
              }
              disabled={connectionState !== "connected"}
            />
          </section>
        </div>
      ) : (
        <JoinScreen
          url={url}
          setUrl={setUrl}
          certHash={certHash}
          setCertHash={setCertHash}
          nickname={nickname}
          setNickname={setNickname}
          participantId={participantId}
          setParticipantId={setParticipantId}
          connecting={connecting}
          onJoin={() => {
            saveJoinPrefs({ url, certHash, name: participantId, nickname });
            void connect(url, participantId, certHash ? [certHash] : [], nickname);
          }}
          onClearSaved={clearSaved}
        />
      )}
      <footer className="folio">MOQT Chat · wired</footer>
    </main>
  );
}
