"use client";

import { useEffect, useRef, useState } from "react";
import Card from "@/components/card";
import Text from "@/components/text";
import Button from "@/components/button";
import Badge from "@/components/badge";
import Row from "@/components/row";
import TextInput from "@/components/text-input";
import { useVoiceChat } from "@/hooks/useVoiceChat";
import { clearJoinPrefs, loadJoinPrefs, saveJoinPrefs } from "@/lib/joinPrefs";
import { useVoiceChatStore, type ChatMessage } from "@/stores/voiceChatStore";

const DEFAULT_URL = "https://localhost:4433/";

const STATUS_LABEL: Record<string, string> = {
  connecting: "Connecting",
  established: "Connected",
  disconnected: "Disconnected",
};

/** Stable per-sender hue so the same guest always gets the same label color. */
function senderHue(senderId: string): number {
  let h = 0;
  for (let i = 0; i < senderId.length; i++) h = (h * 31 + senderId.charCodeAt(i)) >>> 0;
  return h % 360;
}

/** Readable in both schemes: dark tone on light surfaces, light tone on dark. */
function senderColor(senderId: string): string {
  const hue = senderHue(senderId);
  return `light-dark(hsl(${hue}, 70%, 32%), hsl(${hue}, 70%, 72%))`;
}

const guestLabel = (senderId: string) => `Guest-${senderId.slice(0, 4)}`;

function StatusBadge() {
  const connectionState = useVoiceChatStore((s) => s.connectionState);
  const reconnecting = useVoiceChatStore((s) => s.reconnecting);
  const label = reconnecting ? "Reconnecting" : STATUS_LABEL[connectionState];
  const color =
    connectionState === "established" && !reconnecting
      ? "success"
      : connectionState === "disconnected" && !reconnecting
        ? "error"
        : "warning";
  return (
    <Row alignItems="center" gap="2xs">
      <Badge icon="wifi" color={color} scale="md" />
      <Text fontClass="label">{label}</Text>
    </Row>
  );
}

function MicToggle({ onToggleMute }: { onToggleMute: () => void }) {
  const muted = useVoiceChatStore((s) => s.muted);
  return (
    <Button
      label={muted ? "Mic off" : "Mic on"}
      startIcon={muted ? "mic-off" : "mic"}
      color={muted ? "surface" : "primary"}
      variant={muted ? "outline" : "fill"}
      size="sm"
      onClick={onToggleMute}
    />
  );
}

function Chip({ label, color }: { label: string; color?: string }) {
  return (
    <span
      className="caption"
      style={{
        padding: "0.15em 0.7em",
        borderRadius: "1em",
        border: "1px solid var(--lk-outlinevariant)",
        background: "var(--lk-surfacecontainer)",
        color: color ?? "var(--lk-onsurface)",
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </span>
  );
}

function PeerChips() {
  const peers = useVoiceChatStore((s) => s.peers);
  const peerNames = useVoiceChatStore((s) => s.peerNames);
  return (
    <Row alignItems="center" gap="2xs" wrapChildren style={{ padding: "var(--lk-size-2xs) 0" }}>
      <Text fontClass="caption" color="onsurfacevariant">
        {peers.length + 1} in room
      </Text>
      <Chip label="You" />
      {peers.map((p) => (
        <Chip key={p} label={peerNames[p] || guestLabel(p)} color={senderColor(p)} />
      ))}
      {peers.length === 0 && (
        <Text fontClass="caption" color="outline">
          Waiting for others…
        </Text>
      )}
    </Row>
  );
}

function MessageBubble({ m, onRetry }: { m: ChatMessage; onRetry: (id: number) => void }) {
  const peerName = useVoiceChatStore((s) => s.peerNames[m.senderId]);
  const time = new Date(m.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const label = m.own ? "You" : peerName || guestLabel(m.senderId);
  if (m.kind) {
    return (
      <div style={{ textAlign: "center", marginBottom: "var(--lk-size-2xs)" }}>
        <span className="caption" style={{ color: "var(--lk-onsurfacevariant)" }}>
          {`${m.name || guestLabel(m.senderId)} ${m.kind === "join" ? "joined" : "left"} · ${time}`}
        </span>
      </div>
    );
  }
  return (
    <div
      style={{
        display: "flex",
        justifyContent: m.own ? "flex-end" : "flex-start",
        marginBottom: "var(--lk-size-2xs)",
      }}
    >
      <div
        style={{
          maxWidth: "75%",
          padding: "var(--lk-size-2xs) var(--lk-size-xs)",
          borderRadius: "0.75em",
          background: m.own ? "var(--lk-primarycontainer)" : "var(--lk-surfacecontainerhigh)",
          color: m.own ? "var(--lk-onprimarycontainer)" : "var(--lk-onsurface)",
        }}
      >
        <div style={{ display: "flex", gap: "0.6em", alignItems: "baseline" }}>
          <span
            className="caption"
            style={{
              fontWeight: 600,
              color: m.own ? "var(--lk-onprimarycontainer)" : senderColor(m.senderId),
            }}
          >
            {label}
          </span>
          <span className="capline" style={{ opacity: 0.7 }}>
            {time}
          </span>
        </div>
        <Text fontClass="body">{m.text}</Text>
        {m.failed && (
          <div style={{ display: "flex", gap: "0.6em", alignItems: "center", marginTop: "0.3em" }}>
            <span className="caption" style={{ color: "var(--lk-error)" }}>
              Not sent
            </span>
            <Button
              label="Retry"
              color="error"
              variant="outline"
              size="sm"
              onClick={() => onRetry(m.id)}
            />
          </div>
        )}
      </div>
    </div>
  );
}

function MessageList({ onRetry }: { onRetry: (id: number) => void }) {
  const messages = useVoiceChatStore((s) => s.messages);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = listRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages.length]);

  return (
    <div ref={listRef} style={{ flex: 1, minHeight: 0, overflowY: "auto", padding: "var(--lk-size-xs) 0" }}>
      {messages.length === 0 && (
        <Text fontClass="caption" color="outline">
          No messages yet
        </Text>
      )}
      {messages.map((m) => (
        <MessageBubble key={m.id} m={m} onRetry={onRetry} />
      ))}
    </div>
  );
}

function ChatInputRow({ onSend, disabled }: { onSend: (text: string) => void; disabled: boolean }) {
  const [draft, setDraft] = useState("");

  const submit = () => {
    const text = draft.trim();
    if (!text) return;
    onSend(text);
    setDraft("");
  };

  return (
    <Row alignItems="center" gap="2xs" style={{ padding: "var(--lk-size-2xs) 0 var(--lk-size-xs)" }}>
      <div style={{ flex: 1 }}>
        <TextInput
          name="chat-message"
          labelPosition="on-input"
          placeholder="Type a message"
          endIcon="message-square"
          value={draft}
          disabled={disabled}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") submit();
          }}
        />
      </div>
      <Button label="Send" onClick={submit} size="md" disabled={disabled} />
    </Row>
  );
}

function ErrorBanner({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <Card variant="fill" bgColor="errorcontainer" scaleFactor="body">
      <Text color="onerrorcontainer" fontClass="body">
        {message}
      </Text>
    </Card>
  );
}

function JoinScreen({
  url,
  setUrl,
  certHash,
  setCertHash,
  name,
  setName,
  micOff,
  setMicOff,
  connecting,
  onJoin,
  onClearSaved,
}: {
  url: string;
  setUrl: (v: string) => void;
  certHash: string;
  setCertHash: (v: string) => void;
  name: string;
  setName: (v: string) => void;
  micOff: boolean;
  setMicOff: (v: boolean) => void;
  connecting: boolean;
  onJoin: () => void;
  onClearSaved: () => void;
}) {
  return (
    <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ width: "100%", maxWidth: "28em" }}>
        <Card scaleFactor="body">
          <Row alignItems="stretch" gap="sm" style={{ flexDirection: "column" }}>
            <Text fontClass="title3">Join the room</Text>
            <TextInput
              name="Server URL"
              endIcon="globe"
              placeholder={DEFAULT_URL}
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
            <div>
              <TextInput
                name="Certificate hash (SHA-256)"
                endIcon="shield-check"
                placeholder="hex fingerprint"
                value={certHash}
                onChange={(e) => setCertHash(e.target.value)}
              />
              <Text fontClass="caption" color="onsurfacevariant" style={{ marginTop: "var(--lk-size-3xs)" }}>
                Copy it from the server&apos;s startup log. Leave empty for a CA-signed certificate.
              </Text>
            </div>
            <TextInput
              name="Display name"
              endIcon="user"
              placeholder="Optional"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <label
              className="caption"
              style={{ display: "flex", alignItems: "center", gap: "0.5em", cursor: "pointer" }}
            >
              <input
                type="checkbox"
                checked={micOff}
                onChange={(e) => setMicOff(e.target.checked)}
              />
              Join with mic off
            </label>
            <Button
              label={connecting ? "Connecting…" : "Join"}
              color="primary"
              disabled={connecting}
              onClick={onJoin}
            />
            <Row alignItems="center" justifyContent="center">
              <Button
                label="Clear saved info"
                color="surface"
                variant="text"
                size="sm"
                startIcon="eraser"
                style={{ color: "var(--lk-onsurface)" }}
                onClick={onClearSaved}
              />
            </Row>
          </Row>
        </Card>
      </div>
    </div>
  );
}

export default function Home() {
  const [url, setUrl] = useState(DEFAULT_URL);
  const [certHash, setCertHash] = useState("");
  const [name, setName] = useState("");
  const [micOff, setMicOff] = useState(false);
  const [joined, setJoined] = useState(false);
  const { connect, sendChat, retryMessage, toggleMute, leave, fatalError, micError, stats } =
    useVoiceChat();
  const connectionState = useVoiceChatStore((s) => s.connectionState);
  const reconnecting = useVoiceChatStore((s) => s.reconnecting);

  // Switch to the chat screen once the first connection is established; a
  // later disconnect keeps the chat screen (with the "Connection lost" bar).
  useEffect(
    () =>
      useVoiceChatStore.subscribe((s) => {
        if (s.connectionState === "established") setJoined(true);
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
      setName(saved.name);
      setMicOff(saved.micOff);
    }, 0);
    return () => window.clearTimeout(t);
  }, []);

  const clearSaved = () => {
    clearJoinPrefs();
    setUrl(DEFAULT_URL);
    setCertHash("");
    setName("");
    setMicOff(false);
  };

  const connecting = connectionState === "connecting" && !fatalError;
  const lost = joined && connectionState === "disconnected" && !reconnecting;

  return (
    <main
      style={{
        height: "100dvh",
        display: "flex",
        flexDirection: "column",
        width: "100%",
        maxWidth: "48em",
        margin: "0 auto",
        padding: "0 var(--lk-size-sm)",
        boxSizing: "border-box",
      }}
    >
      <header
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "var(--lk-size-xs)",
          padding: "var(--lk-size-2xs) 0",
          borderBottom: "1px solid var(--lk-outlinevariant)",
        }}
      >
        <Text fontClass="title3">WebTransport Chat</Text>
        <Row alignItems="center" gap="xs">
          {joined && stats && (
            <Text fontClass="caption" color="onsurfacevariant">
              {`RTT ${Math.round(stats.rttMs)} ms · loss ${stats.lossPct.toFixed(1)}%`}
            </Text>
          )}
          {joined && <StatusBadge />}
          {joined && <MicToggle onToggleMute={toggleMute} />}
          {joined && (
            <Button
              label="Leave"
              startIcon="log-out"
              color="error"
              variant="fill"
              size="sm"
              onClick={() => {
                leave();
                setJoined(false);
              }}
            />
          )}
        </Row>
      </header>

      {joined && <PeerChips />}

      {reconnecting && (
        <Card variant="fill" bgColor="warningcontainer" scaleFactor="body">
          <Text color="onwarningcontainer" fontClass="body">
            Reconnecting…
          </Text>
        </Card>
      )}
      {lost && (
        <Card variant="fill" bgColor="errorcontainer" scaleFactor="body">
          <Row alignItems="center" justifyContent="space-between" gap="xs">
            <Text color="onerrorcontainer" fontClass="body">
              Connection lost
            </Text>
            <Button label="Rejoin" color="error" size="sm" onClick={() => void connect(url, certHash)} />
          </Row>
        </Card>
      )}
      <ErrorBanner message={fatalError} />
      <ErrorBanner message={micError} />

      {joined ? (
        <>
          <MessageList onRetry={retryMessage} />
          <ChatInputRow onSend={sendChat} disabled={connectionState !== "established"} />
        </>
      ) : (
        <JoinScreen
          url={url}
          setUrl={setUrl}
          certHash={certHash}
          setCertHash={setCertHash}
          name={name}
          setName={setName}
          micOff={micOff}
          setMicOff={setMicOff}
          connecting={connecting}
          onJoin={() => {
            saveJoinPrefs({ url, certHash, name, micOff });
            const s = useVoiceChatStore.getState();
            s.setDisplayName(name.trim());
            if (micOff) s.setMuted(true);
            void connect(url, certHash);
          }}
          onClearSaved={clearSaved}
        />
      )}
    </main>
  );
}
