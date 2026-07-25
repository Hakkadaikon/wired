"use client";

import { useEffect, useRef, useState } from "react";
import Card from "@/components/card";
import Text from "@/components/text";
import Button from "@/components/button";
import Badge from "@/components/badge";
import Row from "@/components/row";
import TextInput from "@/components/text-input";
import { useVoiceChat } from "@/hooks/useVoiceChat";
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
  return (
    <Row alignItems="center" gap="2xs" wrapChildren style={{ padding: "var(--lk-size-2xs) 0" }}>
      <Text fontClass="caption" color="onsurfacevariant">
        {peers.length + 1} in room
      </Text>
      <Chip label="You" />
      {peers.map((p) => (
        <Chip key={p} label={guestLabel(p)} color={senderColor(p)} />
      ))}
      {peers.length === 0 && (
        <Text fontClass="caption" color="outline">
          Waiting for others…
        </Text>
      )}
    </Row>
  );
}

function MessageBubble({ m }: { m: ChatMessage }) {
  const time = new Date(m.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
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
            {m.own ? "You" : guestLabel(m.senderId)}
          </span>
          <span className="capline" style={{ opacity: 0.7 }}>
            {time}
          </span>
        </div>
        <Text fontClass="body">{m.text}</Text>
      </div>
    </div>
  );
}

function MessageList() {
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
      {messages.map((m, i) => (
        <MessageBubble key={i} m={m} />
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
  connecting,
  onJoin,
}: {
  url: string;
  setUrl: (v: string) => void;
  certHash: string;
  setCertHash: (v: string) => void;
  connecting: boolean;
  onJoin: () => void;
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
            <Button
              label={connecting ? "Connecting…" : "Join"}
              color="primary"
              disabled={connecting}
              onClick={onJoin}
            />
          </Row>
        </Card>
      </div>
    </div>
  );
}

export default function Home() {
  const [url, setUrl] = useState(DEFAULT_URL);
  const [certHash, setCertHash] = useState("");
  const [joined, setJoined] = useState(false);
  const { connect, sendChat, toggleMute, fatalError, micError } = useVoiceChat();
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
          {joined && <StatusBadge />}
          {joined && <MicToggle onToggleMute={toggleMute} />}
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
          <MessageList />
          <ChatInputRow onSend={sendChat} disabled={connectionState !== "established"} />
        </>
      ) : (
        <JoinScreen
          url={url}
          setUrl={setUrl}
          certHash={certHash}
          setCertHash={setCertHash}
          connecting={connecting}
          onJoin={() => void connect(url, certHash)}
        />
      )}
    </main>
  );
}
