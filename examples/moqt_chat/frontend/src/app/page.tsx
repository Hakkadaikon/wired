"use client";

import { useEffect, useRef, useState } from "react";
import Card from "@/components/card";
import Text from "@/components/text";
import Button from "@/components/button";
import Badge from "@/components/badge";
import Row from "@/components/row";
import TextInput from "@/components/text-input";
import { useMoqtChat } from "@/hooks/useMoqtChat";
import { clearJoinPrefs, loadJoinPrefs, saveJoinPrefs } from "@/lib/joinPrefs";
import { CANDIDATE_PARTICIPANT_IDS } from "@/lib/moqtClient";
import { useMoqtChatStore, type ChatMessage } from "@/stores/moqtChatStore";

const DEFAULT_URL = "https://localhost:4433/";
const DEFAULT_PARTICIPANT_ID = CANDIDATE_PARTICIPANT_IDS[0];

const STATUS_LABEL: Record<string, string> = {
  connecting: "Connecting",
  connected: "Connected",
  disconnected: "Disconnected",
};

/** Stable per-sender hue so the same participant always gets the same label color. */
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

function StatusBadge() {
  const connectionState = useMoqtChatStore((s) => s.connectionState);
  const label = STATUS_LABEL[connectionState];
  const color =
    connectionState === "connected"
      ? "success"
      : connectionState === "disconnected"
        ? "error"
        : "warning";
  return (
    <Row alignItems="center" gap="2xs">
      <Badge icon="wifi" color={color} scale="md" data-testid="status" data-status={connectionState} />
      <Text fontClass="label">{label}</Text>
    </Row>
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
  const peers = useMoqtChatStore((s) => s.peers);
  return (
    <Row alignItems="center" gap="2xs" wrapChildren style={{ padding: "var(--lk-size-2xs) 0" }}>
      <Text fontClass="caption" color="onsurfacevariant">
        {peers.length + 1} in room
      </Text>
      <Chip label="You" />
      {peers.map((p) => (
        <Chip key={p} label={p} color={senderColor(p)} />
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
  const label = m.own ? "You" : m.senderId;
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
          <span className="caption" style={{ color: "var(--lk-error)" }}>
            Not sent
          </span>
        )}
      </div>
    </div>
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
    <div
      ref={listRef}
      data-testid="messages"
      style={{ flex: 1, minHeight: 0, overflowY: "auto", padding: "var(--lk-size-xs) 0" }}
    >
      {messages.length === 0 && (
        <Text fontClass="caption" color="outline">
          No messages yet
        </Text>
      )}
      {messages.map((m) => (
        <div key={m.id} data-testid="message" data-sender={m.senderId}>
          <MessageBubble m={m} />
        </div>
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
    <Row
      alignItems="center"
      gap="2xs"
      data-testid="chat-form"
      style={{ padding: "var(--lk-size-2xs) 0 var(--lk-size-xs)" }}
    >
      <div style={{ flex: 1 }}>
        <TextInput
          name="chat-message"
          labelPosition="on-input"
          placeholder="Type a message"
          endIcon="message-square"
          value={draft}
          disabled={disabled}
          data-testid="text"
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
              data-testid="url"
              onChange={(e) => setUrl(e.target.value)}
            />
            <div>
              <TextInput
                name="Certificate hash (SHA-256)"
                endIcon="shield-check"
                placeholder="hex fingerprint"
                value={certHash}
                data-testid="certHash"
                onChange={(e) => setCertHash(e.target.value)}
              />
              <Text fontClass="caption" color="onsurfacevariant" style={{ marginTop: "var(--lk-size-3xs)" }}>
                Copy it from the server&apos;s startup log. Leave empty for a CA-signed certificate.
              </Text>
            </div>
            <div>
              <Text fontClass="caption" color="onsurfacevariant">
                Participant ID
              </Text>
              <Row alignItems="center" gap="2xs" style={{ marginTop: "var(--lk-size-3xs)" }} data-testid="author">
                {CANDIDATE_PARTICIPANT_IDS.map((id) => (
                  <Button
                    key={id}
                    label={id}
                    size="sm"
                    color={id === participantId ? "primary" : "surface"}
                    variant={id === participantId ? "fill" : "outline"}
                    style={
                      id === participantId
                        ? undefined
                        : { color: "var(--lk-onsurface)", borderColor: "var(--lk-onsurface)" }
                    }
                    onClick={() => setParticipantId(id)}
                  />
                ))}
              </Row>
            </div>
            <Button
              label={connecting ? "Connecting…" : "Join"}
              color="primary"
              disabled={connecting}
              data-testid="connect"
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
  const [participantId, setParticipantId] = useState(DEFAULT_PARTICIPANT_ID);
  const [joined, setJoined] = useState(false);
  const { connect, sendChat, leave } = useMoqtChat();
  const connectionState = useMoqtChatStore((s) => s.connectionState);

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
        <Text fontClass="title3">{joined ? `🐾 ${participantId}` : "MOQT Chat"}</Text>
        <Row alignItems="center" gap="xs">
          {joined && <StatusBadge />}
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

      {lost && (
        <Card variant="fill" bgColor="errorcontainer" scaleFactor="body">
          <Row alignItems="center" justifyContent="space-between" gap="xs">
            <Text color="onerrorcontainer" fontClass="body">
              Connection lost
            </Text>
            <Button
              label="Rejoin"
              color="error"
              size="sm"
              onClick={() => void connect(url, participantId, certHash ? [certHash] : [])}
            />
          </Row>
        </Card>
      )}

      {joined ? (
        <>
          <MessageList />
          <ChatInputRow onSend={sendChat} disabled={connectionState !== "connected"} />
        </>
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
    </main>
  );
}
