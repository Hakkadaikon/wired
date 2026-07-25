"use client";

import { useState } from "react";
import Card from "@/components/card";
import Text from "@/components/text";
import Button from "@/components/button";
import Badge from "@/components/badge";
import Row from "@/components/row";
import TextInput from "@/components/text-input";
import { useVoiceChat } from "@/hooks/useVoiceChat";
import { useVoiceChatStore } from "@/stores/voiceChatStore";

const DEFAULT_URL = "https://localhost:4433/";

const STATUS_LABEL: Record<string, string> = {
  connecting: "接続中",
  established: "接続済み",
  disconnected: "切断",
};

function StatusBadge() {
  const connectionState = useVoiceChatStore((s) => s.connectionState);
  const reconnecting = useVoiceChatStore((s) => s.reconnecting);
  const label = reconnecting ? "再接続中" : STATUS_LABEL[connectionState];
  const color = connectionState === "established" && !reconnecting ? "success" : "warning";
  return (
    <Row alignItems="center" gap="2xs">
      <Badge icon="wifi" color={color} scale="md" />
      <Text fontClass="label">{label}</Text>
    </Row>
  );
}

function ChatPanel({ onSend }: { onSend: (text: string) => void }) {
  const messages = useVoiceChatStore((s) => s.messages);
  const [draft, setDraft] = useState("");

  const submit = () => {
    const text = draft.trim();
    if (!text) return;
    onSend(text);
    setDraft("");
  };

  return (
    <Card scaleFactor="body" isScrollable>
      <Row alignItems="stretch" gap="xs" style={{ flexDirection: "column" }}>
        <Text fontClass="title3">チャット</Text>
        <div style={{ maxHeight: "16em", overflowY: "auto" }}>
          {messages.length === 0 && (
            <Text fontClass="caption" color="outline">
              まだメッセージはありません
            </Text>
          )}
          {messages.map((m, i) => (
            <Row key={i} alignItems="center" gap="2xs">
              <Text fontClass="caption" color="outline">
                {m.senderId.slice(0, 6)}
              </Text>
              <Text fontClass="body">{m.text}</Text>
            </Row>
          ))}
        </div>
        <Row alignItems="center" gap="2xs">
          <TextInput
            name="chat-message"
            placeholder="メッセージを入力"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") submit();
            }}
          />
          <Button label="送信" onClick={submit} size="md" />
        </Row>
      </Row>
    </Card>
  );
}

function VoiceControls({ onToggleMute }: { onToggleMute: () => void }) {
  const muted = useVoiceChatStore((s) => s.muted);
  return (
    <Row alignItems="center" gap="xs">
      <Button
        label={muted ? "マイクをオンにする" : "マイクをオフにする"}
        startIcon={muted ? "mic-off" : "mic"}
        color={muted ? "surface" : "primary"}
        variant={muted ? "outline" : "fill"}
        onClick={onToggleMute}
      />
    </Row>
  );
}

function ErrorBanner({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <Card variant="fill" bgColor="errorcontainer">
      <Text color="onerrorcontainer" fontClass="body">
        {message}
      </Text>
    </Card>
  );
}

export default function Home() {
  const [url, setUrl] = useState(DEFAULT_URL);
  const [certHash, setCertHash] = useState("");
  const { connect, sendChat, toggleMute, fatalError, micError } = useVoiceChat();
  const connectionState = useVoiceChatStore((s) => s.connectionState);
  const joined = connectionState === "established" || connectionState === "disconnected";

  return (
    <main style={{ maxWidth: "40em", margin: "0 auto", padding: "var(--lk-size-lg)" }}>
      <Row alignItems="center" justifyContent="space-between" gap="sm">
        <Text fontClass="title2">WebTransport チャット</Text>
        {joined && <StatusBadge />}
      </Row>

      <div style={{ marginTop: "var(--lk-size-md)" }}>
        <ErrorBanner message={fatalError} />
        <ErrorBanner message={micError} />
      </div>

      {!joined && (
        <Card scaleFactor="body">
          <Row alignItems="stretch" gap="sm" style={{ flexDirection: "column" }}>
            <TextInput
              name="server-url"
              labelPosition="on-input"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
            <TextInput
              name="cert-hash"
              labelPosition="on-input"
              placeholder="証明書ハッシュ (SHA-256、サーバー起動ログの値)"
              value={certHash}
              onChange={(e) => setCertHash(e.target.value)}
            />
            <Button label="通話に参加" color="primary" onClick={() => connect(url, certHash)} />
          </Row>
        </Card>
      )}

      {joined && (
        <Row alignItems="stretch" gap="md" style={{ flexDirection: "column", marginTop: "var(--lk-size-md)" }}>
          <VoiceControls onToggleMute={toggleMute} />
          <ChatPanel onSend={sendChat} />
        </Row>
      )}
    </main>
  );
}
