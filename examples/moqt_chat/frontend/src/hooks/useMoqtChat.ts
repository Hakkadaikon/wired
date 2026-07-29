"use client";

// Glue layer: wraps MoqtChatClient (moqtClient.ts, untouched) and mirrors
// its callbacks into moqtChatStore. UI components read/write only the
// store; the client instance itself lives in a ref here, never in
// component state.

import { useCallback, useRef } from "react";
import { MoqtChatClient } from "@/lib/moqtClient";
import { registerPageLifecycleCleanup } from "@/lib/pageLifecycle";
import { useMoqtChatStore } from "@/stores/moqtChatStore";

export function useMoqtChat() {
  const store = useMoqtChatStore();
  const clientRef = useRef<MoqtChatClient | null>(null);
  const localIdRef = useRef<string>("");

  const connect = useCallback(
    async (url: string, localId: string, certHashesHex: string[]) => {
      localIdRef.current = localId;
      store.clearPeers();
      store.clearMessages();
      store.setDisplayName(localId);

      const client = new MoqtChatClient(localId, {
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
      });
      clientRef.current = client;

      registerPageLifecycleCleanup({
        closeTransport: () => client.close(),
        getMicTracks: () => [],
      });

      await client.connect(url, certHashesHex);
    },
    [store],
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

  const leave = useCallback(() => {
    clientRef.current?.close();
    clientRef.current = null;
    store.setConnectionState("disconnected");
    store.clearPeers();
    store.clearMessages();
  }, [store]);

  return { connect, sendChat, leave };
}
