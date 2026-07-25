// Client-wide UI state: connection lifecycle, chat history, mute state, and
// the reconnecting flag. Deliberately holds only what a UI needs to render;
// transport/pipeline objects themselves live in the lib layer, not here.

import { create } from "zustand";
import type { ConnectionState } from "../lib/webtransportClient";

export type ChatMessage = {
  senderId: string;
  text: string;
  at: number; // epoch ms
  own: boolean; // true = sent by this client
};

export type VoiceChatState = {
  connectionState: ConnectionState;
  reconnecting: boolean;
  muted: boolean;
  messages: ChatMessage[];
  peers: string[]; // unique non-self sender keys, in observation order
  setConnectionState: (state: ConnectionState) => void;
  setReconnecting: (reconnecting: boolean) => void;
  setMuted: (muted: boolean) => void;
  addMessage: (message: ChatMessage) => void;
  addPeer: (key: string) => void;
  clearPeers: () => void;
};

export const useVoiceChatStore = create<VoiceChatState>((set) => ({
  connectionState: "connecting",
  reconnecting: false,
  muted: false,
  messages: [],
  peers: [],
  setConnectionState: (connectionState) => set({ connectionState }),
  setReconnecting: (reconnecting) => set({ reconnecting }),
  setMuted: (muted) => set({ muted }),
  addMessage: (message) =>
    set((s) => ({ messages: [...s.messages, message] })),
  addPeer: (key) =>
    set((s) => (s.peers.includes(key) ? s : { peers: [...s.peers, key] })),
  clearPeers: () => set({ peers: [] }),
}));
