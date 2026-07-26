// Client-wide UI state: connection lifecycle, chat history, mute state, and
// the reconnecting flag. Deliberately holds only what a UI needs to render;
// transport/pipeline objects themselves live in the lib layer, not here.

import { create } from "zustand";
import type { ConnectionState } from "../lib/webtransportClient";

export type ChatMessage = {
  id: number; // store-assigned, monotonically increasing
  senderId: string;
  name: string; // sender display name; "" when anonymous
  text: string;
  at: number; // epoch ms
  own: boolean; // true = sent by this client
  kind?: "join" | "leave"; // set on presence system rows; absent = normal chat
  failed?: boolean; // own message whose send failed
};

export type VoiceChatState = {
  connectionState: ConnectionState;
  reconnecting: boolean;
  muted: boolean;
  messages: ChatMessage[];
  peers: string[]; // unique non-self sender keys, in observation order
  displayName: string;
  peerNames: Record<string, string>; // sender key -> display name
  setConnectionState: (state: ConnectionState) => void;
  setReconnecting: (reconnecting: boolean) => void;
  setMuted: (muted: boolean) => void;
  addMessage: (message: Omit<ChatMessage, "id">) => number;
  removeMessage: (id: number) => void;
  setDisplayName: (name: string) => void;
  setPeerName: (key: string, name: string) => void;
  addPeer: (key: string) => void;
  removePeer: (key: string) => void;
  clearPeers: () => void;
  clearMessages: () => void;
};

let nextMessageId = 1;

export const useVoiceChatStore = create<VoiceChatState>((set) => ({
  // "disconnected" until the user actually joins -- the join button must not
  // start out in its disabled "Connecting..." state.
  connectionState: "disconnected",
  reconnecting: false,
  muted: false,
  messages: [],
  peers: [],
  displayName: "",
  peerNames: {},
  setConnectionState: (connectionState) => set({ connectionState }),
  setReconnecting: (reconnecting) => set({ reconnecting }),
  setMuted: (muted) => set({ muted }),
  addMessage: (message) => {
    const id = nextMessageId++;
    set((s) => ({ messages: [...s.messages, { ...message, id }] }));
    return id;
  },
  removeMessage: (id) =>
    set((s) => ({ messages: s.messages.filter((m) => m.id !== id) })),
  setDisplayName: (displayName) => set({ displayName }),
  setPeerName: (key, name) =>
    set((s) =>
      name === "" ? s : { peerNames: { ...s.peerNames, [key]: name } },
    ),
  addPeer: (key) =>
    set((s) => (s.peers.includes(key) ? s : { peers: [...s.peers, key] })),
  removePeer: (key) =>
    set((s) => ({ peers: s.peers.filter((p) => p !== key) })),
  clearPeers: () => set({ peers: [] }),
  clearMessages: () => set({ messages: [] }),
}));
