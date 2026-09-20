// Client-wide UI state: connection lifecycle, chat history, mute state, and
// found peers. Deliberately holds only what a UI needs to render; the MOQT
// session itself lives in useMoqtChat/moqtClient, not here.
//
// Unlike webtransport_chat's voiceChatStore, there is no presence
// message/peerNames map: this hub has no presence Object (moqt-plan.md
// decision 2), so a peer's display name is just its participant id
// (moqtClient.ts's candidate ids are already human-readable, e.g. "user1").

import { create } from "zustand";

export type ConnectionState = "connecting" | "connected" | "disconnected";

export type ChatMessage = {
  id: number; // store-assigned, monotonically increasing
  senderId: string;
  text: string;
  at: number; // epoch ms
  own: boolean; // true = sent by this client
  failed?: boolean; // own message whose send failed
};

export type MoqtChatState = {
  connectionState: ConnectionState;
  muted: boolean;
  messages: ChatMessage[];
  peers: string[]; // found participant ids, in observation order
  displayName: string;
  liveError: string | null; // fatal live-movie playback error, if any
  liveFirstGroup: string | null; // first live Group id received (decimal string)
  screenSharing: boolean; // am I currently sharing my screen
  screenTiles: string[]; // participant ids currently sharing, for rendering tiles
  screenShareError: string | null; // screen-share-only error; never surfaces in chat/voice errors
  masterVolume: number; // 0..1, applied on top of every peer's own volume
  peerVolumes: Record<string, number>; // per-sender volume, 0..1; absent key means 1 (unity)
  setConnectionState: (state: ConnectionState) => void;
  setMuted: (muted: boolean) => void;
  addMessage: (message: Omit<ChatMessage, "id">) => number;
  removeMessage: (id: number) => void;
  setDisplayName: (name: string) => void;
  setLiveError: (msg: string | null) => void;
  setLiveFirstGroup: (groupId: string | null) => void;
  addPeer: (id: string) => void;
  removePeer: (id: string) => void;
  clearPeers: () => void;
  clearMessages: () => void;
  setScreenSharing: (sharing: boolean) => void;
  addScreenTile: (id: string) => void;
  removeScreenTile: (id: string) => void;
  setScreenShareError: (msg: string | null) => void;
  setMasterVolume: (v: number) => void;
  setPeerVolume: (id: string, v: number) => void;
};

let nextMessageId = 1;

export const useMoqtChatStore = create<MoqtChatState>((set) => ({
  // "disconnected" until the user actually joins -- the join button must not
  // start out in its disabled "Connecting..." state.
  connectionState: "disconnected",
  muted: false,
  messages: [],
  peers: [],
  displayName: "",
  liveError: null,
  liveFirstGroup: null,
  screenSharing: false,
  screenTiles: [],
  screenShareError: null,
  masterVolume: 1,
  peerVolumes: {},
  setConnectionState: (connectionState) => set({ connectionState }),
  setMuted: (muted) => set({ muted }),
  addMessage: (message) => {
    const id = nextMessageId++;
    set((s) => ({ messages: [...s.messages, { ...message, id }] }));
    return id;
  },
  removeMessage: (id) =>
    set((s) => ({ messages: s.messages.filter((m) => m.id !== id) })),
  setDisplayName: (displayName) => set({ displayName }),
  setLiveError: (liveError) => set({ liveError }),
  setLiveFirstGroup: (liveFirstGroup) => set({ liveFirstGroup }),
  addPeer: (id) =>
    set((s) => (s.peers.includes(id) ? s : { peers: [...s.peers, id] })),
  removePeer: (id) => set((s) => ({ peers: s.peers.filter((p) => p !== id) })),
  clearPeers: () => set({ peers: [] }),
  clearMessages: () => set({ messages: [] }),
  setScreenSharing: (screenSharing) => set({ screenSharing }),
  addScreenTile: (id) =>
    set((s) => (s.screenTiles.includes(id) ? s : { screenTiles: [...s.screenTiles, id] })),
  removeScreenTile: (id) =>
    set((s) => ({ screenTiles: s.screenTiles.filter((t) => t !== id) })),
  setScreenShareError: (screenShareError) => set({ screenShareError }),
  setMasterVolume: (masterVolume) => set({ masterVolume }),
  setPeerVolume: (id, v) =>
    set((s) => ({ peerVolumes: { ...s.peerVolumes, [id]: v } })),
}));
