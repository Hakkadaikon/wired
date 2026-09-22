// Client-wide UI state: connection lifecycle, chat history, mute state, and
// found peers. Deliberately holds only what a UI needs to render; the MOQT
// session itself lives in useMoqtChat/moqtClient, not here.
//
// This hub has no presence Object (moqt-plan.md decision 2) and the
// participant id (moqtClient.ts's CANDIDATE_PARTICIPANT_IDS) never changes --
// it decides track alias, so it can't double as a free-text display name.
// `nicknames` is a purely client-side id -> nickname map, populated by a
// self-announce message riding the chat Object channel (moqtClient.ts's
// buildNicknameObjectMessage); resolveDisplayName falls back to the id
// itself for anyone who hasn't announced one (or didn't set one at all).

import { create } from "zustand";
import { noiseSuppressionDefault } from "@/lib/joinPrefs";
import { SCREEN_TILE_DEFAULT_PX } from "@/lib/screenTileSize";
import type { QualityLevel } from "@/lib/voiceQuality";

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
  nicknames: Record<string, string>; // per-participant self-announced nickname; absent key means none set
  liveError: string | null; // fatal live-movie playback error, if any
  liveFirstGroup: string | null; // first live Group id received (decimal string)
  screenSharing: boolean; // am I currently sharing my screen
  screenTiles: string[]; // participant ids currently sharing, for rendering tiles
  screenShareError: string | null; // screen-share-only error; never surfaces in chat/voice errors
  stalledScreenTiles: Record<string, boolean>; // per-sender "no frame for a while"; absent key renders as false
  screenTileWidth: number; // displayed width of every remote screen tile, px
  maximizedScreenTile: string | null; // remote tile shown fullscreen (or full-width without the API)
  masterVolume: number; // 0..1, applied on top of every peer's own volume
  peerVolumes: Record<string, number>; // per-sender volume, 0..1; absent key means 1 (unity)
  voiceQuality: Record<string, QualityLevel>; // per-sender quality; absent key renders as "none"
  speaking: Record<string, boolean>; // per-sender speaking indicator; absent key renders as false
  localSpeaking: boolean; // this client's own speaking indicator
  noiseSuppressionEnabled: boolean; // RNNoise on/off (masthead "NS" toggle)
  setConnectionState: (state: ConnectionState) => void;
  setMuted: (muted: boolean) => void;
  addMessage: (message: Omit<ChatMessage, "id">) => number;
  removeMessage: (id: number) => void;
  setNickname: (id: string, nickname: string) => void;
  setLiveError: (msg: string | null) => void;
  setLiveFirstGroup: (groupId: string | null) => void;
  addPeer: (id: string) => void;
  removePeer: (id: string) => void;
  clearPeers: () => void;
  clearMessages: () => void;
  setScreenSharing: (sharing: boolean) => void;
  addScreenTile: (id: string) => void;
  removeScreenTile: (id: string) => void;
  clearScreenTiles: () => void;
  setScreenShareError: (msg: string | null) => void;
  setScreenTileStalled: (id: string, stalled: boolean) => void;
  setScreenTileWidth: (px: number) => void;
  setMaximizedScreenTile: (id: string | null) => void;
  setMasterVolume: (v: number) => void;
  setPeerVolume: (id: string, v: number) => void;
  setVoiceQuality: (id: string, level: QualityLevel) => void;
  setSpeaking: (id: string, speaking: boolean) => void;
  setLocalSpeaking: (speaking: boolean) => void;
  setNoiseSuppressionEnabled: (enabled: boolean) => void;
};

let nextMessageId = 1;

export const useMoqtChatStore = create<MoqtChatState>((set) => ({
  // "disconnected" until the user actually joins -- the join button must not
  // start out in its disabled "Connecting..." state.
  connectionState: "disconnected",
  muted: false,
  messages: [],
  peers: [],
  nicknames: {},
  liveError: null,
  liveFirstGroup: null,
  screenSharing: false,
  screenTiles: [],
  screenShareError: null,
  stalledScreenTiles: {},
  screenTileWidth: SCREEN_TILE_DEFAULT_PX,
  maximizedScreenTile: null,
  masterVolume: 1,
  peerVolumes: {},
  voiceQuality: {},
  speaking: {},
  localSpeaking: false,
  noiseSuppressionEnabled:
    typeof window === "undefined" ? true : noiseSuppressionDefault(window.location.search),
  setConnectionState: (connectionState) => set({ connectionState }),
  setMuted: (muted) => set({ muted }),
  addMessage: (message) => {
    const id = nextMessageId++;
    set((s) => ({ messages: [...s.messages, { ...message, id }] }));
    return id;
  },
  removeMessage: (id) =>
    set((s) => ({ messages: s.messages.filter((m) => m.id !== id) })),
  setNickname: (id, nickname) =>
    set((s) => ({ nicknames: { ...s.nicknames, [id]: nickname } })),
  setLiveError: (liveError) => set({ liveError }),
  setLiveFirstGroup: (liveFirstGroup) => set({ liveFirstGroup }),
  addPeer: (id) =>
    set((s) => (s.peers.includes(id) ? s : { peers: [...s.peers, id] })),
  removePeer: (id) => set((s) => ({ peers: s.peers.filter((p) => p !== id) })),
  clearPeers: () => set({ peers: [], voiceQuality: {}, speaking: {} }),
  clearMessages: () => set({ messages: [] }),
  setScreenSharing: (screenSharing) => set({ screenSharing }),
  addScreenTile: (id) =>
    set((s) => (s.screenTiles.includes(id) ? s : { screenTiles: [...s.screenTiles, id] })),
  removeScreenTile: (id) =>
    set((s) => ({
      screenTiles: s.screenTiles.filter((t) => t !== id),
      maximizedScreenTile: s.maximizedScreenTile === id ? null : s.maximizedScreenTile,
    })),
  clearScreenTiles: () =>
    set({ screenTiles: [], stalledScreenTiles: {}, maximizedScreenTile: null }),
  setScreenShareError: (screenShareError) => set({ screenShareError }),
  // Polled every drain tick, so an unchanged flag must not produce a new
  // object (and a re-render) each time.
  setScreenTileWidth: (screenTileWidth) => set({ screenTileWidth }),
  setMaximizedScreenTile: (maximizedScreenTile) => set({ maximizedScreenTile }),
  setScreenTileStalled: (id, stalled) =>
    set((s) =>
      s.stalledScreenTiles[id] === stalled
        ? s
        : { stalledScreenTiles: { ...s.stalledScreenTiles, [id]: stalled } },
    ),
  setMasterVolume: (masterVolume) => set({ masterVolume }),
  setPeerVolume: (id, v) =>
    set((s) => ({ peerVolumes: { ...s.peerVolumes, [id]: v } })),
  setVoiceQuality: (id, level) =>
    set((s) => ({ voiceQuality: { ...s.voiceQuality, [id]: level } })),
  setSpeaking: (id, speaking) =>
    set((s) => ({ speaking: { ...s.speaking, [id]: speaking } })),
  setLocalSpeaking: (localSpeaking) => set({ localSpeaking }),
  setNoiseSuppressionEnabled: (noiseSuppressionEnabled) => set({ noiseSuppressionEnabled }),
}));

/** id -> nickname if one is known, else the id itself -- used everywhere a
 * participant id is rendered (Peers, Volume, screen tile captions, chat
 * sender name), so a peer who never announced a nickname just shows their
 * participant id, unchanged from today's behavior. */
export function resolveDisplayName(id: string, nicknames: Record<string, string>): string {
  return nicknames[id] || id;
}
