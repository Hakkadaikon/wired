// Client-side room separation: the server still broadcasts every datagram to
// every connection (it has no concept of rooms), so each client appends a
// one-byte room tag on send and drops any datagram not tagged for its own
// room on receive. Wire cost is +1 byte per datagram; no server change.

export const ROOMS = ["Fox", "Owl", "Wolf", "Bear"] as const;
export type Room = (typeof ROOMS)[number];

const ROOM_BYTE: Record<Room, number> = { Fox: 1, Owl: 2, Wolf: 3, Bear: 4 };
const BYTE_ROOM = new Map<number, Room>(
  ROOMS.map((room) => [ROOM_BYTE[room], room]),
);

export function tagWithRoom(bytes: Uint8Array, room: Room): Uint8Array {
  const tagged = new Uint8Array(bytes.length + 1);
  tagged.set(bytes, 0);
  tagged[bytes.length] = ROOM_BYTE[room];
  return tagged;
}

export function stripRoomTag(
  tagged: Uint8Array,
): { room: Room; bytes: Uint8Array } | null {
  if (tagged.length === 0) return null;
  const room = BYTE_ROOM.get(tagged[tagged.length - 1]);
  if (room === undefined) return null;
  return { room, bytes: tagged.subarray(0, tagged.length - 1) };
}
