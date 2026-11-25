// A room is a link: `?room=<id>&host=<pubkey>`. The id names the MoQ
// namespace `wired/moqt_chat/<id>/...` and, with the host, the NIP-53 space
// `30312:<host>:<id>`. P1: the hub does not check either yet; rooms are
// kept apart only because every client stays under its own prefix.

import { hostPubkey, spaceA } from "./nostrRoom";
import type { RoomCreate } from "./roomAuth";

export type RoomLink = { id: string; host: string };

const ROOM_ID_BYTES = 16;
// 16 bytes -> 22 unpadded base64url chars; the last carries 2 data bits, so
// only A/Q/g/w are canonical.
const ROOM_ID = /^[A-Za-z0-9_-]{21}[AQgw]$/;

export const isRoomId = (id: string) => ROOM_ID.test(id);

/** A fresh room id: 16 random bytes, unpadded base64url. */
export function newRoomId(): string {
	const b = crypto.getRandomValues(new Uint8Array(ROOM_ID_BYTES));
	return btoa(String.fromCharCode(...b))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
}

/** The page query's room: `{}` without one (create mode), a link (host
 * normalised to hex), or an error to show instead of connecting. */
export function parseRoomLink(search: string): {
	link?: RoomLink;
	error?: string;
} {
	const q = new URLSearchParams(search);
	const id = q.get("room");
	const host = q.get("host");
	if (id === null && host === null) return {};
	if (id === null || !isRoomId(id))
		return { error: "Invalid room link: bad or missing room id." };
	// Read case-insensitively: hex has no case, and bech32 (npub) may be
	// all-uppercase (BIP-173).
	const hex = hostPubkey((host ?? "").toLowerCase());
	if (!hex)
		return { error: "Invalid room link: host must be 64-char hex or npub." };
	return { link: { id, host: hex } };
}

/** url with `room` and `host` set (other parameters kept): the share link
 * from origin + path, the address bar from location.href. */
export function withRoom(url: string, link: RoomLink): string {
	const u = new URL(url);
	u.searchParams.set("room", link.id);
	u.searchParams.set("host", link.host);
	return u.href;
}

/** The fallback display name until the host's space `room` tag is in. */
export const roomName = (id: string) => `Room ${id.slice(0, 6)}`;

/** The page's one room, set by enterRoom before joining (module scope like
 * nostrRoom.current: one page, one room). */
export const activeRoom: RoomLink & { space: string; create?: RoomCreate } = {
	id: "",
	host: "0".repeat(64),
	space: spaceA("0".repeat(64), ""),
};

/** create: this page made the room (Create room), so its connects carry the
 * room's mode and the creator's NIP-05 (roomAuth.ts). */
export function enterRoom(link: RoomLink, create?: RoomCreate): void {
	Object.assign(activeRoom, link, {
		space: spaceA(link.host, link.id),
		create,
	});
	if (create) saveHostedRoom(link.id, create);
}

// What the creating tab knew of its room, for the host's space and meeting
// after a reload (nostrRoomSession.ts). Not activeRoom.create: a reload is no
// create, so its connects carry no creator tags.
// shortcut: same-tab reload only, another device needs a hub-sent field
type Hosted = Pick<RoomCreate, "created" | "mode">;
const hostedKey = (id: string) => `wired-room-host:${id}`;

function saveHostedRoom(id: string, { created, mode }: Hosted): void {
	try {
		sessionStorage.setItem(hostedKey(id), JSON.stringify({ created, mode }));
	} catch {} // storage unavailable: a reload announces `open`
}

const isHosted = (v: Partial<Hosted> | null): v is Hosted =>
	Number.isFinite(v?.created) && (v?.mode === "open" || v?.mode === "auth");

export function hostedRoom(id: string): Hosted | undefined {
	try {
		const v = JSON.parse(sessionStorage.getItem(hostedKey(id)) ?? "null");
		return isHosted(v) ? { created: v.created, mode: v.mode } : undefined;
	} catch {
		return undefined;
	}
}

/** Leaving (or a final close): the next connect is no longer this page's
 * create, and a later Create room starts a fresh `created`. */
export function exitRoom(): void {
	activeRoom.create = undefined;
}
