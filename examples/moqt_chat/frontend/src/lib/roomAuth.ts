// Room access: the NIP-98 token every connect carries in the MoQT SETUP's
// AUTHORIZATION TOKEN (wire.md), the hub's close reason tokens, and the
// room's lifetime. Adapting NIP-98 (HTTP auth) to the WebTransport CONNECT
// is a documented deviation: `u` is the WebTransport URL, `method` CONNECT.

import type { Event, EventTemplate } from "nostr-tools/pure";
import { signOwnEvent } from "./nostr";
import { type RoomLink, withRoom } from "./roomLink";

export const NIP98_KIND = 27235;

/** A room ends this long after it was created. The hub enforces it
 * (--room-lifetime); the host's 30313 `ends` only shows it. */
export const ROOM_LIFETIME_S = 5 * 60 * 60;

export type RoomMode = "open" | "auth";
/** What only the creating page knows: sent on its every connect. */
export type RoomCreate = { mode: RoomMode; nip05: string; created: number };

export function nip98Template(
	url: string,
	room: { id: string; create?: RoomCreate },
	now = Math.floor(Date.now() / 1000),
): EventTemplate {
	const tags = [
		["u", url],
		["method", "CONNECT"],
	];
	const c = room.create;
	if (c) tags.push(["nip05", c.nip05], ["wired-room", room.id, c.mode]);
	return { kind: NIP98_KIND, created_at: now, content: "", tags };
}

/** The hub keeps a creator's token in 1 KiB while it verifies the NIP-05
 * (tasks/moqt-chat-rooms.md); a join's token is held to the same bound. */
export const TOKEN_MAX_BYTES = 1024;

/** The token: the 7 NIP-01 fields in a fixed order, whatever else the
 * extension's object carries. */
const tokenJson = (e: Event) =>
	JSON.stringify({
		id: e.id,
		pubkey: e.pubkey,
		created_at: e.created_at,
		kind: e.kind,
		tags: e.tags,
		content: e.content,
		sig: e.sig,
	});

const byteLength = (s: string) => new TextEncoder().encode(s).length;

async function signed(
	t: EventTemplate,
	pubkey: string,
	sign: (t: EventTemplate, pk: string) => Promise<Event>,
): Promise<Event> {
	try {
		return await sign(t, pubkey);
	} catch {
		// No automatic retry: a declined prompt would only pop up again.
		throw new Error(
			"The Nostr extension did not sign the room's sign-in token. Join again to retry.",
		);
	}
}

/** The WebTransport URL for the room (the server URL + ?room=&host=, so the
 * hub's CONNECT :path carries them) and, logged in, a freshly signed NIP-98
 * event for it: tokens are single-use, so every connect signs again. The
 * creator tags go only with the room host's own key. */
export async function roomSession(
	base: string,
	room: RoomLink & { create?: RoomCreate },
	pubkey: string | null,
	sign: (t: EventTemplate, pk: string) => Promise<Event> = signOwnEvent,
): Promise<{ url: string; token?: string }> {
	const url = withRoom(base, room);
	if (!pubkey) return { url };
	const create = pubkey === room.host ? room.create : undefined;
	const t = nip98Template(url, { id: room.id, create });
	// id and sig have fixed lengths, so the size is known before signing.
	const sized = { ...t, pubkey, id: "0".repeat(64), sig: "0".repeat(128) };
	if (byteLength(tokenJson(sized)) > TOKEN_MAX_BYTES)
		throw new Error(
			"The room's sign-in token would exceed 1 KiB: use a shorter server URL.",
		);
	return { url, token: tokenJson(await signed(t, pubkey, sign)) };
}

/** The hub's close reason tokens (wire.md): each one ends the room for this
 * client -- a final screen, no automatic rejoin. */
export const CLOSE_REASONS: Record<string, string> = {
	"malformed-auth": "The hub could not read this client's sign-in token.",
	"expired-auth":
		"The sign-in token was too old when the hub checked it. Check this computer's clock.",
	unauthorized:
		"The hub refused the sign-in. This room may need a Nostr login.",
	"nip05-unverified":
		"Your NIP-05 address could not be verified, so the room was not created.",
	"room-full": "The room is full: it holds 4 participants.",
	"id-taken":
		"Someone in this room already uses your participant ID. Pick another one and join again.",
	"no-room-slots": "The hub has no free room. Try again later.",
	"no-such-room":
		"This room does not exist. It may have ended, or the hub restarted.",
	"room-ended": "The room has ended.",
};

/** The final screen's message for a close reason; undefined when it is not
 * a reason token (a network loss: rejoin as before). */
export const closeMessage = (reason: string): string | undefined =>
	Object.hasOwn(CLOSE_REASONS, reason) ? CLOSE_REASONS[reason] : undefined;

const pad2 = (n: number) => String(n).padStart(2, "0");

// Clock skew allowed between the host's `ends` and this browser.
const ENDS_SKEW_S = 5 * 60;

/** The countdown to show for a meeting's `ends`, or undefined (hidden) once
 * past or when it lies beyond what a room can last. */
export function remaining(ends: number, now: number): string | undefined {
	const left = ends - now;
	return left > 0 && left <= ROOM_LIFETIME_S + ENDS_SKEW_S
		? countdown(ends, now)
		: undefined;
}

/** "H:MM:SS" left until `ends` (seconds), "0:00:00" once past. */
export function countdown(ends: number, now: number): string {
	const s = Math.max(0, Math.floor(ends - now));
	return `${Math.floor(s / 3600)}:${pad2(Math.floor(s / 60) % 60)}:${pad2(s % 60)}`;
}
