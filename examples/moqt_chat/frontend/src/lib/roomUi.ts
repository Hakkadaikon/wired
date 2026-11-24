// Pure helpers behind the room screen: the countdown's colour, the invite
// link, and which hands just went up (for the "raised their hand" toast).

import type { Event } from "nostr-tools";
import type { ChatMessage, MoqtChatState } from "@/stores/moqtChatStore";
import type { ChatAttachment } from "./moqtClient";
import { acceptPresence, handRaised } from "./nostrRoom";
import { type RoomLink, withRoom } from "./roomLink";

export type TimerLevel = "normal" | "warn" | "danger";

const WARN_S = 30 * 60;
const DANGER_S = 5 * 60;

/** Under 30 min left warns (yellow), under 5 min is danger (red). */
export function timerLevel(leftS: number): TimerLevel {
	if (leftS < DANGER_S) return "danger";
	return leftS < WARN_S ? "warn" : "normal";
}

/** The share link: origin + path only (the page's other parameters, e.g.
 * ?relays=, are the user's own) with `?room=&host=`. */
export const inviteLink = (
	loc: { origin: string; pathname: string },
	room: RoomLink,
) => withRoom(`${loc.origin}${loc.pathname}`, room);

const fresh = (ev: Event | undefined, space: string, now: number) =>
	ev !== undefined && acceptPresence(ev, space, now) && handRaised(ev);

/** Pubkeys whose hand went from a seen "down" to a fresh "up". A first
 * presence (history replay, a join) is no raise; prev is not checked for
 * staleness, so a reconnect's "up" after an old "down" still counts. */
export function newlyRaised(
	prev: Record<string, Event>,
	next: Record<string, Event>,
	space: string,
	now: number,
): string[] {
	return Object.keys(next).filter(
		(pk) =>
			prev[pk] !== undefined &&
			!handRaised(prev[pk]) &&
			fresh(next[pk], space, now),
	);
}

type Retried = Pick<ChatMessage, "id" | "text" | "attachments">;

/** A failed message's Retry: the error clears, the message is sent anew
 * (the send adds its own bubble, or a new failed one), and the old bubble
 * stays on screen until that send is done. */
export async function retryMessage(
	m: Retried,
	send: (text: string, attachments: ChatAttachment[]) => Promise<void>,
	store: Pick<MoqtChatState, "setMessageSendError" | "removeMessage">,
): Promise<void> {
	store.setMessageSendError(null);
	const attachments = (m.attachments ?? []).map((a) => ({
		bytes: a.bytes,
		mimeType: a.mimeType,
	}));
	await send(m.text, attachments);
	store.removeMessage(m.id);
}
