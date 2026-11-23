// A thin MoQ-native Nostr client: Nostr events travel as Objects on the
// participants' chat tracks through the hub, never through a public relay.
// NIP-01 <-> MoQ (wire.md 5.2): EVENT -> one Object on our chat track, OK ->
// the send was accepted, REQ -> the peer chat-track subscriptions (with their
// history fill) + this filter, EOSE -> onHistoryEnd, CLOSE -> unsubscribe.
//
// Kind ranges (NIP-01) map onto MoQ history differently; only regular kinds
// are implemented:
//   regular (1, 2, 4-44, 1000-9999): every event is its own Group, history
//     keeps them all.
//   shortcut: replaceable (0, 3, 10000-19999) and addressable (30000-39999)
//     need "latest per key only" history, ephemeral (20000-29999) needs no
//     history (a datagram); add them when such a kind rides MoQ.

import type { Event } from "nostr-tools/pure";
import { parseVerifiedEvent } from "./nostr";

export type NostrFilter = {
	kinds: number[];
	a: string; // the room coordinate ("#a")
	authors?: string[];
	since?: number;
	limit?: number; // applies to history only
};

export type PublishOptions = {
	// shortcut: moqtClient's chat send path writes no publisher priority yet;
	// pass this through once SUBGROUP_HEADER priority is plumbed.
	priority?: number;
};

export type SubscribeHandlers = {
	// raw: the event JSON exactly as carried in the Object payload.
	onEvent(ev: Event, raw: string): void;
	onHistoryEnd?(): void;
};

// Received events kept for a subscription's history: the chat history fill
// (65 Groups) for each of the 4 participants, rounded up.
const HISTORY_MAX = 512;

export function isRegularKind(kind: number): boolean {
	return (
		kind === 1 ||
		kind === 2 ||
		(kind >= 4 && kind < 45) ||
		(kind >= 1000 && kind < 10000)
	);
}

function hasTag(ev: Event, name: string, value: string): boolean {
	return ev.tags.some((t) => t[0] === name && t[1] === value);
}

function matches(f: NostrFilter, ev: Event): boolean {
	return (
		f.kinds.includes(ev.kind) &&
		hasTag(ev, "a", f.a) &&
		(f.authors?.includes(ev.pubkey) ?? true) &&
		ev.created_at >= (f.since ?? 0)
	);
}

type Sub = { filter: NostrFilter; handlers: SubscribeHandlers };

const PAYLOAD_MAX = 64 * 1024; // larger payloads are dropped unparsed
const FUTURE_SKEW_S = 10 * 60; // created_at further ahead is dropped
const LIVE_PAST_S = 24 * 60 * 60; // live (not history) older than session start - this is dropped

// A timestamp worth showing: not far in the future, and a live event not
// long before this session (history may be older).
function plausibleTime(
	ev: Event,
	live: boolean,
	sessionStart: number,
): boolean {
	const now = Date.now() / 1000;
	if (ev.created_at > now + FUTURE_SKEW_S) return false;
	return !live || ev.created_at >= sessionStart - LIVE_PAST_S;
}

export class MoqNostr {
	/** Payloads dropped as malformed or failing id/signature verification. */
	invalid = 0;
	#history: { ev: Event; raw: string }[] = [];
	#seen = new Set<string>(); // ids in #history: a replayed fill is dropped
	#start = Date.now() / 1000;
	#subs = new Set<Sub>();
	#send: (json: string, opts: PublishOptions) => Promise<void>;

	/** send: one Object on our chat track (MoqtChatClient.sendNostrEvent). */
	constructor(send: (json: string, opts: PublishOptions) => Promise<void>) {
		this.#send = send;
	}

	/** Sends the event JSON unchanged; resolves once the send is accepted. */
	async publish(ev: Event, opts: PublishOptions = {}): Promise<void> {
		if (!isRegularKind(ev.kind))
			throw new Error(`unsupported: kind ${ev.kind} is not a regular kind`);
		await this.#send(JSON.stringify(ev), opts);
	}

	/** Feeds one Nostr payload from a peer's chat track (live, or its
	 * history fill); invalid or implausible ones are counted and dropped, a
	 * repeat of a held id is ignored. Returns the event when it is new. */
	receive(json: string, live = true): Event | undefined {
		const ev = json.length > PAYLOAD_MAX ? undefined : parseVerifiedEvent(json);
		if (!ev || !plausibleTime(ev, live, this.#start)) {
			this.invalid++;
			return undefined;
		}
		if (this.#seen.has(ev.id)) return undefined;
		this.#seen.add(ev.id);
		this.#history.push({ ev, raw: json });
		if (this.#history.length > HISTORY_MAX)
			this.#seen.delete(this.#history.shift()?.ev.id ?? "");
		for (const s of this.#subs)
			if (matches(s.filter, ev)) s.handlers.onEvent(ev, json);
		return ev;
	}

	/** History received so far (newest `limit`), then onHistoryEnd, then live
	 * events. A history fill that lands after this call arrives as live. */
	subscribe(filter: NostrFilter, handlers: SubscribeHandlers): () => void {
		const hits = this.#history.filter((h) => matches(filter, h.ev));
		const keep = filter.limit ?? hits.length;
		const history = hits.slice(Math.max(0, hits.length - keep));
		for (const h of history) handlers.onEvent(h.ev, h.raw);
		handlers.onHistoryEnd?.();
		const sub = { filter, handlers };
		this.#subs.add(sub);
		return () => this.#subs.delete(sub);
	}
}
