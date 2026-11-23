// A thin MoQ-native Nostr client: Nostr events travel as Objects on the
// participants' own tracks through the hub, never through a public relay.
// NIP-01 <-> MoQ (wire.md 5.2): EVENT -> one Object on our track for its
// kind (NOSTR_TRACKS), OK -> the send was accepted, REQ -> the peer track
// subscriptions (with their history fill) + this filter, EOSE ->
// onHistoryEnd, CLOSE -> unsubscribe.
//
// Kind ranges (NIP-01) map onto MoQ history differently:
//   regular (1, 2, 4-44, 1000-9999): every event is its own Group, history
//     keeps them all.
//   replaceable (0, 3, 10000-19999) and addressable (30000-39999): a track
//     of their own whose fill asks for the latest Group only, and history
//     keeps only the newest per key (nostrRoom.ts replaceKey / newer); an
//     older one arriving later is dropped.
//   shortcut: ephemeral (20000-29999) needs no history (a datagram); add it
//     when such a kind rides MoQ.

import type { Event } from "nostr-tools/pure";
import { parseVerifiedEvent } from "./nostr";
import { newer, replaceKey } from "./nostrRoom";

export type NostrFilter = {
	kinds: number[];
	a?: string; // the room coordinate ("#a"); absent = any
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
const LATEST_MAX = 512; // replaceable keys remembered

/** The MoQ track a kind rides, under the participant's namespace. */
export type NostrTrack =
	| "chat"
	| "nostr-presence"
	| "nostr-30312"
	| "nostr-30313"
	| "nostr-react";

/** The Nostr-only tracks; latest: a subscriber's fill asks for the latest
 * Group only (replaceable / addressable kinds), else the chat history depth. */
export const NOSTR_TRACKS: {
	track: Exclude<NostrTrack, "chat">;
	kinds: number[];
	latest: boolean;
}[] = [
	{ track: "nostr-presence", kinds: [10312], latest: true },
	{ track: "nostr-30312", kinds: [30312], latest: true },
	{ track: "nostr-30313", kinds: [30313], latest: true },
	// shortcut: no publisher priority on the wire yet (PublishOptions); give
	// reactions a lower one than chat once SUBGROUP_HEADER priority is plumbed.
	{ track: "nostr-react", kinds: [7, 5], latest: false },
];

const CHAT_KINDS = [1311];

/** The track kind is sent on, undefined for a kind we do not carry. */
export function trackForKind(kind: number): NostrTrack | undefined {
	if (CHAT_KINDS.includes(kind)) return "chat";
	return NOSTR_TRACKS.find((t) => t.kinds.includes(kind))?.track;
}

function hasTag(ev: Event, name: string, value: string): boolean {
	return ev.tags.some((t) => t[0] === name && t[1] === value);
}

function matches(f: NostrFilter, ev: Event): boolean {
	return (
		f.kinds.includes(ev.kind) &&
		(f.a === undefined || hasTag(ev, "a", f.a)) &&
		(f.authors?.includes(ev.pubkey) ?? true) &&
		ev.created_at >= (f.since ?? 0)
	);
}

type Sub = { filter: NostrFilter; handlers: SubscribeHandlers };
type Send = (
	json: string,
	track: NostrTrack,
	opts: PublishOptions,
) => Promise<void>;

const onTrack = (ev: Event, track: NostrTrack) =>
	trackForKind(ev.kind) === track;

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
	// replaceKey -> the newest seen; outlives #history's cap, so an older
	// replay never wins once its key was replaced. One entry per (kind,
	// author[, d]) of the three room kinds, at most LATEST_MAX (oldest
	// updated goes first).
	#latest = new Map<string, Event>();
	#start = Date.now() / 1000;
	#subs = new Set<Sub>();
	#send: Send;
	#accept: (ev: Event) => boolean;

	/** send: one Object on our track (MoqtChatClient.sendNostrEvent);
	 * accept: a verified event worth keeping at all (e.g. 30312/30313 only
	 * from the space's host), checked before it takes a #latest slot. */
	constructor(send: Send, accept: (ev: Event) => boolean = () => true) {
		this.#send = send;
		this.#accept = accept;
	}

	/** Sends the event JSON unchanged on its kind's track; resolves once the
	 * send is accepted. */
	async publish(ev: Event, opts: PublishOptions = {}): Promise<void> {
		const track = trackForKind(ev.kind);
		if (!track) throw new Error(`unsupported: kind ${ev.kind} has no track`);
		await this.#send(JSON.stringify(ev), track, opts);
	}

	/** Feeds one Nostr payload from a peer's track (live, or its history
	 * fill); invalid, implausible or off-track ones are counted and dropped,
	 * a repeat of a held id or a superseded replaceable is ignored. Returns
	 * the event when it is new. */
	receive(json: string, live = true, track: NostrTrack = "chat") {
		const ev = json.length > PAYLOAD_MAX ? undefined : parseVerifiedEvent(json);
		if (!ev || !plausibleTime(ev, live, this.#start) || !onTrack(ev, track)) {
			this.invalid++;
			return undefined;
		}
		if (!this.#accept(ev) || this.#seen.has(ev.id) || !this.#replace(ev))
			return undefined;
		this.#seen.add(ev.id);
		this.#history.push({ ev, raw: json });
		if (this.#history.length > HISTORY_MAX) this.#forget(0);
		for (const s of this.#subs)
			if (matches(s.filter, ev)) s.handlers.onEvent(ev, json);
		return ev;
	}

	// A replaceable/addressable ev newer than the one held under its key
	// takes its place (true); an older one is refused. Regular: true.
	#replace(ev: Event): boolean {
		const key = replaceKey(ev);
		if (key === undefined) return true;
		const held = this.#latest.get(key);
		if (held && !newer(ev, held)) return false;
		const i = this.#history.findIndex((h) => h.ev === held);
		if (i >= 0) this.#forget(i);
		this.#latest.delete(key);
		this.#latest.set(key, ev);
		const oldest = this.#latest.keys().next().value;
		if (this.#latest.size > LATEST_MAX && oldest !== undefined)
			this.#latest.delete(oldest);
		return true;
	}

	#forget(i: number): void {
		const [h] = this.#history.splice(i, 1);
		this.#seen.delete(h.ev.id);
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
