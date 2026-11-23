// Nostr chat: NIP-07 login/signing and NIP-53 kind 1311 live chat events.
// The browser never holds a secret key -- the extension (window.nostr) signs.
// Chat events travel only over the MoQ hub (moqNostr.ts); the public relays
// below are read-only: kind 0 profile REQs, never EVENT or AUTH.

import { AbstractSimplePool } from "nostr-tools/abstract-pool";
import type { Filter } from "nostr-tools/filter";
import { npubEncode } from "nostr-tools/nip19";
import { type Event, type EventTemplate, verifyEvent } from "nostr-tools/pure";

// The NIP-07 surface we use. Typed as returning a plain Event: what an
// extension returns is untrusted until checkOwnChatEvent verifies it.
type Nip07 = {
	getPublicKey(): Promise<string>;
	signEvent(t: EventTemplate): Promise<Event>;
};

export const LIVE_CHAT_KIND = 1311; // NIP-53 live chat message

// shortcut: no kind 30311 room event is published yet, so the room
// coordinate ("30311:<host pubkey>:<d>") is a build-time constant with a
// placeholder host; publish the 30311 event and read its coordinate when the
// room gets a real host.
export const NOSTR_ROOM_A =
	process.env.NEXT_PUBLIC_NOSTR_ROOM_A ||
	`30311:${"0".repeat(64)}:wired-moqt-chat`;

function nip07(): Nip07 | undefined {
	return (window as { nostr?: Nip07 }).nostr;
}

// Extensions inject window.nostr at document_end, possibly after our first
// render, so poll briefly before giving up.
async function waitForNip07(timeoutMs: number): Promise<Nip07> {
	const deadline = Date.now() + timeoutMs;
	for (;;) {
		const n = nip07();
		if (n) return n;
		if (Date.now() >= deadline) throw new Error(LOGIN_ERROR.missing);
		await new Promise((r) => setTimeout(r, 50));
	}
}

/** nostrLogin's failure messages, shown as is on the join screen. */
export const LOGIN_ERROR = {
	missing: "No NIP-07 extension found (e.g. nos2x, Alby).",
	rejected: "The extension declined to share a public key.",
	invalid: "The extension returned an invalid public key.",
};

const HEX64 = /^[0-9a-f]{64}$/;

/** Asks the NIP-07 extension for the user's public key (hex); throws one
 * of LOGIN_ERROR. */
export async function nostrLogin(timeoutMs = 1500): Promise<string> {
	const n = await waitForNip07(timeoutMs);
	const pk = await n.getPublicKey().catch(() => {
		throw new Error(LOGIN_ERROR.rejected);
	});
	if (typeof pk !== "string" || !HEX64.test(pk))
		throw new Error(LOGIN_ERROR.invalid);
	return pk;
}

/** Has the extension sign a kind 1311 event for the room (unchecked: see
 * checkOwnChatEvent). */
export async function signChatEvent(text: string): Promise<Event> {
	return (await waitForNip07(0)).signEvent({
		kind: LIVE_CHAT_KIND,
		created_at: Math.floor(Date.now() / 1000),
		tags: [["a", NOSTR_ROOM_A]],
		content: text,
	});
}

function hasRoomTag(ev: Event): boolean {
	return (
		Array.isArray(ev.tags) &&
		ev.tags.some((t) => t[0] === "a" && t[1] === NOSTR_ROOM_A)
	);
}

function isOwnChat(ev: Event, pubkey: string, text: string): boolean {
	return (
		ev.pubkey === pubkey &&
		ev.content === text &&
		ev.kind === LIVE_CHAT_KIND &&
		hasRoomTag(ev)
	);
}

/** The extension's signed event, checked before it is published: a valid
 * id and signature (on a JSON copy, so no cached "verified" mark counts),
 * our pubkey, the typed text, kind 1311 and the room tag. Throws otherwise. */
export function checkOwnChatEvent(
	ev: Event,
	pubkey: string,
	text: string,
): Event {
	const copy = JSON.parse(JSON.stringify(ev ?? null));
	if (!isObject(copy) || !verifyEvent(copy) || !isOwnChat(copy, pubkey, text))
		throw new Error("the extension returned a mismatched or invalid event");
	return ev;
}

function isObject(v: unknown): v is Event {
	return typeof v === "object" && v !== null;
}

/** Parses a received payload and verifies its id and BIP-340 signature;
 * undefined for anything else.
 * shortcut: the hub relays events without verifying them; clients drop
 * invalid ones, but invalid events still occupy history (fill) slots --
 * verify at the hub when history slots become contended or abused. */
export function parseVerifiedEvent(json: string): Event | undefined {
	let ev: unknown;
	try {
		ev = JSON.parse(json);
	} catch {
		return undefined;
	}
	return isObject(ev) && verifyEvent(ev) ? ev : undefined;
}

/** "npub1abcdef…wxyz": short display form of a hex pubkey. */
export function shortNpub(pubkeyHex: string): string {
	const npub = npubEncode(pubkeyHex);
	return `${npub.slice(0, 11)}…${npub.slice(-4)}`;
}

// --- kind 0 profile names (NIP-01 metadata) --------------------------------

export const DEFAULT_NOSTR_RELAYS = [
	"wss://relay-jp.nostr.wirednet.jp",
	"wss://yabu.me",
	"wss://r.kojira.io",
	"wss://relay.damus.io",
	"wss://relay.primal.net",
];

const RELAY_MAX = 10;
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

function isRelayUrl(s: string): boolean {
	try {
		const u = new URL(s);
		return (
			u.protocol === "wss:" ||
			(u.protocol === "ws:" && LOCAL_HOSTS.has(u.hostname))
		);
	} catch {
		return false;
	}
}

/** The user's relay list (one URL per line, or comma-separated): wss://
 * only (ws:// for localhost), trimmed, deduped, at most RELAY_MAX. */
export function parseRelayList(text: string): string[] {
	const urls = text.split(/[\s,]+/).filter(isRelayUrl);
	return [...new Set(urls)].slice(0, RELAY_MAX);
}

/** Profile relays: `?relays=a,b` overrides the user's list, `?relays=` means
 * none (the e2e harness uses this to stay off public relays). */
export function nostrRelays(
	search: string,
	fallback: string[] = DEFAULT_NOSTR_RELAYS,
): string[] {
	const p = new URLSearchParams(search).get("relays");
	return p === null ? fallback : parseRelayList(p);
}

const PROFILE_WAIT_MS = 3000;
const NAME_MAX = 64;

export type ProfileQuery = (
	relays: string[],
	filter: Filter,
) => Promise<Event[]>;

let pool: AbstractSimplePool | undefined;
// Read-only: the only call on the public relays is this REQ. querySync
// closes it on EOSE from every relay or after maxWait. No onauth, so the
// pool never answers an AUTH challenge either.
const poolQuery: ProfileQuery = (relays, filter) => {
	pool ??= new AbstractSimplePool({
		verifyEvent,
		websocketImplementation: globalThis.WebSocket,
		maxWaitForConnection: PROFILE_WAIT_MS,
		allowConnectingToRelay: (_url, [op]) => op === "read",
	});
	return pool.querySync(relays, filter, { maxWait: PROFILE_WAIT_MS });
};

function isOwnProfile(pubkey: string, e: Event): boolean {
	return e.kind === 0 && e.pubkey === pubkey && verifyEvent(e);
}

export type NostrProfile = { name?: string; picture?: string };

const PICTURE_URL_MAX = 2048;

/** A kind 0 `picture` usable as an <img src>: https: only (no http, data:,
 * javascript:, blob: ...), at most PICTURE_URL_MAX chars. */
export function safePictureUrl(v: unknown): string | undefined {
	if (typeof v !== "string" || v.length > PICTURE_URL_MAX) return undefined;
	try {
		const u = new URL(v);
		// Credentials in a subresource URL are blocked by browsers anyway.
		return u.protocol === "https:" && !u.username && !u.password
			? u.href
			: undefined;
	} catch {
		return undefined;
	}
}

function nameOf(m: { display_name?: unknown; name?: unknown }) {
	const pick = [m.display_name, m.name].find(
		(v) => typeof v === "string" && v.trim() !== "",
	) as string | undefined;
	return pick?.trim().slice(0, NAME_MAX);
}

function profileFrom(content: string): NostrProfile | undefined {
	try {
		const m = JSON.parse(content);
		const p = { name: nameOf(m), picture: safePictureUrl(m.picture) };
		return p.name || p.picture ? p : undefined;
	} catch {
		return undefined;
	}
}

/** The name (display_name, else name) and picture of the newest valid kind
 * 0 event by pubkey. Untrusted text: React renders it as text, never HTML. */
export function profileOf(
	pubkey: string,
	events: Event[],
): NostrProfile | undefined {
	const newest = events
		.filter((e) => isOwnProfile(pubkey, e))
		.sort((a, b) => b.created_at - a.created_at)[0];
	return newest && profileFrom(newest.content);
}

export function profileName(pubkey: string, events: Event[]) {
	return profileOf(pubkey, events)?.name;
}

const PROFILE_DEBOUNCE_MS = 300;
const PROFILE_CHUNK = 50; // authors per REQ
const PROFILE_REQS_PER_MINUTE = 6;
const PROFILE_CACHE_MAX = 256;
const PROFILE_RETRY_MS = 5 * 60_000; // a miss/failure is retried after this

type Cached = { profile?: NostrProfile; at: number; relays: string };

/** Resolves kind 0 profiles (name, picture) for many authors with few REQs: new pubkeys are
 * debounced into one REQ (authors: [...], chunked), REQs are capped per
 * minute, and the cache is bounded (drop-oldest). A miss or failure is
 * cached only until PROFILE_RETRY_MS passes or the relay list changes. */
export class ProfileResolver {
	#cache = new Map<string, Cached>();
	#pending = new Set<string>();
	#relays: string[] = [];
	#sent: number[] = []; // REQ times within the last minute
	#timer: ReturnType<typeof setTimeout> | undefined;

	constructor(
		readonly onProfile: (pubkey: string, profile: NostrProfile) => void,
		readonly query: ProfileQuery = poolQuery,
	) {}

	#fresh(c: Cached | undefined, relays: string): boolean {
		if (!c) return false;
		return (
			c.profile !== undefined ||
			(Date.now() - c.at < PROFILE_RETRY_MS && c.relays === relays)
		);
	}

	request(pubkey: string, relays: string[]): void {
		if (relays.length === 0) return;
		const c = this.#cache.get(pubkey);
		if (this.#fresh(c, relays.join(","))) {
			if (c?.profile) this.onProfile(pubkey, c.profile);
			return;
		}
		if (this.#pending.size >= PROFILE_CACHE_MAX) return;
		this.#pending.add(pubkey);
		this.#relays = relays;
		this.#schedule(PROFILE_DEBOUNCE_MS);
	}

	#schedule(ms: number): void {
		this.#timer ??= setTimeout(() => {
			this.#timer = undefined;
			this.#flush();
		}, ms);
	}

	#remember(pubkey: string, c: Cached): void {
		this.#cache.delete(pubkey);
		this.#cache.set(pubkey, c);
		const oldest = this.#cache.keys().next().value;
		if (this.#cache.size > PROFILE_CACHE_MAX && oldest !== undefined)
			this.#cache.delete(oldest);
	}

	#flush(): void {
		const now = Date.now();
		this.#sent = this.#sent.filter((t) => now - t < 60_000);
		while (this.#pending.size > 0) {
			if (this.#sent.length >= PROFILE_REQS_PER_MINUTE) {
				this.#schedule(this.#sent[0] + 60_000 - now);
				return;
			}
			const chunk = [...this.#pending].slice(0, PROFILE_CHUNK);
			for (const pk of chunk) this.#pending.delete(pk);
			this.#sent.push(now);
			this.#send(chunk, this.#relays);
		}
	}

	#send(authors: string[], relays: string[]): void {
		const key = relays.join(",");
		const miss = { at: Date.now(), relays: key };
		for (const pk of authors) this.#remember(pk, miss); // in flight
		this.query(relays, { kinds: [0], authors, limit: authors.length })
			.then((evs) => {
				for (const pk of authors) {
					const profile = profileOf(pk, evs);
					this.#remember(pk, { ...miss, profile });
					if (profile) this.onProfile(pk, profile);
				}
			})
			.catch(() => {});
	}
}
