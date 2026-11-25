// NIP-53 meeting spaces (30312 space, 30313 meeting, 10312 presence),
// NIP-25 reactions (7) and NIP-09 deletions (5): the unsigned templates we
// ask NIP-07 to sign, and the checks a received event must pass. Every
// event reaching accept* / countReactions / isDeleted is already
// id/signature-verified (moqNostr.receive); these check meaning only.

import { decode } from "nostr-tools/nip19";
import type { Event, EventTemplate } from "nostr-tools/pure";

/** What a reaction or deletion needs to know about its target post. */
export type Target = Pick<Event, "id" | "pubkey" | "kind">;

export const SPACE_KIND = 30312;
export const MEETING_KIND = 30313;
export const PRESENCE_KIND = 10312;
export const REACTION_KIND = 7;
export const DELETION_KIND = 5;

/** Presence older than this is ignored (NIP-53: clients SHOULD ignore
 * stale presence; we refresh every 60 s). */
export const PRESENCE_STALE_S = 3 * 60;
const REACTION_MAX = 32; // "+", "-", an emoji or a :shortcode:

const HEX64 = /^[0-9a-f]{64}$/;
const SPACE_STATUS = ["open", "private", "closed"];
const MEETING_STATUS = ["planned", "live", "ended"];

/** The host's pubkey from config: 64 lowercase hex chars or an npub. */
export function hostPubkey(v: string): string | undefined {
	if (HEX64.test(v)) return v;
	try {
		const r = decode(v);
		return r.type === "npub" ? r.data : undefined;
	} catch {
		return undefined;
	}
}

export const spaceA = (host: string, d: string) => `${SPACE_KIND}:${host}:${d}`;
export const meetingA = (host: string, d: string) =>
	`${MEETING_KIND}:${host}:${d}`;

/** [pubkey, d] of a "<kind>:<pubkey>:<d>" coordinate (d may hold ':'). */
function coordinate(a: string): [string, string] {
	const [, pk = "", ...d] = a.split(":");
	return [pk, d.join(":")];
}

/** The first `name` tag's value. */
export function tag(ev: Event, name: string): string | undefined {
	return ev.tags.find((t) => t[0] === name)?.[1];
}

const hasAll = (ev: Event, names: string[]) => names.every((n) => tag(ev, n));
const oneOf = (ev: Event, name: string, values: string[]) =>
	values.includes(tag(ev, name) ?? "");

function lastTag(ev: Event, name: string): string | undefined {
	return ev.tags.findLast((t) => t[0] === name)?.[1];
}

const now_s = () => Math.floor(Date.now() / 1000);

// --- 30312 space ----------------------------------------------------------

export function spaceTemplate(o: {
	host: string;
	d: string;
	room: string;
	service: string;
	/** `private` for a room that needs a Nostr login (an identity, not an
	 * invite list as NIP-53 reads it: wire.md 5.3). */
	status?: "open" | "private";
	now?: number;
}): EventTemplate {
	return {
		kind: SPACE_KIND,
		created_at: o.now ?? now_s(),
		tags: [
			["d", o.d],
			["room", o.room],
			["status", o.status ?? "open"],
			["service", o.service],
			["p", o.host, "", "Host"],
		],
		content: "",
	};
}

function hasHost(ev: Event): boolean {
	return ev.tags.some(
		(t) => t[0] === "p" && t[1] === ev.pubkey && t[3] === "Host",
	);
}

/** Our space (pubkey and d of `space`) with every required tag. */
export function acceptSpace(ev: Event, space: string): boolean {
	const [host, d] = coordinate(space);
	return (
		ev.kind === SPACE_KIND &&
		ev.pubkey === host &&
		tag(ev, "d") === d &&
		hasAll(ev, ["room", "service"]) &&
		oneOf(ev, "status", SPACE_STATUS) &&
		hasHost(ev)
	);
}

// --- 30313 meeting --------------------------------------------------------

export type MeetingStatus = "planned" | "live" | "ended";

export function meetingTemplate(o: {
	space: string;
	d: string;
	title: string;
	status: MeetingStatus;
	starts: number;
	/** When the room ends (created + ROOM_LIFETIME_S, roomAuth.ts); an
	 * ended meeting's `ends` is when it ended. */
	ends?: number;
	participants?: number;
	now?: number;
}): EventTemplate {
	const now = o.now ?? now_s();
	const tags = [
		["d", o.d],
		["a", o.space],
		["title", o.title],
		["starts", String(o.starts)],
		["status", o.status],
	];
	if (o.participants !== undefined)
		tags.push(["current_participants", String(o.participants)]);
	const ends = o.status === "ended" ? now : o.ends;
	if (ends !== undefined) tags.push(["ends", String(ends)]);
	return { kind: MEETING_KIND, created_at: now, tags, content: "" };
}

/** A meeting of our space, published by the space's host. */
export function acceptMeeting(ev: Event, space: string): boolean {
	return (
		ev.kind === MEETING_KIND &&
		ev.pubkey === coordinate(space)[0] &&
		tag(ev, "a") === space &&
		hasAll(ev, ["d", "title"]) &&
		/^\d+$/.test(tag(ev, "starts") ?? "") &&
		oneOf(ev, "status", MEETING_STATUS)
	);
}

// --- participant binding ----------------------------------------------------

/** Our tag naming the participant id (MoQ track owner) that signed it:
 * only the participant whose own track delivers the event is mapped to its
 * pubkey, so a peer re-carrying someone else's event claims nothing. */
export const PARTICIPANT_TAG = "wired-participant";

const withParticipant = (tags: string[][], participant?: string) =>
	participant ? [...tags, [PARTICIPANT_TAG, participant]] : tags;

/** ev was signed for the participant whose track delivered it. */
export const signedFor = (ev: Event, participant: string) =>
	tag(ev, PARTICIPANT_TAG) === participant;

// --- 10312 presence -------------------------------------------------------

export function presenceTemplate(
	space: string,
	hand: boolean,
	now = now_s(),
	participant?: string,
	muted = false,
): EventTemplate {
	const tags = [["a", space, "", "root"]];
	if (hand) tags.push(["hand", "1"]);
	// Our tag: room events stay on the hub, other NIP-53 clients ignore it.
	if (muted) tags.push(["muted", "1"]);
	return {
		kind: PRESENCE_KIND,
		created_at: now,
		tags: withParticipant(tags, participant),
		content: "",
	};
}

/** Anyone's presence in our space, at most PRESENCE_STALE_S old. */
export function acceptPresence(ev: Event, space: string, now = now_s()) {
	return (
		ev.kind === PRESENCE_KIND &&
		tag(ev, "a") === space &&
		ev.created_at >= now - PRESENCE_STALE_S
	);
}

export const handRaised = (ev: Event) => tag(ev, "hand") === "1";
export const micMuted = (ev: Event) => tag(ev, "muted") === "1";

// --- 1311 chat ------------------------------------------------------------

/** NIP-53 is silent on chat in meeting spaces; we root it at the space and
 * add the live meeting (wire.md: the deviation note). */
export function chatTags(
	space: string,
	meeting?: string,
	participant?: string,
): string[][] {
	const tags = [["a", space, "", "root"]];
	if (meeting) tags.push(["a", meeting]);
	return withParticipant(tags, participant);
}

// --- NIP-01 replaceable / addressable -------------------------------------

const replaceable = (k: number) =>
	k === 0 || k === 3 || (k >= 10000 && k < 20000);
const addressable = (k: number) => k >= 30000 && k < 40000;

/** The key one event replaces another under, or undefined for a regular
 * or ephemeral kind. */
export function replaceKey(ev: Event): string | undefined {
	if (replaceable(ev.kind)) return `${ev.kind}:${ev.pubkey}`;
	if (addressable(ev.kind))
		return `${ev.kind}:${ev.pubkey}:${tag(ev, "d") ?? ""}`;
	return undefined;
}

/** a replaces b (same key): later created_at, on a tie the lowest id. */
export function newer(a: Event, b: Event): boolean {
	if (a.created_at !== b.created_at) return a.created_at > b.created_at;
	return a.id < b.id;
}

// --- 7 reactions ----------------------------------------------------------

export function reactionTemplate(
	target: Target,
	content: string,
	now = now_s(),
): EventTemplate {
	return {
		kind: REACTION_KIND,
		created_at: now,
		tags: [
			["e", target.id],
			["p", target.pubkey],
			["k", String(target.kind)],
		],
		content,
	};
}

// NIP-25: the last e / p tags name the reacted event and its author.
function reactsTo(ev: Event, target: Target): boolean {
	return (
		ev.kind === REACTION_KIND &&
		lastTag(ev, "e") === target.id &&
		lastTag(ev, "p") === target.pubkey &&
		ev.content.length > 0 &&
		ev.content.length <= REACTION_MAX
	);
}

/** Distinct contents one author is counted with per post. */
export const REACTIONS_PER_AUTHOR = 4;
/** A shown count never exceeds this. */
export const REACTION_COUNT_MAX = 999;

/** content -> count for target, one per (pubkey, content), at most
 * REACTIONS_PER_AUTHOR contents per author and REACTION_COUNT_MAX each. */
export function countReactions(
	target: Target,
	events: Iterable<Event>,
): Map<string, number> {
	const seen = new Set<string>();
	const perAuthor = new Map<string, number>();
	const counts = new Map<string, number>();
	for (const ev of events) {
		const key = `${ev.pubkey}\n${ev.content}`;
		const mine = perAuthor.get(ev.pubkey) ?? 0;
		if (!reactsTo(ev, target) || seen.has(key)) continue;
		if (mine >= REACTIONS_PER_AUTHOR) continue;
		seen.add(key);
		perAuthor.set(ev.pubkey, mine + 1);
		const n = (counts.get(ev.content) ?? 0) + 1;
		counts.set(ev.content, Math.min(n, REACTION_COUNT_MAX));
	}
	return counts;
}

/** The contents pubkey already reacted to target with. */
export function reactedWith(
	target: Target,
	events: Iterable<Event>,
	pubkey: string,
): Set<string> {
	const mine = new Set<string>();
	for (const ev of events)
		if (ev.pubkey === pubkey && reactsTo(ev, target)) mine.add(ev.content);
	return mine;
}

// --- 5 deletion -----------------------------------------------------------

export function deletionTemplate(target: Target, now = now_s()): EventTemplate {
	return {
		kind: DELETION_KIND,
		created_at: now,
		tags: [
			["e", target.id],
			["k", String(target.kind)],
		],
		content: "",
	};
}

/** NIP-09: honoured only when the deletion's author wrote the target. */
export function isDeleted(target: Target, deletions: Iterable<Event>): boolean {
	for (const d of deletions)
		if (
			d.kind === DELETION_KIND &&
			d.pubkey === target.pubkey &&
			d.tags.some((t) => t[0] === "e" && t[1] === target.id)
		)
			return true;
	return false;
}
