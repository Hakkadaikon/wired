import { npubEncode } from "nostr-tools/nip19";
import {
	type Event,
	type EventTemplate,
	finalizeEvent,
	getPublicKey,
} from "nostr-tools/pure";
import { describe, expect, it } from "vitest";
import {
	acceptMeeting,
	acceptPresence,
	acceptSpace,
	chatTags,
	countReactions,
	deletionTemplate,
	handRaised,
	hostPubkey,
	isDeleted,
	meetingA,
	meetingTemplate,
	newer,
	PARTICIPANT_TAG,
	PRESENCE_STALE_S,
	presenceTemplate,
	REACTION_COUNT_MAX,
	REACTIONS_PER_AUTHOR,
	reactedWith,
	reactionTemplate,
	replaceKey,
	signedFor,
	spaceA,
	spaceTemplate,
} from "../nostrRoom";

// Fixed test-only secret keys.
const HOST_SK = new Uint8Array(32).fill(7);
const GUEST_SK = new Uint8Array(32).fill(8);
const OTHER_SK = new Uint8Array(32).fill(9);
const HOST = getPublicKey(HOST_SK);
const GUEST = getPublicKey(GUEST_SK);
const D = "wired-moqt-chat";
const SPACE = spaceA(HOST, D);
const NOW = 1_800_000_000;

// finalizeEvent fills in the object it is given: sign a copy.
const sign = (t: EventTemplate, sk = HOST_SK) => finalizeEvent({ ...t }, sk);
const retag = (t: EventTemplate, tags: string[][]) => ({ ...t, tags });
const swap = (t: EventTemplate, name: string, value: string) =>
	retag(
		t,
		t.tags.map((x) => (x[0] === name ? [name, value] : x)),
	);
const without = (t: EventTemplate, name: string) =>
	retag(
		t,
		t.tags.filter((x) => x[0] !== name),
	);

describe("hostPubkey / spaceA", () => {
	it("takes hex or npub, rejects anything else", () => {
		expect(hostPubkey(HOST)).toBe(HOST);
		expect(hostPubkey(npubEncode(HOST))).toBe(HOST);
		expect(hostPubkey(HOST.toUpperCase())).toBeUndefined();
		expect(hostPubkey("npub1junk")).toBeUndefined();
		expect(hostPubkey("")).toBeUndefined();
	});

	it("builds the NIP-01 coordinates", () => {
		expect(SPACE).toBe(`30312:${HOST}:${D}`);
		expect(meetingA(HOST, "m1")).toBe(`30313:${HOST}:m1`);
	});
});

describe("kind 30312 space", () => {
	const t = spaceTemplate({
		host: HOST,
		d: D,
		room: "Wired room",
		service: "https://chat.example/",
		now: NOW,
	});

	it("an auth room's space is status private (NIP-53 deviation: identity, not invite)", () => {
		const p = spaceTemplate({
			host: HOST,
			d: D,
			room: "Wired room",
			service: "https://chat.example/",
			status: "private",
			now: NOW,
		});
		expect(p.tags).toContainEqual(["status", "private"]);
		expect(acceptSpace(sign(p), SPACE)).toBe(true);
	});

	it("carries d, room, status open, service and the host as p Host", () => {
		expect(t.kind).toBe(30312);
		expect(t.tags).toEqual([
			["d", D],
			["room", "Wired room"],
			["status", "open"],
			["service", "https://chat.example/"],
			["p", HOST, "", "Host"],
		]);
	});

	it("is accepted from the host for our coordinate", () => {
		expect(acceptSpace(sign(t), SPACE)).toBe(true);
	});

	it.each<[string, Event]>([
		["another pubkey", sign(t, GUEST_SK)],
		["another d", sign(swap(t, "d", "x"))],
		["no room", sign(without(t, "room"))],
		["no service", sign(without(t, "service"))],
		["no p Host", sign(without(t, "p"))],
		["an unknown status", sign(swap(t, "status", "live"))],
		["a 30313 kind", sign({ ...t, kind: 30313 })],
	])("rejects %s", (_, ev) => {
		expect(acceptSpace(ev, SPACE)).toBe(false);
	});
});

describe("kind 30313 meeting", () => {
	const t = meetingTemplate({
		space: SPACE,
		d: "m1",
		title: "Standup",
		status: "live",
		starts: NOW,
		participants: 2,
		now: NOW,
	});

	it("carries d, a, title, starts, status and current_participants", () => {
		expect(t.kind).toBe(30313);
		expect(t.tags).toEqual([
			["d", "m1"],
			["a", SPACE],
			["title", "Standup"],
			["starts", String(NOW)],
			["status", "live"],
			["current_participants", "2"],
		]);
	});

	it("a live meeting carries the room's ends when given", () => {
		const live = meetingTemplate({
			space: SPACE,
			d: "m1",
			title: "Standup",
			status: "live",
			starts: NOW,
			ends: NOW + 18000,
			now: NOW,
		});
		expect(live.tags).toContainEqual(["ends", String(NOW + 18000)]);
	});

	it("adds ends once ended", () => {
		const ended = meetingTemplate({
			space: SPACE,
			d: "m1",
			title: "Standup",
			status: "ended",
			starts: NOW,
			now: NOW + 60,
		});
		expect(ended.tags).toContainEqual(["ends", String(NOW + 60)]);
		expect(acceptMeeting(sign(ended), SPACE)).toBe(true);
	});

	it("is accepted from the host for our space", () => {
		expect(acceptMeeting(sign(t), SPACE)).toBe(true);
	});

	it.each<[string, Event]>([
		["another pubkey", sign(t, GUEST_SK)],
		["another space", sign(swap(t, "a", spaceA(HOST, "x")))],
		["no title", sign(without(t, "title"))],
		["no starts", sign(without(t, "starts"))],
		["no d", sign(without(t, "d"))],
		["an unknown status", sign(swap(t, "status", "open"))],
	])("rejects %s", (_, ev) => {
		expect(acceptMeeting(ev, SPACE)).toBe(false);
	});
});

describe("kind 10312 presence", () => {
	it("roots the space and adds hand only when raised", () => {
		const down = presenceTemplate(SPACE, false, NOW);
		const up = presenceTemplate(SPACE, true, NOW);
		expect(down.kind).toBe(10312);
		expect(down.tags).toEqual([["a", SPACE, "", "root"]]);
		expect(up.tags).toEqual([
			["a", SPACE, "", "root"],
			["hand", "1"],
		]);
		expect(handRaised(sign(up, GUEST_SK))).toBe(true);
		expect(handRaised(sign(down, GUEST_SK))).toBe(false);
	});

	it("accepts a fresh one for our space, from anyone", () => {
		const ev = sign(presenceTemplate(SPACE, false, NOW), GUEST_SK);
		expect(acceptPresence(ev, SPACE, NOW)).toBe(true);
		expect(acceptPresence(ev, SPACE, NOW + PRESENCE_STALE_S)).toBe(true);
	});

	it("rejects a stale one, another space and another kind", () => {
		const ev = sign(presenceTemplate(SPACE, false, NOW), GUEST_SK);
		expect(acceptPresence(ev, SPACE, NOW + PRESENCE_STALE_S + 1)).toBe(false);
		expect(acceptPresence(ev, spaceA(HOST, "x"), NOW)).toBe(false);
		const k = sign({ ...presenceTemplate(SPACE, false, NOW), kind: 10311 });
		expect(acceptPresence(k, SPACE, NOW)).toBe(false);
	});
});

describe("kind 1311 chat tags", () => {
	it("roots the space and adds the live meeting when there is one", () => {
		expect(chatTags(SPACE)).toEqual([["a", SPACE, "", "root"]]);
		expect(chatTags(SPACE, meetingA(HOST, "m1"))).toEqual([
			["a", SPACE, "", "root"],
			["a", meetingA(HOST, "m1")],
		]);
	});
});

describe("replaceable newest-wins (NIP-01)", () => {
	const at = (created_at: number, sk = GUEST_SK, kind = 10312, d?: string) =>
		sign(
			{
				kind,
				created_at,
				tags: d === undefined ? [] : [["d", d]],
				content: String(Math.random()),
			},
			sk,
		);

	it("keys replaceable by kind:pubkey, addressable by kind:pubkey:d", () => {
		expect(replaceKey(at(NOW))).toBe(`10312:${GUEST}`);
		expect(replaceKey(at(NOW, GUEST_SK, 0))).toBe(`0:${GUEST}`);
		expect(replaceKey(at(NOW, HOST_SK, 30313, "m1"))).toBe(`30313:${HOST}:m1`);
		expect(replaceKey(at(NOW, HOST_SK, 30313))).toBe(`30313:${HOST}:`);
		expect(replaceKey(at(NOW, GUEST_SK, 1311))).toBeUndefined();
		expect(replaceKey(at(NOW, GUEST_SK, 20000))).toBeUndefined();
	});

	it("prefers the later created_at, then the lowest id", () => {
		const a = at(NOW);
		const b = at(NOW + 1);
		expect(newer(b, a)).toBe(true);
		expect(newer(a, b)).toBe(false);
		const c = at(NOW);
		const [lo, hi] = a.id < c.id ? [a, c] : [c, a];
		expect(newer(lo, hi)).toBe(true);
		expect(newer(hi, lo)).toBe(false);
		expect(newer(a, a)).toBe(false);
	});
});

const post = sign(
	{ kind: 1311, created_at: NOW, tags: chatTags(SPACE), content: "hi" },
	GUEST_SK,
);

describe("kind 7 reactions (NIP-25)", () => {
	it("tags the target id, its author and its kind", () => {
		const t = reactionTemplate(post, "+", NOW);
		expect(t.kind).toBe(7);
		expect(t.content).toBe("+");
		expect(t.tags).toEqual([
			["e", post.id],
			["p", GUEST],
			["k", "1311"],
		]);
	});

	it("counts one per (pubkey, content), per target", () => {
		const r = (content: string, sk = HOST_SK, at = NOW) =>
			sign(reactionTemplate(post, content, at), sk);
		const counts = countReactions(post, [
			r("+", HOST_SK),
			r("+", HOST_SK, NOW + 1), // same pubkey and content: once
			r("+", OTHER_SK),
			r("🔥", HOST_SK),
		]);
		expect(counts).toEqual(
			new Map([
				["+", 2],
				["🔥", 1],
			]),
		);
	});

	it("ignores other targets, a wrong p, bad content and other kinds", () => {
		const good = reactionTemplate(post, "+", NOW);
		const evs = [
			sign(retag(good, [["e", "f".repeat(64)], ...good.tags.slice(1)])),
			sign(retag(good, [good.tags[0], ["p", HOST], good.tags[2]])),
			sign({ ...good, content: "" }),
			sign({ ...good, content: "x".repeat(33) }),
			sign({ ...good, kind: 1311 }),
		];
		expect(countReactions(post, evs).size).toBe(0);
	});

	it("reads the target from the last e tag", () => {
		const t = reactionTemplate(post, "+", NOW);
		const ev = sign(retag(t, [["e", "a".repeat(64)], ...t.tags]));
		expect(countReactions(post, [ev]).get("+")).toBe(1);
	});
});

describe("kind 5 deletion (NIP-09)", () => {
	it("tags the target id and kind", () => {
		const t = deletionTemplate(post, NOW);
		expect(t.kind).toBe(5);
		expect(t.tags).toEqual([
			["e", post.id],
			["k", "1311"],
		]);
	});

	it("is honoured only from the target's own author", () => {
		const t = deletionTemplate(post, NOW);
		expect(isDeleted(post, [sign(t, GUEST_SK)])).toBe(true);
		expect(isDeleted(post, [sign(t, HOST_SK)])).toBe(false);
		expect(isDeleted(post, [sign({ ...t, kind: 7 }, GUEST_SK)])).toBe(false);
		const other = sign(retag(t, [["e", "b".repeat(64)]]), GUEST_SK);
		expect(isDeleted(post, [other])).toBe(false);
	});
});

describe("participant binding and reaction caps", () => {
	it("presence and chat carry the participant id; signedFor checks it", () => {
		const p = sign(presenceTemplate(SPACE, false, NOW, "user2"), GUEST_SK);
		expect(p.tags).toContainEqual([PARTICIPANT_TAG, "user2"]);
		expect(signedFor(p, "user2")).toBe(true);
		expect(signedFor(p, "user3")).toBe(false);
		expect(chatTags(SPACE, undefined, "user2")).toContainEqual([
			PARTICIPANT_TAG,
			"user2",
		]);
	});

	it("counts at most REACTIONS_PER_AUTHOR contents per author", () => {
		const evs = ["a", "b", "c", "d", "e"].map((c) =>
			sign(reactionTemplate(post, c, NOW), HOST_SK),
		);
		const counts = countReactions(post, evs);
		expect(counts.size).toBe(REACTIONS_PER_AUTHOR);
		expect(counts.has("e")).toBe(false);
		expect(reactedWith(post, evs, HOST)).toEqual(
			new Set(["a", "b", "c", "d", "e"]),
		);
		expect(reactedWith(post, evs, GUEST).size).toBe(0);
	});

	it("caps a shown count at REACTION_COUNT_MAX", () => {
		const r = sign(reactionTemplate(post, "+", NOW), HOST_SK);
		const many = Array.from({ length: REACTION_COUNT_MAX + 5 }, (_, i) => ({
			...r,
			pubkey: i.toString(16).padStart(64, "0"),
		}));
		// Untouched shape: countReactions trusts verification upstream.
		const fake = many.map((e) => ({
			...e,
			tags: [
				["e", post.id],
				["p", post.pubkey],
			],
		}));
		expect(countReactions(post, fake).get("+")).toBe(REACTION_COUNT_MAX);
	});
});
