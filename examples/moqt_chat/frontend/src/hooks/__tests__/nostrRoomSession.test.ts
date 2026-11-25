import {
	type Event,
	type EventTemplate,
	finalizeEvent,
	getPublicKey,
} from "nostr-tools/pure";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	MEETING_DEBOUNCE_MS,
	NostrRoomSession,
	nostrRoom,
	PRESENCE_EVERY_MS,
	republishPresence,
	toggleMute,
} from "@/hooks/nostrRoomSession";
import { afterRoomEnd, announceRoom } from "@/hooks/useMoqtChat";
import { MoqNostr } from "@/lib/moqNostr";
import {
	countReactions,
	deletionTemplate,
	isDeleted,
	meetingTemplate,
	presenceTemplate,
	reactionTemplate,
	spaceA,
	tag,
} from "@/lib/nostrRoom";
import { ROOM_LIFETIME_S } from "@/lib/roomAuth";
import { enterRoom } from "@/lib/roomLink";
import { EMPTY_NOSTR_ROOM, useMoqtChatStore } from "@/stores/moqtChatStore";

// Fixed test-only keys.
const HOST_SK = new Uint8Array(32).fill(1);
const GUEST_SK = new Uint8Array(32).fill(2);
const HOST = getPublicKey(HOST_SK);
const GUEST = getPublicKey(GUEST_SK);
const D = "test-space";
const SPACE = spaceA(HOST, D);
const NOW = 1_800_000_000;

const keyOf = (pk: string) => (pk === HOST ? HOST_SK : GUEST_SK);
const sign = async (t: EventTemplate, pk: string) =>
	finalizeEvent({ ...t }, keyOf(pk));

function session(pubkey: string | null, now = () => NOW) {
	useMoqtChatStore.setState({
		nostrPubkey: pubkey,
		nostrRoom: EMPTY_NOSTR_ROOM,
		peers: ["user2"],
	});
	const sent: { ev: Event; track: string }[] = [];
	const nostr = new MoqNostr(async (json, track) => {
		sent.push({ ev: JSON.parse(json), track });
	});
	let peersChanged = () => {};
	const room = new NostrRoomSession({
		nostr,
		sign,
		host: HOST,
		d: D,
		room: "Room",
		service: "https://chat.example/",
		participant: () => "user1",
		now,
		watchPeers: (fn) => {
			peersChanged = fn;
			return () => {
				peersChanged = () => {};
			};
		},
	});
	return { room, nostr, sent, peersChanged: () => peersChanged() };
}

const state = () => useMoqtChatStore.getState().nostrRoom;
const kinds = (sent: { ev: Event }[]) => sent.map((s) => s.ev.kind);

beforeEach(() => vi.useFakeTimers({ now: NOW * 1000 }));
afterEach(() => vi.useRealTimers());

describe("NostrRoomSession host lifecycle", () => {
	it("host start: presence, then the space, then a live meeting", async () => {
		const { room, sent } = session(HOST);
		await room.start();
		expect(sent.map((s) => s.track)).toEqual([
			"nostr-presence",
			"nostr-30312",
			"nostr-30313",
		]);
		const [, space, meeting] = sent.map((s) => s.ev);
		expect(tag(space, "service")).toBe("https://chat.example/");
		expect(tag(meeting, "status")).toBe("live");
		expect(tag(meeting, "current_participants")).toBe("2");
		expect(state().space?.id).toBe(space.id);
		expect(state().meeting?.id).toBe(meeting.id);
		expect(room.liveMeeting()).toBe(`30313:${HOST}:${tag(meeting, "d")}`);
		room.stop();
	});

	it("the live meeting ends ROOM_LIFETIME_S after the room was created", async () => {
		enterRoom(
			{ id: D, host: HOST },
			{ mode: "open", nip05: "h@x.y", created: NOW - 60 },
		);
		const { room, sent } = session(HOST);
		await room.start();
		expect(tag(sent[2].ev, "ends")).toBe(String(NOW - 60 + ROOM_LIFETIME_S));
		expect(tag(sent[1].ev, "status")).toBe("open");
		room.stop();
		enterRoom(
			{ id: D, host: HOST },
			{ mode: "auth", nip05: "h@x.y", created: NOW },
		);
		const auth = session(HOST);
		await auth.room.start();
		expect(tag(auth.sent[1].ev, "status")).toBe("private");
		auth.room.stop();
		// P7: a reload of the creating tab keeps created and mode.
		enterRoom({ id: D, host: HOST });
		const reload = session(HOST);
		await reload.room.start();
		expect(tag(reload.sent[1].ev, "status")).toBe("private");
		expect(tag(reload.sent[2].ev, "ends")).toBe(String(NOW + ROOM_LIFETIME_S));
		reload.room.stop();
		sessionStorage.clear();
		enterRoom({ id: D, host: HOST }); // not the creator: from the meeting start
		const again = session(HOST);
		await again.room.start();
		const [, space, m] = again.sent.map((x) => x.ev);
		expect(tag(m, "ends")).toBe(String(space.created_at + ROOM_LIFETIME_S));
		again.room.stop();
	});

	it("participant changes make one debounced meeting update", async () => {
		const { room, sent, peersChanged } = session(HOST);
		await room.start();
		useMoqtChatStore.setState({ peers: ["user2", "user3"] });
		peersChanged();
		peersChanged();
		await vi.advanceTimersByTimeAsync(MEETING_DEBOUNCE_MS);
		expect(kinds(sent)).toEqual([10312, 30312, 30313, 30313]);
		const update = sent[3].ev;
		expect(tag(update, "current_participants")).toBe("3");
		// Same second as the first meeting event: created_at still moves on.
		expect(update.created_at).toBeGreaterThan(sent[2].ev.created_at);
		expect(state().meeting?.id).toBe(update.id);
		room.stop();
	});

	it("end publishes the meeting ended and stops refreshing", async () => {
		const { room, sent } = session(HOST);
		await room.start();
		await room.end();
		const ended = sent[3].ev;
		expect(tag(ended, "status")).toBe("ended");
		expect(tag(ended, "d")).toBe(tag(sent[2].ev, "d"));
		expect(room.liveMeeting()).toBeUndefined();
		await vi.advanceTimersByTimeAsync(PRESENCE_EVERY_MS * 2);
		expect(sent).toHaveLength(4);
	});

	it("a guest publishes presence only; refreshed every minute", async () => {
		const { room, sent } = session(GUEST);
		await room.start();
		await vi.advanceTimersByTimeAsync(PRESENCE_EVERY_MS);
		expect(kinds(sent)).toEqual([10312, 10312]);
		await room.end();
		expect(sent).toHaveLength(2);
	});

	it("without a Nostr login nothing is published", async () => {
		const { room, sent } = session(null);
		await room.start();
		await vi.advanceTimersByTimeAsync(PRESENCE_EVERY_MS);
		expect(sent).toEqual([]);
		await expect(room.setHand(true)).rejects.toThrow(/not logged in/);
	});
});

describe("NostrRoomSession receive and actions", () => {
	const wire = (t: EventTemplate, sk: Uint8Array) =>
		JSON.stringify(finalizeEvent({ ...t }, sk));

	it("hand toggle publishes a presence with the hand tag", async () => {
		const { room, sent } = session(GUEST);
		await room.setHand(true);
		expect(sent[0].ev.tags).toContainEqual(["hand", "1"]);
		expect(state().hand).toBe(true);
		expect(state().presence[GUEST].id).toBe(sent[0].ev.id);
	});

	it("received room events land in the store only when accepted", () => {
		const { nostr } = session(GUEST);
		// d differs per case: one key per (kind, author, d) in MoqNostr.
		const meeting = (sk: Uint8Array, space = SPACE) =>
			meetingTemplate({
				space,
				d: `m-${sk[0]}-${space.length}`,
				title: "T",
				status: "live",
				starts: NOW,
				now: NOW,
			});
		nostr.receive(wire(meeting(GUEST_SK), GUEST_SK), true, "nostr-30313");
		nostr.receive(
			wire(meeting(HOST_SK, spaceA(HOST, "x")), HOST_SK),
			true,
			"nostr-30313",
		);
		expect(state().meeting).toBeNull();
		nostr.receive(wire(meeting(HOST_SK), HOST_SK), true, "nostr-30313");
		expect(state().meeting?.pubkey).toBe(HOST);

		const stale = presenceTemplate(SPACE, true, NOW - 600);
		nostr.receive(wire(stale, HOST_SK), false, "nostr-presence");
		expect(state().presence).toEqual({});
		nostr.receive(
			wire(presenceTemplate(SPACE, true, NOW), HOST_SK),
			true,
			"nostr-presence",
		);
		expect(state().presence[HOST]).toBeDefined();
	});

	it("reactions count once per author, deletions only from the author", async () => {
		const { room, nostr } = session(GUEST);
		const post = finalizeEvent(
			{ kind: 1311, created_at: NOW, tags: [], content: "hi" },
			GUEST_SK,
		);
		await room.react(post, "+");
		nostr.receive(
			wire(reactionTemplate(post, "+", NOW), HOST_SK),
			true,
			"nostr-react",
		);
		nostr.receive(
			wire(reactionTemplate(post, "+", NOW + 1), HOST_SK),
			true,
			"nostr-react",
		);
		expect(countReactions(post, state().reactions).get("+")).toBe(2);

		nostr.receive(
			wire(deletionTemplate(post, NOW), HOST_SK),
			true,
			"nostr-react",
		);
		expect(isDeleted(post, state().deletions[post.id] ?? [])).toBe(false);
		await room.remove(post);
		expect(isDeleted(post, state().deletions[post.id] ?? [])).toBe(true);
	});
});

describe("afterRoomEnd (leave)", () => {
	it("tears down after the host's meeting ended went out, unless rejoined", async () => {
		const { room, sent } = session(HOST);
		await room.start();
		const { nostrRoom } = await import("@/hooks/nostrRoomSession");
		nostrRoom.current = room;
		useMoqtChatStore.setState({ connectionState: "connected" });
		const ref = { current: {} as unknown };
		const done = vi.fn();
		afterRoomEnd(ref, done);
		expect(useMoqtChatStore.getState().connectionState).toBe("disconnected");
		await vi.advanceTimersByTimeAsync(0);
		expect(done).toHaveBeenCalledOnce();
		expect(tag(sent.at(-1)?.ev as Event, "status")).toBe("ended");

		const replaced = vi.fn();
		afterRoomEnd(ref, replaced);
		ref.current = {}; // a new join's client
		await vi.advanceTimersByTimeAsync(2000);
		expect(replaced).not.toHaveBeenCalled();
		nostrRoom.current = null;
	});
});

describe("NostrRoomSession hardening", () => {
	it("presence carries our participant id", async () => {
		const { room, sent } = session(GUEST);
		await room.setHand(false);
		expect(sent[0].ev.tags).toContainEqual(["wired-participant", "user1"]);
	});

	it("a mute toggle republishes presence with the muted tag (D-15)", async () => {
		const { room, sent } = session(GUEST);
		nostrRoom.current = room;
		useMoqtChatStore.setState({ muted: true });
		republishPresence();
		await vi.advanceTimersByTimeAsync(0);
		expect(sent[0].ev.tags).toContainEqual(["muted", "1"]);
		useMoqtChatStore.setState({ muted: false });
		republishPresence();
		await vi.advanceTimersByTimeAsync(0);
		expect(sent[1].ev.tags.some((t) => t[0] === "muted")).toBe(false);
		room.stop();
		republishPresence(); // stopped: nothing more
		await vi.advanceTimersByTimeAsync(0);
		expect(sent).toHaveLength(2);
		nostrRoom.current = session(null).room; // logged out: rejects, swallowed
		republishPresence();
		await vi.advanceTimersByTimeAsync(0);
		nostrRoom.current = null;
	});

	it("toggleMute flips the store and republishes presence", async () => {
		const { room, sent } = session(GUEST);
		nostrRoom.current = room;
		useMoqtChatStore.setState({ muted: false });
		toggleMute();
		await vi.advanceTimersByTimeAsync(0);
		expect(useMoqtChatStore.getState().muted).toBe(true);
		expect(sent[0].ev.tags).toContainEqual(["muted", "1"]);
		useMoqtChatStore.setState({ muted: false });
		room.stop();
		nostrRoom.current = null;
	});

	it("a burst of republishes goes out in order: the last one is current", async () => {
		const sent: Event[] = [];
		let calls = 0;
		const room = new NostrRoomSession({
			nostr: {
				publish: async (ev) => void sent.push(ev),
				subscribe: () => () => {},
			},
			// The first sign is the slow one: unserialized, it would land last.
			sign: (t, pk) =>
				new Promise((r) =>
					setTimeout(
						() => r(finalizeEvent({ ...t }, keyOf(pk))),
						calls++ ? 0 : 50,
					),
				),
		});
		useMoqtChatStore.setState({ nostrPubkey: GUEST, muted: true });
		const first = room.refreshPresence();
		useMoqtChatStore.setState({ muted: false });
		const second = room.refreshPresence();
		await vi.advanceTimersByTimeAsync(100);
		await Promise.all([first, second]);
		// Unserialized, the slow first sign (muted) landed last: [false, true].
		expect(sent).toHaveLength(2);
		expect(sent[1].tags.some((t) => t[0] === "muted")).toBe(false);
		expect(sent[1].created_at).toBeGreaterThan(sent[0].created_at);
		room.stop();
	});

	it("a failed hand raise reverts the stored hand", async () => {
		const { room } = session(GUEST);
		const fail = new NostrRoomSession({
			nostr: {
				publish: vi.fn().mockRejectedValue(new Error("x")),
				subscribe: () => () => {},
			},
			sign,
		});
		await expect(fail.setHand(true)).rejects.toThrow("x");
		expect(state().hand).toBe(false);
		room.stop();
	});

	it("stop during start: no meeting, no peer watch, no presence timer", async () => {
		const { room, sent, peersChanged } = session(HOST);
		const starting = room.start();
		room.stop();
		await starting;
		peersChanged();
		await vi.advanceTimersByTimeAsync(PRESENCE_EVERY_MS * 2);
		expect(kinds(sent)).toEqual([10312]);
		expect(room.liveMeeting()).toBeUndefined();
	});

	it("a second start replaces the presence timer instead of adding one", async () => {
		const { room, sent } = session(GUEST);
		await room.start();
		await room.start();
		await vi.advanceTimersByTimeAsync(PRESENCE_EVERY_MS);
		expect(kinds(sent)).toEqual([10312, 10312, 10312]);
		room.stop();
	});

	it("an old session's live meeting is hidden once a newer space is known", () => {
		const { nostr } = session(GUEST);
		const wire = (t: EventTemplate) =>
			JSON.stringify(finalizeEvent({ ...t }, HOST_SK));
		const old = meetingTemplate({
			space: SPACE,
			d: "old",
			title: "T",
			status: "live",
			starts: NOW - 100,
			now: NOW - 100,
		});
		nostr.receive(wire(old), false, "nostr-30313");
		expect(state().meeting).not.toBeNull();
		const space = {
			kind: 30312,
			created_at: NOW - 10,
			content: "",
			tags: [
				["d", D],
				["room", "R"],
				["status", "open"],
				["service", "s"],
				["p", HOST, "", "Host"],
			],
		};
		nostr.receive(wire(space), false, "nostr-30312");
		expect(state().space).not.toBeNull();
		expect(state().meeting).toBeNull();
	});
});

describe("announceRoom", () => {
	it("a hub refusing the Nostr tracks: announce, no room start, quiet flag", async () => {
		const { room, sent } = session(GUEST);
		const { nostrRoom } = await import("@/hooks/nostrRoomSession");
		nostrRoom.current = room;
		const announce = vi.fn(async () => {});
		await announceRoom({ publishNostrTracks: async () => false, announce });
		expect(announce).toHaveBeenCalledOnce();
		expect(sent).toEqual([]);
		expect(state().unavailable).toBe(true);
		nostrRoom.current = null;
	});
});
