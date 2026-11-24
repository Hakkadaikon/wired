// The NIP-53 meeting space over MoqNostr: what this client publishes
// (presence for everyone logged in; the space and its meeting for the host)
// and how received room events land in the store. Module scope like
// useMoqtChat's chatNostr: one MoQ session, one room session.

import type { Event, EventTemplate } from "nostr-tools/pure";
import type { MoqNostr } from "@/lib/moqNostr";
import { NOSTR_MEETING_TITLE, signOwnEvent } from "@/lib/nostr";
import {
	acceptMeeting,
	acceptPresence,
	acceptSpace,
	DELETION_KIND,
	deletionTemplate,
	MEETING_KIND,
	type MeetingStatus,
	meetingA,
	meetingTemplate,
	newer,
	PRESENCE_KIND,
	presenceTemplate,
	REACTION_KIND,
	reactionTemplate,
	SPACE_KIND,
	spaceA,
	spaceTemplate,
	type Target,
	tag,
} from "@/lib/nostrRoom";
import { activeRoom, roomName } from "@/lib/roomLink";
import {
	type MoqtChatState,
	type NostrRoom,
	useMoqtChatStore,
} from "@/stores/moqtChatStore";

/** NIP-53: presence SHOULD be refreshed; stale after PRESENCE_STALE_S. */
export const PRESENCE_EVERY_MS = 60_000;
/** Participant-count changes within this window make one meeting update. */
export const MEETING_DEBOUNCE_MS = 2_000;
const ROOM_EVENTS_MAX = 512; // reactions kept, newest last
// Posts with a deletion remembered, apart from the reactions' cap (a
// deletion matters as long as its post can be shown).
const DELETED_POSTS_MAX = 4096;
const PRESENCE_MAX = 512; // authors whose presence is held

type Store = Pick<
	MoqtChatState,
	"nostrPubkey" | "nostrRoom" | "peers" | "setNostrRoom"
>;

export type RoomDeps = {
	nostr: Pick<MoqNostr, "publish" | "subscribe">;
	state?: () => Store;
	/** Calls back on every change of the room's participant list. */
	watchPeers?: (onChange: () => void) => () => void;
	sign?: (t: EventTemplate, pubkey: string) => Promise<Event>;
	service?: string; // the space's `service`: the page URL
	host?: string;
	d?: string;
	room?: string;
	title?: string; // the meetings' title
	participant?: () => string; // our participant id, signed into presence
	now?: () => number; // seconds
};

const capped = (evs: Event[]) => evs.slice(-ROOM_EVENTS_MAX);
const newest = (ev: Event, held: Event | null | undefined) =>
	!held || newer(ev, held);

/** Adds value under key, dropping the oldest key past max. */
function bounded<T>(
	rec: Record<string, T>,
	key: string,
	value: T,
	max: number,
) {
	const { [key]: _, ...rest } = rec;
	const keys = Object.keys(rest);
	if (keys.length >= max) delete rest[keys[0]];
	return { ...rest, [key]: value };
}

// A "live" meeting that started before the newest space update is an old
// session's replay (its "ended" never reached us): not shown.
function staleLive(m: Event | null, space: Event | null): boolean {
	if (!m || !space || tag(m, "status") !== "live") return false;
	return Number(tag(m, "starts")) < space.created_at;
}

function applySpace(r: NostrRoom, ev: Event): Partial<NostrRoom> {
	return staleLive(r.meeting, ev)
		? { space: ev, meeting: null }
		: { space: ev };
}

function applyDeletion(r: NostrRoom, ev: Event): Partial<NostrRoom> {
	let deletions = r.deletions;
	for (const [name, id] of ev.tags)
		if (name === "e" && id)
			deletions = bounded(
				deletions,
				id,
				[...(deletions[id] ?? []), ev],
				DELETED_POSTS_MAX,
			);
	return { deletions };
}
// kind -> the store patch an accepted event makes (undefined: dropped).
const APPLY: Record<
	number,
	(r: NostrRoom, ev: Event, space: string) => Partial<NostrRoom> | undefined
> = {
	[SPACE_KIND]: (r, ev, space) =>
		acceptSpace(ev, space) && newest(ev, r.space)
			? applySpace(r, ev)
			: undefined,
	[MEETING_KIND]: (r, ev, space) =>
		acceptMeeting(ev, space) && newest(ev, r.meeting) && !staleLive(ev, r.space)
			? { meeting: ev }
			: undefined,
	[PRESENCE_KIND]: (r, ev, space) =>
		acceptPresence(ev, space) && newest(ev, r.presence[ev.pubkey])
			? { presence: bounded(r.presence, ev.pubkey, ev, PRESENCE_MAX) }
			: undefined,
	[REACTION_KIND]: (r, ev) => ({ reactions: capped([...r.reactions, ev]) }),
	[DELETION_KIND]: applyDeletion,
};

const nowSeconds = () => Math.floor(Date.now() / 1000);

export class NostrRoomSession {
	readonly space: string;
	#d: Required<Omit<RoomDeps, "watchPeers">> & Pick<RoomDeps, "watchPeers">;
	#lastAt = 0;
	#meeting?: { d: string; starts: number };
	#timer?: ReturnType<typeof setInterval>;
	#debounce?: ReturnType<typeof setTimeout>;
	#off: (() => void)[] = [];
	#stopped = false; // stop() ran: start() publishes nothing further

	constructor(deps: RoomDeps) {
		this.#d = {
			state: useMoqtChatStore.getState,
			sign: signOwnEvent,
			service: "",
			host: activeRoom.host,
			d: activeRoom.id,
			room: roomName(activeRoom.id),
			title: NOSTR_MEETING_TITLE,
			participant: () => "",
			now: nowSeconds,
			...deps,
		};
		this.space = spaceA(this.#d.host, this.#d.d);
		const onEvent = (ev: Event) => this.apply(ev);
		for (const f of [
			{ kinds: [SPACE_KIND], authors: [this.#d.host] },
			{ kinds: [MEETING_KIND, PRESENCE_KIND], a: this.space },
			{ kinds: [REACTION_KIND, DELETION_KIND] },
		])
			this.#off.push(deps.nostr.subscribe(f, { onEvent }));
	}

	/** Lands an (already verified) room event in the store if it passes its
	 * kind's checks and is newer than what is held. */
	apply(ev: Event): void {
		const s = this.#d.state();
		const patch = APPLY[ev.kind]?.(s.nostrRoom, ev, this.space);
		if (patch) s.setNostrRoom(patch);
	}

	get isHost(): boolean {
		return this.#d.state().nostrPubkey === this.#d.host;
	}

	/** The live meeting's coordinate (a chat event's second `a`), if any. */
	liveMeeting(): string | undefined {
		const m = this.#d.state().nostrRoom.meeting;
		if (!m || tag(m, "status") !== "live") return undefined;
		return meetingA(m.pubkey, tag(m, "d") ?? "");
	}

	// Signs (NIP-07), publishes on the kind's track and applies locally (our
	// own events never come back). created_at strictly increases, so a quick
	// second update is never lost to the newest-wins tie-break.
	async #publish(t: EventTemplate): Promise<Event> {
		const pubkey = this.#d.state().nostrPubkey;
		if (!pubkey) throw new Error("not logged in with Nostr");
		this.#lastAt = Math.max(t.created_at, this.#lastAt + 1);
		const ev = await this.#d.sign({ ...t, created_at: this.#lastAt }, pubkey);
		await this.#d.nostr.publish(ev);
		this.apply(ev);
		return ev;
	}

	#presence(): Promise<Event> {
		const hand = this.#d.state().nostrRoom.hand;
		const { now, participant } = this.#d;
		return this.#publish(
			presenceTemplate(this.space, hand, now(), participant() || undefined),
		);
	}

	#publishMeeting(status: MeetingStatus): Promise<Event | undefined> {
		const m = this.#meeting;
		if (!m) return Promise.resolve(undefined);
		return this.#publish(
			meetingTemplate({
				space: this.space,
				d: m.d,
				title: this.#d.title,
				status,
				starts: m.starts,
				participants: this.#d.state().peers.length + 1,
				now: this.#d.now(),
			}),
		);
	}

	/** After joining: presence now and every PRESENCE_EVERY_MS; the host
	 * also publishes the space and a new live meeting, updated (debounced)
	 * as participants come and go. No-op without a Nostr login. */
	async start(): Promise<void> {
		clearInterval(this.#timer);
		if (this.#stopped || !this.#d.state().nostrPubkey) return;
		this.#timer = setInterval(
			() => void this.#presence().catch(() => {}),
			PRESENCE_EVERY_MS,
		);
		const onHide = () => void this.end().catch(() => {});
		globalThis.addEventListener?.("pagehide", onHide);
		this.#off.push(() => globalThis.removeEventListener?.("pagehide", onHide));
		await this.#presence();
		if (this.isHost && !this.#stopped) await this.#startMeeting();
	}

	// The meeting starts with the space update, so staleLive never hides it.
	async #startMeeting(): Promise<void> {
		const { host, d, room, service } = this.#d;
		const space = await this.#publish(
			spaceTemplate({ host, d, room, service, now: this.#d.now() }),
		);
		if (this.#stopped) return;
		const starts = space.created_at;
		this.#meeting = { d: `meeting-${starts.toString(36)}`, starts };
		await this.#publishMeeting("live");
		if (this.#stopped) return;
		const off = this.#d.watchPeers?.(() => this.#peersChanged());
		if (off) this.#off.push(off);
	}

	#peersChanged(): void {
		clearTimeout(this.#debounce);
		this.#debounce = setTimeout(
			() => void this.#publishMeeting("live").catch(() => {}),
			MEETING_DEBOUNCE_MS,
		);
	}

	/** Raises or lowers our hand: a fresh presence event. */
	async setHand(hand: boolean): Promise<void> {
		this.#d.state().setNostrRoom({ hand });
		await this.#presence().catch((err) => {
			this.#d.state().setNostrRoom({ hand: !hand }); // not sent: undo
			throw err;
		});
	}

	react(target: Target, content: string): Promise<Event> {
		return this.#publish(reactionTemplate(target, content, this.#d.now()));
	}

	remove(target: Target): Promise<Event> {
		return this.#publish(deletionTemplate(target, this.#d.now()));
	}

	/** Stops publishing; the host's meeting is published ended (best effort:
	 * the caller keeps the session open until this settles). */
	async end(): Promise<void> {
		this.stop();
		await this.#publishMeeting("ended");
		this.#meeting = undefined;
	}

	stop(): void {
		this.#stopped = true;
		clearInterval(this.#timer);
		clearTimeout(this.#debounce);
		for (const off of this.#off.splice(0)) off();
	}
}

/** This MoQ session's room (useMoqtChat's openMoqNostr / closeMoqNostr). */
export const nostrRoom: { current: NostrRoomSession | null } = {
	current: null,
};

const failed = (what: string) => () =>
	useMoqtChatStore.getState().setMessageSendError(`${what} failed`);

export function toggleHand(): void {
	const hand = !useMoqtChatStore.getState().nostrRoom.hand;
	void nostrRoom.current?.setHand(hand).catch(failed("hand raise"));
}

export function reactTo(target: Target, content: string): void {
	void nostrRoom.current?.react(target, content).catch(failed("reaction"));
}

export function deletePost(target: Target): void {
	void nostrRoom.current?.remove(target).catch(failed("delete"));
}

/** Ends the room (host: meeting ended), waiting at most waitMs. */
export function endNostrRoom(waitMs: number): Promise<void> {
	const room = nostrRoom.current;
	if (!room) return Promise.resolve();
	const wait = new Promise<void>((r) => setTimeout(r, waitMs));
	return Promise.race([room.end().catch(() => {}), wait]);
}
