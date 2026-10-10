// MoqtScreenClient's hi/lo variants over a real MoqtChatClient and the fake
// WebTransport (tasks/moqt-trackswitch-plan.md W5): PUBLISH of both variants
// with their own alias ranges, aligned Groups on send, the SSTS pair
// SUBSCRIBE (SWITCHING_SET_ASSIGNMENT), both aliases delivered to one
// participant behind a Group gate, the per-tile quality selection through
// SWITCH_FROM, and the unchanged single-subscription path everywhere the
// extension is off.
import { afterEach, describe, expect, it, vi } from "vitest";
import { CANDIDATE_PARTICIPANT_IDS, MoqtChatClient } from "../moqtClient";
import {
	isScreenTrackAlias,
	MoqtScreenClient,
	ownScreenTrackAlias,
	SCREEN_ALIAS_OFFSET,
	SCREEN_LO_ALIAS_OFFSET,
	SCREEN_SSTS_THRESHOLD_KBPS,
	type ScreenGroupGate,
	type ScreenVariant,
	screenGroupGateAccept,
	screenVariantAlias,
} from "../moqtScreenClient";
import {
	buildScreenSubgroupHeader,
	encodeScreenObjectMessage,
	type ScreenChunk,
} from "../moqtScreenWire";
import {
	bytesToHex,
	bytesToUtf8,
	concatBytes,
	decodeNamespace,
	decodePublish,
	decodeSubgroupHeader,
	decodeSubscribe,
	decodeVarint,
	encodeControlFrame,
	encodeSubscribeOk,
	encodeVarint,
} from "../moqtWire";
import {
	SCREEN_HI_MAX_BITRATE,
	SCREEN_HI_MIN_BITRATE,
	SCREEN_LO_BITRATE,
} from "../screenSharePipeline";
import {
	FakeWebTransport,
	hubSetupBody,
	MSG_PUBLISH,
	MSG_PUBLISH_NAMESPACE,
	MSG_SUBSCRIBE,
	stubWebTransport,
} from "./fakeWebTransport";

const flush = () => vi.advanceTimersByTimeAsync(0);

type Got = { participant: string; seq: number; variant?: ScreenVariant };

async function session(opts: { draft: 19 | 22; hubAlgs?: bigint[] }) {
	vi.useFakeTimers();
	const fake = new FakeWebTransport();
	stubWebTransport(() => fake);
	const got: Got[] = [];
	const routed: { screen?: MoqtScreenClient } = {};
	const chat = new MoqtChatClient("user1", {
		onStatusChange: () => {},
		onMessage: () => {},
		onUnknownUniStream: (header, tail, reader) =>
			routed.screen?.handleIncomingStream(header, tail, reader),
	});
	const screen = new MoqtScreenClient(chat, {
		onScreenChunk: (participant, chunk, variant) =>
			got.push({ participant, seq: chunk.seq, variant }),
	});
	routed.screen = screen;
	const ready = chat.connect("https://hub.example/", []);
	if (opts.draft === 22)
		fake.startD22Control("moqt-22", hubSetupBody(opts.hubAlgs));
	fake.resolveReady();
	await ready;
	await flush();
	return { fake, chat, screen, got };
}

const subscribeOk = () =>
	encodeControlFrame(
		0x4n,
		encodeSubscribeOk({ trackAlias: 9n, parameters: [], trackProperties: [] }),
	);

function paramsHex(body: Uint8Array): string {
	const rid = decodeVarint(body, 0);
	const ns = decodeNamespace(body, rid.len);
	const nameLen = decodeVarint(body, rid.len + ns.len);
	return bytesToHex(
		body.slice(rid.len + ns.len + nameLen.len + Number(nameLen.value)),
	);
}

const trackNameOf = (s: { request: { body: Uint8Array } }) =>
	bytesToUtf8(decodeSubscribe(s.request.body, 22).trackName);

const chunk = (seq: number, keyframe: boolean): ScreenChunk => ({
	seq,
	idx: 0,
	count: 1,
	keyframe,
	timestampUs: 0,
	data: Uint8Array.of(seq),
});

/** One incoming screen stream: SUBGROUP_HEADER(alias, group) + one Object. */
function screenStream(
	alias: bigint,
	group: bigint,
	c: ScreenChunk,
): Uint8Array {
	const body = encodeScreenObjectMessage(c);
	return concatBytes([
		buildScreenSubgroupHeader(alias, group),
		encodeVarint(0n),
		encodeVarint(BigInt(body.length)),
		body,
	]);
}

describe("screen alias ranges", () => {
	it("lo aliases sit right above the hi range: [14, 18) for the 4-id pool", () => {
		const n = BigInt(CANDIDATE_PARTICIPANT_IDS.length);
		expect(SCREEN_LO_ALIAS_OFFSET).toBe(SCREEN_ALIAS_OFFSET + n);
		expect(screenVariantAlias("user1", "lo")).toBe(14n);
		expect(screenVariantAlias("user4", "lo")).toBe(17n);
		expect(ownScreenTrackAlias("user1")).toBe(10n);
	});

	it("isScreenTrackAlias covers both ranges and nothing past them", () => {
		expect(isScreenTrackAlias(9n)).toBe(false);
		expect(isScreenTrackAlias(10n)).toBe(true);
		expect(isScreenTrackAlias(17n)).toBe(true);
		expect(isScreenTrackAlias(18n)).toBe(false);
	});
});

describe("screenGroupGateAccept", () => {
	it("locks onto the first keyframe's (Group, variant); drops the other variant's copy and stale Groups", () => {
		const gate: ScreenGroupGate = {};
		const seq: [bigint, ScreenVariant, boolean][] = [
			[5n, "hi", false], // no keyframe yet
			[5n, "hi", true],
			[5n, "lo", true], // the same Group from the other variant
			[5n, "hi", false],
			[6n, "lo", true], // switched at the boundary
			[5n, "hi", false], // the old variant's tail
			[6n, "hi", false], // the other variant inside the current Group
			[6n, "lo", false],
			[7n, "hi", false], // a Group not opened by its keyframe
			[7n, "hi", true],
		];
		expect(
			seq.map(([g, v, k]) => screenGroupGateAccept(gate, g, v, k)),
		).toEqual([
			false,
			true,
			false,
			true,
			true,
			false,
			false,
			true,
			false,
			true,
		]);
	});

	it("a live keyframe of the bound Group from the other variant takes over a gate a fill bound", () => {
		const gate: ScreenGroupGate = {};
		expect(screenGroupGateAccept(gate, 0x0dn, "lo", true, false)).toBe(true); // lo fill binds 0x0d
		expect(screenGroupGateAccept(gate, 0x0dn, "lo", false, false)).toBe(true);
		expect(screenGroupGateAccept(gate, 0x0dn, "hi", false, true)).toBe(false); // a live delta cannot
		expect(screenGroupGateAccept(gate, 0x0dn, "hi", true, true)).toBe(true); // the hub's live member
		expect(screenGroupGateAccept(gate, 0x0dn, "lo", false, false)).toBe(false); // the fill's rest: dropped
		expect(screenGroupGateAccept(gate, 0x0dn, "hi", false, true)).toBe(true);
	});

	it("a fill keyframe never takes over: neither a fill-bound nor a live-bound Group", () => {
		const fillBound: ScreenGroupGate = {};
		screenGroupGateAccept(fillBound, 5n, "hi", true, false);
		expect(screenGroupGateAccept(fillBound, 5n, "lo", true, false)).toBe(false);
		const liveBound: ScreenGroupGate = {};
		screenGroupGateAccept(liveBound, 5n, "hi", true, true);
		expect(screenGroupGateAccept(liveBound, 5n, "lo", true, true)).toBe(false); // live duplicate: as before
		expect(screenGroupGateAccept(liveBound, 5n, "lo", true, false)).toBe(false);
	});

	it("live data of the fill's own variant confirms it: the other variant can no longer take over", () => {
		const gate: ScreenGroupGate = {};
		screenGroupGateAccept(gate, 5n, "lo", true, false);
		expect(screenGroupGateAccept(gate, 5n, "lo", false, true)).toBe(true);
		expect(screenGroupGateAccept(gate, 5n, "hi", true, true)).toBe(false);
	});

	it("F2: a late keyframe of any older Group (G-1, G-2, ...) never moves the gate back", () => {
		const gate: ScreenGroupGate = {};
		screenGroupGateAccept(gate, 9n, "hi", true);
		expect(screenGroupGateAccept(gate, 8n, "hi", true)).toBe(false);
		expect(screenGroupGateAccept(gate, 7n, "lo", true)).toBe(false);
		expect(screenGroupGateAccept(gate, 0n, "hi", true)).toBe(false);
		expect(screenGroupGateAccept(gate, 9n, "hi", false)).toBe(true); // still on Group 9
	});

	it("a restarted publisher is followed through a fresh gate: subscribeToScreenTrack resets it", async () => {
		vi.useFakeTimers();
		const { chat } = minimalChat();
		Object.assign(chat, {
			sstsAlgorithm: 0xff01n,
			subscribeTrack: vi.fn(async () => false), // already subscribed: re-share
		});
		const got: number[] = [];
		const screen = new MoqtScreenClient(chat, {
			onScreenChunk: (_p, c) => got.push(c.seq),
		});
		await screen.subscribeToScreenTrack("user2");
		const reader = {
			read: vi.fn(async () => ({ value: undefined, done: true })),
			cancel: vi.fn(),
		};
		const push = (group: bigint, seq: number) => {
			const body = encodeScreenObjectMessage(chunk(seq, true));
			const obj = concatBytes([
				encodeVarint(0n),
				encodeVarint(BigInt(body.length)),
				body,
			]);
			screen.handleIncomingStream(
				{
					trackAlias: screenVariantAlias("user2", "hi"),
					groupId: group,
					flags: { properties: false },
				} as never,
				obj,
				reader as never,
			);
		};
		push(9n, 1);
		push(0n, 2); // the publisher's new session: dropped by the old gate...
		await screen.subscribeToScreenTrack("user2"); // ...until its share is announced again
		push(0n, 3);
		await vi.advanceTimersByTimeAsync(0);
		expect(got).toEqual([1, 3]);
		vi.useRealTimers();
	});
});

describe("MoqtScreenClient variants: publishing", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.useRealTimers();
	});

	const published = (fake: FakeWebTransport) =>
		fake.requestsOf(MSG_PUBLISH).map((s) => {
			const p = decodePublish(s.request.body);
			return [bytesToUtf8(p.trackName), p.trackAlias];
		});

	it("d22 + SSTS advertised: PUBLISHes <id>/screen (alias 10) and <id>/screen-lo (alias 14), one namespace", async () => {
		const { fake, screen } = await session({
			draft: 22,
			hubAlgs: [0xff01n, 0n],
		});
		expect(screen.variantsEnabled).toBe(true);
		await screen.publishScreenTrack();
		await flush();
		expect(published(fake)).toEqual([
			["user1", 0n],
			["user1/screen", 10n],
			["user1/screen-lo", 14n],
		]);
		expect(
			fake
				.requestsOf(MSG_PUBLISH_NAMESPACE)
				.map((s) => decodeNamespace(s.request.body, 1).fields.map(bytesToUtf8)),
		).toEqual([["wired", "moqt_chat", "user1", "screen"]]);
	});

	it("d22 without the hub's option, and d19: only <id>/screen, as before", async () => {
		for (const draft of [22, 19] as const) {
			const { fake, screen } = await session({ draft });
			expect(screen.variantsEnabled).toBe(false);
			await screen.publishScreenTrack();
			await flush();
			expect(published(fake)).toEqual([
				["user1", 0n],
				["user1/screen", 10n],
			]);
			vi.unstubAllGlobals();
			vi.useRealTimers();
		}
	});

	it("sendVideoChunk with explicit Groups: one stream per (variant, Group), headers aligned, old one FINed", async () => {
		const { fake, screen } = await session({ draft: 22, hubAlgs: [0xff01n] });
		await screen.publishScreenTrack();
		await flush();
		const before = fake.uniStreams.length;
		const g = screen.allocateGroup();
		await screen.sendVideoChunk(chunk(0, true), { group: g, variant: "hi" });
		await screen.sendVideoChunk(chunk(0, true), { group: g, variant: "lo" });
		await screen.sendVideoChunk(chunk(1, false), { group: g, variant: "hi" });
		const g2 = screen.allocateGroup();
		await screen.sendVideoChunk(chunk(2, true), { group: g2, variant: "lo" });
		await screen.sendVideoChunk(chunk(2, true), { group: g2, variant: "hi" });

		const streams = fake.uniStreams.slice(before);
		const heads = streams.map((s) => {
			const h = decodeSubgroupHeader(concatBytes(s.written)).header;
			return [h.trackAlias, h.groupId];
		});
		expect(g2).toBe(g + 1n);
		expect(heads).toEqual([
			[10n, g],
			[14n, g],
			[14n, g2],
			[10n, g2],
		]);
		expect(streams.map((s) => s.closed)).toEqual([true, true, false, false]);
		expect(streams[0].written).toHaveLength(2); // hi Group g: keyframe + delta on one stream
	});

	it("a lo chunk is dropped when the lo variant is not published (d19 / extension off)", async () => {
		const { fake, screen } = await session({ draft: 19 });
		await screen.publishScreenTrack();
		await flush();
		const before = fake.uniStreams.length;
		await screen.sendVideoChunk(chunk(0, true), { group: 0n, variant: "lo" });
		expect(fake.uniStreams.length).toBe(before);
	});
});

describe("MoqtScreenClient variants: subscribing", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.useRealTimers();
	});

	it("d22 + backpressure advertised: subscribes both variants into one switching set per participant", async () => {
		const { fake, screen } = await session({
			draft: 22,
			hubAlgs: [0xff01n, 0n],
		});
		void screen.subscribeToScreenTrack("user2");
		await flush();
		const subs = fake.requestsOf(MSG_SUBSCRIBE);
		expect(subs.map(trackNameOf)).toEqual(["user2/screen", "user2/screen-lo"]);
		// Next Object + fill Relative Start 1 + SSA {set 1 (user2), 0xff01, kbps, weight 1, activate 2}.
		expect(paramsHex(subs[0].request.body)).toBe(
			"03" + "2105" + "020401210101" + "1e08" + "01c0ff0187d00102",
		);
		// 400 kbps = 0x190 -> 81 90.
		expect(paramsHex(subs[1].request.body)).toBe(
			"03" + "2105" + "020401210101" + "1e08" + "01c0ff0181900102",
		);
	});

	it("a hub offering only the default algorithm gets algorithm 0 in both assignments", async () => {
		const { fake, screen } = await session({ draft: 22, hubAlgs: [0n] });
		void screen.subscribeToScreenTrack("user3");
		await flush();
		const subs = fake.requestsOf(MSG_SUBSCRIBE);
		expect(paramsHex(subs[0].request.body)).toBe(
			"03" + "2105" + "020401210101" + "1e06" + "020087d00102",
		);
		expect(paramsHex(subs[1].request.body)).toBe(
			"03" + "2105" + "020401210101" + "1e06" + "020081900102",
		);
	});

	it("without SSTS (no option, or no common algorithm) and on d19: one plain SUBSCRIBE to <id>/screen", async () => {
		const cases: [19 | 22, bigint[] | undefined, string][] = [
			[22, undefined, "022105020401210101"],
			[22, [7n], "022105020401210101"],
			[19, undefined, "01210102"],
		];
		for (const [draft, hubAlgs, params] of cases) {
			const { fake, screen } = await session({ draft, hubAlgs });
			void screen.subscribeToScreenTrack("user2");
			await flush();
			const subs = fake.requestsOf(MSG_SUBSCRIBE);
			expect(
				subs.map((s) =>
					bytesToUtf8(decodeSubscribe(s.request.body, draft).trackName),
				),
			).toEqual(["user2/screen"]);
			expect(paramsHex(subs[0].request.body)).toBe(params);
			vi.unstubAllGlobals();
			vi.useRealTimers();
		}
	});

	it("both aliases deliver to the same participant, tagged with their variant, through the Group gate", async () => {
		const { fake, screen, got } = await session({
			draft: 22,
			hubAlgs: [0xff01n],
		});
		const sub = screen.subscribeToScreenTrack("user2");
		await flush();
		for (const s of fake.requestsOf(MSG_SUBSCRIBE))
			s.replies.push(subscribeOk()); // no Largest: no fills
		await sub;
		await flush();

		const hi = screenVariantAlias("user2", "hi");
		const lo = screenVariantAlias("user2", "lo");
		fake.incomingUnidirectionalStreams.push(
			screenStream(hi, 5n, chunk(0, true)),
		);
		await flush();
		fake.incomingUnidirectionalStreams.push(
			screenStream(lo, 5n, chunk(70, true)),
		); // duplicate Group: dropped
		await flush();
		fake.incomingUnidirectionalStreams.push(
			screenStream(lo, 6n, chunk(71, true)),
		); // switched to lo
		await flush();
		fake.incomingUnidirectionalStreams.push(
			screenStream(hi, 7n, chunk(20, true)),
		); // and back to hi
		await flush();

		expect(got).toEqual([
			{ participant: "user2", seq: 0, variant: "hi" },
			{ participant: "user2", seq: 71, variant: "lo" },
			{ participant: "user2", seq: 20, variant: "hi" },
		]);
	});

	it("live chunks wait until BOTH variants' fills have ended", async () => {
		const { fake, screen, got } = await session({
			draft: 22,
			hubAlgs: [0xff01n],
		});
		void screen.subscribeToScreenTrack("user2");
		await flush();
		const [hiSub, loSub] = fake.requestsOf(MSG_SUBSCRIBE);
		const largest = encodeControlFrame(
			0x4n,
			encodeSubscribeOk({
				trackAlias: 9n,
				parameters: [{ type: 0x09n, value: { group: 4n, object: 1n } }],
				trackProperties: [],
			}),
		);
		hiSub.replies.push(largest);
		loSub.replies.push(largest);
		await flush();
		// A live lo Group 5 keyframe overtakes both fills.
		fake.incomingUnidirectionalStreams.push(
			screenStream(screenVariantAlias("user2", "lo"), 5n, chunk(9, true)),
		);
		await flush();
		expect(got).toEqual([]);

		// hi fill (FETCH_HEADER with the hi SUBSCRIBE's Request ID): Group 4 keyframe.
		const fill = (rid: bigint, c: ScreenChunk) => {
			const body = encodeScreenObjectMessage(c);
			// fetch Object: flags 0x1c (Group, Object, Priority present; subgroup 0)
			return concatBytes([
				encodeVarint(0x5n),
				encodeVarint(rid),
				encodeVarint(0x1cn),
				encodeVarint(4n),
				encodeVarint(0n),
				Uint8Array.of(0),
				encodeVarint(BigInt(body.length)),
				body,
			]);
		};
		const rid = (s: typeof hiSub) => decodeVarint(s.request.body, 0).value;
		fake.incomingUnidirectionalStreams.push(fill(rid(hiSub), chunk(1, true)));
		await flush();
		expect(got.map((g) => g.seq)).toEqual([1]);
		fake.incomingUnidirectionalStreams.push(fill(rid(loSub), chunk(2, true))); // same Group, other variant: dropped
		await flush();
		expect(got.map((g) => [g.seq, g.variant])).toEqual([
			[1, "hi"],
			[9, "lo"],
		]);
	});
});

describe("MoqtScreenClient per-tile quality", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.useRealTimers();
	});

	async function subscribedPair() {
		const s = await session({ draft: 22, hubAlgs: [0xff01n] });
		const sub = s.screen.subscribeToScreenTrack("user2");
		await flush();
		for (const r of s.fake.requestsOf(MSG_SUBSCRIBE))
			r.replies.push(subscribeOk());
		await sub;
		await flush();
		return s;
	}

	it("auto -> low: the SSTS pair is cancelled and lo alone is subscribed, with no assignment", async () => {
		const { fake, screen } = await subscribedPair();
		const [hiPair, loPair] = fake.requestsOf(MSG_SUBSCRIBE);
		const done = screen.setScreenQuality("user2", "low");
		await flush();
		const lo = fake.requestsOf(MSG_SUBSCRIBE)[2];
		lo.replies.push(subscribeOk());
		await done;
		expect(hiPair.cancelled && loPair.cancelled).toBe(true);
		expect(trackNameOf(lo)).toBe("user2/screen-lo");
		expect(paramsHex(lo.request.body)).toBe("022105020401210101");
		expect(screen.screenQuality("user2")).toBe("low");
	});

	it("low -> high is one SUBSCRIBE with SWITCH_FROM (Soft, Publish Done) of the lo subscription", async () => {
		const { fake, screen, chat } = await subscribedPair();
		const toLow = screen.setScreenQuality("user2", "low");
		await flush();
		const lo = fake.requestsOf(MSG_SUBSCRIBE)[2];
		lo.replies.push(subscribeOk());
		await toLow;

		const toHigh = screen.setScreenQuality("user2", "high");
		await flush();
		const subs = fake.requestsOf(MSG_SUBSCRIBE);
		expect(subs).toHaveLength(4);
		const hi = subs[3];
		const loRid = decodeVarint(lo.request.body, 0).value;
		expect(trackNameOf(hi)).toBe("user2/screen");
		expect(paramsHex(hi.request.body)).toBe(
			`012403${loRid.toString(16).padStart(2, "0")}0180`,
		);
		expect(lo.closed || lo.aborted).toBe(false); // the old one keeps flowing until the hub ends it
		hi.replies.push(subscribeOk());
		await toHigh;
		await flush();
		expect(lo.closed).toBe(true); // FIN, not reset
		expect(lo.aborted).toBe(false);
		expect(chat.isSubscribed("user2/screen-lo")).toBe(false);
		expect(chat.isSubscribed("user2/screen")).toBe(true);
	});

	it("a refused SWITCH_FROM leaves the old subscription in place and the quality unchanged", async () => {
		const { fake, screen, chat } = await subscribedPair();
		const toLow = screen.setScreenQuality("user2", "low");
		await flush();
		fake.requestsOf(MSG_SUBSCRIBE)[2].replies.push(subscribeOk());
		await toLow;
		const toHigh = screen.setScreenQuality("user2", "high");
		await flush();
		fake
			.requestsOf(MSG_SUBSCRIBE)[3]
			.replies.push(
				encodeControlFrame(
					0x5n,
					concatBytes([
						encodeVarint(0x32n),
						encodeVarint(0n),
						encodeVarint(0n),
					]),
				),
			);
		await toHigh;
		expect(chat.isSubscribed("user2/screen-lo")).toBe(true);
		expect(screen.screenQuality("user2")).toBe("low");
	});

	it("high -> auto cancels the single subscription and subscribes the pair again", async () => {
		const { fake, screen } = await subscribedPair();
		const toHigh = screen.setScreenQuality("user2", "high");
		await flush();
		const hi = fake.requestsOf(MSG_SUBSCRIBE)[2];
		hi.replies.push(subscribeOk());
		await toHigh;
		void screen.setScreenQuality("user2", "auto");
		await flush();
		const subs = fake.requestsOf(MSG_SUBSCRIBE);
		expect(hi.cancelled).toBe(true);
		expect(subs.slice(3).map(trackNameOf)).toEqual([
			"user2/screen",
			"user2/screen-lo",
		]);
		expect(screen.screenQuality("user2")).toBe("auto");
	});

	it("is a no-op where the extension is off (d19)", async () => {
		const { fake, screen } = await session({ draft: 19 });
		void screen.subscribeToScreenTrack("user2");
		await flush();
		await screen.setScreenQuality("user2", "low");
		await flush();
		expect(fake.requestsOf(MSG_SUBSCRIBE)).toHaveLength(1);
		expect(screen.screenQuality("user2")).toBe("auto");
	});
});

/** One fill (fetch) stream: FETCH_HEADER(rid) + one fetch Object of `group`. */
function fillStream(rid: bigint, group: bigint, c: ScreenChunk): Uint8Array {
	const body = encodeScreenObjectMessage(c);
	// flags 0x1c: Group, Object and Priority present; subgroup 0
	return concatBytes([
		encodeVarint(0x5n),
		encodeVarint(rid),
		encodeVarint(0x1cn),
		encodeVarint(group),
		encodeVarint(0n),
		Uint8Array.of(0),
		encodeVarint(BigInt(body.length)),
		body,
	]);
}

// A minimal chat stand-in for send-side cases the fake WebTransport cannot
// stage (a write that never settles, a refused lo PUBLISH).
function minimalChat(opts: { loPublishOk?: boolean } = {}) {
	const streams: {
		written: Uint8Array[];
		closed: boolean;
		aborted: boolean;
	}[] = [];
	const state = { hang: false };
	const wt = {
		createUnidirectionalStream: vi.fn(async () => {
			const rec = {
				written: [] as Uint8Array[],
				closed: false,
				aborted: false,
			};
			streams.push(rec);
			return {
				getWriter: () => ({
					write: (c: Uint8Array) => {
						if (state.hang) return new Promise<void>(() => {});
						rec.written.push(c);
						return Promise.resolve();
					},
					close: async () => {
						rec.closed = true;
					},
					abort: async () => {
						rec.aborted = true;
					},
				}),
			};
		}),
	};
	const chat = {
		localId: "user1",
		draft: 22,
		trackSwitching: true,
		webTransport: wt,
		publishTrack: vi.fn(async (name: Uint8Array) =>
			bytesToUtf8(name).endsWith("-lo") ? (opts.loPublishOk ?? true) : true,
		),
		publishNamespace: vi.fn(async () => ({ cancel: vi.fn() })),
	} as unknown as MoqtChatClient;
	return { chat, streams, state };
}

describe("review round 1: send side", () => {
	afterEach(() => vi.useRealTimers());

	it("S2: after a write timeout the dead Group is not reopened; the next Group opens normally", async () => {
		vi.useFakeTimers();
		const { chat, streams, state } = minimalChat();
		const onStreamReset = vi.fn();
		const screen = new MoqtScreenClient(chat, {
			onScreenChunk: vi.fn(),
			onStreamReset,
		});
		await screen.publishScreenTrack();
		await screen.sendVideoChunk(chunk(0, true), { group: 5n, variant: "hi" });
		state.hang = true;
		const failed = screen
			.sendVideoChunk(chunk(1, false), { group: 5n, variant: "hi" })
			.then(
				() => false,
				() => true,
			);
		await vi.advanceTimersByTimeAsync(1000);
		expect(await failed).toBe(true);
		expect(onStreamReset).toHaveBeenCalledTimes(1);
		state.hang = false;

		await screen.sendVideoChunk(chunk(2, false), { group: 5n, variant: "hi" }); // still Group 5: dropped
		expect(streams).toHaveLength(1);
		await screen.sendVideoChunk(chunk(3, true), { group: 6n, variant: "hi" });
		expect(streams).toHaveLength(2);
		expect(
			decodeSubgroupHeader(concatBytes(streams[1].written)).header.groupId,
		).toBe(6n);
	});

	it("S3: loPublished reports whether the lo PUBLISH was accepted", async () => {
		const ok = minimalChat();
		const a = new MoqtScreenClient(ok.chat, { onScreenChunk: vi.fn() });
		expect(a.loPublished).toBe(false);
		await a.publishScreenTrack();
		expect(a.loPublished).toBe(true);

		const refused = minimalChat({ loPublishOk: false });
		const b = new MoqtScreenClient(refused.chat, { onScreenChunk: vi.fn() });
		await b.publishScreenTrack();
		expect(b.loPublished).toBe(false);
	});

	it("F9: the quality queue keeps draining after a call that rejects", async () => {
		const { chat } = minimalChat();
		let failOnce = true;
		const subscribeTrack = vi.fn(async () => true);
		Object.assign(chat, {
			sstsAlgorithm: 0xff01n,
			isSubscribed: () => true,
			subscriptionRequestId: async () => 2n,
			forgetSubscription: vi.fn(),
			unsubscribe: vi.fn(() => {
				if (failOnce) {
					failOnce = false;
					throw new Error("stream refused"); // e.g. the session closing under it
				}
			}),
			subscribeTrack,
		});
		const screen = new MoqtScreenClient(chat, { onScreenChunk: vi.fn() });
		await screen.setScreenQuality("user2", "high"); // rejects inside: swallowed
		await screen.setScreenQuality("user2", "low");
		const names = subscribeTrack.mock.calls.map((c) =>
			bytesToUtf8((c as unknown[])[0] as Uint8Array),
		);
		expect(names.at(-1)).toBe("user2/screen-lo");
	});

	it("F8: SSTS thresholds sit inside each variant's bitrate band", () => {
		expect(SCREEN_SSTS_THRESHOLD_KBPS.lo * 1000n).toBeGreaterThanOrEqual(
			BigInt(SCREEN_LO_BITRATE),
		);
		expect(SCREEN_SSTS_THRESHOLD_KBPS.hi * 1000n).toBeGreaterThan(
			BigInt(SCREEN_HI_MIN_BITRATE),
		);
		expect(SCREEN_SSTS_THRESHOLD_KBPS.hi * 1000n).toBeLessThan(
			BigInt(SCREEN_HI_MAX_BITRATE),
		);
	});

	it("variantsEnabled is exactly the chat client's trackSwitching", () => {
		const { chat } = minimalChat();
		const screen = new MoqtScreenClient(chat, { onScreenChunk: vi.fn() });
		expect(screen.variantsEnabled).toBe(true);
		(chat as unknown as { trackSwitching: boolean }).trackSwitching = false;
		expect(screen.variantsEnabled).toBe(false);
	});
});

describe("review round 1: receive side", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.useRealTimers();
	});

	const refused = () =>
		encodeControlFrame(
			0x5n,
			concatBytes([encodeVarint(0x10n), encodeVarint(0n), encodeVarint(0n)]),
		);

	async function pair() {
		const s = await session({ draft: 22, hubAlgs: [0xff01n] });
		const sub = s.screen.subscribeToScreenTrack("user2");
		await flush();
		return { ...s, sub };
	}

	it("a pair whose lo is refused (a sender without lo) still plays hi", async () => {
		const { fake, screen, got, sub } = await pair();
		const [hi, lo] = fake.requestsOf(MSG_SUBSCRIBE);
		hi.replies.push(subscribeOk());
		lo.replies.push(refused());
		await sub;
		await flush();
		fake.incomingUnidirectionalStreams.push(
			screenStream(screenVariantAlias("user2", "hi"), 5n, chunk(0, true)),
		);
		await flush();
		expect(got).toEqual([{ participant: "user2", seq: 0, variant: "hi" }]);
		expect(screen.screenQuality("user2")).toBe("auto");
	});

	it("S5: choosing Low for a sender without lo restores the previous quality and its subscriptions", async () => {
		const { fake, screen, sub } = await pair();
		for (const r of fake.requestsOf(MSG_SUBSCRIBE))
			r.replies.push(subscribeOk());
		await sub;
		await flush();
		const done = screen.setScreenQuality("user2", "low");
		await flush();
		fake.requestsOf(MSG_SUBSCRIBE)[2].replies.push(refused());
		await flush();
		const subs = fake.requestsOf(MSG_SUBSCRIBE);
		expect(subs.slice(3).map(trackNameOf)).toEqual([
			"user2/screen",
			"user2/screen-lo",
		]); // the auto pair again
		for (const r of subs.slice(3)) r.replies.push(subscribeOk());
		await done;
		expect(screen.screenQuality("user2")).toBe("auto");
	});

	it("S4: quality changes are serialized; a later choice never loses to an earlier one's late answer", async () => {
		const { fake, screen, chat, sub } = await pair();
		for (const r of fake.requestsOf(MSG_SUBSCRIBE))
			r.replies.push(subscribeOk());
		await sub;
		await flush();
		const toHigh = screen.setScreenQuality("user2", "high");
		await flush();
		fake.requestsOf(MSG_SUBSCRIBE)[2].replies.push(subscribeOk());
		await toHigh;

		const toLow = screen.setScreenQuality("user2", "low"); // SWITCH_FROM in flight...
		const toAuto = screen.setScreenQuality("user2", "auto"); // ...when auto is chosen
		await flush();
		expect(fake.requestsOf(MSG_SUBSCRIBE)).toHaveLength(4); // auto waits for low
		fake.requestsOf(MSG_SUBSCRIBE)[3].replies.push(subscribeOk());
		await toLow;
		await flush();
		const subs = fake.requestsOf(MSG_SUBSCRIBE);
		expect(subs.slice(4).map(trackNameOf)).toEqual([
			"user2/screen",
			"user2/screen-lo",
		]);
		for (const r of subs.slice(4)) r.replies.push(subscribeOk());
		await toAuto;
		await flush();
		expect(screen.screenQuality("user2")).toBe("auto");
		expect(subs[3].aborted).toBe(true); // the single lo is cancelled
		expect(subs[4].aborted || subs[4].closed).toBe(false); // the new pair is intact
		expect(subs[5].aborted || subs[5].closed).toBe(false);
		expect(chat.isSubscribed("user2/screen")).toBe(true);
		expect(chat.isSubscribed("user2/screen-lo")).toBe(true);
	});

	it("F6: a peer that leaves mid-change is not subscribed again by the change's continuation", async () => {
		const { fake, screen, sub } = await pair();
		for (const r of fake.requestsOf(MSG_SUBSCRIBE))
			r.replies.push(subscribeOk());
		await sub;
		await flush();
		const done = screen.setScreenQuality("user2", "low");
		await flush();
		screen.forgetParticipant("user2"); // NAMESPACE_DONE while lo's SUBSCRIBE is out
		fake.requestsOf(MSG_SUBSCRIBE)[2].replies.push(refused()); // would restore auto
		await done;
		await flush();
		expect(fake.requestsOf(MSG_SUBSCRIBE)).toHaveLength(3); // no pair re-subscribed
		expect(screen.screenQuality("user2")).toBe("auto");
	});

	// What a NAMESPACE_DONE does: the chat client cancels the peer's
	// subscriptions (#dropPeer), then the hook forgets its screen state.
	const leave = (chat: MoqtChatClient, screen: MoqtScreenClient) => {
		chat.unsubscribe("user2/screen");
		chat.unsubscribe("user2/screen-lo");
		screen.forgetParticipant("user2");
	};

	it("real-browser repro: High -> Auto, the lo fill at 0x0d, then live hi 0x0d renders without waiting for 0x0e", async () => {
		const { fake, screen, got, sub } = await pair();
		for (const r of fake.requestsOf(MSG_SUBSCRIBE))
			r.replies.push(subscribeOk());
		await sub;
		await flush();
		const toHigh = screen.setScreenQuality("user2", "high");
		await flush();
		fake.requestsOf(MSG_SUBSCRIBE)[2].replies.push(subscribeOk());
		await toHigh;
		const hiAlias = screenVariantAlias("user2", "hi");
		fake.incomingUnidirectionalStreams.push(
			screenStream(hiAlias, 0x0cn, chunk(1, true)),
		); // playing hi 0x0c
		await flush();

		const toAuto = screen.setScreenQuality("user2", "auto");
		await flush();
		const [hiSub, loSub] = fake.requestsOf(MSG_SUBSCRIBE).slice(3);
		const largest = (group: bigint) =>
			encodeControlFrame(
				0x4n,
				encodeSubscribeOk({
					trackAlias: 9n,
					parameters: [{ type: 0x09n, value: { group, object: 0n } }],
					trackProperties: [],
				}),
			);
		hiSub.replies.push(largest(0x0cn));
		loSub.replies.push(largest(0x0dn));
		await toAuto;
		await flush();
		const rid = (r: typeof hiSub) => decodeVarint(r.request.body, 0).value;
		fake.incomingUnidirectionalStreams.push(
			fillStream(rid(hiSub), 0x0cn, chunk(2, true)),
		); // hi fill: still 0x0c
		await flush();
		fake.incomingUnidirectionalStreams.push(
			fillStream(rid(loSub), 0x0dn, chunk(3, true)),
		); // lo fill: 0x0d
		await flush();
		fake.incomingUnidirectionalStreams.push(
			screenStream(hiAlias, 0x0dn, chunk(4, true)),
		); // the hub's live 0x0d
		await flush();
		fake.incomingUnidirectionalStreams.push(
			screenStream(hiAlias, 0x0dn, chunk(5, false)),
		);
		await flush();

		const after = got.slice(got.findIndex((g) => g.seq === 2));
		expect(after.map((g) => [g.seq, g.variant])).toEqual([
			[2, "hi"],
			[3, "lo"],
			[4, "hi"], // 0x0d rendered from the live member, not waiting for 0x0e
			[5, "hi"],
		]);
	});

	it("S1 (round 3): a stale change never cancels a rejoined peer's fresh subscriptions", async () => {
		const { fake, screen, chat, got, sub } = await pair();
		for (const r of fake.requestsOf(MSG_SUBSCRIBE))
			r.replies.push(subscribeOk());
		await sub;
		await flush();
		const done = screen.setScreenQuality("user2", "low"); // auto -> low: lo SUBSCRIBE out
		await flush();
		const staleLo = fake.requestsOf(MSG_SUBSCRIBE)[2];
		leave(chat, screen);
		const rejoin = screen.subscribeToScreenTrack("user2"); // the same id, back again
		await flush();
		const [freshHi, freshLo] = fake.requestsOf(MSG_SUBSCRIBE).slice(3);
		freshHi.replies.push(subscribeOk());
		freshLo.replies.push(subscribeOk());
		await rejoin;
		staleLo.replies.push(subscribeOk()); // the old answer lands last
		await done;
		await flush();

		expect(freshHi.aborted || freshLo.aborted).toBe(false);
		expect(chat.isSubscribed("user2/screen")).toBe(true);
		expect(chat.isSubscribed("user2/screen-lo")).toBe(true);
		expect(fake.requestsOf(MSG_SUBSCRIBE)).toHaveLength(5);
		// the rejoin's gate and hold survive: its live stream is delivered
		fake.incomingUnidirectionalStreams.push(
			screenStream(screenVariantAlias("user2", "hi"), 3n, chunk(7, true)),
		);
		await flush();
		expect(got.map((g) => g.seq)).toEqual([7]);
	});

	it("S1 (round 3): a high->low switch whose peer left before it sent sends no SUBSCRIBE", async () => {
		const { fake, screen, chat, sub } = await pair();
		for (const r of fake.requestsOf(MSG_SUBSCRIBE))
			r.replies.push(subscribeOk());
		await sub;
		await flush();
		const toHigh = screen.setScreenQuality("user2", "high");
		await flush();
		fake.requestsOf(MSG_SUBSCRIBE)[2].replies.push(subscribeOk());
		await toHigh;
		const toLow = screen.setScreenQuality("user2", "low");
		leave(chat, screen); // before the switch reads the old Request ID
		await toLow;
		await flush();
		expect(fake.requestsOf(MSG_SUBSCRIBE)).toHaveLength(3);
	});

	it("F6: an accepted SUBSCRIBE that lands after the peer left is cancelled", async () => {
		const { fake, screen, chat, sub } = await pair();
		for (const r of fake.requestsOf(MSG_SUBSCRIBE))
			r.replies.push(subscribeOk());
		await sub;
		await flush();
		const done = screen.setScreenQuality("user2", "low");
		await flush();
		leave(chat, screen);
		const lo = fake.requestsOf(MSG_SUBSCRIBE)[2];
		lo.replies.push(subscribeOk());
		await done;
		await flush();
		expect(chat.isSubscribed("user2/screen-lo")).toBe(false);
		expect(lo.aborted).toBe(true);
		expect(screen.screenQuality("user2")).toBe("auto");
	});

	it("forgetParticipant drops a leaving peer's quality, gate and hold", async () => {
		const { fake, screen, sub } = await pair();
		for (const r of fake.requestsOf(MSG_SUBSCRIBE))
			r.replies.push(subscribeOk());
		await sub;
		await flush();
		const toLow = screen.setScreenQuality("user2", "low");
		await flush();
		fake.requestsOf(MSG_SUBSCRIBE)[2].replies.push(subscribeOk());
		await toLow;
		expect(screen.screenQuality("user2")).toBe("low");
		screen.forgetParticipant("user2");
		expect(screen.screenQuality("user2")).toBe("auto");
	});
});
