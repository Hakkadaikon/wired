import { type Event, finalizeEvent, getPublicKey } from "nostr-tools/pure";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	checkOwnChatEvent,
	DEFAULT_NOSTR_RELAYS,
	LOGIN_ERROR,
	NOSTR_ROOM_A,
	nostrLogin,
	nostrRelays,
	ProfileResolver,
	parseRelayList,
	parseVerifiedEvent,
	profileName,
	shortNpub,
	signChatEvent,
} from "@/lib/nostr";

// Fixed test-only secret key (never used outside this file).
const SK = new Uint8Array(32).fill(7);
const PK = getPublicKey(SK);

function signed(
	over: Partial<{ kind: number; tags: string[][]; content: string }> = {},
) {
	return finalizeEvent(
		{
			kind: 1311,
			created_at: 1_700_000_000,
			tags: [["a", NOSTR_ROOM_A]],
			content: "hello",
			...over,
		},
		SK,
	);
}
// As it arrives off the wire: plain JSON, no cached verification mark.
const wire = (ev: object) => JSON.stringify(ev);

describe("parseVerifiedEvent", () => {
	it("accepts a validly signed event", () => {
		const ev = signed();
		expect(parseVerifiedEvent(wire(ev))?.id).toBe(ev.id);
	});

	it("rejects tampered content (id no longer matches)", () => {
		expect(
			parseVerifiedEvent(wire({ ...signed(), content: "evil" })),
		).toBeUndefined();
	});

	it("rejects a tampered signature", () => {
		const ev = signed();
		const sig = (ev.sig[0] === "0" ? "1" : "0") + ev.sig.slice(1);
		expect(parseVerifiedEvent(wire({ ...ev, sig }))).toBeUndefined();
	});

	it("rejects non-JSON, non-object JSON and malformed events", () => {
		expect(parseVerifiedEvent("{not json")).toBeUndefined();
		expect(parseVerifiedEvent("null")).toBeUndefined();
		expect(parseVerifiedEvent('{"kind":1311}')).toBeUndefined();
	});
});

describe("shortNpub", () => {
	it("shortens the bech32 npub of a hex pubkey", () => {
		const s = shortNpub(PK);
		expect(s.startsWith("npub1")).toBe(true);
		expect(s).toContain("…");
	});
});

describe("NIP-07", () => {
	afterEach(() => {
		delete (window as { nostr?: unknown }).nostr;
	});

	function mockNostr() {
		const nostr = {
			getPublicKey: vi.fn().mockResolvedValue(PK),
			signEvent: vi.fn(async (t) => finalizeEvent(t, SK)),
		};
		(window as { nostr?: unknown }).nostr = nostr;
		return nostr;
	}

	it("nostrLogin returns the extension's pubkey", async () => {
		mockNostr();
		await expect(nostrLogin()).resolves.toBe(PK);
	});

	it("nostrLogin waits for a late-injected extension", async () => {
		setTimeout(mockNostr, 150);
		await expect(nostrLogin()).resolves.toBe(PK);
	});

	it("nostrLogin rejects when no extension appears", async () => {
		await expect(nostrLogin(50)).rejects.toThrow(LOGIN_ERROR.missing);
	});

	it("nostrLogin tells a declined request from an invalid pubkey", async () => {
		const nostr = mockNostr();
		nostr.getPublicKey.mockRejectedValueOnce(new Error("user said no"));
		await expect(nostrLogin()).rejects.toThrow(LOGIN_ERROR.rejected);
		nostr.getPublicKey.mockResolvedValueOnce("npub1notHex");
		await expect(nostrLogin()).rejects.toThrow(LOGIN_ERROR.invalid);
	});

	it("signChatEvent has the extension sign a 1311 event for the room", async () => {
		const nostr = mockNostr();
		const ev = await signChatEvent("hi there");
		expect(nostr.signEvent.mock.calls[0][0]).toMatchObject({
			kind: 1311,
			tags: [["a", NOSTR_ROOM_A]],
			content: "hi there",
		});
		expect(parseVerifiedEvent(JSON.stringify(ev))?.content).toBe("hi there");
	});
});

describe("kind 0 profile name", () => {
	function profile(content: unknown, created_at: number, sk = SK) {
		return finalizeEvent(
			{ kind: 0, created_at, tags: [], content: JSON.stringify(content) },
			sk,
		);
	}
	// Distinct pubkey per test: the name cache is per session (module scope).
	const key = (n: number) => new Uint8Array(32).fill(n);

	it("prefers display_name, then name", () => {
		expect(
			profileName(PK, [profile({ name: "n", display_name: "Disp" }, 1)]),
		).toBe("Disp");
		expect(profileName(PK, [profile({ name: "n", display_name: "" }, 1)])).toBe(
			"n",
		);
		expect(profileName(PK, [profile({ about: "x" }, 1)])).toBeUndefined();
	});

	it("takes the newest valid event across relays", () => {
		const old = profile({ name: "old" }, 1);
		const neu = profile({ name: "new" }, 2);
		expect(profileName(PK, [neu, old])).toBe("new");
		expect(profileName(PK, [old, neu])).toBe("new");
	});

	it("ignores forged, foreign and non-JSON profiles", () => {
		const good = profile({ name: "good" }, 1);
		// Through JSON, as off the wire: finalizeEvent's cached "verified" mark
		// would otherwise survive the spread and skip the check.
		const forged = JSON.parse(
			JSON.stringify({
				...profile({ name: "x" }, 9),
				content: '{"name":"evil"}',
			}),
		);
		const foreign = profile({ name: "other" }, 9, key(9));
		const junk = finalizeEvent(
			{ kind: 0, created_at: 9, tags: [], content: "not json" },
			SK,
		);
		expect(profileName(PK, [forged, foreign, good])).toBe("good");
		// kind 0 is replaceable (NIP-01): a newer unreadable profile wins.
		expect(profileName(PK, [junk, good])).toBeUndefined();
	});

	it("caps the name at 64 chars", () => {
		const long = "a".repeat(200);
		expect(profileName(PK, [profile({ name: long }, 1)])).toHaveLength(64);
	});

	it("nostrRelays: defaults, ?relays= overrides, empty means none", () => {
		expect(nostrRelays("")).toEqual(DEFAULT_NOSTR_RELAYS);
		expect(nostrRelays("?relays=wss://a,wss://b")).toEqual([
			"wss://a",
			"wss://b",
		]);
		expect(nostrRelays("?ns=0&relays=")).toEqual([]);
		expect(nostrRelays("", ["wss://saved"])).toEqual(["wss://saved"]);
		expect(nostrRelays("?relays=http://x", ["wss://saved"])).toEqual([]);
	});

	it("parseRelayList trims, keeps wss (ws only for localhost), dedupes, caps at 10", () => {
		expect(
			parseRelayList(
				"  wss://a.example \n\nwss://a.example\nhttps://b\nws://evil.example\nws://localhost:7777\nws://127.0.0.1\nnot a url",
			),
		).toEqual(["wss://a.example", "ws://localhost:7777", "ws://127.0.0.1"]);
		const many = Array.from({ length: 12 }, (_, i) => `wss://r${i}.example`);
		expect(parseRelayList(many.join("\n"))).toEqual(many.slice(0, 10));
	});
});

describe("public relays are read-only", () => {
	it("the profile lookup sends only REQ/CLOSE frames, never EVENT or AUTH", async () => {
		const frames: string[] = [];
		const pk = getPublicKey(new Uint8Array(32).fill(11));
		const profile = finalizeEvent(
			{ kind: 0, created_at: 1, tags: [], content: '{"name":"zed"}' },
			new Uint8Array(32).fill(11),
		);
		class FakeWs {
			static OPEN = 1;
			static CLOSING = 2;
			static CLOSED = 3;
			readyState = 0;
			onopen: (() => void) | null = null;
			onmessage: ((m: { data: string }) => void) | null = null;
			onclose: (() => void) | null = null;
			onerror: (() => void) | null = null;
			constructor(readonly url: string) {
				setTimeout(() => {
					this.readyState = 1;
					this.onopen?.();
					// A relay asking for auth must not get an AUTH back.
					this.onmessage?.({ data: JSON.stringify(["AUTH", "chal"]) });
				}, 0);
			}
			send(raw: string) {
				frames.push(raw);
				const [type, sub] = JSON.parse(raw);
				if (type !== "REQ") return;
				const reply = (m: unknown[]) =>
					this.onmessage?.({ data: JSON.stringify(m) });
				reply(["EVENT", sub, JSON.parse(JSON.stringify(profile))]);
				reply(["EOSE", sub]);
			}
			close() {
				this.readyState = 3;
			}
		}
		vi.stubGlobal("WebSocket", FakeWs);
		try {
			const got = await new Promise((resolve) =>
				new ProfileResolver((_pk, name) => resolve(name)).request(pk, [
					"wss://fake.example",
				]),
			);
			expect(got).toBe("zed");
		} finally {
			vi.unstubAllGlobals();
		}
		expect(frames.length).toBeGreaterThan(0);
		const types = frames.map((f) => JSON.parse(f)[0]);
		expect(types).toContain("REQ");
		expect(types.filter((t) => t !== "REQ" && t !== "CLOSE")).toEqual([]);
	});
});

describe("checkOwnChatEvent (before publishing the extension's event)", () => {
	const ok = () =>
		finalizeEvent(
			{
				kind: 1311,
				created_at: 1,
				tags: [["a", NOSTR_ROOM_A]],
				content: "hi",
			},
			SK,
		);
	// Off the wire from the extension: no cached verification mark.
	const plain = (ev: object) => JSON.parse(JSON.stringify(ev));

	it("passes the extension's event when it matches", () => {
		const ev = plain(ok());
		expect(checkOwnChatEvent(ev, PK, "hi")).toBe(ev);
	});

	it.each([
		["a bad signature", (e: Event) => ({ ...e, sig: "00".repeat(64) })],
		["changed content", (e: Event) => ({ ...e, content: "other" })],
	])("rejects %s", (_n, mutate) => {
		expect(() => checkOwnChatEvent(plain(mutate(ok())), PK, "hi")).toThrow();
	});

	it("rejects a valid event by another key", () => {
		const other = finalizeEvent(
			{ kind: 1311, created_at: 1, tags: [["a", NOSTR_ROOM_A]], content: "hi" },
			new Uint8Array(32).fill(9),
		);
		expect(() => checkOwnChatEvent(plain(other), PK, "hi")).toThrow();
	});

	it.each([
		["other text", { content: "not what was typed" }],
		["wrong kind", { kind: 1 }],
		["no room tag", { tags: [] }],
		["another room", { tags: [["a", "30311:00:x"]] }],
	])("rejects a validly signed event with %s", (_n, over) => {
		const ev = finalizeEvent(
			{
				kind: 1311,
				created_at: 1,
				tags: [["a", NOSTR_ROOM_A]],
				content: "hi",
				...over,
			},
			SK,
		);
		expect(() => checkOwnChatEvent(plain(ev), PK, "hi")).toThrow();
	});
});

describe("ProfileResolver", () => {
	afterEach(() => vi.useRealTimers());
	const pkOf = (n: number) => getPublicKey(new Uint8Array(32).fill(n));
	const profileBy = (n: number, name: string) =>
		finalizeEvent(
			{ kind: 0, created_at: 1, tags: [], content: JSON.stringify({ name }) },
			new Uint8Array(32).fill(n),
		);
	function setup(answer: () => Promise<Event[]> = async () => []) {
		vi.useFakeTimers();
		const query = vi.fn((_relays: string[], _f: { authors?: string[] }) =>
			answer(),
		);
		const names: string[] = [];
		const r = new ProfileResolver((_pk, name) => names.push(name), query);
		return { r, query, names };
	}

	it("batches pubkeys requested within the debounce into one REQ", async () => {
		const { r, query, names } = setup(async () => [
			profileBy(21, "ann"),
			profileBy(22, "bob"),
		]);
		r.request(pkOf(21), ["wss://r"]);
		r.request(pkOf(22), ["wss://r"]);
		r.request(pkOf(21), ["wss://r"]);
		expect(query).not.toHaveBeenCalled();
		await vi.advanceTimersByTimeAsync(300);
		expect(query).toHaveBeenCalledExactlyOnceWith(["wss://r"], {
			kinds: [0],
			authors: [pkOf(21), pkOf(22)],
			limit: 2,
		});
		expect(names).toEqual(["ann", "bob"]);
		r.request(pkOf(21), ["wss://r"]); // cached: answered, no REQ
		await vi.advanceTimersByTimeAsync(300);
		expect(query).toHaveBeenCalledOnce();
		expect(names).toEqual(["ann", "bob", "ann"]);
	});

	it("chunks many authors and caps REQs per minute", async () => {
		const { r, query } = setup();
		const hex = (i: number) => i.toString(16).padStart(64, "0");
		for (let i = 0; i < 400; i++) r.request(hex(i), ["wss://r"]);
		await vi.advanceTimersByTimeAsync(300);
		// 256 queued at most (the cache cap), 50 authors per REQ: 6 REQs.
		expect(query).toHaveBeenCalledTimes(6);
		expect(query.mock.calls[0][1].authors).toHaveLength(50);
		expect(query.mock.calls[5][1].authors).toHaveLength(6);
		r.request(hex(1000), ["wss://r"]); // the 7th REQ this minute waits
		await vi.advanceTimersByTimeAsync(300);
		expect(query).toHaveBeenCalledTimes(6);
		await vi.advanceTimersByTimeAsync(60_000);
		expect(query).toHaveBeenCalledTimes(7);
	});

	it("retries a miss after 5 minutes or when the relays change, not before", async () => {
		const { r, query } = setup(async () => {
			throw new Error("timeout");
		});
		r.request(pkOf(23), ["wss://r"]);
		await vi.advanceTimersByTimeAsync(300);
		r.request(pkOf(23), ["wss://r"]);
		await vi.advanceTimersByTimeAsync(300);
		expect(query).toHaveBeenCalledTimes(1);
		r.request(pkOf(23), ["wss://other"]);
		await vi.advanceTimersByTimeAsync(300);
		expect(query).toHaveBeenCalledTimes(2);
		await vi.advanceTimersByTimeAsync(5 * 60_000);
		r.request(pkOf(23), ["wss://other"]);
		await vi.advanceTimersByTimeAsync(300);
		expect(query).toHaveBeenCalledTimes(3);
	});

	it("bounds the cache: the oldest name is evicted and fetched again", async () => {
		const { r, query } = setup(async () => [profileBy(24, "old")]);
		r.request(pkOf(24), ["wss://r"]);
		await vi.advanceTimersByTimeAsync(300);
		await vi.advanceTimersByTimeAsync(60_000);
		for (let i = 0; i < 256; i++)
			r.request((i + 0x1000).toString(16).padStart(64, "0"), ["wss://r"]);
		await vi.advanceTimersByTimeAsync(300);
		expect(query).toHaveBeenCalledTimes(1 + 6);
		await vi.advanceTimersByTimeAsync(60_000);
		r.request(pkOf(24), ["wss://r"]);
		await vi.advanceTimersByTimeAsync(300);
		expect(query).toHaveBeenCalledTimes(1 + 6 + 1);
		expect(query.mock.calls.at(-1)?.[1].authors).toEqual([pkOf(24)]);
	});

	it("never queries with no relays", async () => {
		const { r, query } = setup();
		r.request(pkOf(25), []);
		await vi.advanceTimersByTimeAsync(300);
		expect(query).not.toHaveBeenCalled();
	});
});
