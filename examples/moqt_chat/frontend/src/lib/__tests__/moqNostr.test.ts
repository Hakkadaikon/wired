import { finalizeEvent, getPublicKey } from "nostr-tools/pure";
import { describe, expect, it, vi } from "vitest";
import { MoqNostr, type NostrFilter } from "../moqNostr";
import { NOSTR_SPACE_A } from "../nostr";

// Fixed test-only secret keys.
const SK = new Uint8Array(32).fill(7);
const SK2 = new Uint8Array(32).fill(8);
const ROOM: NostrFilter = { kinds: [1311], a: NOSTR_SPACE_A };
const NOW = Math.floor(Date.now() / 1000); // live events must be recent

function chat(
	content: string,
	over: Partial<{ kind: number; tags: string[][]; created_at: number }> = {},
	sk = SK,
) {
	return finalizeEvent(
		{
			kind: 1311,
			created_at: NOW,
			tags: [["a", NOSTR_SPACE_A]],
			content,
			...over,
		},
		sk,
	);
}
// As it arrives off the wire: plain JSON, no cached verification mark.
const wire = (ev: object) => JSON.stringify(ev);

function collect(n: MoqNostr, filter: NostrFilter = ROOM) {
	const seen: string[] = [];
	const off = n.subscribe(filter, {
		onEvent: (e) => seen.push(e.content),
		onHistoryEnd: () => seen.push("END"),
	});
	return { seen, off };
}

describe("MoqNostr.publish", () => {
	it("sends the event JSON unchanged as one chat Object", async () => {
		const send = vi.fn().mockResolvedValue(undefined);
		const ev = chat("hi");
		await new MoqNostr(send).publish(ev, { priority: 3 });
		expect(send).toHaveBeenCalledExactlyOnceWith(JSON.stringify(ev), "chat", {
			priority: 3,
		});
	});

	it("rejects with the send's reason", async () => {
		const n = new MoqNostr(() => Promise.reject(new Error("stream reset")));
		await expect(n.publish(chat("hi"))).rejects.toThrow("stream reset");
	});

	it.each([
		[10312, "nostr-presence"],
		[30312, "nostr-30312"],
		[30313, "nostr-30313"],
		[7, "nostr-react"],
		[5, "nostr-react"],
	])("sends kind %i on its own track %s", async (kind, track) => {
		const send = vi.fn().mockResolvedValue(undefined);
		await new MoqNostr(send).publish(chat("x", { kind }));
		expect(send.mock.calls[0][1]).toBe(track);
	});

	it.each([1, 0, 20000])(
		"rejects kind %i without sending: no track carries it",
		async (kind) => {
			const send = vi.fn();
			await expect(
				new MoqNostr(send).publish(chat("p", { kind })),
			).rejects.toThrow(/unsupported/);
			expect(send).not.toHaveBeenCalled();
		},
	);
});

describe("MoqNostr.subscribe", () => {
	it("receive returns a new verified event, nothing for a repeat or junk", () => {
		const n = new MoqNostr(vi.fn());
		const ev = chat("once");
		expect(n.receive(wire(ev))?.id).toBe(ev.id);
		expect(n.receive(wire(ev))).toBeUndefined();
		expect(n.receive("{not json")).toBeUndefined();
	});

	it("delivers history, then the end marker, then live events", () => {
		const n = new MoqNostr(vi.fn());
		n.receive(wire(chat("old")));
		const { seen } = collect(n);
		n.receive(wire(chat("live")));
		expect(seen).toEqual(["old", "END", "live"]);
	});

	it("limit keeps the newest history events only", () => {
		const n = new MoqNostr(vi.fn());
		for (const t of ["a", "b", "c"]) n.receive(wire(chat(t)));
		expect(collect(n, { ...ROOM, limit: 2 }).seen).toEqual(["b", "c", "END"]);
		expect(collect(n, { ...ROOM, limit: 0 }).seen).toEqual(["END"]);
	});

	it("drops filter mismatches: kind, missing or foreign a tag, author, since", () => {
		const n = new MoqNostr(vi.fn());
		const { seen } = collect(n, {
			...ROOM,
			authors: [getPublicKey(SK)],
			since: NOW - 60,
		});
		n.receive(wire(chat("kind1", { kind: 1 })));
		n.receive(wire(chat("no-a", { tags: [] })));
		n.receive(wire(chat("other-room", { tags: [["a", "30311:00:x"]] })));
		n.receive(wire(chat("stranger", {}, SK2)));
		n.receive(wire(chat("too-old", { created_at: NOW - 120 })));
		n.receive(wire(chat("ok")));
		expect(seen).toEqual(["END", "ok"]);
	});

	it("drops and counts invalid payloads (tampered content or sig, junk)", () => {
		const n = new MoqNostr(vi.fn());
		const { seen } = collect(n);
		const ok = chat("ok");
		const sig = (ok.sig[0] === "0" ? "1" : "0") + ok.sig.slice(1);
		n.receive(wire({ ...ok, content: "tampered" }));
		n.receive(wire({ ...ok, sig }));
		n.receive("{not json");
		n.receive(wire(ok));
		expect(seen).toEqual(["END", "ok"]);
		expect(n.invalid).toBe(3);
	});

	it("hands each event's original payload string, history and live alike", () => {
		const n = new MoqNostr(vi.fn());
		const spaced = (ev: object) => JSON.stringify(ev, null, 1);
		const old = spaced(chat("old"));
		n.receive(old);
		const raws: string[] = [];
		n.subscribe(ROOM, { onEvent: (_e, raw) => raws.push(raw) });
		const live = spaced(chat("live"));
		n.receive(live);
		expect(raws).toEqual([old, live]);
	});

	it("ignores a repeated id, so replays neither repeat nor push out history", () => {
		const n = new MoqNostr(vi.fn());
		const a = wire(chat("a"));
		n.receive(wire(chat("b", { created_at: NOW - 1 })));
		n.receive(a);
		n.receive(a);
		const { seen } = collect(n, { ...ROOM, limit: 2 });
		n.receive(a);
		expect(seen).toEqual(["b", "a", "END"]);
	});

	it("drops oversized payloads and implausible times", () => {
		vi.useFakeTimers({ now: 1_800_000_000_000 });
		try {
			const n = new MoqNostr(vi.fn());
			const { seen } = collect(n);
			n.receive(
				wire(chat("x".repeat(70 * 1024), { created_at: 1_800_000_000 })),
			);
			n.receive(wire(chat("future", { created_at: 1_800_000_000 + 3600 })));
			n.receive(wire(chat("stale live", { created_at: 1_700_000_000 })));
			n.receive(
				wire(chat("old history", { created_at: 1_700_000_000 })),
				false,
			);
			n.receive(wire(chat("now", { created_at: 1_800_000_000 })));
			expect(seen).toEqual(["END", "old history", "now"]);
			expect(n.invalid).toBe(3);
		} finally {
			vi.useRealTimers();
		}
	});

	it("unsubscribe stops delivery", () => {
		const n = new MoqNostr(vi.fn());
		const { seen, off } = collect(n);
		off();
		n.receive(wire(chat("after")));
		expect(seen).toEqual(["END"]);
	});
});

describe("MoqNostr replaceable kinds keep the newest per key", () => {
	const PRES: NostrFilter = { kinds: [10312], a: NOSTR_SPACE_A };
	const pres = (content: string, created_at: number, sk = SK) =>
		chat(content, { kind: 10312, created_at }, sk);
	const P = "nostr-presence" as const;

	it("a newer one replaces the held one in history and goes live", () => {
		const n = new MoqNostr(vi.fn());
		n.receive(wire(pres("old", NOW - 5)), true, P);
		n.receive(wire(pres("other author", NOW - 5, SK2)), true, P);
		const { seen } = collect(n, PRES);
		n.receive(wire(pres("new", NOW)), true, P);
		expect(seen).toEqual(["old", "other author", "END", "new"]);
		expect(collect(n, PRES).seen).toEqual(["other author", "new", "END"]);
	});

	it("an older one arriving later is dropped, not counted invalid", () => {
		const n = new MoqNostr(vi.fn());
		const { seen } = collect(n, PRES);
		n.receive(wire(pres("new", NOW)), true, P);
		expect(n.receive(wire(pres("late old", NOW - 5)), true, P)).toBeUndefined();
		expect(seen).toEqual(["END", "new"]);
		expect(n.invalid).toBe(0);
	});

	it("on a created_at tie the lowest id wins, in either order", () => {
		const a = pres("a", NOW);
		const b = pres("b", NOW);
		const [lo, hi] = a.id < b.id ? [a, b] : [b, a];
		for (const order of [
			[lo, hi],
			[hi, lo],
		]) {
			const n = new MoqNostr(vi.fn());
			for (const ev of order) n.receive(wire(ev), true, P);
			expect(collect(n, PRES).seen).toEqual([lo.content, "END"]);
		}
	});

	it("addressable kinds are keyed by d as well", () => {
		const n = new MoqNostr(vi.fn());
		const m = (d: string, created_at: number) =>
			chat(d, {
				kind: 30313,
				created_at,
				tags: [
					["a", NOSTR_SPACE_A],
					["d", d],
				],
			});
		n.receive(wire(m("m1", NOW - 5)), true, "nostr-30313");
		n.receive(wire(m("m2", NOW)), true, "nostr-30313");
		const MEET = { kinds: [30313], a: NOSTR_SPACE_A };
		expect(collect(n, MEET).seen).toEqual(["m1", "m2", "END"]);
	});

	it("an older replay loses even after the newer left the history cap", () => {
		const n = new MoqNostr(vi.fn());
		const old = pres("old", NOW - 5);
		n.receive(wire(pres("new", NOW)), true, P);
		for (let i = 0; i < 520; i++) n.receive(wire(chat(`c${i}`)));
		expect(n.receive(wire(old), false, P)).toBeUndefined();
		expect(collect(n, PRES).seen).toEqual(["END"]);
	}, 30_000); // 520 signatures
});

describe("MoqNostr track matching", () => {
	it("drops and counts a kind on a track that does not carry it", () => {
		const n = new MoqNostr(vi.fn());
		expect(n.receive(wire(chat("x", { kind: 10312 })))).toBeUndefined();
		expect(n.receive(wire(chat("y")), true, "nostr-react")).toBeUndefined();
		expect(n.invalid).toBe(2);
	});

	it("a filter without a matches any a tag (reactions carry none)", () => {
		const n = new MoqNostr(vi.fn());
		const { seen } = collect(n, { kinds: [7] });
		n.receive(wire(chat("+", { kind: 7, tags: [] })), true, "nostr-react");
		expect(seen).toEqual(["END", "+"]);
	});
});

describe("MoqNostr accept and the latest cap", () => {
	it("drops what accept refuses before it takes a slot", () => {
		const n = new MoqNostr(vi.fn(), (ev) => ev.pubkey !== getPublicKey(SK2));
		const { seen } = collect(n, { kinds: [10312] });
		n.receive(wire(chat("bad", { kind: 10312 }, SK2)), true, "nostr-presence");
		n.receive(wire(chat("ok", { kind: 10312 })), true, "nostr-presence");
		expect(seen).toEqual(["END", "ok"]);
		expect(n.invalid).toBe(0);
	});
});
