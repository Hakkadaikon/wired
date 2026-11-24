import type { EventTemplate } from "nostr-tools/pure";
import { describe, expect, it, vi } from "vitest";
import {
	CLOSE_REASONS,
	closeMessage,
	countdown,
	NIP98_KIND,
	nip98Template,
	ROOM_LIFETIME_S,
	remaining,
	roomSession,
	TOKEN_MAX_BYTES,
} from "../roomAuth";

const HOST = "cd".repeat(32);
const ID = "AAAAAAAAAAAAAAAAAAAAAA";
const URL = `https://hub.example:4433/?room=${ID}&host=${HOST}`;

describe("nip98Template", () => {
	it("a join: kind 27235, empty content, u = the URL, method CONNECT", () => {
		expect(nip98Template(URL, { id: ID }, 1000)).toEqual({
			kind: NIP98_KIND,
			created_at: 1000,
			content: "",
			tags: [
				["u", URL],
				["method", "CONNECT"],
			],
		});
	});

	it("a create adds nip05 and wired-room <id> <mode>", () => {
		const t = nip98Template(
			URL,
			{
				id: ID,
				create: { mode: "auth", nip05: "bob@example.com", created: 1 },
			},
			1000,
		);
		expect(t.tags.slice(2)).toEqual([
			["nip05", "bob@example.com"],
			["wired-room", ID, "auth"],
		]);
	});
});

describe("roomSession", () => {
	const room = { id: ID, host: HOST };
	const sign = vi.fn(async (t: EventTemplate, pubkey: string) => ({
		...t,
		pubkey,
		id: "0".repeat(64), // real lengths: the 1 KiB bound counts them
		sig: "0".repeat(128),
	}));

	it("puts room and host on the server URL; u is that exact string", async () => {
		const s = await roomSession("https://hub.example:4433/", room, HOST, sign);
		expect(s.url).toBe(URL);
		const ev = JSON.parse(s.token ?? "");
		expect(ev.tags[0]).toEqual(["u", s.url]);
		expect(ev.pubkey).toBe(HOST);
	});

	const create = {
		mode: "auth" as const,
		nip05: "bob@example.com",
		created: 1,
	};

	it("the creator tags go only with the room host's own key", async () => {
		const mine = await roomSession(
			"https://h/",
			{ ...room, create },
			HOST,
			sign,
		);
		expect(JSON.parse(mine.token ?? "").tags).toContainEqual([
			"nip05",
			create.nip05,
		]);
		const other = "ef".repeat(32);
		const theirs = await roomSession(
			"https://h/",
			{ ...room, create },
			other,
			sign,
		);
		expect(JSON.parse(theirs.token ?? "").tags).toHaveLength(2); // u, method
	});

	it("the token is the 7 NIP-01 fields in a fixed order, nothing else", async () => {
		const extra = vi.fn(async (t: EventTemplate, pubkey: string) => ({
			sig: "5",
			extra: "x",
			...t,
			pubkey,
			id: "1",
		}));
		const s = await roomSession("https://h/", room, HOST, extra);
		expect(Object.keys(JSON.parse(s.token ?? ""))).toEqual([
			"id",
			"pubkey",
			"created_at",
			"kind",
			"tags",
			"content",
			"sig",
		]);
	});

	it("refuses, before signing, a token over 1 KiB (a long server URL)", async () => {
		sign.mockClear();
		const long = `https://${"a".repeat(TOKEN_MAX_BYTES)}.example/`;
		await expect(roomSession(long, room, HOST, sign)).rejects.toThrow("1 KiB");
		expect(sign).not.toHaveBeenCalled();
	});

	// 435 bytes of fixed JSON + 98 of ?room=&host= leave 491 for the server
	// URL and the nip05 (wire.md 2.1): a 100-char nip05 and a 391-byte URL.
	it("the longest nip05 with a 391-byte server URL fits exactly", async () => {
		const nip05 = `${"a".repeat(64)}@${"b".repeat(32)}.io`; // NIP05_MAX = 100
		const base = `https://${"h".repeat(382)}/`; // 391 bytes
		const s = await roomSession(
			base,
			{ ...room, create: { ...create, nip05 } },
			HOST,
			sign,
		);
		expect(new TextEncoder().encode(s.token).length).toBe(TOKEN_MAX_BYTES);
	});

	it("a sign failure (declined) becomes a message asking to join again", async () => {
		const no = async () => {
			throw new Error("User rejected");
		};
		await expect(roomSession("https://h/", room, HOST, no)).rejects.toThrow(
			"Join again to retry.",
		);
	});

	it("without a login: no token (an open room needs none)", async () => {
		const s = await roomSession("https://hub.example:4433/", room, null, sign);
		expect(s).toEqual({ url: URL });
	});

	it("signs afresh each time (tokens are single-use)", async () => {
		sign.mockClear();
		await roomSession("https://hub.example:4433/", room, HOST, sign);
		await roomSession("https://hub.example:4433/", room, HOST, sign);
		expect(sign).toHaveBeenCalledTimes(2);
	});
});

describe("closeMessage", () => {
	it.each([
		"malformed-auth",
		"expired-auth",
		"unauthorized",
		"nip05-unverified",
		"room-full",
		"id-taken",
		"no-room-slots",
		"no-such-room",
		"room-ended",
	])("%s is final, with a message", (token) => {
		expect(closeMessage(token)).toBe(CLOSE_REASONS[token]);
		expect(closeMessage(token)).toMatch(/\.$/);
	});

	it.each(["", "toString", "ROOM-ENDED", "stream reset"])(
		"%j is not a reason token (rejoin as before)",
		(reason) => expect(closeMessage(reason)).toBeUndefined(),
	);
});

describe("remaining", () => {
	it("hides an ends in the past or beyond the lifetime + skew", () => {
		expect(remaining(1000, 1000)).toBeUndefined();
		expect(remaining(999, 1000)).toBeUndefined();
		expect(remaining(1000 + ROOM_LIFETIME_S + 300, 1000)).toBe("5:05:00");
		expect(remaining(1001 + ROOM_LIFETIME_S + 300, 1000)).toBeUndefined();
		expect(remaining(1060, 1000)).toBe("0:01:00");
	});
});

describe("countdown", () => {
	it("H:MM:SS of what is left, 0:00:00 once past", () => {
		expect(countdown(ROOM_LIFETIME_S, 0)).toBe("5:00:00");
		expect(countdown(3661, 0)).toBe("1:01:01");
		expect(countdown(100, 41)).toBe("0:00:59");
		expect(countdown(100, 100)).toBe("0:00:00");
		expect(countdown(100, 200)).toBe("0:00:00");
	});
});
