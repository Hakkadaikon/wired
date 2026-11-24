import { describe, expect, it, vi } from "vitest";
import { presenceTemplate } from "@/lib/nostrRoom";
import {
	inviteLink,
	newlyRaised,
	retryMessage,
	timerLevel,
} from "@/lib/roomUi";

describe("timerLevel", () => {
	it.each([
		[30 * 60 + 1, "normal"],
		[30 * 60, "normal"],
		[30 * 60 - 1, "warn"],
		[5 * 60, "warn"],
		[5 * 60 - 1, "danger"],
		[0, "danger"],
	])("%i s left is %s", (left, level) => {
		expect(timerLevel(left)).toBe(level);
	});
});

describe("inviteLink", () => {
	const room = { id: `${"r".repeat(21)}A`, host: "a".repeat(64) };
	it("origin + path with room and host only (the page's own query is dropped)", () => {
		expect(
			inviteLink({ origin: "https://h.example", pathname: "/chat/" }, room),
		).toBe(`https://h.example/chat/?room=${room.id}&host=${room.host}`);
	});
});

describe("newlyRaised", () => {
	const SPACE = `30312:${"a".repeat(64)}:room`;
	const NOW = 1_700_000_000;
	const ev = (pubkey: string, hand: boolean, at = NOW, space = SPACE) => ({
		...presenceTemplate(space, hand, at),
		pubkey,
		id: pubkey,
		sig: "",
	});
	const raised = (prev: object, next: object) =>
		newlyRaised(prev as never, next as never, SPACE, NOW);

	it("a hand that went up is listed", () => {
		expect(raised({ p: ev("p", false) }, { p: ev("p", true) })).toEqual(["p"]);
	});
	it("a first presence with the hand up is not (history replay, join)", () => {
		expect(raised({}, { p: ev("p", true) })).toEqual([]);
	});
	it("a seen-down presence counts even when stale (a reconnect)", () => {
		expect(
			raised({ p: ev("p", false, NOW - 3600) }, { p: ev("p", true) }),
		).toEqual(["p"]);
	});
	it("a hand already up, or lowered, is not", () => {
		expect(raised({ p: ev("p", true) }, { p: ev("p", true, NOW + 1) })).toEqual(
			[],
		);
		expect(raised({ p: ev("p", true) }, { p: ev("p", false) })).toEqual([]);
	});
	it("a stale or other-space raise is not", () => {
		const down = { p: ev("p", false) };
		expect(raised(down, { p: ev("p", true, NOW - 3600) })).toEqual([]);
		expect(raised(down, { p: ev("p", true, NOW, "30312:x:y") })).toEqual([]);
	});
});

describe("retryMessage", () => {
	const bytes = new Uint8Array([1]);
	const failed = {
		id: 7,
		senderId: "user1",
		text: "hi",
		at: 1,
		own: true,
		failed: true,
		attachments: [{ bytes, mimeType: "image/png", url: "blob:x" }],
	};

	it("clears the error, re-sends text and attachments, and drops the failed bubble only once the send is done", async () => {
		const order: string[] = [];
		let done: () => void = () => {};
		const send = vi.fn(
			() =>
				new Promise<void>((r) => {
					done = r;
				}),
		);
		const store = {
			setMessageSendError: vi.fn((e: string | null) => order.push(`err:${e}`)),
			removeMessage: vi.fn((id: number) => order.push(`rm:${id}`)),
		};
		const p = retryMessage(failed, send, store);
		expect(send).toHaveBeenCalledWith("hi", [{ bytes, mimeType: "image/png" }]);
		expect(store.removeMessage).not.toHaveBeenCalled(); // still visible
		done();
		await p;
		expect(order).toEqual(["err:null", "rm:7"]);
	});

	it("a text-only message re-sends with no attachments", async () => {
		const send = vi.fn(async () => {});
		const store = { setMessageSendError: vi.fn(), removeMessage: vi.fn() };
		await retryMessage({ id: 8, text: "t" }, send, store);
		expect(send).toHaveBeenCalledWith("t", []);
		expect(store.removeMessage).toHaveBeenCalledWith(8);
	});
});
