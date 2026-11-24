import { npubEncode } from "nostr-tools/nip19";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	activeRoom,
	enterRoom,
	exitRoom,
	isRoomId,
	newRoomId,
	parseRoomLink,
	roomName,
	withRoom,
} from "../roomLink";

const HOST = "ab".repeat(32);
const ID = "AAAAAAAAAAAAAAAAAAAAAA"; // 16 zero bytes

describe("isRoomId", () => {
	it("accepts the base64url of 16 bytes (22 chars, last of A/Q/g/w)", () => {
		expect(isRoomId(ID)).toBe(true);
		expect(isRoomId(`${"_-9z".repeat(5)}Zw`)).toBe(true);
	});
	it.each([
		["21 chars", ID.slice(1)],
		["23 chars", `${ID}A`],
		["padding", `${ID.slice(2)}==`],
		["a non-base64url char", `${ID.slice(1, 21)}+A`],
		["unused low bits set", `${ID.slice(1)}B`],
		["empty", ""],
	])("refuses %s", (_, id) => expect(isRoomId(id)).toBe(false));
});

describe("newRoomId", () => {
	afterEach(() => vi.restoreAllMocks());
	it("encodes 16 random bytes as unpadded base64url", () => {
		vi.spyOn(crypto, "getRandomValues").mockImplementation((a) => {
			(a as Uint8Array).fill(0xff);
			return a;
		});
		expect(newRoomId()).toBe(`${"_".repeat(21)}w`);
	});
	it("gives a valid, fresh id each call", () => {
		const a = newRoomId();
		expect(isRoomId(a)).toBe(true);
		expect(newRoomId()).not.toBe(a);
	});
});

describe("parseRoomLink", () => {
	it("is empty without room and host (create mode)", () => {
		expect(parseRoomLink("")).toEqual({});
		expect(parseRoomLink("?relays=")).toEqual({});
	});
	it("reads an uppercase hex host as lowercase", () => {
		expect(parseRoomLink(`?room=${ID}&host=${HOST.toUpperCase()}`)).toEqual({
			link: { id: ID, host: HOST },
		});
	});
	it("reads a hex or npub host", () => {
		const want = { link: { id: ID, host: HOST } };
		expect(parseRoomLink(`?room=${ID}&host=${HOST}`)).toEqual(want);
		expect(parseRoomLink(`?room=${ID}&host=${npubEncode(HOST)}`)).toEqual(want);
	});
	it.each([
		["a bad id", `?room=x&host=${HOST}`],
		["no host", `?room=${ID}`],
		["a junk npub", `?room=${ID}&host=npub1junk`],
		["a host without room", `?host=${HOST}`],
	])("refuses %s with an error", (_, q) => {
		const r = parseRoomLink(q);
		expect(r.link).toBeUndefined();
		expect(r.error).toMatch(/room link/);
	});
});

describe("withRoom", () => {
	const link = { id: ID, host: HOST };
	it("builds the share link from the page's origin and path", () => {
		expect(withRoom("https://h.example/wired/moqt_chat/", link)).toBe(
			`https://h.example/wired/moqt_chat/?room=${ID}&host=${HOST}`,
		);
	});
	it("keeps other parameters and replaces an old room", () => {
		expect(withRoom(`http://l:1/?relays=&room=old&host=x`, link)).toBe(
			`http://l:1/?relays=&room=${ID}&host=${HOST}`,
		);
	});
});

describe("exitRoom", () => {
	it("forgets that this page created the room (its tags, its created time)", () => {
		enterRoom(
			{ id: ID, host: HOST },
			{ mode: "auth", nip05: "a@b.c", created: 1 },
		);
		exitRoom();
		expect(activeRoom.create).toBeUndefined();
		expect(activeRoom.id).toBe(ID);
	});
});

describe("enterRoom", () => {
	it("sets the room, its NIP-53 space coordinate and namespace", () => {
		enterRoom({ id: ID, host: HOST });
		expect(activeRoom).toEqual({
			id: ID,
			host: HOST,
			space: `30312:${HOST}:${ID}`,
		});
	});
	it("names a room by its id until the host's space says otherwise", () => {
		expect(roomName(ID)).toBe("Room AAAAAA");
	});
});
