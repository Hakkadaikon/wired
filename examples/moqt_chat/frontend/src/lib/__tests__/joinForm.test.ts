import { describe, expect, it } from "vitest";
import {
	certHashError,
	createRoomBlocker,
	joinBlocker,
	shortHash,
	urlError,
} from "../joinForm";

const HEX = "0123456789abcdef".repeat(4);

describe("shortHash", () => {
	it("shows the first 8 and last 8 hex digits", () => {
		expect(shortHash(HEX)).toBe("01234567…89abcdef");
	});

	it("drops colon separators before shortening", () => {
		const colon = HEX.match(/../g)?.join(":") ?? "";
		expect(shortHash(colon)).toBe("01234567…89abcdef");
	});

	it("leaves 16 digits or fewer whole", () => {
		expect(shortHash("0123456789abcdef")).toBe("0123456789abcdef");
		expect(shortHash("")).toBe("");
	});
});

describe("urlError", () => {
	it("accepts an https URL", () => {
		expect(urlError("https://localhost:4433/")).toBeNull();
	});

	it("requires a value", () => {
		expect(urlError("  ")).toBe("Enter the server URL");
	});

	it("rejects text that is not a URL", () => {
		expect(urlError("localhost")).toBe(
			"Enter a full URL, e.g. https://host:4433/",
		);
	});

	it("rejects a fragment, even an empty one (WebTransport refuses it)", () => {
		expect(urlError("https://localhost:4433/#x")).toBe(
			"Remove the #fragment from the URL",
		);
		expect(urlError("https://localhost:4433/#")).toBe(
			"Remove the #fragment from the URL",
		);
	});

	it("rejects a non-https scheme (WebTransport needs https)", () => {
		expect(urlError("http://localhost:4433/")).toBe(
			"WebTransport needs an https:// URL",
		);
	});
});

describe("certHashError", () => {
	it("allows empty (a CA-signed certificate)", () => {
		expect(certHashError("")).toBeNull();
	});

	it("accepts 32 bytes as plain or colon hex", () => {
		expect(certHashError(HEX)).toBeNull();
		expect(certHashError(HEX.match(/../g)?.join(":") ?? "")).toBeNull();
	});

	it("rejects non-hex input", () => {
		expect(certHashError("zz")).toBe("Use hex digits 0-9 and a-f only");
	});

	it("rejects a hash that is not 32 bytes", () => {
		expect(certHashError("abcd")).toBe(
			"A SHA-256 hash is 64 hex digits (32 bytes)",
		);
	});
});

describe("createRoomBlocker", () => {
	it("needs a Nostr login first", () => {
		expect(createRoomBlocker(null, undefined)).toBe(
			"Log in with Nostr to create a room: you become its host.",
		);
	});

	it("needs a NIP-05 address in the kind 0", () => {
		expect(createRoomBlocker("ab", undefined)).toBe(
			"A NIP-05 address is required to create a room",
		);
	});

	it("is clear once logged in with a NIP-05 address", () => {
		expect(createRoomBlocker("ab", "bob@example.com")).toBeNull();
	});
});

describe("joinBlocker", () => {
	it("needs a room first", () => {
		expect(joinBlocker(false, 0)).toBe(
			"Create a room or open a room link first",
		);
	});

	it("counts the fields to fix in Advanced", () => {
		expect(joinBlocker(true, 1)).toBe("Fix 1 field in Advanced");
		expect(joinBlocker(true, 2)).toBe("Fix 2 fields in Advanced");
	});

	it("is clear with a room and valid fields", () => {
		expect(joinBlocker(true, 0)).toBeNull();
	});
});
