import { npubEncode } from "nostr-tools/nip19";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { shortNpub } from "@/lib/nostr";
import { useMoqtChatStore } from "@/stores/moqtChatStore";
import { NostrAuthor, RawNostrEvent } from "../rawNostrEvent";

beforeAll(() => {
	(
		globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }
	).IS_REACT_ACT_ENVIRONMENT = true;
});

let root: Root | null = null;
afterEach(() => {
	act(() => root?.unmount());
	root = null;
	document.body.innerHTML = "";
	vi.unstubAllGlobals();
});

// Odd spacing and an HTML-looking content: the panel must show it as text.
const RAW = '{"id":"e1",  "content":"<b>hi</b>"}';

function render(node = <RawNostrEvent raw={RAW} id="e1" />) {
	const el = document.createElement("div");
	document.body.append(el);
	root = createRoot(el);
	act(() => root?.render(node));
	return el;
}

const toggle = (el: HTMLElement) =>
	el.querySelector<HTMLButtonElement>('[data-testid="nostr-raw-toggle"]');

describe("RawNostrEvent", () => {
	it("is a labelled, collapsed toggle at first", () => {
		const el = render();
		expect(toggle(el)?.getAttribute("aria-label")).toBe("Show raw Nostr event");
		expect(toggle(el)?.getAttribute("aria-expanded")).toBe("false");
		expect(el.querySelector('[data-testid="nostr-raw"]')).toBeNull();
	});

	it("opens a text panel with the verified id, pretty JSON, no HTML", () => {
		const el = render();
		act(() => toggle(el)?.click());
		const panel = el.querySelector('[data-testid="nostr-raw"]');
		expect(toggle(el)?.getAttribute("aria-expanded")).toBe("true");
		expect(panel?.textContent).toContain("verified · id e1");
		expect(panel?.querySelector("pre")?.textContent).toBe(
			JSON.stringify(JSON.parse(RAW), null, 2),
		);
		expect(panel?.querySelector("b")).toBeNull();
	});

	it("Copy raw copies the original string, not the pretty one", () => {
		const writeText = vi.fn().mockResolvedValue(undefined);
		vi.stubGlobal("navigator", { clipboard: { writeText } });
		const el = render();
		act(() => toggle(el)?.click());
		const copy = Array.from(el.querySelectorAll("button")).find(
			(b) => b.textContent === "Copy raw",
		);
		act(() => copy?.click());
		expect(writeText).toHaveBeenCalledWith(RAW);
	});
});

describe("RawNostrEvent with unsigned extra keys", () => {
	it("says the extra keys are not covered by the signature", () => {
		const el = render(<RawNostrEvent raw='{"id":"e1","x":1}' id="e1" />);
		act(() => toggle(el)?.click());
		expect(el.textContent).toContain(
			"unsigned extra keys are not covered by the signature",
		);
	});
});

describe("NostrAuthor", () => {
	const PK = "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";

	it("shows the profile name next to the short npub and the badge, full npub as title", () => {
		useMoqtChatStore.getState().setNostrProfile(PK, { name: "alice" });
		const el = render(<NostrAuthor pubkey={PK} />);
		const author = el.querySelector(".nostr-author");
		expect(author?.getAttribute("title")).toBe(npubEncode(PK));
		expect(el.textContent).toBe(`alice ${shortNpub(PK)} ✓ verified Nostr`);
	});

	it("shows the short npub alone (with the badge) before a name lands", () => {
		const other = PK.replace(/^1b/, "2b");
		const el = render(<NostrAuthor pubkey={other} />);
		expect(el.querySelector('[data-testid="nostr-npub"]')?.textContent).toBe(
			shortNpub(other),
		);
		expect(el.textContent).toContain("✓ verified Nostr");
	});
});

describe("NostrAvatar", () => {
	const PK = "3b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";
	const PIC = "https://img.example/a.png";

	it("renders the picture as a decorative, no-referrer, lazy img", () => {
		useMoqtChatStore
			.getState()
			.setNostrProfile(PK, { name: "carol", picture: PIC });
		const el = render(<NostrAuthor pubkey={PK} />);
		const img = el.querySelector("img");
		expect(img?.getAttribute("src")).toBe(PIC);
		expect(img?.getAttribute("alt")).toBe("");
		expect(img?.getAttribute("referrerpolicy")).toBe("no-referrer");
		expect(img?.getAttribute("loading")).toBe("lazy");
		expect(img?.getAttribute("decoding")).toBe("async");
		expect(el.textContent).toContain("carol");
	});

	it("falls back to the placeholder when the image fails to load", () => {
		useMoqtChatStore
			.getState()
			.setNostrProfile(PK, { name: "carol", picture: PIC });
		const el = render(<NostrAuthor pubkey={PK} />);
		act(() => {
			el.querySelector("img")?.dispatchEvent(new Event("error"));
		});
		expect(el.querySelector("img")).toBeNull();
		const ph = el.querySelector(".nostr-avatar--placeholder");
		expect(ph?.getAttribute("data-initial")).toBe("C");
		expect(ph?.getAttribute("aria-hidden")).toBe("true");
	});

	it("shows the placeholder without a picture, initial kept out of the text", () => {
		const other = PK.replace(/^3b/, "4b");
		const el = render(<NostrAuthor pubkey={other} />);
		expect(el.querySelector("img")).toBeNull();
		expect(el.querySelector(".nostr-avatar--placeholder")).not.toBeNull();
		expect(el.textContent?.startsWith("npub1")).toBe(true);
	});
});
