import { npubEncode } from "nostr-tools/nip19";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { shortNpub } from "@/lib/nostr";
import { useMoqtChatStore } from "@/stores/moqtChatStore";
import { NostrAuthor, NostrName, RawNostrEvent } from "../rawNostrEvent";

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

describe("RawNostrEvent foot", () => {
	it("the ⋯ toggle relabels itself to Hide once open", () => {
		const el = render();
		expect(toggle(el)?.textContent).toBe("⋯");
		act(() => toggle(el)?.click());
		expect(toggle(el)?.getAttribute("aria-label")).toBe("Hide raw Nostr event");
	});

	it("has a focusable check described by the verified tooltip", () => {
		const el = render();
		const mark = el.querySelector<HTMLButtonElement>(
			'[data-testid="nostr-verified"]',
		);
		expect(mark?.getAttribute("aria-label")).toBe("Verified Nostr event");
		const tip = document.getElementById(
			mark?.getAttribute("aria-describedby") ?? "",
		);
		expect(tip?.getAttribute("role")).toBe("tooltip");
		expect(tip?.textContent).toBe(
			"Verified Nostr event: id and BIP-340 signature checked",
		);
	});
});

describe("VerifiedMark tooltip", () => {
	it("Esc hides the shown tip without moving focus; a new focus shows it", () => {
		const el = render();
		const mark = el.querySelector<HTMLButtonElement>(
			'[data-testid="nostr-verified"]',
		);
		const wrap = () => mark?.parentElement?.hasAttribute("data-dismissed");
		act(() => mark?.focus());
		act(() => {
			window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
		});
		expect(wrap()).toBe(true);
		expect(document.activeElement).toBe(mark);
		act(() => mark?.blur());
		act(() => mark?.focus());
		expect(wrap()).toBe(false);
	});

	it("ignores Esc while the tip is not shown", () => {
		const el = render();
		act(() => {
			window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
		});
		expect(el.querySelector("[data-dismissed]")).toBeNull();
	});
});

describe("NostrName", () => {
	it("is NostrAuthor's line 1 as plain text", () => {
		const pk =
			"6b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";
		expect(render(<NostrName pubkey={pk} />).textContent).toBe(shortNpub(pk));
		act(() => useMoqtChatStore.getState().setNostrProfile(pk, { name: "dee" }));
		expect(document.body.textContent).toContain("dee");
	});
});

describe("NostrAuthor", () => {
	const PK = "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";
	const names = (el: HTMLElement) =>
		Array.from(el.querySelectorAll(".nostr-author__names > *")).map(
			(n) => n.textContent,
		);

	it("shows display_name over @name, full npub as title, no npub text", () => {
		useMoqtChatStore
			.getState()
			.setNostrProfile(PK, { displayName: "Alice A", name: "alice" });
		const el = render(<NostrAuthor pubkey={PK} />);
		expect(el.querySelector(".nostr-author")?.getAttribute("title")).toBe(
			npubEncode(PK),
		);
		expect(names(el)).toEqual(["Alice A", "@alice"]);
	});

	it("shows name alone when display_name is missing", () => {
		const other = PK.replace(/^1b/, "5b");
		useMoqtChatStore.getState().setNostrProfile(other, { name: "bob" });
		expect(names(render(<NostrAuthor pubkey={other} />))).toEqual(["bob"]);
	});

	it("falls back to the short npub alone before a profile lands", () => {
		const other = PK.replace(/^1b/, "2b");
		expect(names(render(<NostrAuthor pubkey={other} />))).toEqual([
			shortNpub(other),
		]);
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
