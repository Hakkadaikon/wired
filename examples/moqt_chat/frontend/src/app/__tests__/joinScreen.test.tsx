import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { useMoqtChatStore } from "@/stores/moqtChatStore";
import { JoinScreen, NostrAccount } from "../joinScreen";

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
	useMoqtChatStore.setState({ nostrPubkey: null });
	vi.unstubAllGlobals();
	vi.useRealTimers();
});

function mount(node: React.ReactNode) {
	const el = document.createElement("div");
	document.body.append(el);
	root = createRoot(el);
	act(() => root?.render(node));
	return el;
}

const HASH = "ab".repeat(32);
const ROOM = { id: "AAAAAAAAAAAAAAAAAAAAAA", host: "cd".repeat(32) };

function join(over: Partial<Parameters<typeof JoinScreen>[0]> = {}) {
	const props = {
		url: "https://localhost:4433/",
		setUrl: () => {},
		certHash: HASH,
		setCertHash: () => {},
		nickname: "",
		setNickname: () => {},
		participantId: "user1",
		setParticipantId: () => {},
		connecting: false,
		onJoin: vi.fn(),
		onClearSaved: vi.fn(),
		relaysText: "wss://relay.example",
		setRelaysText: () => {},
		room: ROOM,
		roomError: null,
		setRoom: () => {},
		...over,
	};
	return { el: mount(<JoinScreen {...props} />), props };
}

const q = (el: HTMLElement, id: string) =>
	el.querySelector<HTMLElement>(`[data-testid="${id}"]`);

describe("JoinScreen", () => {
	it("hides the connection fields in a closed Advanced disclosure", () => {
		const { el } = join();
		const details = q(el, "url")?.closest("details");
		expect(details?.open).toBe(false);
		expect(q(el, "advanced")?.textContent).toContain("abababab…abababab");
		expect(q(el, "connect")?.hasAttribute("disabled")).toBe(false);
	});

	it("an invalid field opens Advanced and shows why", () => {
		const { el } = join({ url: "http://x/", certHash: "abcd" });
		expect(q(el, "url")?.closest("details")?.open).toBe(true);
		const url = q(el, "url");
		expect(url?.getAttribute("aria-invalid")).toBe("true");
		expect(
			document.getElementById(url?.getAttribute("aria-describedby") ?? "")
				?.textContent,
		).toBe("WebTransport needs an https:// URL");
		expect(q(el, "certHash")?.getAttribute("aria-invalid")).toBe("true");
	});

	it("the summary counts the errors and Join says what to fix", () => {
		const { el } = join({ url: "http://x/", certHash: "abcd" });
		expect(q(el, "advanced")?.textContent).toContain("2 errors");
		expect(q(el, "connect")?.hasAttribute("disabled")).toBe(true);
		expect(q(el, "join-blocker")?.textContent).toBe("Fix 2 fields in Advanced");
	});

	it("without a room Join is disabled and says why", () => {
		const { el } = join({ room: null });
		expect(q(el, "connect")?.hasAttribute("disabled")).toBe(true);
		expect(q(el, "join-blocker")?.textContent).toBe(
			"Create a room or open a room link first",
		);
	});

	it("the copy button copies the full certificate hash", async () => {
		const writeText = vi.fn().mockResolvedValue(undefined);
		vi.stubGlobal("navigator", { clipboard: { writeText } });
		const { el } = join();
		await act(async () => q(el, "copy-certHash")?.click());
		expect(writeText).toHaveBeenCalledWith(HASH);
	});

	const tipText = (b: HTMLElement | null) =>
		document.getElementById(b?.getAttribute("aria-describedby") ?? "")
			?.textContent;

	it("Copied is announced, then reverts after 2 s or on a new value", async () => {
		vi.useFakeTimers();
		const writeText = vi.fn().mockResolvedValue(undefined);
		vi.stubGlobal("navigator", { clipboard: { writeText } });
		const { el, props } = join();
		const copy = () => q(el, "copy-certHash");
		await act(async () => copy()?.click());
		expect(tipText(copy())).toBe("Copied");
		expect(copy()?.closest(".field__row")?.textContent).toContain("Copied");
		act(() => vi.advanceTimersByTime(2000));
		expect(tipText(copy())).toBe("Copy");
		await act(async () => copy()?.click());
		act(() =>
			root?.render(<JoinScreen {...props} certHash={"cd".repeat(32)} />),
		);
		expect(tipText(copy())).toBe("Copy");
	});

	it("an empty field has nothing to copy", async () => {
		const writeText = vi.fn().mockResolvedValue(undefined);
		vi.stubGlobal("navigator", { clipboard: { writeText } });
		const { el } = join({ certHash: "" });
		await act(async () => q(el, "copy-certHash")?.click());
		expect(writeText).not.toHaveBeenCalled();
		expect(tipText(q(el, "copy-certHash"))).toBe("Nothing to copy yet");
	});

	it("marks the chosen slot with a check and aria-pressed", () => {
		const { el } = join();
		const group = q(el, "author");
		expect(group?.tagName).toBe("FIELDSET"); // implicit role=group
		expect(
			document.getElementById(group?.getAttribute("aria-labelledby") ?? "")
				?.textContent,
		).toBe("Choose a participant slot (max 4)");
		const slot = q(el, "participant-user1");
		expect(slot?.getAttribute("aria-pressed")).toBe("true");
		expect(slot?.querySelector("svg")).not.toBeNull();
		expect(q(el, "participant-user2")?.querySelector("svg")).toBeNull();
	});

	const type = (input: HTMLElement | null, v: string) =>
		act(() => {
			const proto = Object.getPrototypeOf(input);
			Object.getOwnPropertyDescriptor(proto, "value")?.set?.call(input, v);
			input?.dispatchEvent(new Event("input", { bubbles: true }));
		});

	it("edits reach the setters; Reset restores the default relays", () => {
		const setUrl = vi.fn();
		const setRelaysText = vi.fn();
		const setParticipantId = vi.fn();
		const setNickname = vi.fn();
		const { el } = join({
			setUrl,
			setRelaysText,
			setParticipantId,
			setNickname,
		});
		type(q(el, "nickname"), "Ann");
		expect(setNickname).toHaveBeenLastCalledWith("Ann");
		type(q(el, "url"), "https://hub.example/");
		expect(setUrl).toHaveBeenLastCalledWith("https://hub.example/");
		type(q(el, "nostr-relays"), " wss://a.example ");
		act(() =>
			q(el, "nostr-relays")?.dispatchEvent(
				new FocusEvent("focusout", { bubbles: true }),
			),
		);
		expect(setRelaysText).toHaveBeenLastCalledWith("wss://relay.example");
		act(() =>
			[...el.querySelectorAll("button")]
				.find((b) => b.textContent === "Reset relays to defaults")
				?.click(),
		);
		expect(setRelaysText.mock.lastCall?.[0]).toContain("wss://");
		act(() => q(el, "participant-user2")?.click());
		expect(setParticipantId).toHaveBeenCalledWith("user2");
	});

	it("Advanced re-opens if collapsed while invalid, then stays open", () => {
		const { el, props } = join({ certHash: "abcd" });
		const details = q(el, "url")?.closest("details") as HTMLDetailsElement;
		const toggle = (open: boolean) =>
			act(() => {
				details.open = open;
				details.dispatchEvent(new Event("toggle"));
			});
		toggle(false);
		expect(details.open).toBe(true);
		toggle(true);
		act(() => root?.render(<JoinScreen {...props} certHash={HASH} />));
		expect(details.open).toBe(true);
		toggle(false);
		expect(details.open).toBe(false);
	});

	it("Join submits once ready and shows Connecting… while it connects", () => {
		const { el, props } = join();
		act(() => (q(el, "connect") as HTMLButtonElement).click());
		expect(props.onJoin).toHaveBeenCalledOnce();
		act(() => root?.unmount());
		const busy = join({ connecting: true });
		expect(q(busy.el, "connect")?.textContent).toBe("Connecting…");
		expect(q(busy.el, "connect")?.hasAttribute("disabled")).toBe(true);
		act(() =>
			q(busy.el, "connect")
				?.closest("form")
				?.dispatchEvent(
					new Event("submit", { bubbles: true, cancelable: true }),
				),
		);
		expect(busy.props.onJoin).not.toHaveBeenCalled();
	});

	it("a refused copy says to copy by hand", async () => {
		vi.stubGlobal("navigator", {});
		const { el } = join();
		const copy = q(el, "copy-url") as HTMLElement;
		await act(async () => copy.click());
		expect(
			document.getElementById(copy.getAttribute("aria-describedby") ?? "")
				?.textContent,
		).toBe("Could not copy: select the text and copy it by hand");
	});

	it("Delete saved connection info asks first, naming what goes", () => {
		const { el, props } = join();
		act(() => q(el, "clear-saved")?.click());
		const dialog = q(el, "clear-saved-dialog");
		expect(dialog?.textContent).toContain(
			"server URL, certificate hash, participant slot, display name and profile relays",
		);
		act(() => q(el, "clear-saved-cancel")?.click());
		expect(props.onClearSaved).not.toHaveBeenCalled();
		expect(document.activeElement).toBe(q(el, "clear-saved"));
		expect(q(el, "clear-saved-dialog")).toBeNull();
		act(() => q(el, "clear-saved")?.click());
		act(() => q(el, "clear-saved-confirm")?.click());
		expect(props.onClearSaved).toHaveBeenCalledOnce();
		expect(q(el, "clear-saved-dialog")).toBeNull();
		// Esc on the native modal closes it: nothing is deleted.
		act(() => q(el, "clear-saved")?.click());
		act(() => q(el, "clear-saved-dialog")?.dispatchEvent(new Event("close")));
		expect(q(el, "clear-saved-dialog")).toBeNull();
		expect(props.onClearSaved).toHaveBeenCalledOnce();
	});
});

describe("NostrAccount", () => {
	it("shows Connecting… (disabled) while the extension answers", async () => {
		let answer: (pk: string) => void = () => {};
		vi.stubGlobal("nostr", {
			getPublicKey: () =>
				new Promise<string>((r) => {
					answer = r;
				}),
		});
		const el = mount(<NostrAccount setNickname={() => {}} />);
		await act(async () => q(el, "nostr-login")?.click());
		expect(q(el, "nostr-login")?.textContent).toBe("Connecting…");
		expect(q(el, "nostr-login")?.hasAttribute("disabled")).toBe(true);
		act(() => {
			window.dispatchEvent(new Event("focus"));
		});
		expect(q(el, "nostr-login")?.hasAttribute("disabled")).toBe(false);
		await act(async () => q(el, "nostr-login")?.click());
		await act(async () => answer("not hex"));
		expect(q(el, "nostr-login")?.hasAttribute("disabled")).toBe(false);
		expect(q(el, "nostr-login-error")?.textContent).not.toBe("");
	});

	it("a login sets the key and nickname; Log out clears both", async () => {
		const pk = "cd".repeat(32);
		useMoqtChatStore.setState({ nostrRelays: [] });
		vi.stubGlobal("nostr", { getPublicKey: async () => pk });
		const setNickname = vi.fn();
		const el = mount(<NostrAccount setNickname={setNickname} />);
		await act(async () => q(el, "nostr-login")?.click());
		expect(useMoqtChatStore.getState().nostrPubkey).toBe(pk);
		expect(setNickname).toHaveBeenLastCalledWith(
			expect.stringMatching(/^npub/),
		);
		act(() =>
			[...el.querySelectorAll("button")]
				.find((b) => b.textContent === "Log out")
				?.click(),
		);
		expect(useMoqtChatStore.getState().nostrPubkey).toBeNull();
		expect(setNickname).toHaveBeenLastCalledWith("");
	});

	it("a login with no answer frees the button after 30 s", async () => {
		vi.useFakeTimers();
		vi.stubGlobal("nostr", { getPublicKey: () => new Promise(() => {}) });
		const el = mount(<NostrAccount setNickname={() => {}} />);
		await act(async () => q(el, "nostr-login")?.click());
		expect(q(el, "nostr-login")?.hasAttribute("disabled")).toBe(true);
		act(() => vi.advanceTimersByTime(30_000));
		expect(q(el, "nostr-login")?.hasAttribute("disabled")).toBe(false);
	});

	it("says Logged in once a key is known", () => {
		useMoqtChatStore.setState({ nostrPubkey: "cd".repeat(32) });
		const el = mount(<NostrAccount setNickname={() => {}} />);
		expect(q(el, "nostr-user")?.textContent).toContain("Logged in");
	});
});
