import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { activeRoom, isRoomId, type RoomLink } from "@/lib/roomLink";
import { useMoqtChatStore } from "@/stores/moqtChatStore";
import { RoomPicker } from "../roomPicker";

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
	useMoqtChatStore.setState({ nostrPubkey: null, nostrProfiles: {} });
	history.replaceState(null, "", "/");
	vi.unstubAllGlobals();
});

const HOST = "cd".repeat(32);
const ID = "AAAAAAAAAAAAAAAAAAAAAA";

function render(props: {
	room: RoomLink | null;
	error?: string | null;
	onRoom?: (l: RoomLink) => void;
}) {
	const el = document.createElement("div");
	document.body.append(el);
	root = createRoot(el);
	act(() =>
		root?.render(
			<RoomPicker
				room={props.room}
				error={props.error ?? null}
				onRoom={props.onRoom ?? (() => {})}
			/>,
		),
	);
	return el;
}

const q = (el: HTMLElement, id: string) =>
	el.querySelector<HTMLElement>(`[data-testid="${id}"]`);

describe("RoomPicker", () => {
	it("without a room, Create room needs a Nostr login (the creator hosts)", () => {
		const el = render({ room: null });
		expect(q(el, "create-room")?.hasAttribute("disabled")).toBe(true);
		expect(q(el, "share-link")).toBeNull();
	});

	const login = (nip05?: string) =>
		useMoqtChatStore.setState({
			nostrPubkey: HOST,
			nostrProfiles: nip05 ? { [HOST]: { nip05 } } : {},
		});

	it("a login without a kind 0 nip05 cannot create: it says why", () => {
		login();
		const el = render({ room: null });
		expect(q(el, "create-room")?.hasAttribute("disabled")).toBe(true);
		expect(q(el, "nip05-required")?.textContent).toBe(
			"A NIP-05 address is required to create a room",
		);
	});

	it("Create room makes a fresh id hosted by the login and puts it in the URL", () => {
		login("bob@example.com");
		history.replaceState(null, "", "/?relays=");
		const onRoom = vi.fn();
		const el = render({ room: null, onRoom });
		act(() => q(el, "create-room")?.click());
		const link: RoomLink = onRoom.mock.calls[0][0];
		expect(isRoomId(link.id)).toBe(true);
		expect(link.host).toBe(HOST);
		expect(activeRoom.id).toBe(link.id);
		expect(location.search).toBe(`?relays=&room=${link.id}&host=${HOST}`);
		expect(activeRoom.create).toMatchObject({
			mode: "open", // the default
			nip05: "bob@example.com",
		});
	});

	it("the creator may make joining need a Nostr login", () => {
		login("bob@example.com");
		const el = render({ room: null });
		expect(q(el, "room-mode-open")?.getAttribute("aria-pressed")).toBe("true");
		act(() => q(el, "room-mode-auth")?.click());
		expect(q(el, "room-mode-auth")?.getAttribute("aria-pressed")).toBe("true");
		act(() => q(el, "create-room")?.click());
		expect(activeRoom.create?.mode).toBe("auth");
	});

	it("with a room, says which one and offers a copyable share link", () => {
		const writeText = vi.fn().mockResolvedValue(undefined);
		vi.stubGlobal("navigator", { clipboard: { writeText } });
		history.replaceState(null, "", `/chat/?relays=&room=${ID}&host=${HOST}`);
		const el = render({ room: { id: ID, host: HOST } });
		expect(q(el, "room-joining")?.textContent).toBe(`Joining room ${ID}`);
		const want = `${location.origin}/chat/?room=${ID}&host=${HOST}`;
		expect((q(el, "share-link") as HTMLInputElement).value).toBe(want);
		act(() => q(el, "copy-share-link")?.click());
		expect(writeText).toHaveBeenCalledWith(want);
		expect(q(el, "create-room")).toBeNull();
	});

	it("says so when the share link cannot be copied", async () => {
		const writeText = vi.fn().mockRejectedValue(new Error("denied"));
		vi.stubGlobal("navigator", { clipboard: { writeText } });
		const el = render({ room: { id: ID, host: HOST } });
		expect(q(el, "copy-error")).toBeNull();
		await act(async () => q(el, "copy-share-link")?.click());
		expect(q(el, "copy-error")?.textContent).toBe(
			"Could not copy: select the link and copy it by hand.",
		);
	});

	it("shows an invalid link's error", () => {
		const el = render({ room: null, error: "Invalid room link: x" });
		expect(q(el, "room-error")?.textContent).toBe("Invalid room link: x");
	});
});
