import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { presenceTemplate } from "@/lib/nostrRoom";
import { activeRoom } from "@/lib/roomLink";
import { EMPTY_NOSTR_ROOM, useMoqtChatStore } from "@/stores/moqtChatStore";
import { PeerBadges } from "../peerBadges";

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
});

function render(node: React.ReactNode) {
	const el = document.createElement("div");
	document.body.append(el);
	root = createRoot(el);
	act(() => root?.render(node));
	return el;
}

const PEER = "b".repeat(64);
const labels = (el: HTMLElement) =>
	[...el.querySelectorAll("[aria-label]")].map((e) =>
		e.getAttribute("aria-label"),
	);

function peerState(muted: boolean) {
	const t = presenceTemplate(
		activeRoom.space,
		false,
		Math.floor(Date.now() / 1000),
		undefined,
		muted,
	);
	useMoqtChatStore.setState({
		muted: false,
		peerPubkeys: { user2: PEER },
		speaking: { user2: true },
		nostrRoom: {
			...EMPTY_NOSTR_ROOM,
			presence: { [PEER]: { ...t, pubkey: PEER, id: PEER, sig: "" } },
		},
	});
}

describe("PeerBadges remote mute (D-15 / D-21)", () => {
	it("a silent peer whose presence says muted shows Muted", () => {
		peerState(true);
		useMoqtChatStore.setState({ speaking: {} });
		const el = render(<PeerBadges id="user2" handTestId="h" />);
		expect(labels(el)).toEqual(["Muted"]);
	});

	it("speech we hear beats a peer's declared mute", () => {
		peerState(true);
		const el = render(<PeerBadges id="user2" handTestId="h" />);
		expect(labels(el)).toEqual(["Speaking"]);
	});

	it("an unmuted speaking peer keeps the speaking icon", () => {
		peerState(false);
		const el = render(<PeerBadges id="user2" handTestId="h" />);
		expect(labels(el)).toEqual(["Speaking"]);
	});

	it("a peer without a pubkey has no presence: speaking only", () => {
		peerState(true);
		useMoqtChatStore.setState({ peerPubkeys: {} });
		const el = render(<PeerBadges id="user2" handTestId="h" />);
		expect(labels(el)).toEqual(["Speaking"]);
	});

	it("a fresh raised hand still shows", () => {
		peerState(false);
		const { presence } = useMoqtChatStore.getState().nostrRoom;
		const ev = presence[PEER];
		useMoqtChatStore.getState().setNostrRoom({
			presence: { [PEER]: { ...ev, tags: [...ev.tags, ["hand", "1"]] } },
		});
		const el = render(<PeerBadges id="user2" handTestId="h" />);
		expect(labels(el)).toEqual(["Speaking", "Hand raised"]);
	});

	it("our own row follows the local mute", () => {
		peerState(false);
		useMoqtChatStore.setState({ muted: true });
		const el = render(<PeerBadges id="own" handTestId="h" />);
		expect(labels(el)).toEqual(["Muted"]);
	});
});
