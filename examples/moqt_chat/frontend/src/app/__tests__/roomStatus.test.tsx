import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { shortNpub } from "@/lib/nostr";
import { presenceTemplate } from "@/lib/nostrRoom";
import { CLOSE_REASONS } from "@/lib/roomAuth";
import { enterRoom } from "@/lib/roomLink";
import { useMoqtChatStore } from "@/stores/moqtChatStore";
import {
	Countdown,
	RoomClosed,
	useEndOnRoomClosed,
	useHandToasts,
} from "../roomStatus";
import { showToast, Toast } from "../toast";

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
	vi.useRealTimers();
});

function render(node: React.ReactNode) {
	const el = document.createElement("div");
	document.body.append(el);
	root = createRoot(el);
	act(() => root?.render(node));
	return el;
}

const q = (el: HTMLElement, id: string) =>
	el.querySelector<HTMLElement>(`[data-testid="${id}"]`);

describe("RoomClosed", () => {
	it.each(Object.keys(CLOSE_REASONS))("%s: its message and Back", (token) => {
		const onBack = vi.fn();
		const el = render(<RoomClosed token={token} onBack={onBack} />);
		expect(q(el, "room-closed-message")?.textContent).toBe(
			CLOSE_REASONS[token],
		);
		act(() => q(el, "room-closed-back")?.click());
		expect(onBack).toHaveBeenCalledOnce();
	});

	it("takes the focus to its heading when it appears", () => {
		const el = render(<RoomClosed token="room-ended" onBack={() => {}} />);
		expect(document.activeElement).toBe(el.querySelector("h1"));
	});
});

function Probe({ end }: { end: () => void }) {
	useEndOnRoomClosed(end);
	return null;
}

describe("useEndOnRoomClosed", () => {
	it("ends the session once, as soon as a final reason lands", () => {
		const end = vi.fn();
		render(<Probe end={end} />);
		expect(end).not.toHaveBeenCalled();
		act(() => useMoqtChatStore.getState().setRoomClosed("room-full"));
		act(() => useMoqtChatStore.getState().setMuted(true)); // any other change
		expect(end).toHaveBeenCalledOnce();
		act(() => useMoqtChatStore.getState().setRoomClosed(null));
		expect(end).toHaveBeenCalledOnce();
	});
});

describe("Countdown", () => {
	it("shows the time left and ticks each second", () => {
		vi.useFakeTimers({ now: 1_000_000 * 1000 });
		const el = render(<Countdown ends={1_000_000 + 3601} />);
		expect(q(el, "room-countdown")?.textContent).toBe("1:00:01 left");
		act(() => vi.advanceTimersByTime(2000));
		expect(q(el, "room-countdown")?.textContent).toBe("0:59:59 left");
	});

	it("hides once past, and an ends beyond what a room can last", () => {
		vi.useFakeTimers({ now: 1_000_000 * 1000 });
		const el = render(<Countdown ends={1_000_001} />);
		expect(q(el, "room-countdown")).not.toBeNull();
		act(() => vi.advanceTimersByTime(1000));
		expect(q(el, "room-countdown")).toBeNull();
		act(() => root?.render(<Countdown ends={1_000_000 + 10 * 3600} />));
		expect(q(el, "room-countdown")).toBeNull();
	});
});

describe("Countdown colour (D-37)", () => {
	const T0 = 1_000_000;
	it("normal at 30 min, warn under 30 min, danger under 5 min", () => {
		vi.useFakeTimers({ now: T0 * 1000 });
		const el = render(<Countdown ends={T0 + 30 * 60 + 1} />);
		expect(q(el, "room-countdown")?.dataset.level).toBe("normal");
		act(() => vi.advanceTimersByTime(2000));
		expect(q(el, "room-countdown")?.dataset.level).toBe("warn");
		act(() => vi.advanceTimersByTime(25 * 60 * 1000));
		expect(q(el, "room-countdown")?.dataset.level).toBe("danger");
	});

	it("no toast when joining with under 5 min left, nor once past", () => {
		vi.useFakeTimers({ now: T0 * 1000 });
		showToast("start");
		const el = render(
			<>
				<Toast />
				<Countdown ends={T0 + 60} />
			</>,
		);
		const toast = () => q(el, "toast")?.textContent;
		expect(toast()).toBe("start");
		for (let i = 0; i < 120; i++) {
			act(() => vi.advanceTimersByTime(1000));
			expect(toast()).not.toContain("5 minutes");
		}
	});

	it("toasts once when 5 min are left", () => {
		vi.useFakeTimers({ now: T0 * 1000 });
		const el = render(
			<>
				<Toast />
				<Countdown ends={T0 + 5 * 60 + 1} />
			</>,
		);
		act(() => showToast("before"));
		expect(q(el, "toast")?.textContent).toBe("before");
		act(() => vi.advanceTimersByTime(2000));
		expect(q(el, "toast")?.textContent).toBe("5 minutes left in this room");
		act(() => showToast("after"));
		act(() => vi.advanceTimersByTime(1000));
		expect(q(el, "toast")?.textContent).toBe("after");
	});
});

function HandProbe() {
	useHandToasts();
	return <Toast />;
}

describe("useHandToasts (D-23)", () => {
	const SPACE = `30312:${"a".repeat(64)}:${"r".repeat(21)}A`;
	const presence = (pubkey: string, hand: boolean) => ({
		...presenceTemplate(SPACE, hand, Math.floor(Date.now() / 1000)),
		pubkey,
		id: pubkey,
		sig: "",
	});
	const setPresence = (p: Record<string, ReturnType<typeof presence>>) =>
		act(() => useMoqtChatStore.getState().setNostrRoom({ presence: p }));

	it("a peer's raised hand toasts its name to everyone; our own does not", () => {
		enterRoom({ id: `${"r".repeat(21)}A`, host: "a".repeat(64) });
		const peer = "b".repeat(64);
		const me = "c".repeat(64);
		act(() => {
			useMoqtChatStore.getState().setNostrPubkey(me);
			useMoqtChatStore
				.getState()
				.setNostrProfile(peer, { displayName: "Alice" });
		});
		const el = render(<HandProbe />);
		const toast = () => q(el, "toast")?.textContent;
		act(() => showToast("start"));
		// Joining: hands already up (history replay) do not toast.
		setPresence({ [me]: presence(me, false), [peer]: presence(peer, true) });
		expect(toast()).toBe("start");
		setPresence({ [me]: presence(me, true), [peer]: presence(peer, false) });
		expect(toast()).toBe("start"); // our own raise
		setPresence({ [me]: presence(me, true), [peer]: presence(peer, true) });
		expect(toast()).toBe("Alice raised their hand");
		const anon = "d".repeat(64);
		setPresence({ [anon]: presence(anon, false) });
		setPresence({ [anon]: presence(anon, true) });
		expect(toast()).toBe(`${shortNpub(anon)} raised their hand`);
	});
});
