import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { CLOSE_REASONS } from "@/lib/roomAuth";
import { useMoqtChatStore } from "@/stores/moqtChatStore";
import { Countdown, RoomClosed, useEndOnRoomClosed } from "../roomStatus";

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
