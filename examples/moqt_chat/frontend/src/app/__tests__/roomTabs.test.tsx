import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { RoomTabs, useEscToClose } from "../roomTabs";

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

describe("RoomTabs (D-31)", () => {
	it("Video / Chat / People, the current one aria-current; a tap picks a view", () => {
		const onView = vi.fn();
		const el = document.createElement("div");
		document.body.append(el);
		root = createRoot(el);
		act(() => root?.render(<RoomTabs view="chat" onView={onView} />));
		const tabs = [...el.querySelectorAll("button")];
		expect(tabs.map((b) => b.textContent)).toEqual(["Video", "Chat", "People"]);
		expect(tabs.map((b) => b.getAttribute("aria-current"))).toEqual([
			null,
			"true",
			null,
		]);
		act(() => tabs[2].click());
		expect(onView).toHaveBeenCalledWith("people");
	});
});

function EscProbe({ open, close }: { open: boolean; close: () => void }) {
	useEscToClose(open, close);
	return null;
}

describe("useEscToClose (drawer)", () => {
	const key = (k: string) =>
		act(() => {
			window.dispatchEvent(new KeyboardEvent("keydown", { key: k }));
		});
	it("Esc closes an open drawer; other keys and a closed drawer do nothing", () => {
		const close = vi.fn();
		const el = document.createElement("div");
		document.body.append(el);
		root = createRoot(el);
		act(() => root?.render(<EscProbe open={false} close={close} />));
		key("Escape");
		expect(close).not.toHaveBeenCalled();
		act(() => root?.render(<EscProbe open={true} close={close} />));
		key("a");
		expect(close).not.toHaveBeenCalled();
		key("Escape");
		expect(close).toHaveBeenCalledOnce();
	});
});
