import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { showToast, TOAST_MS, Toast } from "../toast";

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

function render() {
	const el = document.createElement("div");
	document.body.append(el);
	root = createRoot(el);
	act(() => root?.render(<Toast />));
	return el.querySelector<HTMLElement>('[data-testid="toast"]');
}

describe("Toast", () => {
	it("is an empty live region until a toast is shown", () => {
		const t = render();
		expect(t?.getAttribute("role")).toBe("status");
		expect(t?.textContent).toBe("");
	});

	it("shows the text, then clears it after TOAST_MS", () => {
		vi.useFakeTimers();
		const t = render();
		act(() => showToast("Alice raised their hand"));
		expect(t?.textContent).toBe("Alice raised their hand");
		act(() => vi.advanceTimersByTime(TOAST_MS));
		expect(t?.textContent).toBe("");
	});

	it("a newer toast replaces the shown one and gets its own full time", () => {
		vi.useFakeTimers();
		const t = render();
		act(() => showToast("one"));
		act(() => vi.advanceTimersByTime(TOAST_MS - 1));
		act(() => showToast("two"));
		act(() => vi.advanceTimersByTime(TOAST_MS - 1));
		expect(t?.textContent).toBe("two");
		act(() => vi.advanceTimersByTime(1));
		expect(t?.textContent).toBe("");
	});
});
