import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { ChatMessage } from "@/stores/moqtChatStore";
import { SendState } from "../sendState";

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

const m = (patch: Partial<ChatMessage>): ChatMessage => ({
	id: 1,
	senderId: "user1",
	text: "hi",
	at: 0,
	own: true,
	...patch,
});

describe("SendState (D-24)", () => {
	it("pending: a polite live status with the spinner, no Retry", () => {
		const el = render(<SendState m={m({ pending: true })} onRetry={vi.fn()} />);
		const live = el.querySelector('[aria-live="polite"]');
		expect(live?.textContent).toBe("Sending");
		expect(el.querySelector(".icon--spin")).not.toBeNull();
		expect(el.querySelector('[data-testid="message-retry"]')).toBeNull();
	});

	it("failed: Not sent with Retry, which re-sends this message", () => {
		const onRetry = vi.fn(async () => {});
		const msg = m({ failed: true });
		const el = render(<SendState m={msg} onRetry={onRetry} />);
		expect(el.textContent).toContain("Not sent");
		act(() =>
			el.querySelector<HTMLElement>('[data-testid="message-retry"]')?.click(),
		);
		expect(onRetry).toHaveBeenCalledWith(msg);
	});

	it("sent: nothing", () => {
		const el = render(<SendState m={m({})} onRetry={vi.fn()} />);
		expect(el.innerHTML).toBe("");
	});
});
