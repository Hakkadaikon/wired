import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { InfoTip, Tooltip } from "../tooltip";

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

function pointer(type: string, target: Element, pointerType: string) {
	const e = new Event(type, { bubbles: true });
	Object.defineProperty(e, "pointerType", { value: pointerType });
	act(() => {
		target.dispatchEvent(e);
	});
}

const esc = () =>
	act(() => {
		window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
	});

describe("Tooltip", () => {
	const button = (el: HTMLElement) =>
		el.querySelector("button") as HTMLButtonElement;
	const tipOf = (b: HTMLElement) =>
		document.getElementById(b.getAttribute("aria-describedby") ?? "");

	it("describes its trigger with a role=tooltip text", () => {
		const el = render(
			<Tooltip tip="Copy the full value">
				<button type="button">Copy</button>
			</Tooltip>,
		);
		const tip = tipOf(button(el));
		expect(tip?.getAttribute("role")).toBe("tooltip");
		expect(tip?.textContent).toBe("Copy the full value");
	});

	it("a touch tap pins it open, a second tap or Esc closes it", () => {
		const el = render(
			<Tooltip tip="Join in this slot">
				<button type="button">user1</button>
			</Tooltip>,
		);
		const wrap = () => button(el).parentElement as HTMLElement;
		pointer("pointerup", button(el), "touch");
		expect(wrap().hasAttribute("data-open")).toBe(true);
		pointer("pointerup", button(el), "touch");
		expect(wrap().hasAttribute("data-open")).toBe(false);
		pointer("pointerup", button(el), "touch");
		esc();
		expect(wrap().hasAttribute("data-open")).toBe(false);
		expect(wrap().hasAttribute("data-dismissed")).toBe(true);
	});

	it("a mouse click does not pin; a tap elsewhere unpins", () => {
		const el = render(
			<Tooltip tip="tip">
				<button type="button">b</button>
			</Tooltip>,
		);
		const wrap = () => button(el).parentElement as HTMLElement;
		pointer("pointerup", button(el), "mouse");
		expect(wrap().hasAttribute("data-open")).toBe(false);
		pointer("pointerup", button(el), "touch");
		pointer("pointerdown", document.body, "touch");
		expect(wrap().hasAttribute("data-open")).toBe(false);
	});

	it("other keys and a tap inside leave a pinned tip open", () => {
		const el = render(
			<Tooltip tip="tip">
				<button type="button">b</button>
			</Tooltip>,
		);
		const wrap = () => button(el).parentElement as HTMLElement;
		pointer("pointerup", button(el), "touch");
		act(() => {
			window.dispatchEvent(new KeyboardEvent("keydown", { key: "a" }));
		});
		pointer("pointerdown", button(el), "touch");
		expect(wrap().hasAttribute("data-open")).toBe(true);
		expect(wrap().hasAttribute("data-dismissed")).toBe(false);
	});

	it("Esc hides a focused tip; hover or a new focus shows it again", () => {
		const el = render(
			<Tooltip tip="tip">
				<button type="button">b</button>
			</Tooltip>,
		);
		const wrap = button(el).parentElement as HTMLElement;
		act(() => button(el).focus());
		esc();
		expect(wrap.hasAttribute("data-dismissed")).toBe(true);
		expect(document.activeElement).toBe(button(el));
		act(() => {
			wrap.dispatchEvent(new MouseEvent("mouseenter"));
		});
		expect(wrap.hasAttribute("data-dismissed")).toBe(false);
		esc();
		act(() => button(el).blur());
		act(() => button(el).focus());
		expect(wrap.hasAttribute("data-dismissed")).toBe(false);
	});

	it("Esc does nothing while the tip is not shown", () => {
		const el = render(
			<Tooltip tip="tip">
				<button type="button">b</button>
			</Tooltip>,
		);
		esc();
		expect(el.querySelector("[data-dismissed]")).toBeNull();
	});

	it("InfoTip is a labelled icon button carrying the hint", () => {
		const el = render(<InfoTip label="About relays" tip="Only names" />);
		expect(button(el).getAttribute("aria-label")).toBe("About relays");
		expect(tipOf(button(el))?.textContent).toBe("Only names");
	});
});
