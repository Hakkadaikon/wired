import { describe, expect, it } from "vitest";
import { isMuteShortcut } from "../shortcuts";

const key = (
	k: string,
	target: EventTarget | null = document.body,
	extra: Partial<KeyboardEvent> = {},
) => ({
	key: k,
	ctrlKey: false,
	metaKey: false,
	altKey: false,
	shiftKey: false,
	repeat: false,
	target,
	...extra,
});

describe("isMuteShortcut", () => {
	it("M or m toggles mute", () => {
		expect(isMuteShortcut(key("m"))).toBe(true);
		expect(isMuteShortcut(key("M"))).toBe(true);
	});

	it("ignores other keys and held repeats", () => {
		expect(isMuteShortcut(key("n"))).toBe(false);
		expect(isMuteShortcut(key("m", document.body, { repeat: true }))).toBe(
			false,
		);
	});

	it("leaves browser shortcuts and Shift+M alone", () => {
		for (const mod of ["ctrlKey", "metaKey", "altKey", "shiftKey"])
			expect(isMuteShortcut(key("m", document.body, { [mod]: true }))).toBe(
				false,
			);
	});

	it("never fires while typing", () => {
		for (const tag of ["input", "textarea", "select"])
			expect(isMuteShortcut(key("m", document.createElement(tag)))).toBe(false);
		const editable = document.createElement("div");
		editable.setAttribute("contenteditable", "true");
		expect(isMuteShortcut(key("m", editable))).toBe(false);
	});

	it("fires on a focused button (not a text field)", () => {
		expect(isMuteShortcut(key("m", document.createElement("button")))).toBe(
			true,
		);
		expect(isMuteShortcut(key("m", null))).toBe(true);
	});
});
