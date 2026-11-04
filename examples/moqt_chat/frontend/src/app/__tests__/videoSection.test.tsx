import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { VideoSourceView } from "@/lib/videoSourceController";
import { useMoqtChatStore } from "@/stores/moqtChatStore";
import { VideoSection } from "../videoSection";

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

function render(connected: boolean, video: Partial<VideoSourceView> = {}) {
	// a second render in one test must not leave the first root subscribed
	act(() => root?.unmount());
	useMoqtChatStore.getState().setVideo({
		source: "off",
		background: "none",
		error: null,
		...video,
	});
	const props = {
		connected,
		onToggle: vi.fn(),
		onBackground: vi.fn(),
		onPickFile: vi.fn(),
	};
	const host = document.createElement("div");
	document.body.append(host);
	root = createRoot(host);
	act(() => root?.render(<VideoSection {...props} />));
	const q = <T extends Element>(id: string) =>
		host.querySelector(`[data-testid="${id}"]`) as T;
	return {
		props,
		camera: q<HTMLButtonElement>("camera-toggle"),
		file: q<HTMLButtonElement>("video-file-toggle"),
		select: q<HTMLSelectElement>("background-select"),
		input: q<HTMLInputElement>("video-file-input"),
		error: () => q<HTMLElement>("video-error"),
	};
}

describe("VideoSection", () => {
	it("while connected both toggles are enabled", () => {
		const v = render(true);
		expect([v.camera.disabled, v.file.disabled]).toEqual([false, false]);
	});

	it("while disconnected only the active source stays pressable, to turn it off", () => {
		const v = render(false, { source: "camera" });
		expect(v.camera.disabled).toBe(false);
		expect(v.file.disabled).toBe(true);
		act(() => v.camera.click());
		expect(v.props.onToggle).toHaveBeenCalledExactlyOnceWith("camera");
		const off = render(false);
		expect([off.camera.disabled, off.file.disabled]).toEqual([true, true]);
	});

	it("the background select shows the store's mode and calls the setter", () => {
		const v = render(true, { background: "blur" });
		expect(v.select.value).toBe("blur");
		act(() => {
			v.select.value = "image";
			v.select.dispatchEvent(new Event("change", { bubbles: true }));
		});
		expect(v.props.onBackground).toHaveBeenCalledExactlyOnceWith("image");
	});

	it("the file input hands the chosen file to pickVideoFile", () => {
		const v = render(true);
		const file = new File(["x"], "clip.mp4", { type: "video/mp4" });
		Object.defineProperty(v.input, "files", { value: [file] });
		act(() => {
			v.input.dispatchEvent(new Event("change", { bubbles: true }));
		});
		expect(v.props.onPickFile).toHaveBeenCalledExactlyOnceWith(file);
	});

	it("a cancelled file dialog (no file) picks nothing", () => {
		const v = render(true);
		Object.defineProperty(v.input, "files", { value: [] });
		act(() => {
			v.input.dispatchEvent(new Event("change", { bubbles: true }));
		});
		expect(v.props.onPickFile).not.toHaveBeenCalled();
	});

	it("only the live source's toggle is pressed", () => {
		const pressed = (v: ReturnType<typeof render>) =>
			[v.camera, v.file].map((b) => b.getAttribute("aria-pressed"));
		expect(pressed(render(true, { source: "camera" }))).toEqual([
			"true",
			"false",
		]);
		act(() => root?.unmount());
		expect(pressed(render(true, { source: "file" }))).toEqual([
			"false",
			"true",
		]);
	});

	it("a video error is shown under the section, and nothing without one", () => {
		const v = render(true, { error: "camera could not be started" });
		expect(v.error()?.textContent).toBe("camera could not be started");
		act(() =>
			useMoqtChatStore
				.getState()
				.setVideo({ source: "off", background: "none", error: null }),
		);
		expect(v.error()).toBeNull();
	});
});
