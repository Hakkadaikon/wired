import { describe, expect, it, vi } from "vitest";
import { drawFrameInto, fitCanvasToFrame } from "../screenTileSize";

describe("fitCanvasToFrame", () => {
	it("resizes the backing store to the frame's size when it differs", () => {
		const canvas = { width: 320, height: 180 };
		expect(fitCanvasToFrame(canvas, 1280, 720)).toBe(true);
		expect(canvas).toEqual({ width: 1280, height: 720 });
	});

	it("leaves an already-matching canvas untouched (a width write clears it)", () => {
		const canvas = { width: 1280, height: 720 };
		expect(fitCanvasToFrame(canvas, 1280, 720)).toBe(false);
	});

	it("ignores a missing or zero dimension", () => {
		const canvas = { width: 320, height: 180 };
		expect(fitCanvasToFrame(canvas, undefined, 720)).toBe(false);
		expect(fitCanvasToFrame(canvas, 1280, 0)).toBe(false);
		expect(canvas).toEqual({ width: 320, height: 180 });
	});
});

describe("drawFrameInto", () => {
	it("sizes the registered canvas to the frame and draws it; an unmounted key is a no-op", () => {
		const ctx = { drawImage: vi.fn() };
		const canvas = { width: 320, height: 180, getContext: () => ctx };
		const canvases = new Map([
			["user2", canvas as unknown as HTMLCanvasElement],
		]);
		const frame = { codedWidth: 480, codedHeight: 270 } as never;
		drawFrameInto(canvases, "user2", frame);
		drawFrameInto(canvases, "user3", frame);
		expect([canvas.width, canvas.height]).toEqual([480, 270]);
		expect(ctx.drawImage).toHaveBeenCalledExactlyOnceWith(
			frame,
			0,
			0,
			480,
			270,
		);
	});

	it("sizes to the visible display size, not the padded coded size", () => {
		const ctx = { drawImage: vi.fn() };
		const canvas = { width: 0, height: 0, getContext: () => ctx };
		const canvases = new Map([["own", canvas as unknown as HTMLCanvasElement]]);
		const frame = {
			codedWidth: 480,
			codedHeight: 290,
			displayWidth: 480,
			displayHeight: 270,
		} as never;
		drawFrameInto(canvases, "own", frame);
		expect([canvas.width, canvas.height]).toEqual([480, 270]);
		expect(ctx.drawImage).toHaveBeenCalledWith(frame, 0, 0, 480, 270);
	});
});
