import { describe, expect, it, vi } from "vitest";
import {
	coverScale,
	createBackgroundCompositor,
	modeUniform,
} from "../backgroundCompositor";

describe("modeUniform", () => {
	it("is 0 for blur and 1 for image", () => {
		expect(modeUniform("blur")).toBe(0);
		expect(modeUniform("image")).toBe(1);
	});
});

describe("coverScale", () => {
	it("is [1,1] when the aspect ratios match", () => {
		expect(coverScale(1280, 720, 640, 360)).toEqual([1, 1]);
	});

	it("crops the background's height when the frame is wider", () => {
		expect(coverScale(100, 100, 1600, 900)).toEqual([1, 900 / 1600]);
	});

	it("crops the background's width when the frame is taller", () => {
		expect(coverScale(1600, 900, 100, 100)).toEqual([900 / 1600, 1]);
	});
});

// A WebGL2 stand-in: GL constants read back as their names, every call is
// a recorded spy, and a uniform location is its name.
function fakeGl(linked = true) {
	const fns = new Map<string, ReturnType<typeof vi.fn>>();
	const impl: Record<string, (...a: unknown[]) => unknown> = {
		getProgramParameter: () => linked,
		getProgramInfoLog: () => "bad shader",
		getUniformLocation: (_p, name) => name,
		createTexture: () => ({ tex: fns.get("createTexture")?.mock.calls.length }),
	};
	const gl = new Proxy({} as Record<string, unknown>, {
		get(_t, k: string) {
			if (/^[A-Z0-9_]+$/.test(k)) return k;
			if (!fns.has(k)) fns.set(k, vi.fn(impl[k] ?? (() => ({}))));
			return fns.get(k);
		},
	});
	const calls = (k: string) => fns.get(k)?.mock.calls ?? [];
	const order = (k: string) => fns.get(k)?.mock.invocationCallOrder ?? [];
	return { gl, calls, order };
}

const canvasWith = (gl: unknown) => ({
	width: 1,
	height: 1,
	getContext: vi.fn(() => gl),
});
const mask = { data: new Uint8Array(4), width: 2, height: 2 };
const frame = (w: number, h: number) =>
	({ displayWidth: w, displayHeight: h }) as unknown as VideoFrame;

describe("createBackgroundCompositor", () => {
	it("throws without WebGL2", () => {
		expect(() =>
			createBackgroundCompositor(canvasWith(null) as never, {} as never),
		).toThrow("WebGL2 unavailable");
	});

	it("throws the link log when the shaders do not link", () => {
		const { gl } = fakeGl(false);
		expect(() =>
			createBackgroundCompositor(canvasWith(gl) as never, {} as never),
		).toThrow("compositor link: bad shader");
	});

	it("binds the three samplers and uploads the background once", () => {
		const { gl, calls, order } = fakeGl();
		const bg = { width: 4, height: 4 };
		createBackgroundCompositor(canvasWith(gl) as never, bg as never);
		// one program, bound once (a second link would drop the uniforms)
		expect(calls("useProgram")).toHaveLength(1);
		expect(calls("uniform1i")).toEqual([
			["frame", 0],
			["mask", 1],
			["background", 2],
		]);
		// the background image itself is uploaded, once, not per frame
		expect(calls("texImage2D")).toHaveLength(1);
		expect(calls("texImage2D")[0].at(-1)).toBe(bg);
		// ...into unit 2: the activeTexture right before the upload is
		// TEXTURE0 + 2 (the fake's constants are strings, so "TEXTURE02")
		const upload = order("texImage2D")[0];
		const units = order("activeTexture")
			.map((n, i) => [n, calls("activeTexture")[i][0]] as const)
			.filter(([n]) => n < upload);
		expect(units.at(-1)?.[1]).toBe("TEXTURE02");
		// ...after a texture is bound while unit 2 is active, or the upload
		// goes nowhere
		expect(order("bindTexture")).toHaveLength(3);
		const bind = Math.max(...order("bindTexture").filter((n) => n < upload));
		expect(units.filter(([n]) => n < bind).at(-1)?.[1]).toBe("TEXTURE02");
		expect(calls("compileShader")).toHaveLength(2);
	});

	it("sizes the canvas to the frame, sets mode, cover scale and blur radius, then draws", () => {
		const { gl, calls } = fakeGl();
		const canvas = canvasWith(gl);
		const bg = { videoWidth: 100, videoHeight: 100 };
		const c = createBackgroundCompositor(canvas as never, bg as never);
		c.render(frame(1600, 900), mask, "blur");
		expect([canvas.width, canvas.height]).toEqual([1600, 900]);
		expect(calls("viewport")).toEqual([[0, 0, 1600, 900]]);
		expect(calls("uniform1i").at(-1)).toEqual(["mode", 0]);
		expect(calls("uniform2fv")).toEqual([["bgScale", [1, 900 / 1600]]]);
		const r = 0.03 * 900;
		expect(calls("uniform2f")).toEqual([["blurRadius", r / 1600, r / 900]]);
		expect(calls("texImage2D").at(-1)?.slice(2, 5)).toEqual(["R8", 2, 2]);
		expect(calls("drawArrays")).toEqual([["TRIANGLES", 0, 3]]);
	});

	it("resizes the canvas only when the frame's size differs", () => {
		const { gl } = fakeGl();
		const size = { w: 1, h: 1, writes: 0 };
		const canvas = {
			getContext: () => gl,
			get width() {
				return size.w;
			},
			set width(v) {
				size.w = v;
				size.writes++;
			},
			get height() {
				return size.h;
			},
			set height(v) {
				size.h = v;
				size.writes++;
			},
		};
		const bg = { naturalWidth: 10, naturalHeight: 10 };
		const c = createBackgroundCompositor(canvas as never, bg as never);
		c.render(frame(1, 1), mask, "image");
		expect(size.writes).toBe(0);
		c.render(frame(1, 2), mask, "image");
		expect([size.w, size.h, size.writes]).toEqual([1, 2, 2]);
	});

	it("close deletes its three textures and the program", () => {
		const { gl, calls } = fakeGl();
		const c = createBackgroundCompositor(canvasWith(gl) as never, {} as never);
		c.close();
		expect(calls("deleteTexture")).toHaveLength(3);
		expect(calls("deleteProgram")).toHaveLength(1);
	});
});
