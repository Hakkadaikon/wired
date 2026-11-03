import { describe, expect, it } from "vitest";
import {
	coverScale,
	FRAGMENT_SHADER,
	modeUniform,
	VERTEX_SHADER,
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

describe("shader sources", () => {
	it("are GLSL ES 3.00", () => {
		expect(VERTEX_SHADER.startsWith("#version 300 es")).toBe(true);
		expect(FRAGMENT_SHADER.startsWith("#version 300 es")).toBe(true);
	});
});
