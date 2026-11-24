import { beforeEach, describe, expect, it, vi } from "vitest";
import {
	clampSplit,
	defaultSplit,
	gridColumns,
	loadSplit,
	SPLIT_STEP,
	saveSplit,
	splitKey,
	stageMode,
} from "../stageLayout";

const mem = new Map<string, string>();
const memStorage = {
	getItem: (k: string) => mem.get(k) ?? null,
	setItem: (k: string, v: string) => void mem.set(k, String(v)),
};

describe("defaultSplit", () => {
	it("halves the column while a share is live", () => {
		expect(defaultSplit("share")).toBe(0.5);
	});
	it("gives the cameras the golden minor part", () => {
		expect(defaultSplit("camera")).toBe(0.382);
	});
});

describe("stageMode", () => {
	it("is share while this page shares", () => {
		expect(stageMode(true, ["own"], {})).toBe("share");
	});
	it("is share while a remote share delivers frames", () => {
		expect(stageMode(false, ["user1"], {})).toBe("share");
	});
	it("is camera when the only remote share has stalled (stopped)", () => {
		expect(stageMode(false, ["user1"], { user1: true })).toBe("camera");
	});
	it("is camera with no share at all", () => {
		expect(stageMode(false, [], {})).toBe("camera");
	});
});

describe("clampSplit", () => {
	it("keeps a ratio that leaves both minimums", () => {
		expect(clampSplit(0.4, 1000, 100, 200)).toBe(0.4);
	});
	it("raises a ratio below the stage minimum", () => {
		expect(clampSplit(0.05, 1000, 100, 200)).toBe(0.1);
	});
	it("lowers a ratio above the chat minimum", () => {
		expect(clampSplit(0.95, 1000, 100, 200)).toBe(0.8);
	});
	it("splits by the minimums when the column cannot hold both", () => {
		expect(clampSplit(0.9, 200, 100, 300)).toBe(0.25);
	});
});

describe("splitKey", () => {
	it("moves up / left by one step", () => {
		expect(splitKey(0.5, "ArrowUp")).toBeCloseTo(0.5 - SPLIT_STEP);
		expect(splitKey(0.5, "ArrowLeft")).toBeCloseTo(0.5 - SPLIT_STEP);
	});
	it("moves down / right by one step", () => {
		expect(splitKey(0.5, "ArrowDown")).toBeCloseTo(0.5 + SPLIT_STEP);
		expect(splitKey(0.5, "ArrowRight")).toBeCloseTo(0.5 + SPLIT_STEP);
	});
	it("jumps to the ends on Home / End (the caller clamps)", () => {
		expect(splitKey(0.5, "Home")).toBe(0);
		expect(splitKey(0.5, "End")).toBe(1);
	});
	it("ignores any other key", () => {
		expect(splitKey(0.5, "a")).toBeNull();
	});
});

describe("loadSplit / saveSplit", () => {
	beforeEach(() => {
		mem.clear();
		vi.stubGlobal("localStorage", memStorage);
	});

	it("falls back to the default when nothing is stored", () => {
		expect(loadSplit("share")).toBe(0.5);
	});
	it("round-trips a ratio per mode", () => {
		saveSplit("camera", 0.6);
		expect(loadSplit("camera")).toBe(0.6);
		expect(loadSplit("share")).toBe(0.5);
	});
	it("ignores a stored value outside (0, 1) or not a number", () => {
		mem.set("moqtChat.stageSplit.camera", "1.5");
		expect(loadSplit("camera")).toBe(0.382);
		mem.set("moqtChat.stageSplit.camera", "nope");
		expect(loadSplit("camera")).toBe(0.382);
	});
	it("survives a storage that throws", () => {
		vi.stubGlobal("localStorage", {
			getItem: () => {
				throw new Error("blocked");
			},
			setItem: () => {
				throw new Error("blocked");
			},
		});
		expect(loadSplit("share")).toBe(0.5);
		expect(() => saveSplit("share", 0.7)).not.toThrow();
	});
});

describe("gridColumns", () => {
	it("uses one column for zero or one tile", () => {
		expect(gridColumns(0, 800, 450)).toBe(1);
		expect(gridColumns(1, 800, 450)).toBe(1);
	});
	it("puts two tiles side by side in a wide area", () => {
		expect(gridColumns(2, 1600, 450)).toBe(2);
	});
	it("stacks two tiles in a tall area", () => {
		expect(gridColumns(2, 400, 900)).toBe(1);
	});
	it("makes a 2x2 grid for four tiles in a 16:9 area", () => {
		expect(gridColumns(4, 1600, 900)).toBe(2);
	});
	it("puts three tiles in a row in a strip", () => {
		expect(gridColumns(3, 1800, 300)).toBe(3);
	});
	it("uses one column while the area has no size yet", () => {
		expect(gridColumns(3, 0, 0)).toBe(1);
	});
});
