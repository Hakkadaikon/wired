import { describe, expect, it } from "vitest";
import {
	type BackgroundMode,
	frameAction,
	initialVideoSource,
	step,
	type VideoSourceEvent,
	type VideoSourceState,
} from "../videoSourceMachine";

function run(events: VideoSourceEvent[], from = initialVideoSource) {
	let s = from;
	for (const e of events) s = step(s, e).state;
	return s;
}

const cameraLive: VideoSourceEvent[] = [
	{ kind: "selectCamera" },
	{ kind: "cameraAcquired", gen: 1 },
];

const held = (s: VideoSourceState) => s.camHeld !== null || s.fileHeld !== null;

// Safety properties that must hold after every step.
const invariants: [string, (s: VideoSourceState) => boolean][] = [
	["at most one source held", (s) => s.camHeld === null || s.fileHeld === null],
	[
		"camera held only for the current camera",
		(s) => s.camHeld === null || (s.camHeld === s.gen && s.sel === "camera"),
	],
	[
		"file held only for the current file",
		(s) => s.fileHeld === null || (s.fileHeld === s.gen && s.sel === "file"),
	],
	["published only while selected", (s) => !s.published || s.sel !== "off"],
	["a held source is published", (s) => !held(s) || s.published],
	[
		"off holds nothing",
		(s) => s.sel !== "off" || (!s.published && !held(s) && s.seg === "none"),
	],
	["leaving turns off", (s) => !s.left || s.sel === "off"],
	[
		"segmenter only for a camera with a background",
		(s) => s.seg === "none" || (s.sel === "camera" && s.bg !== "none"),
	],
	[
		"never raw with a background",
		(s) => s.bg === "none" || frameAction(s) !== "raw",
	],
	["an error means off", (s) => !s.error || s.sel === "off"],
];

describe("videoSourceMachine", () => {
	it("starts off, publishing nothing and dropping frames", () => {
		expect(initialVideoSource).toMatchObject({
			sel: "off",
			gen: 0,
			bg: "none",
			published: false,
			camHeld: null,
			fileHeld: null,
		});
		expect(frameAction(initialVideoSource)).toBe("drop");
	});

	it("selecting the camera bumps the generation and requests it", () => {
		const r = step(initialVideoSource, { kind: "selectCamera" });
		expect(r.state).toMatchObject({ sel: "camera", gen: 1 });
		expect(r.effects).toEqual([{ kind: "acquireCamera", gen: 1 }]);
	});

	it("a current camera capture is held, published and sent raw", () => {
		const s = run([{ kind: "selectCamera" }]);
		const r = step(s, { kind: "cameraAcquired", gen: 1 });
		expect(r.state).toMatchObject({ camHeld: 1, published: true });
		expect(r.effects).toEqual([{ kind: "publish" }, { kind: "keyframe" }]);
		expect(frameAction(r.state)).toBe("raw");
	});

	it("a stale camera capture is released and never published", () => {
		const s = run([{ kind: "selectCamera" }, { kind: "selectCamera" }]);
		const r = step(s, { kind: "cameraAcquired", gen: 1 });
		expect(r.state).toEqual(s);
		expect(r.effects).toEqual([
			{ kind: "releaseStale", source: "camera", gen: 1 },
		]);
	});

	it("a camera capture arriving after a switch to the file is stale", () => {
		const s = run([{ kind: "selectCamera" }, { kind: "selectFile" }]);
		const r = step(s, { kind: "cameraAcquired", gen: 2 });
		expect(r.state.camHeld).toBeNull();
		expect(r.effects).toEqual([
			{ kind: "releaseStale", source: "camera", gen: 2 },
		]);
	});

	it("switching camera to file releases the camera and keeps the track", () => {
		const s = run(cameraLive);
		const r = step(s, { kind: "selectFile" });
		expect(r.state).toMatchObject({
			sel: "file",
			gen: 2,
			camHeld: null,
			published: true,
		});
		expect(r.effects).toEqual([
			{ kind: "releaseCamera" },
			{ kind: "playFile", gen: 2 },
		]);
		expect(frameAction(r.state)).toBe("drop");
	});

	it("a playing file is held and forces a keyframe without republishing", () => {
		const s = run([...cameraLive, { kind: "selectFile" }]);
		const r = step(s, { kind: "filePlaying", gen: 2 });
		expect(r.state.fileHeld).toBe(2);
		expect(r.effects).toEqual([{ kind: "keyframe" }]);
		expect(frameAction(r.state)).toBe("file");
	});

	it("a stale file is released", () => {
		const s = run([{ kind: "selectFile" }, { kind: "off" }]);
		const r = step(s, { kind: "filePlaying", gen: 1 });
		expect(r.state).toEqual(s);
		expect(r.effects).toEqual([
			{ kind: "releaseStale", source: "file", gen: 1 },
		]);
	});

	it("switching file to camera releases the file", () => {
		const s = run([{ kind: "selectFile" }, { kind: "filePlaying", gen: 1 }]);
		const r = step(s, { kind: "selectCamera" });
		expect(r.state.fileHeld).toBeNull();
		expect(r.effects).toEqual([
			{ kind: "releaseFile" },
			{ kind: "acquireCamera", gen: 2 },
		]);
	});

	it("a current camera failure returns to off with an error", () => {
		const s = run([...cameraLive, { kind: "selectCamera" }]);
		const r = step(s, { kind: "cameraFailed", gen: 2 });
		expect(r.state).toMatchObject({
			sel: "off",
			published: false,
			error: true,
		});
		expect(r.effects).toEqual([{ kind: "unpublish" }]);
	});

	it("a current file failure returns to off with an error", () => {
		const r = step(run([{ kind: "selectFile" }]), {
			kind: "fileFailed",
			gen: 1,
		});
		expect(r.state).toMatchObject({ sel: "off", error: true });
		expect(r.effects).toEqual([]);
	});

	it("a stale failure changes nothing", () => {
		const s = run([{ kind: "selectCamera" }, { kind: "selectCamera" }]);
		expect(step(s, { kind: "cameraFailed", gen: 1 })).toEqual({
			state: s,
			effects: [],
		});
		expect(step(s, { kind: "fileFailed", gen: 2 })).toEqual({
			state: s,
			effects: [],
		});
	});

	it("selecting a source again clears the error", () => {
		const s = run([{ kind: "selectFile" }, { kind: "fileFailed", gen: 1 }]);
		expect(step(s, { kind: "selectCamera" }).state.error).toBe(false);
		expect(step(s, { kind: "selectFile" }).state.error).toBe(false);
	});

	it("off releases everything, unpublishes and closes the segmenter", () => {
		const s = run([
			{ kind: "setBackground", mode: "blur" },
			...cameraLive,
			{ kind: "segmenterReady", gen: 1 },
		]);
		const r = step(s, { kind: "off" });
		expect(r.state).toMatchObject({
			sel: "off",
			camHeld: null,
			published: false,
			seg: "none",
		});
		expect(r.effects).toEqual([
			{ kind: "releaseCamera" },
			{ kind: "closeSegmenter" },
			{ kind: "unpublish" },
		]);
	});

	it("a load that finished unwanted does not block the next one", () => {
		const s = run([
			...cameraLive,
			{ kind: "setBackground", mode: "blur" },
			{ kind: "setBackground", mode: "none" },
			{ kind: "segmenterReady", gen: 1 },
		]);
		const r = step(s, { kind: "setBackground", mode: "blur" });
		expect(r.effects).toEqual([{ kind: "loadSegmenter", gen: 1 }]);
	});

	it("off while already off does nothing", () => {
		expect(step(initialVideoSource, { kind: "off" })).toEqual({
			state: initialVideoSource,
			effects: [],
		});
	});

	it("leave turns off and ignores every later user event", () => {
		const s = step(run(cameraLive), { kind: "leave" });
		expect(s.state).toMatchObject({ left: true, sel: "off", camHeld: null });
		expect(s.effects).toEqual([
			{ kind: "releaseCamera" },
			{ kind: "unpublish" },
		]);
		const user: VideoSourceEvent[] = [
			{ kind: "setBackground", mode: "blur" },
			{ kind: "selectCamera" },
			{ kind: "selectFile" },
			{ kind: "off" },
			{ kind: "leave" },
		];
		for (const e of user) {
			expect(step(s.state, e)).toEqual({ state: s.state, effects: [] });
		}
	});

	it("a capture completing after leave is released", () => {
		const s = run([{ kind: "selectCamera" }, { kind: "leave" }]);
		const r = step(s, { kind: "cameraAcquired", gen: 1 });
		expect(r.state.published).toBe(false);
		expect(r.effects).toEqual([
			{ kind: "releaseStale", source: "camera", gen: 1 },
		]);
	});

	it("selecting the camera with a background starts a segmenter load", () => {
		const s = run([{ kind: "setBackground", mode: "image" }]);
		const r = step(s, { kind: "selectCamera" });
		expect(r.effects).toEqual([
			{ kind: "acquireCamera", gen: 1 },
			{ kind: "loadSegmenter", gen: 1 },
		]);
	});

	it("restarting the camera keeps a ready segmenter", () => {
		const s = run([
			{ kind: "setBackground", mode: "blur" },
			...cameraLive,
			{ kind: "segmenterReady", gen: 1 },
		]);
		const r = step(s, { kind: "selectCamera" });
		expect(r.state.seg).toBe("ready");
		expect(r.effects).toEqual([
			{ kind: "releaseCamera" },
			{ kind: "acquireCamera", gen: 2 },
		]);
	});

	it("picking a background on a live camera loads once and keeps the camera", () => {
		const s = run(cameraLive);
		const r = step(s, { kind: "setBackground", mode: "blur" });
		expect(r.state).toMatchObject({ bg: "blur", camHeld: 1, published: true });
		expect(r.effects).toEqual([{ kind: "loadSegmenter", gen: 1 }]);
		expect(frameAction(r.state)).toBe("drop");
		const again = step(r.state, { kind: "setBackground", mode: "image" });
		expect(again.effects).toEqual([]);
	});

	it("picking a background without the camera loads nothing", () => {
		const s = run([{ kind: "selectFile" }]);
		const r = step(s, { kind: "setBackground", mode: "blur" });
		expect(r.state.bg).toBe("blur");
		expect(r.effects).toEqual([]);
	});

	it("a wanted segmenter becomes ready and frames are composited", () => {
		const s = run([...cameraLive, { kind: "setBackground", mode: "blur" }]);
		const r = step(s, { kind: "segmenterReady", gen: 1 });
		expect(r.state.seg).toBe("ready");
		expect(r.effects).toEqual([]);
		expect(frameAction(r.state)).toBe("composite");
	});

	it("a failed segmenter withholds frames and picking a mode retries", () => {
		const s = run([...cameraLive, { kind: "setBackground", mode: "blur" }]);
		const r = step(s, { kind: "segmenterFailed", gen: 1 });
		expect(r.state.seg).toBe("failed");
		expect(frameAction(r.state)).toBe("drop");
		const retry = step(r.state, { kind: "setBackground", mode: "blur" });
		expect(retry.state.seg).toBe("none");
		expect(retry.effects).toEqual([{ kind: "loadSegmenter", gen: 1 }]);
	});

	it("a segmenter nobody wants is released, the held one stays", () => {
		const s = run([
			{ kind: "setBackground", mode: "blur" },
			{ kind: "selectCamera" },
			{ kind: "selectCamera" },
			{ kind: "segmenterReady", gen: 2 },
		]);
		const r = step(s, { kind: "segmenterReady", gen: 1 });
		expect(r.state).toEqual(s);
		expect(r.effects).toEqual([
			{ kind: "releaseStale", source: "segmenter", gen: 1 },
		]);
		const failed = step(s, { kind: "segmenterFailed", gen: 1 });
		expect(failed).toEqual({ state: s, effects: [] });
	});

	it("dropping the background closes the segmenter and sends raw", () => {
		const s = run([
			...cameraLive,
			{ kind: "setBackground", mode: "blur" },
			{ kind: "segmenterReady", gen: 1 },
		]);
		const r = step(s, { kind: "setBackground", mode: "none" });
		expect(r.state).toMatchObject({ bg: "none", seg: "none", camHeld: 1 });
		expect(r.effects).toEqual([{ kind: "closeSegmenter" }]);
		expect(frameAction(r.state)).toBe("raw");
	});

	it("switching to the file closes a ready segmenter", () => {
		const s = run([
			...cameraLive,
			{ kind: "setBackground", mode: "blur" },
			{ kind: "segmenterReady", gen: 1 },
		]);
		const r = step(s, { kind: "selectFile" });
		expect(r.state.seg).toBe("none");
		expect(r.effects).toContainEqual({ kind: "closeSegmenter" });
	});

	it("holds its safety properties over random event sequences", () => {
		let seed = 12345;
		const rand = (n: number) => {
			seed = (seed * 1103515245 + 12345) % 2147483648;
			return seed % n;
		};
		const modes: BackgroundMode[] = ["none", "blur", "image"];
		const gk = [
			"cameraAcquired",
			"cameraFailed",
			"filePlaying",
			"fileFailed",
			"segmenterReady",
			"segmenterFailed",
		] as const;
		const pick = (s: VideoSourceState): VideoSourceEvent => {
			const i = rand(9);
			if (i === 0) return { kind: "selectCamera" };
			if (i === 1) return { kind: "selectFile" };
			if (i === 2) return { kind: rand(20) ? "off" : "leave" };
			if (i === 3) return { kind: "setBackground", mode: modes[rand(3)] };
			return { kind: gk[rand(gk.length)], gen: rand(s.gen + 2) };
		};
		for (let walk = 0; walk < 300; walk++) {
			let s = initialVideoSource;
			for (let n = 0; n < 40; n++) {
				const prevGen = s.gen;
				s = step(s, pick(s)).state;
				for (const [name, holds] of invariants) {
					expect(holds(s), name).toBe(true);
				}
				expect(s.gen).toBeGreaterThanOrEqual(prevGen);
			}
		}
	});
});
