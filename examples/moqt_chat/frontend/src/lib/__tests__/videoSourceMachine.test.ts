import { describe, expect, it } from "vitest";
import {
	type BackgroundMode,
	frameAction,
	initialVideoSource,
	type StepResult,
	step,
	type VideoFailure,
	type VideoSourceEvent,
	type VideoSourceState,
	videoErrorMessage,
} from "../videoSourceMachine";

function run(events: VideoSourceEvent[], from = initialVideoSource) {
	let s = from;
	for (const e of events) s = step(s, e).state;
	return s;
}

const FILE_URL = "/videos/sample.mp4";
const selectFile: VideoSourceEvent = { kind: "selectFile", url: FILE_URL };

const cameraLive: VideoSourceEvent[] = [
	{ kind: "selectCamera" },
	{ kind: "cameraAcquired", gen: 1 },
];

const held = (s: VideoSourceState) => s.camHeld !== null || s.fileHeld !== null;

const SUCCESS = {
	cameraAcquired: "camera",
	filePlaying: "file",
	segmenterReady: "segmenter",
} as const;

// Whether the state still wants what a successful completion delivers.
const wants = (s: VideoSourceState, source: string, gen: number) =>
	source === "segmenter"
		? s.sel === "camera" && s.bg !== "none" && s.segGen === gen
		: s.sel === source && s.gen === gen;

// The source of a successful completion the state no longer wants, or null.
function staleSuccess(s: VideoSourceState, e: VideoSourceEvent) {
	const source = SUCCESS[e.kind as keyof typeof SUCCESS];
	if (!source) return null;
	const gen = (e as { gen: number }).gen;
	return wants(s, source, gen) && s.gen === gen ? null : source;
}

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
		const s = run([{ kind: "selectCamera" }, selectFile]);
		const r = step(s, { kind: "cameraAcquired", gen: 2 });
		expect(r.state.camHeld).toBeNull();
		expect(r.effects).toEqual([
			{ kind: "releaseStale", source: "camera", gen: 2 },
		]);
	});

	it("switching camera to file releases the camera and keeps the track", () => {
		const s = run(cameraLive);
		const r = step(s, selectFile);
		expect(r.state).toMatchObject({
			sel: "file",
			gen: 2,
			camHeld: null,
			published: true,
		});
		expect(r.effects).toEqual([
			{ kind: "releaseCamera" },
			{ kind: "playFile", gen: 2, url: FILE_URL },
		]);
		expect(frameAction(r.state)).toBe("drop");
	});

	it("a playing file is held and forces a keyframe without republishing", () => {
		const s = run([...cameraLive, selectFile]);
		const r = step(s, { kind: "filePlaying", gen: 2 });
		expect(r.state.fileHeld).toBe(2);
		expect(r.effects).toEqual([{ kind: "keyframe" }]);
		expect(frameAction(r.state)).toBe("file");
	});

	it("a stale file is released", () => {
		const s = run([selectFile, { kind: "off" }]);
		const r = step(s, { kind: "filePlaying", gen: 1 });
		expect(r.state).toEqual(s);
		expect(r.effects).toEqual([
			{ kind: "releaseStale", source: "file", gen: 1 },
		]);
	});

	it("switching file to camera releases the file", () => {
		const s = run([selectFile, { kind: "filePlaying", gen: 1 }]);
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
			error: "camera",
		});
		expect(r.effects).toEqual([{ kind: "unpublish" }]);
	});

	it("a current file failure returns to off with an error", () => {
		const r = step(run([selectFile]), {
			kind: "fileFailed",
			gen: 1,
		});
		expect(r.state).toMatchObject({ sel: "off", error: "file" });
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
		const s = run([selectFile, { kind: "fileFailed", gen: 1 }]);
		expect(step(s, { kind: "selectCamera" }).state.error).toBeNull();
		expect(step(s, selectFile).state.error).toBeNull();
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
			selectFile,
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
		const s = run([selectFile]);
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

	it("a ready segmenter that is lost later (context lost) is closed and frames are withheld", () => {
		const s = run([
			...cameraLive,
			{ kind: "setBackground", mode: "blur" },
			{ kind: "segmenterReady", gen: 1 },
		]);
		const r = step(s, { kind: "segmenterLost" });
		expect(r.state.seg).toBe("failed");
		expect(r.effects).toEqual([{ kind: "closeSegmenter" }]);
		expect(frameAction(r.state)).toBe("drop");
		expect(videoErrorMessage(r.state)).toBe(
			"background effect could not be loaded",
		);
		const none = step(r.state, { kind: "setBackground", mode: "none" });
		expect(none.effects).toEqual([]);
		expect(frameAction(none.state)).toBe("raw");
	});

	it("a lost report without a ready segmenter changes nothing", () => {
		const s = run([...cameraLive, { kind: "setBackground", mode: "blur" }]);
		expect(step(s, { kind: "segmenterLost" })).toEqual({
			state: s,
			effects: [],
		});
	});

	it("a failure of the current source turns it off with that failure", () => {
		const s = run(cameraLive);
		const r = step(s, { kind: "failed", gen: 1, failure: "publish" });
		expect(r.state).toMatchObject({ sel: "off", error: "publish" });
		expect(r.effects).toEqual([
			{ kind: "releaseCamera" },
			{ kind: "unpublish" },
		]);
		expect(videoErrorMessage(r.state)).toBe("video could not be published");
	});

	it("a failure of an older selection or while off changes nothing", () => {
		const s = run([...cameraLive, selectFile]);
		const stale = { kind: "failed", gen: 1, failure: "frames" } as const;
		expect(step(s, stale)).toEqual({ state: s, effects: [] });
		const off = run([{ kind: "off" }], s);
		const now = { kind: "failed", gen: 2, failure: "encode" } as const;
		expect(step(off, now)).toEqual({ state: off, effects: [] });
	});

	it("the message is derived from the failure kind", () => {
		const msg = (error: VideoSourceState["error"], seg = "none" as const) =>
			videoErrorMessage({ ...initialVideoSource, error, seg });
		expect(msg(null)).toBeNull();
		expect(msg("camera")).toBe("camera could not be started");
		expect(msg("file")).toBe("video file could not be played");
		expect(msg("publish")).toBe("video could not be published");
		expect(msg("encode")).toBe("video could not be encoded");
		expect(msg("frames")).toBe("video frames stopped");
	});

	it("an error stays across background changes while off, until the next selection", () => {
		const s = run([selectFile, { kind: "fileFailed", gen: 1 }]);
		const r = run(
			[
				{ kind: "setBackground", mode: "blur" },
				{ kind: "setBackground", mode: "none" },
			],
			s,
		);
		expect(r.error).toBe("file");
		expect(step(r, { kind: "selectCamera" }).state.error).toBeNull();
	});

	it("switching blur to image keeps the ready segmenter", () => {
		const s = run([
			...cameraLive,
			{ kind: "setBackground", mode: "blur" },
			{ kind: "segmenterReady", gen: 1 },
		]);
		const r = step(s, { kind: "setBackground", mode: "image" });
		expect(r.effects).toEqual([]);
		expect(r.state).toMatchObject({ bg: "image", seg: "ready" });
		expect(frameAction(r.state)).toBe("composite");
	});

	it("after a segmenter failure, background none clears the error and sends raw", () => {
		const s = run([
			...cameraLive,
			{ kind: "setBackground", mode: "blur" },
			{ kind: "segmenterFailed", gen: 1 },
		]);
		expect(videoErrorMessage(s)).toBe("background effect could not be loaded");
		const r = step(s, { kind: "setBackground", mode: "none" });
		expect(videoErrorMessage(r.state)).toBeNull();
		expect(frameAction(r.state)).toBe("raw");
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
		const r = step(s, selectFile);
		expect(r.state.seg).toBe("none");
		expect(r.effects).toContainEqual({ kind: "closeSegmenter" });
	});
});

// A resource the state stops holding must be let go by an effect of the
// same step.
function checkEffects(s: VideoSourceState, r: StepResult) {
	const fx = new Set(
		r.effects.map((f) =>
			f.kind === "releaseStale" ? `${f.kind}:${f.source}` : f.kind,
		),
	);
	const n = r.state;
	const rules: [string, boolean, string[]][] = [
		[
			"camera released",
			s.camHeld !== null && n.camHeld === null,
			["releaseCamera"],
		],
		[
			"file released",
			s.fileHeld !== null && n.fileHeld === null,
			["releaseFile"],
		],
		[
			"segmenter closed",
			s.seg === "ready" && n.seg !== "ready",
			["closeSegmenter"],
		],
		["unpublished", s.published && !n.published, ["unpublish"]],
	];
	for (const [name, happened, any] of rules)
		if (happened)
			expect(
				any.some((k) => fx.has(k)),
				name,
			).toBe(true);
}

// VSM_SEED=<n> replays another walk (n in 1..2^32-1; 0 is xorshift's fixed point).
const WALK_SEED = Number(process.env.VSM_SEED ?? 12345);
if (!Number.isInteger(WALK_SEED) || WALK_SEED < 1 || WALK_SEED >= 2 ** 32)
	throw new Error(`VSM_SEED must be an integer in 1..2^32-1: ${WALK_SEED}`);

describe("videoSourceMachine random walks", () => {
	it("holds its safety properties over random event sequences", () => {
		let seed = WALK_SEED;
		// xorshift32: exact in 32-bit integers, unlike an LCG in doubles
		const rand = (n: number) => {
			seed ^= seed << 13;
			seed ^= seed >>> 17;
			seed ^= seed << 5;
			return (seed >>> 0) % n;
		};
		const modes: BackgroundMode[] = ["none", "blur", "image"];
		const failures: VideoFailure[] = ["publish", "encode", "frames"];
		const gk = [
			"cameraAcquired",
			"cameraFailed",
			"filePlaying",
			"fileFailed",
			"segmenterReady",
			"segmenterFailed",
		] as const;
		// the last one (a completion) is picked 5 times in 11
		const picks: ((gen: number) => VideoSourceEvent)[] = [
			() => ({ kind: "selectCamera" }),
			() => selectFile,
			() => ({ kind: rand(20) ? "off" : "leave" }),
			() => ({ kind: "setBackground", mode: modes[rand(3)] }),
			() => ({ kind: "segmenterLost" }),
			(gen) => ({ kind: "failed", gen, failure: failures[rand(3)] }),
			(gen) => ({ kind: gk[rand(gk.length)], gen }),
		];
		const pick = (s: VideoSourceState) => {
			const gen = rand(s.gen + 2);
			return picks[Math.min(rand(11), picks.length - 1)](gen);
		};
		const counts = new Map<string, number>();
		const seen = (k: string) => counts.set(k, (counts.get(k) ?? 0) + 1);
		for (let walk = 0; walk < 300; walk++) {
			let s = initialVideoSource;
			for (let n = 0; n < 40; n++) {
				const e = pick(s);
				const r = step(s, e);
				seen(e.kind);
				const source = staleSuccess(s, e);
				if (source !== null) {
					seen("staleSuccess");
					expect(r.effects).toContainEqual({
						kind: "releaseStale",
						source,
						gen: (e as { gen: number }).gen,
					});
				}
				checkEffects(s, r);
				expect(r.state.gen).toBeGreaterThanOrEqual(s.gen);
				s = r.state;
				for (const [name, holds] of invariants) {
					expect(holds(s), name).toBe(true);
				}
			}
		}
		const kinds = [...gk, "selectCamera", "selectFile", "off", "leave"];
		for (const k of [...kinds, "setBackground", "segmenterLost", "failed"]) {
			expect(counts.get(k) ?? 0, k).toBeGreaterThanOrEqual(20);
		}
		expect(counts.get("staleSuccess") ?? 0).toBeGreaterThanOrEqual(20);
		// 12k steps: ~3 s plain, near the 5 s default under coverage
	}, 30_000);
});
