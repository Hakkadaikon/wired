// Outgoing video source controller (camera / file / off), as a pure reducer:
// events in, next state and effects out; the hook carries the effects out.
// Each acquisition is tagged with the generation of the selection that
// started it, so a completion that arrives after the user moved on is
// recognised as stale and released instead of published.

export type Selection = "off" | "camera" | "file";
export type BackgroundMode = "none" | "blur" | "image";
export type SegmenterState = "none" | "ready" | "failed";
/** Why the source was turned off: what could not be done. */
export type VideoFailure = "camera" | "file" | "publish" | "encode" | "frames";

export interface VideoSourceState {
	sel: Selection;
	gen: number;
	bg: BackgroundMode;
	left: boolean;
	published: boolean;
	seg: SegmenterState;
	/** generation of the segmenter load in flight, if any */
	segGen: number | null;
	camHeld: number | null;
	fileHeld: number | null;
	/** kept until the next selection */
	error: VideoFailure | null;
}

export type VideoSourceEvent =
	| { kind: "selectCamera" | "off" | "leave" | "segmenterLost" }
	| { kind: "selectFile"; url: string }
	| { kind: "setBackground"; mode: BackgroundMode }
	| { kind: "failed"; gen: number; failure: VideoFailure }
	| {
			kind:
				| "cameraAcquired"
				| "cameraFailed"
				| "filePlaying"
				| "fileFailed"
				| "segmenterReady"
				| "segmenterFailed";
			gen: number;
	  };

export type VideoSourceEffect =
	| { kind: "acquireCamera" | "loadSegmenter"; gen: number }
	| { kind: "playFile"; gen: number; url: string }
	| { kind: "releaseCamera" | "releaseFile" | "closeSegmenter" }
	| { kind: "publish" | "unpublish" | "keyframe" }
	| {
			kind: "releaseStale";
			source: "camera" | "file" | "segmenter";
			gen: number;
	  };

export type FrameAction = "file" | "raw" | "composite" | "drop";

export interface StepResult {
	state: VideoSourceState;
	effects: VideoSourceEffect[];
}

export const initialVideoSource: VideoSourceState = {
	sel: "off",
	gen: 0,
	bg: "none",
	left: false,
	published: false,
	seg: "none",
	segGen: null,
	camHeld: null,
	fileHeld: null,
	error: null,
};

type Fx = VideoSourceEffect[];

/** Releases held sources and the ready segmenter (when dropSeg). */
function releaseAll(s: VideoSourceState, fx: Fx, dropSeg: boolean) {
	if (s.camHeld !== null) fx.push({ kind: "releaseCamera" });
	if (s.fileHeld !== null) fx.push({ kind: "releaseFile" });
	const seg = dropSeg ? "none" : s.seg;
	if (s.seg === "ready" && seg === "none") fx.push({ kind: "closeSegmenter" });
	return { camHeld: null, fileHeld: null, seg };
}

/** Starts a segmenter load for the current camera unless one is ready or in flight. */
function wantSegmenter(s: VideoSourceState, fx: Fx): VideoSourceState {
	const needed = s.sel === "camera" && s.bg !== "none" && s.seg !== "ready";
	if (!needed || s.segGen === s.gen) return s;
	fx.push({ kind: "loadSegmenter", gen: s.gen });
	return { ...s, seg: "none", segGen: s.gen };
}

function select(s: VideoSourceState, url: string | null, fx: Fx) {
	const gen = s.gen + 1;
	const sel = url === null ? "camera" : "file";
	const held = releaseAll(s, fx, sel === "file");
	fx.push(
		url === null
			? { kind: "acquireCamera", gen }
			: { kind: "playFile", gen, url },
	);
	return wantSegmenter({ ...s, ...held, sel, gen, error: null }, fx);
}

function turnOff(s: VideoSourceState, fx: Fx, left: boolean): VideoSourceState {
	const held = releaseAll(s, fx, true);
	if (s.published) fx.push({ kind: "unpublish" });
	return { ...s, ...held, sel: "off", published: false, left };
}

function setBackground(s: VideoSourceState, mode: BackgroundMode, fx: Fx) {
	if (mode !== "none") return wantSegmenter({ ...s, bg: mode }, fx);
	if (s.seg === "ready") fx.push({ kind: "closeSegmenter" });
	return { ...s, bg: mode, seg: "none" as const };
}

function sourceDone(
	s: VideoSourceState,
	source: "camera" | "file",
	gen: number,
	ok: boolean,
	fx: Fx,
): VideoSourceState {
	if (s.sel !== source || s.gen !== gen) {
		if (ok) fx.push({ kind: "releaseStale", source, gen });
		return s;
	}
	if (!ok) return { ...turnOff(s, fx, s.left), error: source };
	if (!s.published) fx.push({ kind: "publish" });
	fx.push({ kind: "keyframe" });
	const held = source === "camera" ? { camHeld: gen } : { fileHeld: gen };
	return { ...s, ...held, published: true };
}

/** A failure of the current selection; an older or turned-off one is moot. */
function failed(
	s: VideoSourceState,
	gen: number,
	failure: VideoFailure,
	fx: Fx,
) {
	if (s.sel === "off" || s.gen !== gen) return s;
	return { ...turnOff(s, fx, s.left), error: failure };
}

/** The ready segmenter broke later (e.g. its WebGL context was lost). */
function loseSegmenter(s: VideoSourceState, fx: Fx): VideoSourceState {
	if (s.seg !== "ready") return s;
	fx.push({ kind: "closeSegmenter" });
	return { ...s, seg: "failed" };
}

function segmenterDone(
	s: VideoSourceState,
	gen: number,
	ok: boolean,
	fx: Fx,
): VideoSourceState {
	const wanted =
		s.sel === "camera" && s.gen === gen && s.bg !== "none" && s.segGen === gen;
	if (!wanted) {
		if (ok) fx.push({ kind: "releaseStale", source: "segmenter", gen });
		// the load is over either way, so a later pick may start a new one
		return s.segGen === gen ? { ...s, segGen: null } : s;
	}
	return { ...s, seg: ok ? "ready" : "failed", segGen: null };
}

type Handlers = {
	[K in VideoSourceEvent["kind"]]: (
		s: VideoSourceState,
		e: VideoSourceEvent & { kind: K },
		fx: Fx,
	) => VideoSourceState;
};

const userEvents = new Set([
	"selectCamera",
	"selectFile",
	"off",
	"leave",
	"setBackground",
]);

const handlers: Handlers = {
	selectCamera: (s, _e, fx) => select(s, null, fx),
	selectFile: (s, e, fx) => select(s, e.url, fx),
	off: (s, _e, fx) => (s.sel === "off" ? s : turnOff(s, fx, false)),
	leave: (s, _e, fx) => turnOff(s, fx, true),
	setBackground: (s, e, fx) => setBackground(s, e.mode, fx),
	cameraAcquired: (s, e, fx) => sourceDone(s, "camera", e.gen, true, fx),
	cameraFailed: (s, e, fx) => sourceDone(s, "camera", e.gen, false, fx),
	filePlaying: (s, e, fx) => sourceDone(s, "file", e.gen, true, fx),
	fileFailed: (s, e, fx) => sourceDone(s, "file", e.gen, false, fx),
	segmenterReady: (s, e, fx) => segmenterDone(s, e.gen, true, fx),
	segmenterFailed: (s, e, fx) => segmenterDone(s, e.gen, false, fx),
	segmenterLost: (s, _e, fx) => loseSegmenter(s, fx),
	failed: (s, e, fx) => failed(s, e.gen, e.failure, fx),
};

export function step(s: VideoSourceState, e: VideoSourceEvent): StepResult {
	if (s.left && userEvents.has(e.kind)) return { state: s, effects: [] };
	const effects: Fx = [];
	const handle = handlers[e.kind] as (
		s: VideoSourceState,
		e: VideoSourceEvent,
		fx: Fx,
	) => VideoSourceState;
	return { state: handle(s, e, effects), effects };
}

/** What to do with the next frame; never raw while a background is selected. */
export function frameAction(s: VideoSourceState): FrameAction {
	if (s.fileHeld !== null) return "file";
	if (s.camHeld === null) return "drop";
	if (s.bg === "none") return "raw";
	return s.seg === "ready" ? "composite" : "drop";
}

const FAILURE_MESSAGE: Record<VideoFailure, string> = {
	camera: "camera could not be started",
	file: "video file could not be played",
	publish: "video could not be published",
	encode: "video could not be encoded",
	frames: "video frames stopped",
};

/** The error to show for this state, if any. */
export function videoErrorMessage(s: VideoSourceState): string | null {
	if (s.error) return FAILURE_MESSAGE[s.error];
	return s.seg === "failed" ? "background effect could not be loaded" : null;
}
