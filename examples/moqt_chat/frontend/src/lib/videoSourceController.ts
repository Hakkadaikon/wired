// Send side of the camera track: drives videoSourceMachine.ts and carries
// out every effect it returns -- acquiring and releasing the camera / file /
// background processor, starting the encoder pipeline, publishing -- and
// pumps the held source's frames through the machine's frame gate. Every
// browser API is injected, so tests run it with fakes.
//
// A completion is parked under its generation while the machine looks at
// it: a stale one is released by the machine's releaseStale effect, a
// current one moves into `held` afterwards.

import type {
	BackgroundCompositor,
	BackgroundMode as CompositeMode,
} from "./backgroundCompositor";
import type { SegmentMask } from "./segmenter";
import {
	type BackgroundMode,
	frameAction,
	initialVideoSource,
	type Selection,
	step,
	type VideoFailure,
	type VideoSourceEffect,
	type VideoSourceEvent,
	videoErrorMessage,
} from "./videoSourceMachine";

export type FrameLike = { close?: () => void; timestamp?: number };
type TrackLike = { stop: () => void };
type ProcessorLike = {
	readable: {
		getReader: () => { read: () => Promise<{ value: unknown; done: boolean }> };
	};
};

/** A playing camera or file: the video track to read and how to end it. */
export type SourceHandle = { track: TrackLike; stop: () => void };

/** Person/background compositing; null when this frame has no result. */
export type BackgroundProcessor = {
	process(frame: FrameLike, mode: CompositeMode): FrameLike | null;
	stop(): void;
};

export type PipelineLike = {
	pushFrame: (frame: FrameLike) => void;
	requestKeyframe: () => void;
	stop: () => void;
};

export type VideoSourceView = {
	source: Selection;
	background: BackgroundMode;
	error: string | null;
};

export type VideoSourceDeps = {
	getUserMedia: (c: {
		video: true;
		audio: false;
	}) => Promise<{ getVideoTracks: () => TrackLike[] }>;
	playFile: (url: string) => Promise<SourceHandle>;
	defaultFileUrl: string;
	makeProcessor: (track: TrackLike) => ProcessorLike;
	/** `onFail`: the processor broke after loading (WebGL context lost). */
	loadBackground: (onFail: () => void) => Promise<BackgroundProcessor>;
	/** `onError`: the running encoder failed. */
	startPipeline: (onError: () => void) => Promise<PipelineLike>;
	publish: () => Promise<void>;
	unpublish: () => void;
	drawPreview: (frame: FrameLike) => void;
	onChange: (view: VideoSourceView) => void;
};

export type VideoSourceController = {
	/** Pressing the active source turns it off; the other one switches. */
	toggle: (source: "camera" | "file") => void;
	/** Streams a picked file (its object URL) instead of the sample. */
	pickFile: (url: string) => void;
	setBackground: (mode: BackgroundMode) => void;
	leave: () => void;
	/** The send stream was reopened: the next frame must be a keyframe. */
	requestKeyframe: () => void;
};

type Resource = { stop: () => void };
type Source = "camera" | "file" | "segmenter";

const DONE: Record<
	Source,
	[VideoSourceEvent["kind"], VideoSourceEvent["kind"]]
> = {
	camera: ["cameraAcquired", "cameraFailed"],
	file: ["filePlaying", "fileFailed"],
	segmenter: ["segmenterReady", "segmenterFailed"],
};

/** What the frame loop does with one read: a held source that ends by
 * itself (unplugged, revoked) is a failure; a released one just ends, and
 * its in-flight frame is closed. */
export function frameStep(
	done: boolean,
	held: boolean,
): "fail" | "end" | "close" | "send" {
	if (done) return held ? "fail" : "end";
	return held ? "send" : "close";
}

/** True when `effects` release `source`'s completion at `gen` as stale. */
export function isStale(
	effects: readonly VideoSourceEffect[],
	source: Source,
	gen: number,
): boolean {
	return effects.some(
		(fx) =>
			fx.kind === "releaseStale" && fx.source === source && fx.gen === gen,
	);
}

export function createVideoSourceController(
	deps: VideoSourceDeps,
): VideoSourceController {
	let state = initialVideoSource;
	let pipeline: PipelineLike | null = null;
	// Bumped by unpublish: a pipeline start begun before it is stale.
	let pubSeq = 0;
	const held: Partial<Record<Source, Resource>> = {};
	const pending = new Map<string, Resource>();

	const dispatch = (e: VideoSourceEvent) => {
		const r = step(state, e);
		state = r.state;
		for (const fx of r.effects) run(fx);
		deps.onChange({
			source: state.sel,
			background: state.bg,
			error: videoErrorMessage(state),
		});
		return r.effects;
	};

	const release = (source: Source) => {
		held[source]?.stop();
		held[source] = undefined;
	};

	const fail = (source: Source, gen: number) =>
		dispatch({ kind: DONE[source][1], gen } as VideoSourceEvent);
	// A failure of the published track, whichever source feeds it now.
	const failNow = (failure: VideoFailure) =>
		dispatch({ kind: "failed", gen: state.gen, failure });

	const arrive = (source: Source, gen: number, res: Resource) => {
		const key = `${source}:${gen}`;
		pending.set(key, res); // so releaseStale can stop it
		const fx = dispatch({ kind: DONE[source][0], gen } as VideoSourceEvent);
		pending.delete(key);
		if (isStale(fx, source, gen)) return;
		held[source] = res;
		if (source !== "segmenter")
			void pump(res as SourceHandle).catch(() =>
				dispatch({ kind: "failed", gen, failure: "frames" }),
			);
	};

	const acquire = (
		source: Source,
		gen: number,
		start: () => Promise<Resource>,
	) => {
		Promise.resolve()
			.then(start)
			.then(
				(res) => arrive(source, gen, res),
				() => fail(source, gen),
			);
	};

	const startCamera = async (): Promise<SourceHandle> => {
		const media = await deps.getUserMedia({ video: true, audio: false });
		const track = media.getVideoTracks()[0];
		if (!track) throw new Error("no camera track");
		return { track, stop: () => track.stop() };
	};

	const loadBackground = () => {
		const slot: { res?: BackgroundProcessor } = {};
		const onFail = () => {
			if (slot.res && held.segmenter === slot.res)
				dispatch({ kind: "segmenterLost" });
		};
		return deps.loadBackground(onFail).then((res) => {
			slot.res = res;
			return res;
		});
	};

	const startPublish = async () => {
		const seq = ++pubSeq;
		try {
			const p = await deps.startPipeline(() => {
				if (seq === pubSeq) failNow("encode");
			});
			if (seq !== pubSeq) return p.stop();
			pipeline = p;
			await deps.publish();
			if (seq !== pubSeq) deps.unpublish(); // an announce that raced the off
		} catch {
			if (seq === pubSeq) failNow("publish");
		}
	};

	const unpublish = () => {
		pubSeq++;
		pipeline?.stop();
		pipeline = null;
		deps.unpublish();
	};

	const effects: {
		[K in VideoSourceEffect["kind"]]: (
			fx: VideoSourceEffect & { kind: K },
		) => void;
	} = {
		acquireCamera: (fx) => acquire("camera", fx.gen, startCamera),
		playFile: (fx) => acquire("file", fx.gen, () => deps.playFile(fx.url)),
		loadSegmenter: (fx) => acquire("segmenter", fx.gen, loadBackground),
		releaseCamera: () => release("camera"),
		releaseFile: () => release("file"),
		closeSegmenter: () => release("segmenter"),
		publish: () => void startPublish(),
		unpublish,
		keyframe: () => pipeline?.requestKeyframe(),
		releaseStale: (fx) => {
			const key = `${fx.source}:${fx.gen}`;
			pending.get(key)?.stop();
			pending.delete(key);
		},
	};
	const run = (fx: VideoSourceEffect) => effects[fx.kind](fx as never);

	// Composited frame, or null: never the raw frame (fail-closed).
	const composite = (frame: FrameLike): FrameLike | null => {
		const proc = held.segmenter as BackgroundProcessor | undefined;
		try {
			return proc?.process(frame, state.bg as CompositeMode) ?? null;
		} catch {
			return null;
		} finally {
			frame.close?.();
		}
	};

	const send = (frame: FrameLike) => {
		const action = frameAction(state);
		if (action === "drop" || !pipeline) return frame.close?.();
		const out = action === "composite" ? composite(frame) : frame;
		if (!out) return;
		try {
			deps.drawPreview(out);
		} catch {
			// the preview is cosmetic; the frame still goes out
		}
		pipeline.pushFrame(out);
	};

	const pump = async (res: SourceHandle) => {
		const reader = deps.makeProcessor(res.track).readable.getReader();
		const isHeld = () => held.camera === res || held.file === res;
		for (;;) {
			const { value, done } = await reader.read();
			const frame = value as FrameLike;
			const next = frameStep(done, isHeld());
			if (next === "fail") throw new Error("source ended");
			if (next === "end") return;
			if (next === "close") return frame.close?.();
			send(frame);
		}
	};

	return {
		toggle: (source) => {
			if (state.sel === source) return dispatch({ kind: "off" });
			if (source === "camera") return dispatch({ kind: "selectCamera" });
			dispatch({ kind: "selectFile", url: deps.defaultFileUrl });
		},
		pickFile: (url) => dispatch({ kind: "selectFile", url }),
		setBackground: (mode) => dispatch({ kind: "setBackground", mode }),
		leave: () => dispatch({ kind: "leave" }),
		requestKeyframe: () => pipeline?.requestKeyframe(),
	};
}

export type BackgroundDeps = {
	loadImage: () => Promise<TexImageSource>;
	loadSegmenter: () => Promise<{
		segment(frame: never, timestampMs: number): SegmentMask | undefined;
		close(): void;
	}>;
	createCompositor: (
		background: TexImageSource,
	) => Pick<BackgroundCompositor, "render" | "close">;
	/** The compositor's canvas as a new frame at `timestamp` (µs). */
	snapshot: (timestamp: number) => FrameLike;
	onContextLost: (cb: () => void) => void;
};

/** Segmenter + compositor as one BackgroundProcessor. A frame without a
 * mask, a throwing segment/render, or a lost WebGL context yields no frame;
 * a lost context also reports onFail. */
export async function loadBackgroundProcessor(
	deps: BackgroundDeps,
	onFail: () => void,
): Promise<BackgroundProcessor> {
	const image = await deps.loadImage();
	const seg = await deps.loadSegmenter();
	let comp: Pick<BackgroundCompositor, "render" | "close">;
	try {
		comp = deps.createCompositor(image);
	} catch (err) {
		seg.close();
		throw err;
	}
	let lost = false;
	deps.onContextLost(() => {
		lost = true;
		onFail();
	});
	return {
		process(frame, mode) {
			if (lost) return null;
			const t = frame.timestamp ?? 0;
			const m = seg.segment(frame as never, t / 1000);
			if (!m?.mask) return null;
			comp.render(
				frame as VideoFrame,
				{ data: m.mask, width: m.width, height: m.height },
				mode,
			);
			return deps.snapshot(t);
		},
		stop() {
			comp.close();
			seg.close();
		},
	};
}

export type VideoElementLike = {
	src: string;
	loop: boolean;
	muted: boolean;
	play: () => Promise<void>;
	pause: () => void;
	removeAttribute: (name: string) => void;
	load: () => void;
	captureStream: () => {
		getVideoTracks: () => TrackLike[];
		getTracks: () => TrackLike[];
	};
};

/** Plays `url` looped and muted (its audio is neither heard nor sent) and
 * hands over the captured video track. Stopping or failing unloads the
 * element and revokes a picked file's object URL. */
export async function playLoopedVideo(
	video: VideoElementLike,
	url: string,
	revoke: (url: string) => void,
): Promise<SourceHandle> {
	const unload = () => {
		video.pause();
		video.removeAttribute("src");
		video.load();
		if (url.startsWith("blob:")) revoke(url);
	};
	video.loop = true;
	video.muted = true;
	video.src = url;
	try {
		await video.play();
		const stream = video.captureStream();
		const track = stream.getVideoTracks()[0];
		if (!track) throw new Error("no video track");
		return {
			track,
			stop: () => {
				for (const t of stream.getTracks()) t.stop();
				unload();
			},
		};
	} catch (err) {
		unload();
		throw err;
	}
}
