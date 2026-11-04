"use client";

// The camera track for useMoqtChat: per session, a MoqtScreenClient on
// CAMERA_TRACK, its receive side (cameraReceiver.ts -> camera tiles) and
// the send-side source controller (videoSourceController.ts) wired to real
// browser APIs -- the default camera, a looped muted <video> for the mp4,
// MediaPipe + the WebGL compositor for the background, and the
// screen-share encoder pipeline. Assets come from the app's own base path
// (next.config.ts), the same way noiseSuppressor's worklet does. A failure
// of our own source stays in the store's video error, never in chat, voice
// or screen sharing; a peer's undecodable camera only goes to the console.

import { useCallback, useRef } from "react";
import { createBackgroundCompositor } from "@/lib/backgroundCompositor";
import { createCameraReceiver } from "@/lib/cameraReceiver";
import type { MoqtChatClient } from "@/lib/moqtClient";
import { CAMERA_TRACK, MoqtScreenClient } from "@/lib/moqtScreenClient";
import type { SubgroupHeader } from "@/lib/moqtWire";
import { startScreenSharePipeline } from "@/lib/screenSharePipeline";
import { type DrawableFrame, drawFrameInto } from "@/lib/screenTileSize";
import { loadSegmenter } from "@/lib/segmenter";
import {
	createVideoSourceController,
	loadBackgroundProcessor,
	playLoopedVideo,
	type VideoElementLike,
	type VideoSourceController,
	type VideoSourceDeps,
} from "@/lib/videoSourceController";
import type { BackgroundMode } from "@/lib/videoSourceMachine";
import { type ConnectionState, useMoqtChatStore } from "@/stores/moqtChatStore";

const BASE_PATH = process.env.NEXT_PUBLIC_BASE_PATH ?? "";

/* v8 ignore start -- browser-only (Image.decode, OffscreenCanvas, VideoFrame, MediaPipe wasm): e2e s22-camera runs it */
async function loadImage(url: string): Promise<HTMLImageElement> {
	const img = new Image();
	img.src = url;
	await img.decode();
	return img;
}

function loadBrowserBackground(onFail: () => void) {
	const canvas = new OffscreenCanvas(1, 1);
	return loadBackgroundProcessor(
		{
			loadImage: () => loadImage(`${BASE_PATH}/backgrounds/default.jpg`),
			loadSegmenter: async () =>
				loadSegmenter({
					vision: await import("@mediapipe/tasks-vision"),
					basePath: BASE_PATH,
				}),
			createCompositor: (bg) => createBackgroundCompositor(canvas, bg),
			snapshot: (timestamp) => new VideoFrame(canvas, { timestamp }),
			onContextLost: (cb) => canvas.addEventListener("webglcontextlost", cb),
		},
		onFail,
	);
}
/* v8 ignore stop */

/** One session's camera track, as useMoqtChat drives it. */
export type CameraSession = {
	/** Reads an incoming camera-track uni stream (uniStreamRoute.ts). */
	handleIncomingStream(
		header: SubgroupHeader,
		firstChunk: Uint8Array,
		reader: ReadableStreamDefaultReader<Uint8Array>,
	): void;
	subscribe(id: string): Promise<void>;
	/** A peer's camera went away: its tile and its subscription state. */
	forget(id: string): void;
	tick(now: number): void;
	source: VideoSourceController;
	leave(): void;
	/** A dropped connection turns the source off at once (camera/file
	 * released, unpublished) rather than at the next connect's teardown. */
	onStatus(status: ConnectionState): void;
};

function startPipeline(client: MoqtScreenClient, onEncodeError: () => void) {
	// The frames come from the controller (pushFrame), not a capture.
	return startScreenSharePipeline({
		getDisplayMedia: async () => ({ getVideoTracks: () => [] }),
		VideoEncoderCtor: VideoEncoder as never,
		sendVideoChunk: (chunk) => client.sendVideoChunk(chunk),
		contentHint: "motion",
		onEncodeError,
	});
}

function createSource(
	client: MoqtScreenClient,
	canvases: Map<string, HTMLCanvasElement>,
	makeProcessor: VideoSourceDeps["makeProcessor"],
): VideoSourceController {
	return createVideoSourceController({
		getUserMedia: (c) => navigator.mediaDevices.getUserMedia(c),
		playFile: (url) =>
			playLoopedVideo(
				document.createElement("video") as unknown as VideoElementLike,
				url,
				(u) => URL.revokeObjectURL(u),
			),
		defaultFileUrl: `${BASE_PATH}/videos/sample.mp4`,
		makeProcessor,
		loadBackground: loadBrowserBackground,
		startPipeline: (onError) => startPipeline(client, onError),
		publish: () => client.publishScreenTrack(),
		unpublish: () => client.close(),
		drawPreview: (frame) =>
			drawFrameInto(canvases, "own", frame as DrawableFrame),
		onChange: (view) => useMoqtChatStore.getState().setVideo(view),
	});
}

function createCameraSession(
	chat: MoqtChatClient,
	canvases: Map<string, HTMLCanvasElement>,
	makeProcessor: VideoSourceDeps["makeProcessor"],
): CameraSession {
	const store = useMoqtChatStore.getState;
	store().setVideo({ source: "off", background: "none", error: null });
	const receive = createCameraReceiver({
		VideoDecoderCtor: VideoDecoder as never,
		EncodedVideoChunkCtor: EncodedVideoChunk as never,
		draw: (id, frame) => drawFrameInto(canvases, id, frame as DrawableFrame),
		addTile: (id) => store().addCameraTile(id),
		removeTile: (id) => store().removeCameraTile(id),
		onError: (msg) => console.warn(msg),
		now: () => performance.now(),
	});
	const client = new MoqtScreenClient(
		chat,
		{
			onStreamReset: () => source.requestKeyframe(),
			onScreenChunk: (id, chunk) => receive.onChunk(id, chunk),
		},
		CAMERA_TRACK,
	);
	const source = createSource(client, canvases, makeProcessor);
	return {
		handleIncomingStream: (header, firstChunk, reader) =>
			client.handleIncomingStream(header, firstChunk, reader),
		subscribe: (id) => client.subscribeToScreenTrack(id),
		forget: (id) => {
			receive.forget(id);
			client.forgetParticipant(id);
		},
		tick: receive.tick,
		source,
		// Turning the source off releases the camera/file and, if published,
		// unpublishes (client.close()); unpublished there is nothing to close.
		leave: () => source.leave(),
		onStatus: (status) => {
			if (status === "disconnected") source.leave();
		},
	};
}

export function useCameraVideo(
	makeProcessor: VideoSourceDeps["makeProcessor"],
) {
	const session = useRef<CameraSession | null>(null);
	// One <canvas> per camera tile, "own" for the local preview.
	const canvases = useRef<Map<string, HTMLCanvasElement>>(new Map());
	const start = useCallback(
		(chat: MoqtChatClient) => {
			session.current = createCameraSession(
				chat,
				canvases.current,
				makeProcessor,
			);
		},
		[makeProcessor],
	);
	const registerCameraCanvas = useCallback(
		(id: string, el: HTMLCanvasElement | null) => {
			if (el) canvases.current.set(id, el);
			else canvases.current.delete(id);
		},
		[],
	);
	const toggleVideoSource = useCallback((source: "camera" | "file") => {
		session.current?.source.toggle(source);
	}, []);
	const pickVideoFile = useCallback((file: File) => {
		session.current?.source.pickFile(URL.createObjectURL(file));
	}, []);
	const setVideoBackground = useCallback((mode: BackgroundMode) => {
		session.current?.source.setBackground(mode);
	}, []);
	return {
		session,
		start,
		api: {
			registerCameraCanvas,
			toggleVideoSource,
			pickVideoFile,
			setVideoBackground,
		},
	};
}
