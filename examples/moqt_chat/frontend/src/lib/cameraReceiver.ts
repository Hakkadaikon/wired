// Receive side of the camera tracks: per-sender frame reassembly, one
// decoder per sender (screenReceivePipeline.ts), a tile per sender while
// its frames arrive, and stall removal -- kept apart from the screen
// tiles' own maps so the two never share a decoder or a reassembler.
// A sender that turns the camera off withdraws its namespace (forget); a
// sender that vanishes without that stalls and is forgotten by tick().

import {
	type ScreenChunk,
	type ScreenFrameReassembler,
	screenFrameReassemblerInit,
	screenFrameReassemblerPush,
} from "./moqtScreenWire";
import {
	createScreenReceivePipeline,
	type ScreenReceivePipelineDeps,
} from "./screenReceivePipeline";
import { cameraTap } from "./screenTap";
import {
	createStallDetector,
	SCREEN_STALL_MS,
	type StallDetector,
} from "./stallDetector";

type DecodedFrame = {
	close?: () => void;
	codedWidth?: number;
	codedHeight?: number;
	displayWidth?: number;
	displayHeight?: number;
};

export type CameraReceiverDeps = Pick<
	ScreenReceivePipelineDeps,
	"VideoDecoderCtor" | "EncodedVideoChunkCtor"
> & {
	draw: (senderId: string, frame: DecodedFrame) => void;
	addTile: (senderId: string) => void;
	removeTile: (senderId: string) => void;
	onError: (msg: string) => void;
	now: () => number;
};

export type CameraReceiver = {
	onChunk: (senderId: string, chunk: ScreenChunk) => void;
	/** Forgets every sender whose frames stalled. */
	tick: (now: number) => void;
	/** Drops a sender's tile, decoder and reassembly state. */
	forget: (senderId: string) => void;
};

// The visible size: a decoded frame's coded size can carry padding.
const visibleSize = (vf: DecodedFrame) => ({
	width: vf.displayWidth ?? vf.codedWidth ?? 0,
	height: vf.displayHeight ?? vf.codedHeight ?? 0,
});

const DECODE_FAILED = "a peer's camera could not be decoded";

export function createCameraReceiver(deps: CameraReceiverDeps): CameraReceiver {
	const reassemblers = new Map<string, ScreenFrameReassembler>();
	// width/height/codec ride only on a keyframe's first chunk.
	const meta = new Map<
		string,
		Pick<ScreenChunk, "width" | "height" | "codec">
	>();
	const stalls = new Map<string, StallDetector>();

	const onFrame = (senderId: string, frame: unknown) => {
		const vf = frame as DecodedFrame;
		try {
			const now = deps.now();
			deps.addTile(senderId);
			deps.draw(senderId, vf);
			if (!stalls.has(senderId))
				stalls.set(senderId, createStallDetector(SCREEN_STALL_MS));
			stalls.get(senderId)?.frame(now);
			cameraTap({ senderId, ...visibleSize(vf), t: now });
		} finally {
			vf.close?.();
		}
	};

	const pipeline = createScreenReceivePipeline({
		VideoDecoderCtor: deps.VideoDecoderCtor,
		EncodedVideoChunkCtor: deps.EncodedVideoChunkCtor,
		onFrame,
		onDecodeError: () => deps.onError(DECODE_FAILED),
	});

	const reassemble = (senderId: string, chunk: ScreenChunk) => {
		let r = reassemblers.get(senderId);
		if (!r) {
			r = screenFrameReassemblerInit();
			reassemblers.set(senderId, r);
		}
		if (chunk.keyframe && chunk.idx === 0) meta.set(senderId, chunk);
		return screenFrameReassemblerPush(r, chunk);
	};

	const forget = (senderId: string) => {
		stalls.delete(senderId);
		reassemblers.delete(senderId);
		meta.delete(senderId);
		pipeline.closeSender(senderId);
		deps.removeTile(senderId);
	};

	return {
		onChunk: (senderId, chunk) => {
			try {
				const data = reassemble(senderId, chunk);
				if (!data) return;
				const m = meta.get(senderId);
				pipeline.handleFrame(senderId, {
					data,
					keyframe: chunk.keyframe,
					width: m?.width,
					height: m?.height,
					codec: m?.codec,
				});
			} catch {
				// a bad camera stream must never break chat, voice or screen
				deps.onError(DECODE_FAILED);
			}
		},
		tick: (now) => {
			for (const [id, d] of stalls) if (d.isStalled(now)) forget(id);
		},
		forget,
	};
}
