// Screen-share capture -> VP8 encode -> chunk -> send pipeline. Mirrors
// micPipeline.ts's shape exactly: getDisplayMedia and VideoEncoder are both
// injected so tests can supply fakes instead of real browser APIs, and
// sendGate.ts (not a new gate) serializes sends against the one long-lived
// stream moqtScreenClient.ts's sendVideoChunk writes to.
//
// createSendGate's declared signature carries Uint8Array, but its body
// (sendGate.ts) never touches the payload's type -- it only forwards
// whatever `send` returns. sendVideoChunk takes a structured ScreenChunk
// (not raw bytes, unlike sendVoiceFrame) plus its Group, so the gate is
// instantiated over a { chunk, group } item via an `as` cast at this one
// call site (gateFor) rather than widening sendGate.ts's own type for every
// other caller.
//
// Track switching (sendLoVideoChunk set): a second encoder makes the "lo"
// variant (screenLoSize, SCREEN_LO_BITRATE) from the same frames. Each
// variant has its own gate and send chain; one keyframe decision covers
// both, and each keyframe decision draws one Group from allocateGroup, so
// Group g of hi and lo start on the same captured frame. Every encode()
// records its frame's Group; each output takes the Group of the frame it
// came from (matched by timestamp, so a frame one encoder drops shifts
// nothing). Without sendLoVideoChunk nothing of this runs: one encoder, and
// sendVideoChunk gets no Group (the transport opens one per keyframe).

import type { ScreenChunk } from "./moqtScreenWire";
import { createSendGate } from "./sendGate";

// getDisplayMedia's width/height are IDEAL constraints, not a promise: a
// portrait window or a non-16:9 monitor is captured at its own size (a 4K
// screen is scaled down to fit 1080p, a 1080p one comes through as is).
// The encoder is configured to whatever size the frames actually have --
// configuring it to a fixed size would make VideoEncoder scale the frames
// into that shape without keeping their aspect, and the bitstream itself
// would then be the distorted one.
const CAPTURE_WIDTH = 1920;
const CAPTURE_HEIGHT = 1080;
// Encoder size until the first frame reports its own.
const DEFAULT_WIDTH = 1280;
const DEFAULT_HEIGHT = 720;
const FRAME_RATE = 10;
const CODEC = "vp8";
const MAX_CHUNK_BYTES = 480;
// A keyframe lets a late-joining/reassembling receiver resync; 2s is the
// brief's cadence, not derived from anything finer-grained.
const KEYFRAME_INTERVAL_MS = 2000;
// Latest wins: once this many frames sit unencoded (encoder or send path
// not keeping up), a new frame is dropped instead of queued -- a queued
// backlog only adds delay the viewer can never get back.
const MAX_ENCODE_QUEUE = 2;
// The same rule for the send side: once more than this many encoded frames
// wait on the network (the link carries less than the encoder's bitrate --
// e.g. a full-screen share showing its own viewer turns every frame into
// full-screen motion), new frames are dropped before encode(), so the
// backlog, and the delay it adds, stays bounded.
const MAX_SEND_BACKLOG = 1;
// Bitrate scales with the pixel rate so 1080p text stays legible instead of
// being squeezed into 720p's budget: 0.12 bit per pixel per frame is
// 1.1 Mbps at 720p10 and 2.5 Mbps at 1080p10, clamped to [1, 4] Mbps.
const BITS_PER_PIXEL_FRAME = 0.12;
const MIN_BITRATE = 1_000_000;
const MAX_BITRATE = 4_000_000;
/** hi's bitrate band (screenBitrate's clamp), for the SSTS threshold. */
export const SCREEN_HI_MIN_BITRATE = MIN_BITRATE;
export const SCREEN_HI_MAX_BITRATE = MAX_BITRATE;

// The low-quality variant (track switching, moqtScreenClient.ts): at most
// 640 wide, a flat ~350 kbps -- inside the 300-400 kbps the hub's
// switching set treats as "lo" (SSTS threshold 400 kbps) -- same fps.
export const SCREEN_LO_MAX_WIDTH = 640;
export const SCREEN_LO_BITRATE = 350_000;

const even = (n: number) => Math.max(2, n - (n % 2));

/** The lo variant's encoded size for a capture of width x height: width
 * scaled down to SCREEN_LO_MAX_WIDTH keeping the aspect, both even. */
export function screenLoSize(
	width: number,
	height: number,
): { width: number; height: number } {
	const scale = Math.min(1, SCREEN_LO_MAX_WIDTH / width);
	return {
		width: even(Math.round(width * scale)),
		height: even(Math.round(height * scale)),
	};
}

export function screenBitrate(
	width: number,
	height: number,
	fps = FRAME_RATE,
): number {
	const wanted = Math.round(width * height * fps * BITS_PER_PIXEL_FRAME);
	return Math.min(MAX_BITRATE, Math.max(MIN_BITRATE, wanted));
}

type EncodedChunk = {
	byteLength: number;
	type: string;
	/** The input frame's timestamp (EncodedVideoChunk.timestamp). */
	timestamp?: number;
	copyTo: (dst: Uint8Array) => void;
};

type MediaStreamTrackLike = {
	stop: () => void;
	addEventListener: (type: "ended", cb: () => void) => void;
	// "detail" tells the browser's encoder this is text/UI, not motion video
	// (MediaStreamTrack.contentHint).
	contentHint?: string;
	getSettings?: () => { width?: number; height?: number };
};

export type ScreenSharePipelineDeps = {
	getDisplayMedia: (constraints: {
		video: { width: number; height: number; frameRate: number };
		audio: boolean;
	}) => Promise<{ getVideoTracks: () => MediaStreamTrackLike[] }>;
	VideoEncoderCtor: new (init: {
		output: (chunk: EncodedChunk, metadata: unknown) => void;
		error: (err: unknown) => void;
	}) => {
		configure: (config: unknown) => void;
		encode: (frame: unknown, opts?: { keyFrame: boolean }) => void;
		close: () => void;
		encodeQueueSize?: number;
	};
	/** `group` is set only with sendLoVideoChunk (the variants' aligned
	 * Group); without it the transport opens a Group per keyframe itself. */
	sendVideoChunk: (chunk: ScreenChunk, group?: bigint) => void | Promise<void>;
	/** Present: also encode the low-quality variant from the same frames
	 * (track switching). Each encoded frame of either variant then carries
	 * the Group its encode() call was made in. */
	sendLoVideoChunk?: (
		chunk: ScreenChunk,
		group: bigint,
	) => void | Promise<void>;
	/** The Group counter both variants share (MoqtScreenClient.allocateGroup):
	 * called once per keyframe decision. A local counter from 0 without it. */
	allocateGroup?: () => bigint;
	/** Whether the lo encoder runs (default always): false while the lo
	 * track is not published (MoqtScreenClient.loPublished), so a refused lo
	 * PUBLISH costs no second encode. Turning on forces a keyframe, so lo's
	 * first Group starts aligned with hi's. */
	loActive?: () => boolean;
	onError?: (err: unknown) => void;
	onEncodeError?: (err: unknown) => void;
};

export type ScreenFrameLike = {
	close?: () => void;
	codedWidth?: number;
	codedHeight?: number;
	/** VideoFrame.timestamp: matches each encoder output to its frame. */
	timestamp?: number;
};

export type ScreenSharePipeline = {
	stop: () => void;
	stopped: boolean;
	/** Feeds one captured video frame to the encoder. Exposed so tests can
	 * drive frames without a real MediaStreamTrackProcessor; production
	 * wiring (Task 7) reads frames off the track the same way micPipeline.ts
	 * reads audio frames off its processor. */
	pushFrame: (frame: ScreenFrameLike) => void;
	/** Makes the next pushed frame a keyframe regardless of the cadence --
	 * for when the send stream was reopened and the receiver needs to
	 * resync (moqtScreenClient.ts's onStreamReset). */
	requestKeyframe: () => void;
};

function splitIntoChunks(bytes: Uint8Array): Uint8Array[] {
	const pieces: Uint8Array[] = [];
	for (let off = 0; off < bytes.length; off += MAX_CHUNK_BYTES) {
		pieces.push(bytes.slice(off, off + MAX_CHUNK_BYTES));
	}
	return pieces.length > 0 ? pieces : [bytes];
}

function toScreenChunks(
	seq: number,
	isKeyframe: boolean,
	buffer: Uint8Array,
	width: number,
	height: number,
): ScreenChunk[] {
	const pieces = splitIntoChunks(buffer);
	return pieces.map((data, idx) => ({
		seq,
		idx,
		count: pieces.length,
		keyframe: isKeyframe,
		timestampUs: 0,
		data,
		...(isKeyframe && idx === 0 ? { width, height, codec: CODEC } : {}),
	}));
}

async function sendPieces(
	pieces: ScreenChunk[],
	gatedSend: (item: SendItem) => Promise<void>,
	group: bigint | undefined,
): Promise<void> {
	for (const chunk of pieces) {
		await gatedSend({ chunk, group });
	}
}

type SendItem = { chunk: ScreenChunk; group?: bigint };

type Encoder = InstanceType<ScreenSharePipelineDeps["VideoEncoderCtor"]>;

/** One encoder and its send path: the hi (as captured) or lo variant. */
type Lane = {
	encoder: Encoder;
	size: (w: number, h: number) => { width: number; height: number };
	bitrate: (w: number, h: number) => number;
	// The size the encoder is configured to (stamped on its keyframes).
	width: number;
	height: number;
	seq: number;
	// Serializes this lane's frames' piece sends (see output's doc below).
	sendChain: Promise<void>;
	// Encoded frames of this lane not fully sent yet.
	unsent: number;
	gatedSend: (item: SendItem) => Promise<void>;
	// Variants only: the Group of every frame handed to encode(), in order,
	// until its output arrives; and the last Group a keyframe opened.
	inFlight: { timestamp?: number; group: bigint }[];
	keyedGroup?: bigint;
};

// The Group an encoder output belongs to: the oldest in-flight frame with
// its timestamp (entries before it are frames the encoder dropped).
function takeGroup(
	lane: Lane,
	timestamp: number | undefined,
): bigint | undefined {
	for (;;) {
		const entry = lane.inFlight.shift();
		if (!entry) return undefined;
		if (
			timestamp === undefined ||
			entry.timestamp === undefined ||
			entry.timestamp === timestamp
		)
			return entry.group;
	}
}

function gateFor(
	send: (chunk: ScreenChunk, group?: bigint) => void | Promise<void>,
) {
	const forward = (item: SendItem) =>
		item.group === undefined ? send(item.chunk) : send(item.chunk, item.group);
	return createSendGate(
		forward as unknown as (bytes: Uint8Array) => void | Promise<void>,
	) as unknown as (item: SendItem) => Promise<void>;
}

export async function startScreenSharePipeline(
	deps: ScreenSharePipelineDeps,
): Promise<ScreenSharePipeline> {
	let media: { getVideoTracks: () => MediaStreamTrackLike[] };
	try {
		media = await deps.getDisplayMedia({
			video: {
				width: CAPTURE_WIDTH,
				height: CAPTURE_HEIGHT,
				frameRate: FRAME_RATE,
			},
			audio: false,
		});
	} catch (err) {
		deps.onError?.(err);
		throw err;
	}
	const track = media.getVideoTracks()[0];
	if (track) track.contentHint = "detail";
	const settings = track?.getSettings?.() ?? {};
	let width = settings.width ?? DEFAULT_WIDTH;
	let height = settings.height ?? DEFAULT_HEIGHT;

	const variants = deps.sendLoVideoChunk !== undefined;
	let localGroup = 0n;
	const allocateGroup = deps.allocateGroup ?? (() => localGroup++);
	// Variants only: the Group the next encoded frame belongs to.
	let currentGroup = 0n;
	let lastKeyframeAt = -Infinity;
	let loWasActive = false;
	// The lanes fed this frame: hi always, lo while loActive() holds.
	const activeLanes = (): Lane[] => {
		const loOn = variants && (deps.loActive?.() ?? true);
		if (loOn && !loWasActive) lastKeyframeAt = -Infinity;
		loWasActive = loOn;
		return loOn ? lanes : lanes.slice(0, 1);
	};

	const configure = (lane: Lane) => {
		const size = lane.size(width, height);
		lane.width = size.width;
		lane.height = size.height;
		lane.encoder.configure({
			codec: CODEC,
			width: size.width,
			height: size.height,
			bitrate: lane.bitrate(width, height),
			latencyMode: "realtime",
		});
	};

	// A frame of a new size (the shared window was resized, or the first
	// frame differs from the track's advertised settings) re-configures the
	// encoders and forces a keyframe, since only a keyframe carries the size
	// the receiver decodes against.
	const followFrameSize = (frame: ScreenFrameLike) => {
		const fw = frame.codedWidth;
		const fh = frame.codedHeight;
		if (!fw || !fh || (fw === width && fh === height)) return;
		width = fw;
		height = fh;
		lanes.forEach(configure);
		lastKeyframeAt = -Infinity;
	};

	const backedUp = (lane: Lane) =>
		(lane.encoder.encodeQueueSize ?? 0) > MAX_ENCODE_QUEUE ||
		lane.unsent > MAX_SEND_BACKLOG;

	const lanes: Lane[] = [];
	const pipeline: ScreenSharePipeline = {
		stopped: false,
		stop: () => {
			pipeline.stopped = true;
			track?.stop();
			lanes.forEach((lane) => lane.encoder.close());
		},
		requestKeyframe: () => {
			lastKeyframeAt = -Infinity;
		},
		pushFrame: (frame) => {
			if (pipeline.stopped) return;
			const fed = activeLanes();
			// Latest wins, for every variant at once: a frame one encoder cannot
			// take is dropped for both, so they stay frame-aligned.
			if (fed.some(backedUp)) {
				frame.close?.();
				return;
			}
			followFrameSize(frame);
			const now = Date.now();
			const forceKeyframe = now - lastKeyframeAt >= KEYFRAME_INTERVAL_MS;
			if (forceKeyframe) lastKeyframeAt = now;
			// One keyframe decision for every variant, and with variants one new
			// Group: Group g of hi and lo both open on this very frame.
			if (variants && forceKeyframe) currentGroup = allocateGroup();
			for (const lane of fed) {
				if (variants)
					lane.inFlight.push({
						timestamp: frame.timestamp,
						group: currentGroup,
					});
				lane.encoder.encode(frame, { keyFrame: forceKeyframe });
			}
			frame.close?.();
		},
	};

	// Sends one encoder output of `lane` as <=480-byte pieces.
	const onOutput = (lane: Lane, chunk: EncodedChunk) => {
		if (pipeline.stopped) return;
		const buffer = new Uint8Array(chunk.byteLength);
		chunk.copyTo(buffer);
		const isKey = chunk.type === "key";
		let group: bigint | undefined;
		if (variants) {
			group =
				takeGroup(lane, chunk.timestamp) ?? lane.keyedGroup ?? currentGroup;
			if (isKey) lane.keyedGroup = group;
			// This Group's keyframe never came out of this encoder (dropped): its
			// stream would open on a delta no receiver can decode, so the delta
			// is not sent and the next frame starts a fresh Group.
			else if (group !== lane.keyedGroup) {
				pipeline.requestKeyframe();
				return;
			}
		}
		// ponytail: the size stamped here is the CURRENT encoder size; a
		// resize between encode() and this output() would stamp the new size
		// on the old frame. The keyframe forced by the resize follows right
		// behind, so the receiver resyncs within one frame either way.
		const pieces = toScreenChunks(
			lane.seq++,
			isKey,
			buffer,
			lane.width,
			lane.height,
		);
		// Sequential, awaited sends within a frame -- NOT fire-and-forget.
		// sendGate's latest-wins coalescing (right for standalone voice
		// frames) would drop pieces of the SAME frame if fired concurrently,
		// and moqtScreenWire.ts's reassembler discards a frame missing any
		// one chunk. Awaiting each call keeps the gate never "inFlight" when
		// the next piece of this frame arrives, so none of them get
		// coalesced away. Chained onto the lane's sendChain (not a detached
		// IIFE) so this guarantee also holds ACROSS frames: output() itself can
		// fire again before a prior frame's loop has finished (real encode() is
		// async). .catch keeps one frame's rejection from wedging the chain.
		lane.unsent++;
		lane.sendChain = lane.sendChain
			.then(() => sendPieces(pieces, lane.gatedSend, group))
			.catch(() => {})
			.finally(() => lane.unsent--);
	};

	const makeLane = (
		send: (chunk: ScreenChunk, group?: bigint) => void | Promise<void>,
		size: Lane["size"],
		bitrate: Lane["bitrate"],
	): Lane => {
		const lane = {
			size,
			bitrate,
			width,
			height,
			seq: 0,
			unsent: 0,
			sendChain: Promise.resolve(),
			gatedSend: gateFor(send),
			inFlight: [],
		} as unknown as Lane;
		lane.encoder = new deps.VideoEncoderCtor({
			output: (chunk) => onOutput(lane, chunk),
			error: (err) => {
				deps.onEncodeError?.(err);
			},
		});
		configure(lane);
		return lane;
	};

	lanes.push(
		makeLane(
			deps.sendVideoChunk,
			(w, h) => ({ width: w, height: h }),
			screenBitrate,
		),
	);
	if (deps.sendLoVideoChunk) {
		const sendLo = deps.sendLoVideoChunk;
		lanes.push(
			makeLane(
				(chunk, group) => sendLo(chunk, group ?? 0n),
				screenLoSize,
				() => SCREEN_LO_BITRATE,
			),
		);
	}

	track?.addEventListener("ended", () => {
		pipeline.stop();
	});

	return pipeline;
}
