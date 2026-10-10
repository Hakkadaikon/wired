// The screen share's hi/lo variants (tasks/moqt-trackswitch-plan.md W5):
// with sendLoVideoChunk the pipeline runs a second, low-quality encoder over
// the SAME captured frames, takes ONE keyframe decision for both, and stamps
// each encoded frame with the Group its encode() call was made in, so Group g
// of both variants starts at the same keyframe instant however the two
// encoders' outputs interleave (or whichever frame one of them drops).
import { describe, expect, it, vi } from "vitest";
import type { ScreenChunk } from "../moqtScreenWire";
import {
	SCREEN_LO_BITRATE,
	SCREEN_LO_MAX_WIDTH,
	screenLoSize,
	startScreenSharePipeline,
} from "../screenSharePipeline";

function fakeTrack(settings = { width: 1920, height: 1080 }) {
	return {
		stop: vi.fn(),
		addEventListener: vi.fn(),
		getSettings: () => settings,
	};
}

type Output = (chunk: unknown, metadata: unknown) => void;

/** Encoders whose outputs the test releases by hand (per encoder, in
 * encode order), each stamped with its input frame's timestamp like a real
 * EncodedVideoChunk. */
function deferredEncoders() {
	const instances: {
		output: Output;
		configs: Record<string, unknown>[];
		encodes: { frame: { timestamp: number }; opts: { keyFrame: boolean } }[];
		queued: { timestamp: number; key: boolean }[];
		encodeQueueSize: number;
		closed: boolean;
	}[] = [];
	const ctor = vi.fn(function (
		this: unknown,
		init: { output: Output; error: (e: unknown) => void },
	) {
		const inst = {
			output: init.output,
			configs: [] as Record<string, unknown>[],
			encodes: [] as {
				frame: { timestamp: number };
				opts: { keyFrame: boolean };
			}[],
			queued: [] as { timestamp: number; key: boolean }[],
			encodeQueueSize: 0,
			closed: false,
		};
		instances.push(inst);
		return {
			configure: (c: Record<string, unknown>) => inst.configs.push(c),
			encode: (frame: { timestamp: number }, opts: { keyFrame: boolean }) => {
				inst.encodes.push({ frame, opts });
				inst.queued.push({ timestamp: frame.timestamp, key: opts.keyFrame });
			},
			close: () => {
				inst.closed = true;
			},
			get encodeQueueSize() {
				return inst.encodeQueueSize;
			},
		};
	});
	/** Emits encoder i's next queued output (or drops it: `drop`). */
	const release = (i: number, drop = false) => {
		const q = instances[i].queued.shift();
		if (!q || drop) return;
		const bytes = new Uint8Array(10).fill(i);
		instances[i].output(
			{
				byteLength: 10,
				type: q.key ? "key" : "delta",
				timestamp: q.timestamp,
				copyTo: (d: Uint8Array) => d.set(bytes),
			},
			{},
		);
	};
	return { ctor, instances, release };
}

const frame = (timestamp: number) => ({ close: vi.fn(), timestamp });
const tick = () => new Promise((r) => setTimeout(r, 0));

async function startVariants(track = fakeTrack()) {
	const enc = deferredEncoders();
	const hi: { chunk: ScreenChunk; group?: bigint }[] = [];
	const lo: { chunk: ScreenChunk; group: bigint }[] = [];
	let next = 40n; // a session's shared counter need not start at 0
	const allocateGroup = vi.fn(() => next++);
	const pipeline = await startScreenSharePipeline({
		getDisplayMedia: async () => ({ getVideoTracks: () => [track] }),
		VideoEncoderCtor: enc.ctor as never,
		sendVideoChunk: async (chunk, group) => {
			hi.push({ chunk, group });
		},
		sendLoVideoChunk: async (chunk, group) => {
			lo.push({ chunk, group });
		},
		allocateGroup,
	});
	return { enc, hi, lo, pipeline, allocateGroup };
}

describe("screenLoSize", () => {
	it("scales width down to SCREEN_LO_MAX_WIDTH keeping the aspect, even dimensions", () => {
		expect(SCREEN_LO_MAX_WIDTH).toBe(640);
		expect(screenLoSize(1920, 1080)).toEqual({ width: 640, height: 360 });
		expect(screenLoSize(1280, 1024)).toEqual({ width: 640, height: 512 });
		expect(screenLoSize(1366, 768)).toEqual({ width: 640, height: 360 });
	});

	it("leaves a frame already within 640 wide as is (boundary 640 included)", () => {
		expect(screenLoSize(640, 480)).toEqual({ width: 640, height: 480 });
		expect(screenLoSize(405, 720)).toEqual({ width: 404, height: 720 });
	});
});

describe("screenSharePipeline variants", () => {
	it("without sendLoVideoChunk only one encoder runs and sendVideoChunk gets no Group (d19 / extension-less)", async () => {
		const enc = deferredEncoders();
		const sent: unknown[][] = [];
		const pipeline = await startScreenSharePipeline({
			getDisplayMedia: async () => ({ getVideoTracks: () => [fakeTrack()] }),
			VideoEncoderCtor: enc.ctor as never,
			sendVideoChunk: async (...args) => {
				sent.push(args);
			},
		});
		pipeline.pushFrame(frame(0));
		enc.release(0);
		await tick();
		expect(enc.ctor).toHaveBeenCalledTimes(1);
		expect(sent).toHaveLength(1);
		expect(sent[0]).toHaveLength(1);
	});

	it("runs a second encoder: lo at <=640 wide and SCREEN_LO_BITRATE, same codec/mode/fps", async () => {
		const { enc } = await startVariants();
		expect(enc.ctor).toHaveBeenCalledTimes(2);
		expect(enc.instances[0].configs[0]).toMatchObject({
			width: 1920,
			height: 1080,
			codec: "vp8",
		});
		expect(enc.instances[1].configs[0]).toMatchObject({
			codec: "vp8",
			width: 640,
			height: 360,
			bitrate: SCREEN_LO_BITRATE,
			latencyMode: "realtime",
		});
		expect(SCREEN_LO_BITRATE).toBeGreaterThanOrEqual(300_000);
		expect(SCREEN_LO_BITRATE).toBeLessThanOrEqual(400_000);
	});

	it("encodes every captured frame on both encoders with ONE keyframe decision (cadence and requestKeyframe)", async () => {
		const { enc, pipeline } = await startVariants();
		const f0 = frame(0);
		pipeline.pushFrame(f0);
		pipeline.pushFrame(frame(100_000));
		pipeline.requestKeyframe();
		pipeline.pushFrame(frame(200_000));
		const opts = (i: number) =>
			enc.instances[i].encodes.map((e) => e.opts.keyFrame);
		expect(opts(0)).toEqual([true, false, true]);
		expect(opts(1)).toEqual([true, false, true]);
		expect(enc.instances[0].encodes[0].frame).toBe(f0);
		expect(enc.instances[1].encodes[0].frame).toBe(f0);
		expect(f0.close).toHaveBeenCalledTimes(1); // after both encode() calls
	});

	it("Group g of hi and lo starts at the same keyframe instant, however the outputs interleave", async () => {
		const { enc, hi, lo, pipeline, allocateGroup } = await startVariants();
		pipeline.pushFrame(frame(0));
		pipeline.pushFrame(frame(100_000));
		pipeline.requestKeyframe();
		pipeline.pushFrame(frame(200_000));
		// hi's three outputs all come before any of lo's.
		enc.release(0);
		enc.release(0);
		enc.release(0);
		await tick();
		enc.release(1);
		enc.release(1);
		enc.release(1);
		await tick();

		const shape = (xs: { chunk: ScreenChunk; group?: bigint }[]) =>
			xs.map((x) => [x.group, x.chunk.keyframe]);
		expect(shape(hi)).toEqual([
			[40n, true],
			[40n, false],
			[41n, true],
		]);
		expect(shape(lo)).toEqual(shape(hi));
		expect(allocateGroup).toHaveBeenCalledTimes(2); // one shared counter, once per keyframe decision
		expect(lo[0].chunk).toMatchObject({ width: 640, height: 360 });
		expect(hi[0].chunk).toMatchObject({ width: 1920, height: 1080 });
	});

	it("a frame one encoder drops does not shift the other frames' Groups (matched by timestamp)", async () => {
		const { enc, lo, pipeline } = await startVariants();
		pipeline.pushFrame(frame(0));
		pipeline.pushFrame(frame(100_000));
		pipeline.requestKeyframe();
		pipeline.pushFrame(frame(200_000));
		enc.release(1); // frame 0
		enc.release(1, true); // frame 100000 dropped by the lo encoder
		enc.release(1); // frame 200000
		await tick();
		expect(lo.map((x) => [x.group, x.chunk.keyframe])).toEqual([
			[40n, true],
			[41n, true],
		]);
	});

	it("a delta opening a Group (its keyframe was dropped) is not sent and asks for a fresh keyframe", async () => {
		const { enc, lo, pipeline } = await startVariants();
		pipeline.pushFrame(frame(0));
		enc.release(0);
		enc.release(1);
		pipeline.requestKeyframe();
		pipeline.pushFrame(frame(100_000)); // keyframe, Group 41
		pipeline.pushFrame(frame(200_000)); // delta, Group 41
		enc.release(1, true); // lo drops Group 41's keyframe...
		enc.release(1); // ...so its first Group-41 output is a delta
		await tick();
		// The undecodable delta itself is not sent: lo has only Group 40's keyframe.
		expect(lo.map((x) => [x.group, x.chunk.keyframe])).toEqual([[40n, true]]);
		pipeline.pushFrame(frame(300_000));
		expect(enc.instances[1].encodes.at(-1)?.opts.keyFrame).toBe(true);
		expect(enc.instances[0].encodes.at(-1)?.opts.keyFrame).toBe(true);
	});

	it("S3: loActive() false keeps the lo encoder idle; turning on forces a keyframe and a new Group on both", async () => {
		const enc = deferredEncoders();
		let active = false;
		let next = 0n;
		const pipeline = await startScreenSharePipeline({
			getDisplayMedia: async () => ({ getVideoTracks: () => [fakeTrack()] }),
			VideoEncoderCtor: enc.ctor as never,
			sendVideoChunk: vi.fn(),
			sendLoVideoChunk: vi.fn(),
			allocateGroup: () => next++,
			loActive: () => active,
		});
		pipeline.pushFrame(frame(0));
		pipeline.pushFrame(frame(100_000));
		expect(enc.instances[1].encodes).toHaveLength(0);
		expect(enc.instances[0].encodes.map((e) => e.opts.keyFrame)).toEqual([
			true,
			false,
		]);
		active = true;
		pipeline.pushFrame(frame(200_000));
		expect(enc.instances[0].encodes.at(-1)?.opts.keyFrame).toBe(true);
		expect(enc.instances[1].encodes.map((e) => e.opts.keyFrame)).toEqual([
			true,
		]);
		expect(next).toBe(2n);
	});

	it("a resize reconfigures both encoders (lo scaled) and forces a keyframe on both", async () => {
		const { enc, pipeline } = await startVariants();
		pipeline.pushFrame({
			...frame(0),
			codedWidth: 1920,
			codedHeight: 1080,
		} as never);
		pipeline.pushFrame({
			...frame(100_000),
			codedWidth: 1280,
			codedHeight: 1024,
		} as never);
		expect(enc.instances[0].configs.at(-1)).toMatchObject({
			width: 1280,
			height: 1024,
		});
		expect(enc.instances[1].configs.at(-1)).toMatchObject({
			width: 640,
			height: 512,
			bitrate: SCREEN_LO_BITRATE,
		});
		expect(enc.instances[0].encodes[1].opts.keyFrame).toBe(true);
		expect(enc.instances[1].encodes[1].opts.keyFrame).toBe(true);
	});

	it("a backlog on either encoder drops the frame for both (keeps them frame-aligned)", async () => {
		const { enc, pipeline } = await startVariants();
		enc.instances[1].encodeQueueSize = 3;
		const f = frame(0);
		pipeline.pushFrame(f);
		expect(enc.instances[0].encodes).toHaveLength(0);
		expect(enc.instances[1].encodes).toHaveLength(0);
		expect(f.close).toHaveBeenCalledTimes(1);
	});

	it("stop() closes both encoders", async () => {
		const { enc, pipeline } = await startVariants();
		pipeline.stop();
		expect(enc.instances.map((i) => i.closed)).toEqual([true, true]);
	});
});
