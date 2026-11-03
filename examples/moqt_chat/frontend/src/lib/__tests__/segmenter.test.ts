import { describe, expect, it, vi } from "vitest";
import {
	confidenceToBytes,
	loadSegmenter,
	nextTimestamp,
	type SegmenterDeps,
} from "../segmenter";

describe("confidenceToBytes", () => {
	it("maps 0, 0.5 and 1 to 0, 128 and 255", () => {
		expect([...confidenceToBytes(new Float32Array([0, 0.5, 1]))]).toEqual([
			0, 128, 255,
		]);
	});

	it("clamps values outside [0,1]", () => {
		expect([...confidenceToBytes(new Float32Array([-0.2, 1.3]))]).toEqual([
			0, 255,
		]);
	});

	it("writes into the given buffer and returns it", () => {
		const out = new Uint8Array(2);
		expect(confidenceToBytes(new Float32Array([1, 0]), out)).toBe(out);
		expect([...out]).toEqual([255, 0]);
	});
});

describe("nextTimestamp", () => {
	it("keeps a timestamp later than the previous one", () => {
		expect(nextTimestamp(10, 15)).toBe(15);
	});

	it("bumps an equal timestamp by 1 ms", () => {
		expect(nextTimestamp(10, 10)).toBe(11);
	});

	it("bumps an earlier timestamp to previous + 1 ms", () => {
		expect(nextTimestamp(10, 3)).toBe(11);
	});
});

function fakeVision(failDelegates: string[] = []) {
	const result = {
		confidenceMasks: [
			{
				width: 2,
				height: 1,
				getAsFloat32Array: () => new Float32Array([0, 1]),
			},
		],
		close: vi.fn(),
	};
	const seg = {
		segmentForVideo: vi.fn((_frame: unknown, _ms: number) => result),
		close: vi.fn(),
	};
	const createFromOptions = vi.fn(
		async (_fs: unknown, opts: { baseOptions: { delegate: string } }) => {
			if (failDelegates.includes(opts.baseOptions.delegate))
				throw new Error(`no ${opts.baseOptions.delegate}`);
			return seg;
		},
	);
	const forVisionTasks = vi.fn(async () => "fileset");
	const vision = {
		FilesetResolver: { forVisionTasks },
		ImageSegmenter: { createFromOptions },
	} as unknown as SegmenterDeps["vision"];
	return { vision, seg, result, createFromOptions, forVisionTasks };
}

describe("loadSegmenter", () => {
	it("loads the wasm and model from <basePath>/mediapipe with the GPU delegate", async () => {
		const f = fakeVision();
		await loadSegmenter({ vision: f.vision, basePath: "/wired/moqt_chat" });
		expect(f.forVisionTasks).toHaveBeenCalledWith("/wired/moqt_chat/mediapipe");
		expect(f.createFromOptions).toHaveBeenCalledTimes(1);
		expect(f.createFromOptions).toHaveBeenCalledWith("fileset", {
			baseOptions: {
				modelAssetPath: "/wired/moqt_chat/mediapipe/selfie_segmenter.tflite",
				delegate: "GPU",
			},
			runningMode: "VIDEO",
			outputConfidenceMasks: true,
			outputCategoryMask: false,
		});
	});

	it("falls back to the CPU delegate when GPU creation throws", async () => {
		const f = fakeVision(["GPU"]);
		await loadSegmenter({ vision: f.vision, basePath: "" });
		expect(f.createFromOptions).toHaveBeenCalledTimes(2);
		expect(f.createFromOptions.mock.calls[1][1].baseOptions.delegate).toBe(
			"CPU",
		);
	});

	it("rejects when both delegates fail", async () => {
		const f = fakeVision(["GPU", "CPU"]);
		await expect(
			loadSegmenter({ vision: f.vision, basePath: "" }),
		).rejects.toThrow("no CPU");
	});

	it("segment() returns the byte mask and closes the MediaPipe result", async () => {
		const f = fakeVision();
		const s = await loadSegmenter({ vision: f.vision, basePath: "" });
		const frame = {} as TexImageSource;
		const m = s.segment(frame, 5);
		expect(f.seg.segmentForVideo).toHaveBeenCalledWith(frame, 5);
		expect([...m.mask]).toEqual([0, 255]);
		expect([m.width, m.height]).toEqual([2, 1]);
		expect(f.result.close).toHaveBeenCalledTimes(1);
	});

	it("segment() passes strictly increasing timestamps", async () => {
		const f = fakeVision();
		const s = await loadSegmenter({ vision: f.vision, basePath: "" });
		const frame = {} as TexImageSource;
		s.segment(frame, 5);
		s.segment(frame, 5);
		s.segment(frame, 2);
		expect(f.seg.segmentForVideo.mock.calls.map((c) => c[1])).toEqual([
			5, 6, 7,
		]);
	});

	it("close() closes the MediaPipe segmenter", async () => {
		const f = fakeVision();
		const s = await loadSegmenter({ vision: f.vision, basePath: "" });
		s.close();
		expect(f.seg.close).toHaveBeenCalledTimes(1);
	});
});
