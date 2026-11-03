// Person segmentation with MediaPipe's selfie segmenter: one confidence
// mask per camera frame, as bytes ready for an R8 texture.
import type * as vision from "@mediapipe/tasks-vision";

export type SegmenterDeps = {
	/** The MediaPipe module (injected so tests can use fakes). */
	vision: Pick<typeof vision, "FilesetResolver" | "ImageSegmenter">;
	/** The app's base path ("" in dev, "/wired/moqt_chat" on Pages). */
	basePath: string;
};

export type SegmentMask = { mask: Uint8Array; width: number; height: number };

export type Segmenter = {
	segment(frame: TexImageSource | VideoFrame, timestampMs: number): SegmentMask;
	close(): void;
};

/** Confidence in [0,1] to a byte: clamp, then round(x * 255). */
export function confidenceToBytes(
	f32: Float32Array,
	out = new Uint8Array(f32.length),
): Uint8Array {
	for (let i = 0; i < f32.length; i++)
		out[i] = Math.round(Math.min(1, Math.max(0, f32[i])) * 255);
	return out;
}

/** segmentForVideo needs strictly increasing timestamps. */
export function nextTimestamp(prevMs: number, ms: number): number {
	return ms > prevMs ? ms : prevMs + 1;
}

async function create(
	deps: SegmenterDeps,
	delegate: "GPU" | "CPU",
): Promise<vision.ImageSegmenter> {
	const dir = `${deps.basePath}/mediapipe`;
	const fileset = await deps.vision.FilesetResolver.forVisionTasks(dir);
	return deps.vision.ImageSegmenter.createFromOptions(fileset, {
		baseOptions: { modelAssetPath: `${dir}/selfie_segmenter.tflite`, delegate },
		runningMode: "VIDEO",
		outputConfidenceMasks: true,
		outputCategoryMask: false,
	});
}

export async function loadSegmenter(deps: SegmenterDeps): Promise<Segmenter> {
	const seg = await create(deps, "GPU").catch(() => create(deps, "CPU"));
	let lastMs = Number.NEGATIVE_INFINITY;
	return {
		segment(frame, timestampMs) {
			lastMs = nextTimestamp(lastMs, timestampMs);
			const result = seg.segmentForVideo(frame, lastMs);
			// biome-ignore lint/style/noNonNullAssertion: outputConfidenceMasks is on
			const m = result.confidenceMasks![0];
			const mask = confidenceToBytes(m.getAsFloat32Array());
			const out = { mask, width: m.width, height: m.height };
			result.close();
			return out;
		},
		close: () => seg.close(),
	};
}
