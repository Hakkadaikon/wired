import { describe, expect, it, vi } from "vitest";
import {
	createVideoSourceController,
	type FrameLike,
	loadBackgroundProcessor,
	playLoopedVideo,
	type VideoSourceDeps,
} from "../videoSourceController";

const flush = () => new Promise((r) => setTimeout(r, 0));

// A track whose processor yields the frames the test pushes, and ends on stop().
function fakeTrack() {
	const queue: unknown[] = [];
	let wake: (() => void) | null = null;
	const track = {
		stopped: false,
		stop: vi.fn(() => {
			track.stopped = true;
			wake?.();
		}),
		push(frame: unknown) {
			queue.push(frame);
			wake?.();
		},
		reader: {
			async read(): Promise<{ value: unknown; done: boolean }> {
				for (;;) {
					if (track.stopped) return { value: undefined, done: true };
					if (queue.length) return { value: queue.shift(), done: false };
					await new Promise<void>((r) => {
						wake = r;
					});
				}
			},
		},
	};
	return track;
}

type Track = ReturnType<typeof fakeTrack>;

const frame = (name: string) => ({ name, timestamp: 1000, close: vi.fn() });

function deferred<T>() {
	let resolve!: (v: T) => void;
	let reject!: (e: unknown) => void;
	const promise = new Promise<T>((res, rej) => {
		resolve = res;
		reject = rej;
	});
	return { promise, resolve, reject };
}

function setup(over: Partial<VideoSourceDeps> = {}) {
	const camera = fakeTrack();
	const file = fakeTrack();
	const pipeline = {
		pushFrame: vi.fn(),
		requestKeyframe: vi.fn(),
		stop: vi.fn(),
	};
	const fileStop = vi.fn(() => file.stop());
	const views: { source: string; background: string; error: string | null }[] =
		[];
	// each acquisition hands over a live track, as a fresh one would be
	const deps: VideoSourceDeps = {
		getUserMedia: vi.fn(async () => {
			camera.stopped = false;
			return { getVideoTracks: () => [camera] };
		}),
		playFile: vi.fn(async () => {
			file.stopped = false;
			return { track: file, stop: fileStop };
		}),
		defaultFileUrl: "/videos/sample.mp4",
		makeProcessor: (track) => ({
			readable: { getReader: () => (track as Track).reader },
		}),
		loadBackground: vi.fn(async () => ({
			process: (f: FrameLike) => ({
				name: `comp(${(f as { name: string }).name})`,
				timestamp: 0,
				close: vi.fn(),
			}),
			stop: vi.fn(),
		})),
		startPipeline: vi.fn(async () => pipeline),
		publish: vi.fn(async () => {}),
		unpublish: vi.fn(),
		drawPreview: vi.fn(),
		onChange: (v) => views.push(v),
		...over,
	};
	const ctl = createVideoSourceController(deps);
	const pushed = () =>
		pipeline.pushFrame.mock.calls.map((c) => (c[0] as { name: string }).name);
	const view = () => views.at(-1);
	return { ctl, deps, camera, file, fileStop, pipeline, pushed, view };
}

describe("videoSourceController", () => {
	it("camera on publishes and pushes raw frames with a preview", async () => {
		const t = setup();
		t.ctl.toggle("camera");
		await flush();
		expect(t.deps.getUserMedia).toHaveBeenCalledWith({
			video: true,
			audio: false,
		});
		expect(t.deps.publish).toHaveBeenCalledTimes(1);
		t.camera.push(frame("c1"));
		await flush();
		expect(t.pushed()).toEqual(["c1"]);
		expect(t.deps.drawPreview).toHaveBeenCalledTimes(1);
		expect(t.view()).toEqual({
			source: "camera",
			background: "none",
			error: null,
		});
	});

	it("an image background drops frames until the segmenter is ready, then composites", async () => {
		const seg =
			deferred<Awaited<ReturnType<VideoSourceDeps["loadBackground"]>>>();
		const t = setup({ loadBackground: vi.fn(() => seg.promise) });
		t.ctl.toggle("camera");
		t.ctl.setBackground("image");
		await flush();
		const raw = frame("c1");
		t.camera.push(raw);
		await flush();
		expect(t.pushed()).toEqual([]);
		expect(raw.close).toHaveBeenCalled();
		seg.resolve({
			process: (f) => ({
				name: `comp(${(f as { name: string }).name})`,
				timestamp: 0,
			}),
			stop: vi.fn(),
		});
		await flush();
		const c2 = frame("c2");
		t.camera.push(c2);
		await flush();
		expect(t.pushed()).toEqual(["comp(c2)"]);
		expect(c2.close).toHaveBeenCalled();
		expect(t.view()?.background).toBe("image");
	});

	it("changing the background keeps the camera and its track", async () => {
		const t = setup();
		t.ctl.toggle("camera");
		await flush();
		t.ctl.setBackground("blur");
		t.ctl.setBackground("none");
		await flush();
		expect(t.deps.getUserMedia).toHaveBeenCalledTimes(1);
		expect(t.camera.stop).not.toHaveBeenCalled();
	});

	it("switching to the file stops the camera track and pushes file frames", async () => {
		const t = setup();
		t.ctl.toggle("camera");
		await flush();
		t.ctl.toggle("file");
		expect(t.camera.stop).toHaveBeenCalled();
		await flush();
		expect(t.deps.playFile).toHaveBeenCalledWith("/videos/sample.mp4");
		expect(t.pipeline.requestKeyframe).toHaveBeenCalled();
		expect(t.deps.publish).toHaveBeenCalledTimes(1);
		t.file.push(frame("f1"));
		await flush();
		expect(t.pushed()).toEqual(["f1"]);
		expect(t.view()?.source).toBe("file");
	});

	it("a picked file plays that url; toggling again goes back to the sample", async () => {
		const t = setup();
		t.ctl.pickFile("blob:x");
		await flush();
		expect(t.deps.playFile).toHaveBeenLastCalledWith("blob:x");
		t.ctl.toggle("file");
		expect(t.fileStop).toHaveBeenCalled();
		t.ctl.toggle("file");
		await flush();
		expect(t.deps.playFile).toHaveBeenLastCalledWith("/videos/sample.mp4");
	});

	it("a getUserMedia that resolves after off is stopped and never published", async () => {
		const gum = deferred<{ getVideoTracks: () => Track[] }>();
		const t = setup({ getUserMedia: vi.fn(() => gum.promise) });
		t.ctl.toggle("camera");
		t.ctl.toggle("camera");
		gum.resolve({ getVideoTracks: () => [t.camera] });
		await flush();
		expect(t.camera.stop).toHaveBeenCalled();
		expect(t.deps.publish).not.toHaveBeenCalled();
		expect(t.view()?.source).toBe("off");
	});

	it("a getUserMedia that resolves after switching to the file is stopped", async () => {
		const gum = deferred<{ getVideoTracks: () => Track[] }>();
		const t = setup({ getUserMedia: vi.fn(() => gum.promise) });
		t.ctl.toggle("camera");
		t.ctl.toggle("file");
		gum.resolve({ getVideoTracks: () => [t.camera] });
		await flush();
		expect(t.camera.stop).toHaveBeenCalled();
		t.file.push(frame("f1"));
		await flush();
		expect(t.pushed()).toEqual(["f1"]);
	});

	it("off unpublishes and stops the track, the pipeline and the segmenter", async () => {
		const stop = vi.fn();
		const t = setup({
			loadBackground: vi.fn(async () => ({ process: () => null, stop })),
		});
		t.ctl.toggle("camera");
		t.ctl.setBackground("blur");
		await flush();
		t.ctl.toggle("camera");
		expect(t.camera.stop).toHaveBeenCalled();
		expect(t.pipeline.stop).toHaveBeenCalled();
		expect(t.deps.unpublish).toHaveBeenCalledTimes(1);
		expect(stop).toHaveBeenCalled();
		// the track this off stopped ending is not a failure
		await flush();
		expect(t.view()).toMatchObject({ source: "off", error: null });
	});

	it("a camera failure shows an error and returns to off", async () => {
		const t = setup({
			getUserMedia: vi.fn(async () => {
				throw new Error("denied");
			}),
		});
		t.ctl.toggle("camera");
		await flush();
		expect(t.view()).toEqual({
			source: "off",
			background: "none",
			error: "camera could not be started",
		});
		expect(t.deps.publish).not.toHaveBeenCalled();
	});

	it("a file failure shows its own error", async () => {
		const t = setup({
			playFile: vi.fn(async () => {
				throw new Error("bad mp4");
			}),
		});
		t.ctl.toggle("file");
		await flush();
		expect(t.view()?.error).toBe("video file could not be played");
	});

	it("a pipeline that fails to start turns the source off with an error", async () => {
		const t = setup({
			startPipeline: vi.fn(async () => {
				throw new Error("no encoder");
			}),
		});
		t.ctl.toggle("camera");
		await flush();
		expect(t.camera.stop).toHaveBeenCalled();
		expect(t.view()?.source).toBe("off");
		expect(t.view()?.error).toBe("video could not be published");
	});

	it("a publish that rejects turns the source off with a publish error", async () => {
		const t = setup({
			publish: vi.fn(async () => {
				throw new Error("announce refused");
			}),
		});
		t.ctl.toggle("file");
		await flush();
		expect(t.fileStop).toHaveBeenCalled();
		expect(t.pipeline.stop).toHaveBeenCalled();
		expect(t.view()).toEqual({
			source: "off",
			background: "none",
			error: "video could not be published",
		});
	});

	it("a publish that resolves after off is withdrawn again", async () => {
		const pub = deferred<void>();
		const t = setup({ publish: vi.fn(() => pub.promise) });
		t.ctl.toggle("camera");
		await flush();
		t.ctl.toggle("camera");
		expect(t.deps.unpublish).toHaveBeenCalledTimes(1);
		pub.resolve();
		await flush();
		expect(t.deps.unpublish).toHaveBeenCalledTimes(2);
	});

	it("an encode error turns the source off and stays until the next selection", async () => {
		let encodeError = () => {};
		const t = setup({
			startPipeline: vi.fn(async (onError: () => void) => {
				encodeError = onError;
				return t.pipeline;
			}),
		});
		t.ctl.toggle("camera");
		await flush();
		encodeError();
		expect(t.camera.stop).toHaveBeenCalled();
		t.ctl.setBackground("blur");
		expect(t.view()).toEqual({
			source: "off",
			background: "blur",
			error: "video could not be encoded",
		});
		t.ctl.toggle("camera");
		expect(t.view()?.error).toBeNull();
	});

	it("an encode error of a stopped pipeline does not touch the next one", async () => {
		let encodeError = () => {};
		const t = setup({
			startPipeline: vi.fn(async (onError: () => void) => {
				encodeError = onError;
				return t.pipeline;
			}),
		});
		t.ctl.toggle("camera");
		await flush();
		const old = encodeError;
		t.ctl.toggle("camera");
		t.ctl.toggle("camera");
		await flush();
		old();
		expect(t.view()).toMatchObject({ source: "camera", error: null });
	});

	it("a processor that cannot be made turns the source off with a frames error", async () => {
		const t = setup({
			makeProcessor: () => {
				throw new Error("no MediaStreamTrackProcessor");
			},
		});
		t.ctl.toggle("camera");
		await flush();
		expect(t.camera.stop).toHaveBeenCalled();
		expect(t.view()).toMatchObject({
			source: "off",
			error: "video frames stopped",
		});
	});

	it("a pushFrame that throws turns the source off with a frames error", async () => {
		const t = setup();
		t.pipeline.pushFrame.mockImplementation(() => {
			throw new Error("encoder closed");
		});
		t.ctl.toggle("camera");
		await flush();
		t.camera.push(frame("c1"));
		await flush();
		expect(t.view()).toMatchObject({
			source: "off",
			error: "video frames stopped",
		});
	});

	it("a preview that throws does not stop the frame going out", async () => {
		const t = setup({
			drawPreview: vi.fn(() => {
				throw new Error("canvas");
			}),
		});
		t.ctl.toggle("camera");
		await flush();
		t.camera.push(frame("c1"));
		await flush();
		expect(t.pushed()).toEqual(["c1"]);
		expect(t.view()).toMatchObject({ source: "camera", error: null });
	});

	it("a frame before the pipeline exists is closed, not pushed", async () => {
		const p = deferred<{
			pushFrame: () => void;
			requestKeyframe: () => void;
			stop: () => void;
		}>();
		const t = setup({ startPipeline: vi.fn(() => p.promise) });
		t.ctl.toggle("camera");
		await flush();
		const early = frame("early");
		t.camera.push(early);
		await flush();
		expect(early.close).toHaveBeenCalled();
		p.resolve(t.pipeline);
		await flush();
		expect(t.pushed()).toEqual([]);
	});

	it("the held camera ending by itself turns the source off", async () => {
		const t = setup();
		t.ctl.toggle("camera");
		await flush();
		t.camera.stop(); // unplugged: the track ends without the controller
		await flush();
		expect(t.view()).toMatchObject({
			source: "off",
			error: "video frames stopped",
		});
		expect(t.deps.unpublish).toHaveBeenCalled();
	});

	it("a camera without a video track fails and holds nothing", async () => {
		const makeProcessor = vi.fn();
		const t = setup({
			getUserMedia: vi.fn(async () => ({ getVideoTracks: () => [] })),
			makeProcessor,
		});
		t.ctl.toggle("camera");
		await flush();
		expect(t.view()).toMatchObject({
			source: "off",
			error: "camera could not be started",
		});
		expect(makeProcessor).not.toHaveBeenCalled();
		expect(t.deps.publish).not.toHaveBeenCalled();
	});

	it("an off while the pipeline is starting stops that pipeline", async () => {
		const p = deferred<{
			pushFrame: () => void;
			requestKeyframe: () => void;
			stop: () => void;
		}>();
		const t = setup({ startPipeline: vi.fn(() => p.promise) });
		t.ctl.toggle("camera");
		await flush();
		t.ctl.toggle("camera");
		p.resolve(t.pipeline);
		await flush();
		expect(t.pipeline.stop).toHaveBeenCalled();
		expect(t.deps.publish).not.toHaveBeenCalled();
	});

	it("leave cleans up and ignores later picks", async () => {
		const t = setup();
		t.ctl.toggle("camera");
		await flush();
		t.ctl.leave();
		expect(t.camera.stop).toHaveBeenCalled();
		expect(t.deps.unpublish).toHaveBeenCalled();
		t.ctl.toggle("camera");
		expect(t.deps.getUserMedia).toHaveBeenCalledTimes(1);
	});

	it("a segmenter that loads after leave is stopped", async () => {
		const seg =
			deferred<Awaited<ReturnType<VideoSourceDeps["loadBackground"]>>>();
		const t = setup({ loadBackground: vi.fn(() => seg.promise) });
		t.ctl.toggle("camera");
		t.ctl.setBackground("blur");
		t.ctl.leave();
		const stop = vi.fn();
		seg.resolve({ process: () => null, stop });
		await flush();
		expect(stop).toHaveBeenCalled();
	});

	it("a background failure reported after it was ready withholds frames and shows an error", async () => {
		let fail = () => {};
		const stop = vi.fn();
		const t = setup({
			loadBackground: vi.fn(async (onFail: () => void) => {
				fail = onFail;
				return { process: () => ({ name: "comp", timestamp: 0 }), stop };
			}),
		});
		t.ctl.toggle("camera");
		t.ctl.setBackground("blur");
		await flush();
		fail();
		expect(stop).toHaveBeenCalled();
		t.camera.push(frame("c1"));
		await flush();
		expect(t.pushed()).toEqual([]);
		expect(t.view()?.error).toBe("background effect could not be loaded");
	});

	it("a lost background after reselecting the camera still withholds frames", async () => {
		let fail = () => {};
		const t = setup({
			loadBackground: vi.fn(async (onFail: () => void) => {
				fail = onFail;
				return {
					process: () => ({ name: "comp", timestamp: 0 }),
					stop: vi.fn(),
				};
			}),
		});
		t.ctl.toggle("camera");
		t.ctl.setBackground("blur");
		await flush();
		t.ctl.toggle("file");
		t.ctl.toggle("camera");
		await flush();
		fail();
		t.camera.push(frame("c1"));
		await flush();
		expect(t.pushed()).toEqual([]);
		expect(t.view()?.error).toBe("background effect could not be loaded");
	});

	it("a lost report from a background already released changes nothing", async () => {
		let fail = () => {};
		const t = setup({
			loadBackground: vi.fn(async (onFail: () => void) => {
				fail = onFail;
				return {
					process: () => ({ name: "comp", timestamp: 0 }),
					stop: vi.fn(),
				};
			}),
		});
		t.ctl.toggle("camera");
		t.ctl.setBackground("blur");
		await flush();
		t.ctl.setBackground("none");
		const before = t.view();
		fail();
		expect(t.view()).toBe(before);
		t.camera.push(frame("c1"));
		await flush();
		expect(t.pushed()).toEqual(["c1"]);
	});

	it("after a background load failure, background none clears the error and raw frames flow", async () => {
		const t = setup({
			loadBackground: vi.fn(async () => {
				throw new Error("wasm");
			}),
		});
		t.ctl.toggle("camera");
		t.ctl.setBackground("blur");
		await flush();
		expect(t.view()?.error).toBe("background effect could not be loaded");
		t.ctl.setBackground("none");
		expect(t.view()?.error).toBeNull();
		t.camera.push(frame("c1"));
		await flush();
		expect(t.pushed()).toEqual(["c1"]);
	});

	it("the preview draws exactly the pushed (composited) frame, never a dropped one", async () => {
		const seg =
			deferred<Awaited<ReturnType<VideoSourceDeps["loadBackground"]>>>();
		const t = setup({ loadBackground: vi.fn(() => seg.promise) });
		t.ctl.toggle("camera");
		t.ctl.setBackground("blur");
		await flush();
		t.camera.push(frame("dropped"));
		await flush();
		expect(t.deps.drawPreview).not.toHaveBeenCalled();
		seg.resolve({
			process: (f) => ({
				name: `comp(${(f as { name: string }).name})`,
				timestamp: 0,
			}),
			stop: vi.fn(),
		});
		await flush();
		t.camera.push(frame("c2"));
		await flush();
		const drawn = vi.mocked(t.deps.drawPreview).mock.calls.map((c) => c[0]);
		expect(drawn).toEqual(t.pipeline.pushFrame.mock.calls.map((c) => c[0]));
		expect(drawn).toEqual([{ name: "comp(c2)", timestamp: 0 }]);
	});

	it("a reopened send stream asks the running pipeline for a keyframe", async () => {
		const t = setup();
		t.ctl.requestKeyframe();
		t.ctl.toggle("camera");
		await flush();
		t.pipeline.requestKeyframe.mockClear();
		t.ctl.requestKeyframe();
		expect(t.pipeline.requestKeyframe).toHaveBeenCalledTimes(1);
	});

	it("mp4 audio is never processed: only the player's video track is read", async () => {
		const makeProcessor = vi.fn((track: unknown) => ({
			readable: { getReader: () => (track as Track).reader },
		}));
		const t = setup({ makeProcessor });
		t.ctl.toggle("file");
		await flush();
		expect(makeProcessor).toHaveBeenCalledExactlyOnceWith(t.file);
	});
});

describe("loadBackgroundProcessor (fail-closed per frame)", () => {
	function bg(over: {
		segment?: () => unknown;
		render?: () => void;
		createCompositor?: () => never;
	}) {
		const comp = {
			render: vi.fn((..._args: unknown[]) => over.render?.()),
			close: vi.fn(),
		};
		const seg = {
			segment: vi.fn(
				over.segment ??
					(() => ({ mask: new Uint8Array(4), width: 2, height: 2 })),
			),
			close: vi.fn(),
		};
		let lost = () => {};
		const onFail = vi.fn();
		const load = () =>
			loadBackgroundProcessor(
				{
					loadImage: async () => ({}) as TexImageSource,
					loadSegmenter: async () => seg as never,
					createCompositor: over.createCompositor ?? (() => comp),
					snapshot: (t) => ({ name: `snap@${t}`, timestamp: t }),
					onContextLost: (cb) => {
						lost = cb;
					},
				},
				onFail,
			);
		return { comp, seg, load, onFail, lose: () => lost() };
	}

	// Drives a controller with an image background backed by `b` and returns
	// what was pushed for one camera frame.
	async function pushOne(b: ReturnType<typeof bg>) {
		const t = setup({ loadBackground: () => b.load() });
		t.ctl.toggle("camera");
		t.ctl.setBackground("image");
		await flush();
		const f = frame("c1");
		t.camera.push(f);
		await flush();
		return { t, f };
	}

	it("segments, composites and snapshots at the frame's timestamp", async () => {
		const b = bg({});
		const { t } = await pushOne(b);
		expect(b.seg.segment).toHaveBeenCalledWith(expect.anything(), 1);
		expect(b.comp.render.mock.calls[0][2]).toBe("image");
		expect(t.pushed()).toEqual(["snap@1000"]);
	});

	it("segment throws: nothing is pushed", async () => {
		const b = bg({
			segment: () => {
				throw new Error("wasm");
			},
		});
		const { t, f } = await pushOne(b);
		expect(t.pushed()).toEqual([]);
		expect(f.close).toHaveBeenCalled();
	});

	it("segment returns no mask: nothing is pushed", async () => {
		const b = bg({ segment: () => undefined });
		const { t } = await pushOne(b);
		expect(t.pushed()).toEqual([]);
		expect(b.comp.render).not.toHaveBeenCalled();
	});

	it("render throws: nothing is pushed", async () => {
		const b = bg({
			render: () => {
				throw new Error("gl");
			},
		});
		const { t } = await pushOne(b);
		expect(t.pushed()).toEqual([]);
	});

	it("compositor creation fails: the load fails (segmenterFailed), the segmenter is closed, nothing is pushed", async () => {
		const b = bg({
			createCompositor: () => {
				throw new Error("WebGL2 unavailable");
			},
		});
		await expect(b.load()).rejects.toThrow("WebGL2");
		expect(b.seg.close).toHaveBeenCalled();
		const { t } = await pushOne(b);
		expect(t.pushed()).toEqual([]);
		expect(t.view()?.error).toBe("background effect could not be loaded");
	});

	it("a lost WebGL context reports failure and withholds frames", async () => {
		const b = bg({});
		const p = await b.load();
		b.lose();
		expect(b.onFail).toHaveBeenCalled();
		expect(p.process({ timestamp: 0 }, "blur")).toBeNull();
	});

	it("stop closes the compositor and the segmenter", async () => {
		const b = bg({});
		(await b.load()).stop();
		expect(b.comp.close).toHaveBeenCalled();
		expect(b.seg.close).toHaveBeenCalled();
	});
});

describe("playLoopedVideo", () => {
	function fakeVideo(play = async () => {}) {
		const video = {
			src: "",
			loop: false,
			muted: false,
			play: vi.fn(play),
			pause: vi.fn(),
			removeAttribute: vi.fn(),
			load: vi.fn(),
			captureStream: vi.fn(() => ({
				getVideoTracks: () => [videoTrack],
				getTracks: () => [videoTrack, audioTrack],
			})),
		};
		const videoTrack = { stop: vi.fn() };
		const audioTrack = { stop: vi.fn() };
		return { video, videoTrack, audioTrack };
	}

	it("plays muted and looped and hands over only the video track", async () => {
		const v = fakeVideo();
		const h = await playLoopedVideo(v.video, "/videos/sample.mp4", vi.fn());
		expect(v.video).toMatchObject({
			muted: true,
			loop: true,
			src: "/videos/sample.mp4",
		});
		expect(h.track).toBe(v.videoTrack);
	});

	it("stop ends every captured track, unloads, and revokes a picked file's url", async () => {
		const v = fakeVideo();
		const revoke = vi.fn();
		const h = await playLoopedVideo(v.video, "blob:x", revoke);
		h.stop();
		expect(v.videoTrack.stop).toHaveBeenCalled();
		expect(v.audioTrack.stop).toHaveBeenCalled();
		expect(v.video.pause).toHaveBeenCalled();
		expect(revoke).toHaveBeenCalledWith("blob:x");
	});

	it("the bundled sample's url is not revoked", async () => {
		const v = fakeVideo();
		const revoke = vi.fn();
		(await playLoopedVideo(v.video, "/videos/sample.mp4", revoke)).stop();
		expect(revoke).not.toHaveBeenCalled();
	});

	it("a play failure unloads and revokes, then rejects", async () => {
		const v = fakeVideo(async () => {
			throw new Error("decode");
		});
		const revoke = vi.fn();
		await expect(playLoopedVideo(v.video, "blob:y", revoke)).rejects.toThrow();
		expect(revoke).toHaveBeenCalledWith("blob:y");
		expect(v.video.load).toHaveBeenCalled();
	});

	it("a capture without a video track unloads and revokes, then rejects", async () => {
		const v = fakeVideo();
		v.video.captureStream.mockReturnValue({
			getVideoTracks: () => [],
			getTracks: () => [v.audioTrack],
		});
		const revoke = vi.fn();
		await expect(playLoopedVideo(v.video, "blob:z", revoke)).rejects.toThrow();
		expect(revoke).toHaveBeenCalledWith("blob:z");
		expect(v.video.load).toHaveBeenCalled();
	});
});
