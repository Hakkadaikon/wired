import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	vi,
} from "vitest";
import type { MoqtChatClient } from "@/lib/moqtClient";
import { CAMERA_TRACK } from "@/lib/moqtScreenClient";
import { startScreenSharePipeline } from "@/lib/screenSharePipeline";
import { drawFrameInto } from "@/lib/screenTileSize";
import { playLoopedVideo } from "@/lib/videoSourceController";
import { useMoqtChatStore } from "@/stores/moqtChatStore";
import { useCameraVideo } from "../useCameraVideo";

// Every lib the hook wires is replaced by a recorder, so each test checks
// one wire: what the hook hands to which dependency.
const rec = vi.hoisted(() => ({
	source: {} as Record<string, unknown>,
	receiver: {} as Record<string, unknown>,
	client: {} as Record<string, unknown>,
}));

vi.mock("@/lib/videoSourceController", () => ({
	createVideoSourceController: vi.fn((deps) => {
		rec.source = {
			deps,
			toggle: vi.fn(),
			pickFile: vi.fn(),
			setBackground: vi.fn(),
			leave: vi.fn(),
			requestKeyframe: vi.fn(),
		};
		return rec.source;
	}),
	loadBackgroundProcessor: vi.fn(),
	playLoopedVideo: vi.fn(),
}));
vi.mock("@/lib/cameraReceiver", () => ({
	createCameraReceiver: vi.fn((deps) => {
		rec.receiver = { deps, onChunk: vi.fn(), tick: vi.fn(), forget: vi.fn() };
		return rec.receiver;
	}),
}));
vi.mock("@/lib/moqtScreenClient", async (orig) => ({
	...(await orig<object>()),
	MoqtScreenClient: vi.fn(function (this: object, chat, callbacks, kind) {
		rec.client = Object.assign(this, {
			chat,
			callbacks,
			kind,
			handleIncomingStream: vi.fn(),
			subscribeToScreenTrack: vi.fn(async () => {}),
			forgetParticipant: vi.fn(),
			sendVideoChunk: vi.fn(),
			publishScreenTrack: vi.fn(async () => {}),
			close: vi.fn(),
		});
	}),
}));
vi.mock("@/lib/screenSharePipeline", () => ({
	startScreenSharePipeline: vi.fn(async () => ({})),
}));
vi.mock("@/lib/screenTileSize", async (orig) => ({
	...(await orig<object>()),
	drawFrameInto: vi.fn(),
}));

type Fns = Record<string, (...a: unknown[]) => unknown>;
const sourceDeps = () => rec.source.deps as Fns & { defaultFileUrl: string };
const receiverDeps = () => rec.receiver.deps as Fns;
const client = () => rec.client as Fns & Record<string, unknown>;
const source = () => rec.source as Fns;

beforeAll(() => {
	(
		globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }
	).IS_REACT_ACT_ENVIRONMENT = true;
});
// WebCodecs are not in jsdom; the hook only passes the constructors on.
beforeEach(() => {
	for (const name of ["VideoDecoder", "EncodedVideoChunk", "VideoEncoder"])
		vi.stubGlobal(name, function Ctor() {});
});

let root: Root | null = null;
afterEach(() => {
	act(() => root?.unmount());
	root = null;
	vi.clearAllMocks();
	vi.unstubAllGlobals();
});

function renderHook() {
	const out: { hook?: ReturnType<typeof useCameraVideo> } = {};
	const makeProcessor = vi.fn();
	function Probe() {
		out.hook = useCameraVideo(makeProcessor);
		return null;
	}
	root = createRoot(document.createElement("div"));
	act(() => root?.render(<Probe />));
	return { hook: out.hook as ReturnType<typeof useCameraVideo>, makeProcessor };
}

const chat = {} as MoqtChatClient;

function started() {
	const r = renderHook();
	r.hook.start(chat);
	const session = r.hook.session.current;
	if (!session) throw new Error("no session");
	return { ...r, session };
}

describe("useCameraVideo", () => {
	it("a dropped connection turns the source off at once; other states do not", () => {
		const { session } = started();
		session.onStatus("connecting");
		session.onStatus("connected");
		expect(source().leave).not.toHaveBeenCalled();
		session.onStatus("disconnected");
		expect(source().leave).toHaveBeenCalledTimes(1);
	});

	it("the api is a no-op before start", () => {
		const { hook } = renderHook();
		expect(() => {
			hook.api.toggleVideoSource("camera");
			hook.api.pickVideoFile(new File([], "a.mp4"));
			hook.api.setVideoBackground("blur");
		}).not.toThrow();
	});

	it("start resets the video view and builds a camera-track client", () => {
		useMoqtChatStore
			.getState()
			.setVideo({ source: "camera", background: "blur", error: "x" });
		const { makeProcessor } = started();
		expect(useMoqtChatStore.getState().video).toEqual({
			source: "off",
			background: "none",
			error: null,
		});
		expect(client().chat).toBe(chat);
		expect(client().kind).toBe(CAMERA_TRACK);
		expect(sourceDeps().makeProcessor).toBe(makeProcessor);
		expect(sourceDeps().defaultFileUrl).toBe("/videos/sample.mp4");
	});

	it("the api drives the session's source", () => {
		const { hook } = started();
		vi.stubGlobal("URL", { ...URL, createObjectURL: () => "blob:f" });
		hook.api.toggleVideoSource("file");
		hook.api.pickVideoFile(new File([], "a.mp4"));
		hook.api.setVideoBackground("image");
		vi.unstubAllGlobals();
		expect(source().toggle).toHaveBeenCalledWith("file");
		expect(source().pickFile).toHaveBeenCalledWith("blob:f");
		expect(source().setBackground).toHaveBeenCalledWith("image");
	});

	it("registered canvases are the ones tiles and the preview draw into", () => {
		const { hook } = started();
		const el = document.createElement("canvas");
		hook.api.registerCameraCanvas("own", el);
		sourceDeps().drawPreview("f1");
		const canvases = vi.mocked(drawFrameInto).mock.calls[0][0];
		expect(vi.mocked(drawFrameInto)).toHaveBeenCalledWith(
			canvases,
			"own",
			"f1",
		);
		expect(canvases.get("own")).toBe(el);
		receiverDeps().draw("peer", "f2");
		expect(vi.mocked(drawFrameInto)).toHaveBeenLastCalledWith(
			canvases,
			"peer",
			"f2",
		);
		hook.api.registerCameraCanvas("own", null);
		expect(canvases.has("own")).toBe(false);
	});

	it("the receiver's tiles land in the store and errors only in the console", () => {
		started();
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		useMoqtChatStore.getState().clearCameraTiles();
		receiverDeps().addTile("peer");
		expect(useMoqtChatStore.getState().cameraTiles).toEqual(["peer"]);
		receiverDeps().removeTile("peer");
		expect(useMoqtChatStore.getState().cameraTiles).toEqual([]);
		receiverDeps().onError("bad");
		expect(warn).toHaveBeenCalledWith("bad");
		expect(typeof receiverDeps().now()).toBe("number");
		warn.mockRestore();
	});

	it("the client's callbacks reach the receiver and the source", () => {
		started();
		const cb = client().callbacks as unknown as Fns;
		cb.onScreenChunk("peer", "chunk");
		expect(rec.receiver.onChunk).toHaveBeenCalledWith("peer", "chunk");
		cb.onStreamReset();
		expect(source().requestKeyframe).toHaveBeenCalledTimes(1);
	});

	it("the session forwards streams, subscriptions, forgets, ticks and leave", async () => {
		const { session } = started();
		session.handleIncomingStream("h" as never, "c" as never, "r" as never);
		expect(client().handleIncomingStream).toHaveBeenCalledWith("h", "c", "r");
		await session.subscribe("peer");
		expect(client().subscribeToScreenTrack).toHaveBeenCalledWith("peer");
		session.forget("peer");
		expect(rec.receiver.forget).toHaveBeenCalledWith("peer");
		expect(client().forgetParticipant).toHaveBeenCalledWith("peer");
		session.tick(5);
		expect(rec.receiver.tick).toHaveBeenCalledWith(5);
		session.leave();
		expect(source().leave).toHaveBeenCalledTimes(1);
	});

	it("the source's camera, file and publish deps go to the browser and the client", async () => {
		started();
		const getUserMedia = vi.fn();
		vi.stubGlobal("navigator", { mediaDevices: { getUserMedia } });
		sourceDeps().getUserMedia({ video: true, audio: false });
		vi.unstubAllGlobals();
		expect(getUserMedia).toHaveBeenCalledWith({ video: true, audio: false });

		const revoke = vi
			.spyOn(URL, "revokeObjectURL")
			.mockImplementation(() => {});
		sourceDeps().playFile("blob:x");
		const [video, url, unload] = vi.mocked(playLoopedVideo).mock.calls[0];
		expect((video as unknown as HTMLElement).tagName).toBe("VIDEO");
		expect(url).toBe("blob:x");
		unload("blob:x");
		expect(revoke).toHaveBeenCalledWith("blob:x");
		revoke.mockRestore();

		await sourceDeps().publish();
		expect(client().publishScreenTrack).toHaveBeenCalledTimes(1);
		sourceDeps().unpublish();
		expect(client().close).toHaveBeenCalledTimes(1);
		sourceDeps().onChange({ source: "file", background: "none", error: null });
		expect(useMoqtChatStore.getState().video.source).toBe("file");
	});

	it("the pipeline encodes controller-pushed frames onto the camera client", async () => {
		started();
		const onError = vi.fn();
		await sourceDeps().startPipeline(onError);
		const opts = vi.mocked(startScreenSharePipeline).mock.calls[0][0];
		expect(opts.contentHint).toBe("motion");
		expect(opts.onEncodeError).toBe(onError);
		expect((await opts.getDisplayMedia({} as never)).getVideoTracks()).toEqual(
			[],
		);
		opts.sendVideoChunk("chunk" as never);
		expect(client().sendVideoChunk).toHaveBeenCalledWith("chunk");
	});
});
