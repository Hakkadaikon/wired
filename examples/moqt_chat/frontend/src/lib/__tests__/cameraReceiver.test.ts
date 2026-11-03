import { afterEach, describe, expect, it, vi } from "vitest";
import { createCameraReceiver } from "../cameraReceiver";
import type { ScreenChunk } from "../moqtScreenWire";
import { SCREEN_STALL_MS } from "../stallDetector";

// A decoder that outputs one frame per decode() call, asynchronously like
// WebCodecs, sized like the frame the next decode() is told to produce.
type Decoded = { close: ReturnType<typeof vi.fn>; [k: string]: unknown };
const decoded: Decoded[] = [];
const decoders: { close: ReturnType<typeof vi.fn> }[] = [];
// Per-test replacements for the fake decoder's methods.
let override: (init: { error: (e: unknown) => void }) => object = () => ({});
let nextFrame: Record<string, number> = { codedWidth: 480, codedHeight: 270 };
const FakeDecoder = vi.fn(function (
	this: unknown,
	init: { output: (f: unknown) => void; error: (e: unknown) => void },
) {
	const d = {
		configure: vi.fn(),
		close: vi.fn(),
		decode: vi.fn(() => {
			const f = { ...nextFrame, close: vi.fn() };
			decoded.push(f);
			queueMicrotask(() => init.output(f));
		}),
		...override(init),
	};
	decoders.push(d);
	return d;
});
const settle = () => new Promise((r) => setTimeout(r, 0));
const FakeChunk = vi.fn(function (this: unknown, init: unknown) {
	return init;
});

const key = (seq: number): ScreenChunk => ({
	seq,
	idx: 0,
	count: 1,
	keyframe: true,
	timestampUs: 0,
	data: new Uint8Array([1, 2, 3]),
	width: 480,
	height: 270,
	codec: "vp8",
});

function setup() {
	const deps = {
		VideoDecoderCtor: FakeDecoder as never,
		EncodedVideoChunkCtor: FakeChunk as never,
		draw: vi.fn(),
		addTile: vi.fn(),
		removeTile: vi.fn(),
		onError: vi.fn(),
		now: vi.fn(() => 0),
	};
	return { deps, rx: createCameraReceiver(deps) };
}

afterEach(() => {
	decoded.length = 0;
	decoders.length = 0;
	nextFrame = { codedWidth: 480, codedHeight: 270 };
	override = () => ({});
	delete (globalThis as { __wiredCameraTap?: unknown }).__wiredCameraTap;
});

describe("cameraReceiver", () => {
	it("a decoded frame shows the tile, draws it, taps it and is closed", async () => {
		const tap: unknown[] = [];
		(globalThis as { __wiredCameraTap?: unknown[] }).__wiredCameraTap = tap;
		const { deps, rx } = setup();
		rx.onChunk("user1", key(0));
		await settle();
		expect(deps.addTile).toHaveBeenCalledWith("user1");
		expect(deps.draw).toHaveBeenCalledWith("user1", decoded[0]);
		expect(decoded[0].close).toHaveBeenCalled();
		expect(tap).toEqual([
			{ senderId: "user1", width: 480, height: 270, t: expect.any(Number) },
		]);
	});

	it("taps the visible size, not the padded coded size", async () => {
		const tap: unknown[] = [];
		(globalThis as { __wiredCameraTap?: unknown[] }).__wiredCameraTap = tap;
		nextFrame = {
			codedWidth: 480,
			codedHeight: 290,
			displayWidth: 480,
			displayHeight: 270,
		};
		const { rx } = setup();
		rx.onChunk("user1", key(0));
		await settle();
		expect(tap).toEqual([
			{ senderId: "user1", width: 480, height: 270, t: expect.any(Number) },
		]);
	});

	it("works without a tap installed", async () => {
		const { deps, rx } = setup();
		rx.onChunk("user1", key(0));
		await settle();
		expect(deps.draw).toHaveBeenCalled();
	});

	it("a sender whose frames stall loses its tile", async () => {
		const { deps, rx } = setup();
		rx.onChunk("user1", key(0));
		await settle();
		rx.tick(SCREEN_STALL_MS - 1);
		expect(deps.removeTile).not.toHaveBeenCalled();
		rx.tick(SCREEN_STALL_MS);
		expect(deps.removeTile).toHaveBeenCalledExactlyOnceWith("user1");
		rx.tick(SCREEN_STALL_MS * 2);
		expect(deps.removeTile).toHaveBeenCalledTimes(1);
	});

	it("forget closes the decoder, removes the tile, and the next keyframe brings it back", async () => {
		const { deps, rx } = setup();
		rx.onChunk("user1", key(0));
		await settle();
		rx.forget("user1");
		expect(decoders[0].close).toHaveBeenCalled();
		expect(deps.removeTile).toHaveBeenCalledWith("user1");
		rx.onChunk("user1", key(1));
		await settle();
		expect(deps.addTile).toHaveBeenCalledTimes(2);
	});

	it("a malformed chunk is ignored without throwing", async () => {
		const { deps, rx } = setup();
		expect(() =>
			rx.onChunk("user1", { ...key(0), idx: 5 } as ScreenChunk),
		).not.toThrow();
		await settle();
		expect(deps.draw).not.toHaveBeenCalled();
		expect(deps.onError).not.toHaveBeenCalled();
	});

	const DECODE_FAILED = "a peer's camera could not be decoded";

	it("a decoder that rejects its configuration is reported, not thrown", () => {
		override = () => ({
			configure: () => {
				throw new Error("unsupported codec");
			},
		});
		const { deps, rx } = setup();
		expect(() => rx.onChunk("user1", key(0))).not.toThrow();
		expect(deps.onError).toHaveBeenCalledExactlyOnceWith(DECODE_FAILED);
	});

	it("a decode that throws is reported", () => {
		override = () => ({
			decode: () => {
				throw new Error("bad chunk");
			},
		});
		const { deps, rx } = setup();
		expect(() => rx.onChunk("user1", key(0))).not.toThrow();
		expect(deps.onError).toHaveBeenCalledExactlyOnceWith(DECODE_FAILED);
	});

	it("the decoder's error callback is reported", async () => {
		override = (init) => ({
			decode: () => queueMicrotask(() => init.error(new Error("corrupt"))),
		});
		const { deps, rx } = setup();
		rx.onChunk("user1", key(0));
		await settle();
		expect(deps.onError).toHaveBeenCalledExactlyOnceWith(DECODE_FAILED);
		expect(deps.draw).not.toHaveBeenCalled();
	});

	it("a draw that throws in the decoder's output is caught there and reported", async () => {
		const { deps, rx } = setup();
		deps.draw.mockImplementation(() => {
			throw new Error("canvas");
		});
		rx.onChunk("user1", key(0));
		await settle();
		expect(deps.onError).toHaveBeenCalled();
		expect(decoded[0].close).toHaveBeenCalled();
	});

	it("two senders interleaved get separate tiles; forgetting one leaves the other", async () => {
		const { deps, rx } = setup();
		const two = (seq: number): ScreenChunk => ({ ...key(seq), count: 2 });
		const tail = (seq: number): ScreenChunk => ({
			...two(seq),
			idx: 1,
			keyframe: true,
		});
		rx.onChunk("user1", two(0));
		rx.onChunk("user2", two(0));
		rx.onChunk("user1", tail(0));
		rx.onChunk("user2", tail(0));
		await settle();
		expect(deps.addTile.mock.calls).toEqual([["user1"], ["user2"]]);
		expect(decoders).toHaveLength(2);
		expect(deps.draw.mock.calls.map((c) => c[0])).toEqual(["user1", "user2"]);
		rx.forget("user1");
		expect(deps.removeTile).toHaveBeenCalledExactlyOnceWith("user1");
		expect(decoders[1].close).not.toHaveBeenCalled();
		rx.onChunk("user2", key(1));
		await settle();
		expect(deps.draw).toHaveBeenLastCalledWith("user2", decoded[2]);
	});

	it("a stall retires only the sender that stopped", async () => {
		const { deps, rx } = setup();
		rx.onChunk("user1", key(0));
		await settle();
		deps.now.mockReturnValue(SCREEN_STALL_MS - 1);
		rx.onChunk("user2", key(0));
		await settle();
		rx.tick(SCREEN_STALL_MS);
		expect(deps.removeTile).toHaveBeenCalledExactlyOnceWith("user1");
	});
});
