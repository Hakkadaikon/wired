import { afterEach, describe, expect, it, vi } from "vitest";
import { createCameraReceiver } from "../cameraReceiver";
import type { ScreenChunk } from "../moqtScreenWire";
import { SCREEN_STALL_MS } from "../stallDetector";

// A decoder that outputs one 480x270 frame per decode() call.
const decoded: { close: ReturnType<typeof vi.fn> }[] = [];
const FakeDecoder = vi.fn(function (
	this: unknown,
	init: { output: (f: unknown) => void },
) {
	return {
		configure: vi.fn(),
		decode: vi.fn(() => {
			const f = { codedWidth: 480, codedHeight: 270, close: vi.fn() };
			decoded.push(f);
			init.output(f);
		}),
	};
});
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
	delete (globalThis as { __wiredCameraTap?: unknown }).__wiredCameraTap;
});

describe("cameraReceiver", () => {
	it("a decoded frame shows the tile, draws it, taps it and is closed", () => {
		const tap: unknown[] = [];
		(globalThis as { __wiredCameraTap?: unknown[] }).__wiredCameraTap = tap;
		const { deps, rx } = setup();
		rx.onChunk("user1", key(0));
		expect(deps.addTile).toHaveBeenCalledWith("user1");
		expect(deps.draw).toHaveBeenCalledWith("user1", decoded[0]);
		expect(decoded[0].close).toHaveBeenCalled();
		expect(tap).toEqual([
			{ senderId: "user1", width: 480, height: 270, t: expect.any(Number) },
		]);
	});

	it("works without a tap installed", () => {
		const { deps, rx } = setup();
		rx.onChunk("user1", key(0));
		expect(deps.draw).toHaveBeenCalled();
	});

	it("a sender whose frames stall loses its tile", () => {
		const { deps, rx } = setup();
		rx.onChunk("user1", key(0));
		rx.tick(SCREEN_STALL_MS - 1);
		expect(deps.removeTile).not.toHaveBeenCalled();
		rx.tick(SCREEN_STALL_MS);
		expect(deps.removeTile).toHaveBeenCalledExactlyOnceWith("user1");
		rx.tick(SCREEN_STALL_MS * 2);
		expect(deps.removeTile).toHaveBeenCalledTimes(1);
	});

	it("forget removes the tile and the next keyframe brings it back", () => {
		const { deps, rx } = setup();
		rx.onChunk("user1", key(0));
		rx.forget("user1");
		expect(deps.removeTile).toHaveBeenCalledWith("user1");
		rx.onChunk("user1", key(1));
		expect(deps.addTile).toHaveBeenCalledTimes(2);
	});

	it("a malformed chunk reports an error instead of throwing", () => {
		const { deps, rx } = setup();
		expect(() =>
			rx.onChunk("user1", { ...key(0), idx: 5 } as ScreenChunk),
		).not.toThrow();
		const bad = setup();
		bad.deps.draw.mockImplementation(() => {
			throw new Error("canvas");
		});
		expect(() => bad.rx.onChunk("user1", key(0))).not.toThrow();
		expect(bad.deps.onError).toHaveBeenCalled();
		expect(deps.draw).not.toHaveBeenCalled();
	});
});
