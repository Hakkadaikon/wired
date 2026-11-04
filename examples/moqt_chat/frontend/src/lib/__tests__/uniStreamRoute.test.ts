import { describe, expect, it, vi } from "vitest";
import {
	ownCameraTrackAlias,
	ownScreenTrackAlias,
	screenVariantAlias,
} from "../moqtScreenClient";
import type { SubgroupHeader } from "../moqtWire";
import { routeUniStream } from "../uniStreamRoute";

const sink = () => ({ handleIncomingStream: vi.fn() });
const header = (trackAlias: bigint) => ({ trackAlias }) as SubgroupHeader;
const reader = {} as ReadableStreamDefaultReader<Uint8Array>;

describe("routeUniStream", () => {
	it("with camera and screen both active, each alias reaches its own receiver", () => {
		const to = { camera: sink(), screen: sink(), voice: sink() };
		const streams = [
			ownCameraTrackAlias("user2"),
			ownScreenTrackAlias("user2"),
			screenVariantAlias("user3", "lo"),
			ownCameraTrackAlias("user3"),
			3n, // an audio alias
		].map(header);
		for (const h of streams) routeUniStream(h, new Uint8Array(), reader, to);
		const got = (s: ReturnType<typeof sink>) =>
			s.handleIncomingStream.mock.calls.map((c) => c[0]);
		expect(got(to.camera)).toEqual([streams[0], streams[3]]);
		expect(got(to.screen)).toEqual([streams[1], streams[2]]);
		expect(got(to.voice)).toEqual([streams[4]]);
	});

	it("cancels a video stream nobody receives instead of leaving it open", () => {
		const cancel = vi.fn(() => Promise.resolve());
		const r = { cancel } as unknown as ReadableStreamDefaultReader<Uint8Array>;
		routeUniStream(header(ownCameraTrackAlias("user2")), new Uint8Array(), r, {
			camera: null,
			screen: sink(),
			voice: sink(),
		});
		expect(cancel).toHaveBeenCalled();
	});

	it("a cancel that rejects (stream already gone) is swallowed", () => {
		// the rejection gets a handler, so it is never an unhandled one
		const pending = { catch: vi.fn() };
		const r = {
			cancel: () => pending,
		} as unknown as ReadableStreamDefaultReader<Uint8Array>;
		routeUniStream(header(3n), new Uint8Array(), r, {
			camera: sink(),
			screen: sink(),
			voice: null,
		});
		expect(pending.catch).toHaveBeenCalledOnce();
		expect(() =>
			pending.catch.mock.calls[0][0](new Error("gone")),
		).not.toThrow();
	});
});
