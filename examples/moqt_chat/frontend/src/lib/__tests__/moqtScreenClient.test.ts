import { afterEach, describe, expect, it, vi } from "vitest";
import { CANDIDATE_PARTICIPANT_IDS, type MoqtChatClient } from "../moqtClient";
import {
	CAMERA_ALIAS_OFFSET,
	CAMERA_TRACK,
	isCameraTrackAlias,
	MoqtScreenClient,
	ownCameraTrackAlias,
	ownScreenTrackAlias,
	SCREEN_ALIAS_OFFSET,
	SCREEN_WRITE_TIMEOUT_MS,
} from "../moqtScreenClient";
import {
	decodeScreenObjectMessage,
	encodeScreenObjectMessage,
} from "../moqtScreenWire";
import {
	concatBytes,
	decodeSubgroupHeader,
	decodeSubgroupObject,
	encodeVarint,
	hexToBytes,
	MoqtMalformedTrackError,
} from "../moqtWire";

describe("ownScreenTrackAlias", () => {
	it("SCREEN_ALIAS_OFFSET is CANDIDATE_PARTICIPANT_IDS.length * 2 + 2 (10 for the current 4-id pool)", () => {
		expect(SCREEN_ALIAS_OFFSET).toBe(
			BigInt(CANDIDATE_PARTICIPANT_IDS.length * 2 + 2),
		);
		expect(SCREEN_ALIAS_OFFSET).toBe(10n);
	});

	it("is distinct per participant (no two screen aliases collide)", () => {
		const aliases = CANDIDATE_PARTICIPANT_IDS.map(ownScreenTrackAlias);
		expect(new Set(aliases).size).toBe(aliases.length);
	});

	it("covers exactly [offset, offset+N) for id=0..N-1 (boundary check)", () => {
		const offset = SCREEN_ALIAS_OFFSET;
		const aliases = CANDIDATE_PARTICIPANT_IDS.map(ownScreenTrackAlias).sort(
			(a, b) => (a < b ? -1 : a > b ? 1 : 0),
		);
		expect(aliases[0]).toBe(offset);
		expect(aliases[aliases.length - 1]).toBe(
			offset + BigInt(CANDIDATE_PARTICIPANT_IDS.length) - 1n,
		);
	});
});

// Minimal fake, same shape as moqtVoiceClient.test.ts's fakeWebTransport:
// only createUnidirectionalStream is exercised by sendVideoChunk.
function fakeWebTransport() {
	const writes: Uint8Array[] = [];
	let closed = false;
	const wt = {
		// While set, write() never settles -- a flow-control window that
		// never opens, from the writer's point of view.
		hang: false,
		writer: {
			write: vi.fn((chunk: Uint8Array) => {
				if (wt.hang) return new Promise<void>(() => {});
				writes.push(chunk);
				return Promise.resolve();
			}),
			close: vi.fn(async () => {
				closed = true;
			}),
			abort: vi.fn(async () => {}),
		},
		createUnidirectionalStream: vi.fn(async () => ({
			getWriter: () => wt.writer,
		})),
		webTransport: undefined as unknown as WebTransport,
		writes,
		get closed() {
			return closed;
		},
	};
	wt.webTransport = {
		createUnidirectionalStream: wt.createUnidirectionalStream,
	} as unknown as WebTransport;
	return wt;
}

function fakeChatClient(
	wt: ReturnType<typeof fakeWebTransport>,
): MoqtChatClient {
	return {
		localId: "user1",
		webTransport: wt.webTransport,
		publishTrack: vi.fn(async () => true),
		subscribeTrack: vi.fn(async () => true),
		publishNamespace: vi.fn(async () => ({ cancel: vi.fn() })),
		dataStreamEnded: vi.fn(),
		dataStreamFailed: vi.fn(),
	} as unknown as MoqtChatClient;
}

describe("MoqtScreenClient.sendVideoChunk", () => {
	it("opens exactly one uni stream on the first call, and reuses its writer after", async () => {
		const wt = fakeWebTransport();
		const client = new MoqtScreenClient(fakeChatClient(wt), {
			onScreenChunk: vi.fn(),
		});
		await client.publishScreenTrack();

		await client.sendVideoChunk({
			seq: 0,
			idx: 0,
			count: 1,
			keyframe: true,
			timestampUs: 0,
			data: new Uint8Array([1, 2, 3]),
		});
		await client.sendVideoChunk({
			seq: 1,
			idx: 0,
			count: 1,
			keyframe: false,
			timestampUs: 1,
			data: new Uint8Array([4, 5, 6]),
		});

		expect(wt.createUnidirectionalStream).toHaveBeenCalledTimes(1);
		expect(wt.writer.write).toHaveBeenCalledTimes(2);
	});

	it("close() FINs the writer", async () => {
		const wt = fakeWebTransport();
		const client = new MoqtScreenClient(fakeChatClient(wt), {
			onScreenChunk: vi.fn(),
		});
		await client.publishScreenTrack();
		await client.sendVideoChunk({
			seq: 0,
			idx: 0,
			count: 1,
			keyframe: true,
			timestampUs: 0,
			data: new Uint8Array([1]),
		});

		client.close();
		await Promise.resolve();

		expect(wt.writer.close).toHaveBeenCalledTimes(1);
	});

	it("close() before any chunk was sent is a no-op (no writer to close)", () => {
		const wt = fakeWebTransport();
		const client = new MoqtScreenClient(fakeChatClient(wt), {
			onScreenChunk: vi.fn(),
		});
		expect(() => client.close()).not.toThrow();
		expect(wt.writer.close).not.toHaveBeenCalled();
	});

	it("round-trips a chunk through the wire so the reassembled Object decodes back", async () => {
		const wt = fakeWebTransport();
		const client = new MoqtScreenClient(fakeChatClient(wt), {
			onScreenChunk: vi.fn(),
		});
		await client.publishScreenTrack();
		await client.sendVideoChunk({
			seq: 7,
			idx: 0,
			count: 1,
			keyframe: true,
			timestampUs: 123,
			width: 1920,
			height: 1080,
			codec: "vp8",
			data: new Uint8Array([9, 8, 7]),
		});

		const wire = concatBytes(wt.writes);
		const { len: headerLen } = decodeSubgroupHeader(wire);
		const { object } = decodeSubgroupObject(wire, headerLen, false, 0n, true);
		const { chunk } = decodeScreenObjectMessage(object.payload);
		expect(chunk.seq).toBe(7);
		expect(chunk.data).toEqual(new Uint8Array([9, 8, 7]));
	});
});

const chunkAt = (seq: number) => ({
	seq,
	idx: 0,
	count: 1,
	keyframe: false,
	timestampUs: 0,
	data: new Uint8Array([seq]),
});

describe("MoqtScreenClient.sendVideoChunk write timeout", () => {
	afterEach(() => vi.useRealTimers());

	it("aborts a write that hangs past the timeout, resets, and reopens on the next chunk", async () => {
		vi.useFakeTimers();
		const wt = fakeWebTransport();
		const onStreamReset = vi.fn();
		const client = new MoqtScreenClient(fakeChatClient(wt), {
			onScreenChunk: vi.fn(),
			onStreamReset,
		});
		await client.publishScreenTrack();
		await client.sendVideoChunk(chunkAt(0));

		wt.hang = true;
		// Handler attached up front: the rejection lands mid-advance, before
		// an `await expect(...).rejects` could observe it.
		const rejected = client.sendVideoChunk(chunkAt(1)).then(
			() => false,
			() => true,
		);
		await vi.advanceTimersByTimeAsync(SCREEN_WRITE_TIMEOUT_MS - 1);
		expect(wt.writer.abort).not.toHaveBeenCalled();
		await vi.advanceTimersByTimeAsync(1);
		expect(await rejected).toBe(true);
		expect(wt.writer.abort).toHaveBeenCalledTimes(1);
		expect(onStreamReset).toHaveBeenCalledTimes(1);

		wt.hang = false;
		await client.sendVideoChunk(chunkAt(2));
		expect(wt.createUnidirectionalStream).toHaveBeenCalledTimes(2);
		// The reopened stream starts over with a SUBGROUP_HEADER, not a bare Object.
		const last = wt.writes[wt.writes.length - 1];
		expect(decodeSubgroupHeader(last).header.trackAlias).toBe(
			ownScreenTrackAlias("user1"),
		);
	});

	it("times out a createUnidirectionalStream that never resolves, without a writer to abort", async () => {
		vi.useFakeTimers();
		const wt = fakeWebTransport();
		wt.createUnidirectionalStream.mockImplementation(
			() => new Promise(() => {}),
		);
		const onStreamReset = vi.fn();
		const client = new MoqtScreenClient(fakeChatClient(wt), {
			onScreenChunk: vi.fn(),
			onStreamReset,
		});
		await client.publishScreenTrack();
		const rejected = client.sendVideoChunk(chunkAt(0)).then(
			() => false,
			() => true,
		);
		await vi.advanceTimersByTimeAsync(SCREEN_WRITE_TIMEOUT_MS);
		expect(await rejected).toBe(true);
		expect(wt.writer.abort).not.toHaveBeenCalled();
		expect(onStreamReset).toHaveBeenCalledTimes(1);
	});
});

describe("MoqtScreenClient.handleIncomingStream", () => {
	it("routes a second stream from the same sender to the same onScreenChunk", () => {
		const wt = fakeWebTransport();
		const onScreenChunk = vi.fn();
		const client = new MoqtScreenClient(fakeChatClient(wt), { onScreenChunk });
		const header = {
			trackAlias: ownScreenTrackAlias("user2"),
			groupId: 0n,
			flags: { properties: false },
		};
		const object = (seq: number) => {
			const body = encodeScreenObjectMessage(chunkAt(seq));
			return concatBytes([
				encodeVarint(0n),
				encodeVarint(BigInt(body.length)),
				body,
			]);
		};
		const doneReader = {
			read: vi.fn(async () => ({ value: undefined, done: true })),
			cancel: vi.fn(),
		};
		client.handleIncomingStream(
			header as never,
			object(0),
			doneReader as never,
		);
		client.handleIncomingStream(
			header as never,
			object(1),
			doneReader as never,
		);
		expect(onScreenChunk.mock.calls.map((c) => [c[0], c[1].seq])).toEqual([
			["user2", 0],
			["user2", 1],
		]);
	});

	// user2's screen stream whose SUBGROUP_HEADER has the PROPERTIES bit:
	// one Object (delta 0) with the given Properties (hex, Length first),
	// read to FIN.
	async function receive(props: string, cut = 0, more = false) {
		const wt = fakeWebTransport();
		const chat = fakeChatClient(wt);
		const onScreenChunk = vi.fn();
		const client = new MoqtScreenClient(chat, { onScreenChunk });
		const body = encodeScreenObjectMessage(chunkAt(3));
		const object = concatBytes([
			hexToBytes(`00${props}`),
			encodeVarint(BigInt(body.length)),
			body,
		]);
		const first = object.slice(0, cut || undefined);
		const reads = more
			? [{ value: object.slice(first.length), done: false }]
			: [];
		client.handleIncomingStream(
			{
				trackAlias: ownScreenTrackAlias("user2"),
				groupId: 0n,
				flags: { properties: true },
			} as never,
			first,
			{
				read: async () => reads.shift() ?? { done: true },
				cancel: vi.fn(),
			} as never,
		);
		await new Promise((r) => setTimeout(r, 0));
		return { wt, chat, onScreenChunk, object: first };
	}

	it("decodes past the Object Properties the header announces", async () => {
		const { onScreenChunk } = await receive("020207");
		expect(onScreenChunk.mock.calls.map((c) => c[1].seq)).toEqual([3]);
	});

	it("a Mandatory Track Property is a Malformed Track of user2/screen (3.7)", async () => {
		const { onScreenChunk, chat } = await receive("04c0400001");
		expect(onScreenChunk).not.toHaveBeenCalled();
		expect(chat.dataStreamFailed).toHaveBeenCalledWith(
			"user2/screen",
			expect.any(MoqtMalformedTrackError),
		);
	});

	it("an Object split across reads is decoded once whole", async () => {
		const { onScreenChunk, chat } = await receive("020207", 5, true);
		expect(onScreenChunk).toHaveBeenCalledTimes(1);
		expect(chat.dataStreamEnded).toHaveBeenCalledWith(
			expect.anything(),
			new Uint8Array(0),
		);
	});

	it("a FIN inside an Object hands the rest to dataStreamEnded", async () => {
		const { onScreenChunk, chat, wt, object } = await receive("020207", 5);
		expect(onScreenChunk).not.toHaveBeenCalled();
		expect(chat.dataStreamEnded).toHaveBeenCalledWith(wt.webTransport, object);
	});

	it("cancels the reader for a track alias outside the screen range", () => {
		const wt = fakeWebTransport();
		const client = new MoqtScreenClient(fakeChatClient(wt), {
			onScreenChunk: vi.fn(),
		});
		const cancel = vi.fn(async () => {});
		const reader = {
			cancel,
			read: vi.fn(),
		} as unknown as ReadableStreamDefaultReader<Uint8Array>;
		client.handleIncomingStream(
			{ trackAlias: 0n, groupId: 0n, flags: { properties: false } } as never,
			new Uint8Array(),
			reader,
		);
		expect(cancel).toHaveBeenCalledTimes(1);
	});
});

describe("MoqtScreenClient Groups and discovery", () => {
	it("each keyframe starts a new Group on a fresh stream; the old one is FINed", async () => {
		const wt = fakeWebTransport();
		const client = new MoqtScreenClient(fakeChatClient(wt), {
			onScreenChunk: vi.fn(),
		});
		await client.publishScreenTrack();

		await client.sendVideoChunk({ ...chunkAt(0), keyframe: true });
		await client.sendVideoChunk(chunkAt(1));
		await client.sendVideoChunk({ ...chunkAt(2), keyframe: true });

		expect(wt.createUnidirectionalStream).toHaveBeenCalledTimes(2);
		expect(wt.writer.close).toHaveBeenCalledTimes(1);
		const groups = wt.writes
			.filter((w) => w[0] === 0x70)
			.map((w) => decodeSubgroupHeader(w).header.groupId);
		expect(groups).toEqual([0n, 1n]);
	});

	it("a keyframe's later chunks stay in the Group its first chunk opened", async () => {
		const wt = fakeWebTransport();
		const client = new MoqtScreenClient(fakeChatClient(wt), {
			onScreenChunk: vi.fn(),
		});
		await client.publishScreenTrack();

		await client.sendVideoChunk({ ...chunkAt(0), keyframe: true, count: 2 });
		await client.sendVideoChunk({
			...chunkAt(0),
			keyframe: true,
			count: 2,
			idx: 1,
		});

		expect(wt.createUnidirectionalStream).toHaveBeenCalledTimes(1);
	});

	it("publishScreenTrack PUBLISHes once per session but announces <id>/screen on every share; close() withdraws it", async () => {
		const wt = fakeWebTransport();
		const chat = fakeChatClient(wt);
		const cancel = vi.fn();
		(chat as unknown as { publishNamespace: unknown }).publishNamespace = vi.fn(
			async () => ({ cancel }),
		);
		const client = new MoqtScreenClient(chat, { onScreenChunk: vi.fn() });

		await client.publishScreenTrack();
		client.close();
		await client.publishScreenTrack();

		expect(chat.publishTrack).toHaveBeenCalledTimes(1);
		expect(
			(chat as unknown as { publishNamespace: ReturnType<typeof vi.fn> })
				.publishNamespace.mock.calls,
		).toEqual([[["user1", "screen"]], [["user1", "screen"]]]);
		expect(cancel).toHaveBeenCalledTimes(1);
	});

	it("a re-share announced while already subscribed holds nothing back (no fetch will end it)", async () => {
		const wt = fakeWebTransport();
		const chat = fakeChatClient(wt);
		(chat.subscribeTrack as ReturnType<typeof vi.fn>).mockResolvedValue(false); // label already subscribed
		const onScreenChunk = vi.fn();
		const client = new MoqtScreenClient(chat, { onScreenChunk });

		await client.subscribeToScreenTrack("user2");
		const body = encodeScreenObjectMessage({ ...chunkAt(0), keyframe: true });
		const live = concatBytes([
			encodeVarint(0n),
			encodeVarint(BigInt(body.length)),
			body,
		]);
		const doneReader = {
			read: vi.fn(async () => ({ value: undefined, done: true })),
			cancel: vi.fn(),
		};
		const header = {
			trackAlias: ownScreenTrackAlias("user2"),
			groupId: 0n,
			flags: { properties: false },
		};
		client.handleIncomingStream(header as never, live, doneReader as never);
		await Promise.resolve();

		expect(onScreenChunk).toHaveBeenCalledTimes(1);
	});

	it("subscribe joins from the current keyframe Group: fetched chunks first, live ones held until the fetch ends", async () => {
		const wt = fakeWebTransport();
		const chat = fakeChatClient(wt);
		const onScreenChunk = vi.fn();
		const client = new MoqtScreenClient(chat, { onScreenChunk });

		await client.subscribeToScreenTrack("user2");
		const [, label, history] = (chat.subscribeTrack as ReturnType<typeof vi.fn>)
			.mock.calls[0];
		expect(label).toBe("user2/screen");
		expect(history.joiningStart).toBe(0n);

		// A live chunk overtakes the fetch...
		const body = encodeScreenObjectMessage(chunkAt(2));
		const live = concatBytes([
			encodeVarint(0n),
			encodeVarint(BigInt(body.length)),
			body,
		]);
		const doneReader = {
			read: vi.fn(async () => ({ value: undefined, done: true })),
			cancel: vi.fn(),
		};
		const header = {
			trackAlias: ownScreenTrackAlias("user2"),
			groupId: 4n,
			flags: { properties: false },
		};
		client.handleIncomingStream(header as never, live, doneReader as never);
		await Promise.resolve();
		expect(onScreenChunk).not.toHaveBeenCalled();

		// ...but is delivered after the keyframe Group's fetched chunks.
		history.onObject({
			group: 4n,
			object: 0n,
			payload: encodeScreenObjectMessage({ ...chunkAt(0), keyframe: true }),
		});
		history.onObject({
			group: 4n,
			object: 1n,
			payload: encodeScreenObjectMessage(chunkAt(1)),
		});
		history.onDone();
		expect(onScreenChunk.mock.calls.map((c) => [c[0], c[1].seq])).toEqual([
			["user2", 0],
			["user2", 1],
			["user2", 2],
		]);
	});
});

describe("isCameraTrackAlias", () => {
	it("is true only for [18, 22)", () => {
		expect(CAMERA_ALIAS_OFFSET).toBe(18n);
		expect(isCameraTrackAlias(17n)).toBe(false);
		expect(isCameraTrackAlias(18n)).toBe(true);
		expect(isCameraTrackAlias(21n)).toBe(true);
		expect(isCameraTrackAlias(22n)).toBe(false);
	});

	it("ownCameraTrackAlias is 18 + the participant's index", () => {
		expect(CANDIDATE_PARTICIPANT_IDS.map(ownCameraTrackAlias)).toEqual([
			18n,
			19n,
			20n,
			21n,
		]);
	});
});

describe("MoqtScreenClient with CAMERA_TRACK", () => {
	const cameraClient = (
		chat: MoqtChatClient,
		onScreenChunk = vi.fn(),
	): MoqtScreenClient =>
		new MoqtScreenClient(chat, { onScreenChunk }, CAMERA_TRACK);
	const liveObject = (seq: number) => {
		const body = encodeScreenObjectMessage({ ...chunkAt(seq), keyframe: true });
		return concatBytes([
			encodeVarint(0n),
			encodeVarint(BigInt(body.length)),
			body,
		]);
	};

	it("publishes <id>/camera at the camera alias, announces [id, camera], and never a lo variant", async () => {
		const wt = fakeWebTransport();
		const chat = fakeChatClient(wt);
		(chat as unknown as { trackSwitching: boolean }).trackSwitching = true;
		const client = cameraClient(chat);

		await client.publishScreenTrack();
		await client.sendVideoChunk({ ...chunkAt(0), keyframe: true });

		expect(client.variantsEnabled).toBe(false);
		expect(
			(chat.publishTrack as ReturnType<typeof vi.fn>).mock.calls.map(
				([name, alias]) => [new TextDecoder().decode(name), alias],
			),
		).toEqual([["user1/camera", ownCameraTrackAlias("user1")]]);
		expect(chat.publishNamespace).toHaveBeenCalledWith(["user1", "camera"]);
		expect(decodeSubgroupHeader(wt.writes[0]).header.trackAlias).toBe(
			ownCameraTrackAlias("user1"),
		);
	});

	it("subscribes <peer>/camera", async () => {
		const wt = fakeWebTransport();
		const chat = fakeChatClient(wt);
		await cameraClient(chat).subscribeToScreenTrack("user2");
		const [name, label] = (chat.subscribeTrack as ReturnType<typeof vi.fn>).mock
			.calls[0];
		expect(new TextDecoder().decode(name)).toBe("user2/camera");
		expect(label).toBe("user2/camera");
	});

	it("subscribe joins <peer>/camera from the current keyframe Group, like the screen", async () => {
		const chat = fakeChatClient(fakeWebTransport());
		const onScreenChunk = vi.fn();
		const client = cameraClient(chat, onScreenChunk);

		await client.subscribeToScreenTrack("user2");
		const [, label, history] = (chat.subscribeTrack as ReturnType<typeof vi.fn>)
			.mock.calls[0];
		expect(label).toBe("user2/camera");
		expect(history.joiningStart).toBe(0n);

		const body = encodeScreenObjectMessage(chunkAt(2));
		const live = concatBytes([
			encodeVarint(0n),
			encodeVarint(BigInt(body.length)),
			body,
		]);
		client.handleIncomingStream(
			{
				trackAlias: ownCameraTrackAlias("user2"),
				groupId: 4n,
				flags: { properties: false },
			} as never,
			live,
			{
				read: vi.fn(async () => ({ value: undefined, done: true })),
				cancel: vi.fn(),
			} as never,
		);
		await Promise.resolve();
		expect(onScreenChunk).not.toHaveBeenCalled();

		history.onObject({
			group: 4n,
			object: 0n,
			payload: encodeScreenObjectMessage({ ...chunkAt(0), keyframe: true }),
		});
		history.onObject({
			group: 4n,
			object: 1n,
			payload: encodeScreenObjectMessage(chunkAt(1)),
		});
		history.onDone();
		expect(onScreenChunk.mock.calls.map((c) => [c[0], c[1].seq])).toEqual([
			["user2", 0],
			["user2", 1],
			["user2", 2],
		]);
	});

	it("routes a camera-alias stream to onScreenChunk and cancels a screen-alias one", () => {
		const onScreenChunk = vi.fn();
		const client = cameraClient(
			fakeChatClient(fakeWebTransport()),
			onScreenChunk,
		);
		const reader = () => ({
			read: vi.fn(async () => ({ value: undefined, done: true })),
			cancel: vi.fn(async () => {}),
		});
		const screen = reader();
		client.handleIncomingStream(
			{
				trackAlias: ownScreenTrackAlias("user2"),
				groupId: 0n,
				flags: { properties: false },
			} as never,
			liveObject(0),
			screen as never,
		);
		client.handleIncomingStream(
			{
				trackAlias: ownCameraTrackAlias("user2"),
				groupId: 0n,
				flags: { properties: false },
			} as never,
			liveObject(1),
			reader() as never,
		);
		expect(screen.cancel).toHaveBeenCalledTimes(1);
		expect(onScreenChunk.mock.calls.map((c) => [c[0], c[1].seq, c[2]])).toEqual(
			[["user2", 1, "hi"]],
		);
	});

	it("a screen client cancels a camera-alias stream", () => {
		const onScreenChunk = vi.fn();
		const client = new MoqtScreenClient(fakeChatClient(fakeWebTransport()), {
			onScreenChunk,
		});
		const cancel = vi.fn(async () => {});
		client.handleIncomingStream(
			{
				trackAlias: ownCameraTrackAlias("user2"),
				groupId: 0n,
				flags: { properties: false },
			} as never,
			liveObject(0),
			{ cancel, read: vi.fn() } as never,
		);
		expect(cancel).toHaveBeenCalledTimes(1);
		expect(onScreenChunk).not.toHaveBeenCalled();
	});
});
