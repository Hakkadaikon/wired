import { afterEach, describe, expect, it, vi } from "vitest";
import { NOSTR_TRACKS } from "../moqNostr";
import {
	buildChatObjectMessage,
	type MoqtChatCallbacks,
	MoqtChatClient,
	nostrTrackAlias,
	nostrTrackOfAlias,
} from "../moqtClient";
import {
	bytesToUtf8,
	concatBytes,
	decodePublish,
	decodeSubgroupHeader,
	decodeSubscribe,
	encodeControlFrame,
	encodeRequestError,
} from "../moqtWire";
import {
	FakeWebTransport,
	MSG_PUBLISH,
	MSG_SUBSCRIBE,
	stubWebTransport,
	subscribeParamsHex,
} from "./fakeWebTransport";

const flush = () => vi.advanceTimersByTimeAsync(0);

async function connected(callbacks: Partial<MoqtChatCallbacks> = {}) {
	vi.useFakeTimers();
	const fake = new FakeWebTransport();
	stubWebTransport(() => fake);
	const client = new MoqtChatClient("user1", "room1", {
		onStatusChange: () => {},
		onMessage: () => {},
		...callbacks,
	});
	const ready = client.connect("https://hub.example/", []);
	fake.startControl();
	fake.resolveReady();
	await ready;
	await flush();
	return { fake, client };
}

afterEach(() => {
	vi.unstubAllGlobals();
	vi.useRealTimers();
});

describe("Nostr track aliases", () => {
	it("map each (participant, track) to a distinct alias above camera and back", () => {
		const seen = new Set<bigint>();
		for (const id of ["user1", "user2", "user3", "user4"])
			for (const { track } of NOSTR_TRACKS) {
				const a = nostrTrackAlias(id, track);
				expect(a).toBeGreaterThanOrEqual(22n); // camera ends at 4 * 5 + 2
				expect(nostrTrackOfAlias(a)).toEqual({ participant: id, track });
				seen.add(a);
			}
		expect(seen.size).toBe(16);
		for (const a of [0n, 21n, 38n])
			expect(nostrTrackOfAlias(a)).toBeUndefined();
	});
});

describe("MoqtChatClient Nostr tracks", () => {
	it("publishNostrTracks PUBLISHes the four tracks under their aliases", async () => {
		const { fake, client } = await connected();
		void client.publishNostrTracks();
		await flush();
		const pubs = fake
			.requestsOf(MSG_PUBLISH)
			.map((r) => decodePublish(r.request.body))
			.filter((p) => bytesToUtf8(p.trackName).includes("nostr"));
		expect(pubs.map((p) => [bytesToUtf8(p.trackName), p.trackAlias])).toEqual(
			NOSTR_TRACKS.map(({ track }) => [
				`user1/${track}`,
				nostrTrackAlias("user1", track),
			]),
		);
	});

	it("latest-only tracks ask for 1 Group (Relative Start 1), reactions 65", async () => {
		const { fake, client } = await connected();
		void client.subscribeNostrTracks("user2");
		await flush();
		const params = Object.fromEntries(
			fake
				.requestsOf(MSG_SUBSCRIBE)
				.map((r) => [
					bytesToUtf8(decodeSubscribe(r.request.body).trackName),
					subscribeParamsHex(r.request.body),
				]),
		);
		expect(params).toEqual({
			"user2/nostr-presence": "0221050201210101",
			"user2/nostr-30312": "0221050201210101",
			"user2/nostr-30313": "0221050201210101",
			"user2/nostr-react": "0221050201210141",
		});
	});

	it("sendNostrEvent puts each kind's event on its track, one Group each", async () => {
		const { fake, client } = await connected();
		await expect(
			client.sendNostrEvent('{"kind":7}', "nostr-react"),
		).rejects.toThrow(/not published/);
		await client.publishNostrTracks();
		const before = fake.uniStreams.length;
		await client.sendNostrEvent('{"kind":7}', "nostr-react");
		await client.sendNostrEvent('{"kind":7}', "nostr-react");
		await client.sendNostrEvent('{"kind":1311}');
		const headers = fake.uniStreams
			.slice(before)
			.map((u) => decodeSubgroupHeader(concatBytes(u.written)).header);
		expect(headers.map((h) => [h.trackAlias, h.groupId])).toEqual([
			[nostrTrackAlias("user1", "nostr-react"), 0n],
			[nostrTrackAlias("user1", "nostr-react"), 1n],
			[0n, 0n],
		]);
	});

	it("hands a Nostr track's Object to onNostrEvent with its participant and track", async () => {
		const got: unknown[] = [];
		const messages = vi.fn();
		const { fake } = await connected({
			onMessage: messages,
			onNostrEvent: (...args) => got.push(args),
		});
		const json = '{"kind":10312}';
		fake.incomingUnidirectionalStreams.push(
			buildChatObjectMessage({
				trackAlias: nostrTrackAlias("user2", "nostr-presence"),
				groupId: 0n,
				text: json,
			}),
		);
		await flush();
		expect(got).toEqual([[json, true, "user2", "nostr-presence"]]);
		expect(messages).not.toHaveBeenCalled();
	});

	it("a hub-refused Nostr track is not sent on; publishNostrTracks says false", async () => {
		const { fake, client } = await connected();
		fake.autoAnswer = (type) => (type === MSG_PUBLISH ? refusal() : undefined);
		expect(await client.publishNostrTracks()).toBe(false);
		await expect(
			client.sendNostrEvent('{"kind":10312}', "nostr-presence"),
		).rejects.toThrow(/not published/);
	});

	it("a refused Nostr SUBSCRIBE is sent once more while the peer stays", async () => {
		const { fake, client } = await connected();
		void client.subscribeTrack(utf8("user2"), "user2"); // the peer's chat
		void client.subscribeNostrTracks("user2");
		await flush();
		const presence = () =>
			fake
				.requestsOf(MSG_SUBSCRIBE)
				.filter((r) =>
					bytesToUtf8(decodeSubscribe(r.request.body).trackName).endsWith(
						"nostr-presence",
					),
				);
		presence()[0].replies.push(refusal());
		await flush();
		expect(presence()).toHaveLength(1);
		await vi.advanceTimersByTimeAsync(3000);
		expect(presence()).toHaveLength(2);
		presence()[1].replies.push(refusal());
		await vi.advanceTimersByTimeAsync(10_000);
		expect(presence()).toHaveLength(2); // once only
	});
});

const utf8 = (t: string) => new TextEncoder().encode(t);
// REQUEST_ERROR (0x5) UNAUTHORIZED: not INTERNAL_ERROR, so no live-only retry.
const refusal = () =>
	encodeControlFrame(
		0x5n,
		encodeRequestError({
			errorCode: 0x1n,
			retryInterval: 0n,
			errorReason: new Uint8Array(0),
		}),
	);
