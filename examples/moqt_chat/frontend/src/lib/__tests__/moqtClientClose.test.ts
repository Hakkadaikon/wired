// draft-ietf-moq-transport-23 12.2: a protocol violation the client reads
// (a control message Length over 65535, a malformed fetch item) closes the
// WebTransport session with the 16.12.1 code it names; running out of bytes
// only waits for more. Also the 3.7 refusal of a hub PUBLISH.
import { afterEach, describe, expect, it, vi } from "vitest";
import { MoqtChatClient, ownTrackAlias } from "../moqtClient";
import {
	concatBytes,
	decodeRequestError,
	decodeSubscribe,
	encodeControlFrame,
	encodePublish,
	encodeSubscribeOk,
	encodeVarint,
	hexToBytes,
	MoqtTruncatedError,
	utf8ToBytes,
} from "../moqtWire";
import {
	FakeControlReplies,
	FakeWebTransport,
	MSG_PUBLISH,
	MSG_SUBSCRIBE,
	stubWebTransport,
} from "./fakeWebTransport";

const flush = () => vi.advanceTimersByTimeAsync(0);
const hex = (s: string) => hexToBytes(s.replace(/ /g, ""));

async function connected23() {
	vi.useFakeTimers();
	const fake = new FakeWebTransport();
	stubWebTransport(() => fake);
	const client = new MoqtChatClient("user1", {
		onStatusChange: () => {},
		onMessage: () => {},
	});
	const ready = client.connect("https://hub.example/", []);
	fake.startControl();
	fake.resolveReady();
	await ready;
	await flush();
	return { fake, client };
}

const subscribeOk = (largest: { group: bigint; object: bigint }) =>
	encodeControlFrame(
		0x4n,
		encodeSubscribeOk({
			trackAlias: 9n,
			parameters: [{ type: 0x09n, value: largest }],
			trackProperties: [],
		}),
	);

const history = (joiningStart: bigint, got: string[] = [], done = vi.fn()) => ({
	joiningStart,
	onObject: (o: { group: bigint; object: bigint; payload: Uint8Array }) =>
		got.push(`${o.group}/${o.object}:${new TextDecoder().decode(o.payload)}`),
	onDone: done,
});

describe("MoqtChatClient protocol violations (draft-23 12.2)", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.useRealTimers();
	});

	const closedWith = (fake: FakeWebTransport) => ({
		calls: fake.closeCalls,
		code: fake.closeInfo?.closeCode,
	});

	it("a control message Length over 65535 on the hub's control stream closes FIELD_LENGTH_EXCEEDED (9)", async () => {
		const { fake } = await connected23();

		fake.serverControl.push(hexToBytes("07c10000")); // Length 65536
		await flush();

		expect(closedWith(fake)).toEqual({ calls: 1, code: 0x401 });
	});

	it("an over-long control message on a request stream closes the session too", async () => {
		const { fake, client } = await connected23();

		void client.subscribeTrack(utf8ToBytes("user2"), "user2");
		await flush();
		fake.requestsOf(MSG_SUBSCRIBE)[0].replies.push(hexToBytes("04c10000"));
		await flush();

		expect(closedWith(fake)).toEqual({ calls: 1, code: 0x401 });
	});

	it("a malformed fill stream item closes MALFORMED_OBJECT (11.4.1) and ends the history", async () => {
		const { fake, client } = await connected23();
		const done = vi.fn();

		const sub = client.subscribeTrack(
			utf8ToBytes("user2"),
			"user2",
			history(16n, [], done),
		);
		await flush();
		const [s] = fake.requestsOf(MSG_SUBSCRIBE);
		s.replies.push(subscribeOk({ group: 5n, object: 0n }));
		await sub;
		const rid = decodeSubscribe(s.request.body).requestId;
		// Serialization Flags 0x82: no flag set and no indicator.
		fake.incomingUnidirectionalStreams.push(
			concatBytes([hexToBytes("05"), encodeVarint(rid), hexToBytes("8082")]),
		);
		await flush();

		expect(closedWith(fake)).toEqual({ calls: 1, code: 0x201 });
		expect(done).toHaveBeenCalledOnce();
	});

	it("a fill Object split across reads is waited for, not a violation", async () => {
		const { fake, client } = await connected23();
		const got: string[] = [];

		const sub = client.subscribeTrack(
			utf8ToBytes("user2"),
			"user2",
			history(16n, got),
		);
		await flush();
		const [s] = fake.requestsOf(MSG_SUBSCRIBE);
		s.replies.push(subscribeOk({ group: 5n, object: 0n }));
		await sub;
		const rid = decodeSubscribe(s.request.body).requestId;
		const fill = new FakeControlReplies();
		fill.push(
			concatBytes([hexToBytes("05"), encodeVarint(rid), hexToBytes("1c05")]),
		);
		fake.incomingUnidirectionalStreams.pushStream(fill);
		await flush();
		fill.push(hexToBytes("0080026869"));
		fill.end();
		await flush();

		expect(got).toEqual(["5/0:hi"]);
		expect(fake.closeCalls).toBe(0);
	});

	// A SUBSCRIBE for user2's chat with history, answered with Largest
	// Object 5/0, plus the fill stream it gets (FETCH_HEADER pushed by the
	// caller): the request, the history's onObject log and onDone.
	async function filling(onObject?: (got: string[]) => void) {
		const { fake, client } = await connected23();
		const got: string[] = [];
		const done = vi.fn();
		const h = history(16n, got, done);
		const sub = client.subscribeTrack(utf8ToBytes("user2"), "user2", {
			...h,
			onObject: (o) => {
				h.onObject(o);
				onObject?.(got);
			},
		});
		await flush();
		const [s] = fake.requestsOf(MSG_SUBSCRIBE);
		s.replies.push(subscribeOk({ group: 5n, object: 0n }));
		await sub;
		const rid = decodeSubscribe(s.request.body).requestId;
		const fill = new FakeControlReplies();
		fake.incomingUnidirectionalStreams.pushStream(fill);
		return { fake, client, s, rid, fill, got, done };
	}

	it("a FIN inside a fill Object closes TRUNCATED_OBJECT (11.3) and ends the history", async () => {
		const { fake, rid, fill, done } = await filling();

		fill.push(
			concatBytes([hexToBytes("05"), encodeVarint(rid), hexToBytes("1c05")]),
		);
		fill.end();
		await flush();

		expect(closedWith(fake)).toEqual({ calls: 1, code: 0x203 });
		expect(done).toHaveBeenCalledOnce();
	});

	it("a first chunk shorter than FETCH_HEADER waits for the rest", async () => {
		const { fake, rid, fill, got } = await filling();

		fill.push(hexToBytes("05"));
		await flush();
		fill.push(concatBytes([encodeVarint(rid), hexToBytes("1c050080026869")]));
		fill.end();
		await flush();

		expect(got).toEqual(["5/0:hi"]);
		expect(fake.closeCalls).toBe(0);
	});

	it("a FIN before the FETCH_HEADER is whole ends the stream quietly", async () => {
		const { fake, fill, got } = await filling();

		fill.push(hexToBytes("05"));
		fill.end();
		await flush();

		expect(got).toEqual([]);
		expect(fake.closeCalls).toBe(0);
	});

	it("a fill Object with a Mandatory Track Property cancels the subscription, not the session (3.7, 12.1)", async () => {
		const { fake, client, s, rid, fill, got, done } = await filling();
		void client.subscribeTrack(utf8ToBytes("user3"), "user3");
		await flush();
		const other = fake.requestsOf(MSG_SUBSCRIBE)[1];

		// Flags 0x3c: G5 O0 prio 0x80, Properties {0x4000: 1}, payload "a".
		fill.push(
			concatBytes([
				hexToBytes("05"),
				encodeVarint(rid),
				hex("3c 05 00 80 04 c04000 01 01 61"),
			]),
		);
		await flush();

		expect(got).toEqual([]);
		expect(s.cancelled).toBe(true);
		expect(other.cancelled).toBe(false);
		expect(done).toHaveBeenCalledOnce();
		expect(fake.closeCalls).toBe(0);
	});

	it("a MoqtTruncatedError thrown by onObject is not taken for running out of bytes", async () => {
		const { rid, fill, got } = await filling((got) => {
			if (got.length === 1) throw new MoqtTruncatedError("app");
		});

		fill.push(
			concatBytes([
				hexToBytes("05"),
				encodeVarint(rid),
				hexToBytes("1c050080026869"),
			]),
		);
		await flush();
		fill.push(hexToBytes("010178"));
		await flush();

		expect(got).toEqual(["5/0:hi"]);
	});

	it("a FIN inside a chat Object closes TRUNCATED_OBJECT", async () => {
		const { fake } = await connected23();

		// SUBGROUP_HEADER 0x70, user2's alias, Group 0; Object 0 says 5 bytes, has 2.
		fake.incomingUnidirectionalStreams.push(
			concatBytes([
				hexToBytes("70"),
				encodeVarint(ownTrackAlias("user2")),
				hex("00 00 05 6869"),
			]),
		);
		await flush();

		expect(closedWith(fake)).toEqual({ calls: 1, code: 0x203 });
	});

	it("a chat Object with a Mandatory Track Property cancels that chat subscription (3.7)", async () => {
		const { fake, client } = await connected23();
		const onMessage = vi.fn();
		void client.subscribeTrack(utf8ToBytes("user2"), "user2");
		await flush();
		const [s] = fake.requestsOf(MSG_SUBSCRIBE);
		s.replies.push(subscribeOk({ group: 0n, object: 0n }));
		await flush();

		// 0x71: SUBGROUP_HEADER with the PROPERTIES bit.
		fake.incomingUnidirectionalStreams.push(
			concatBytes([
				hexToBytes("71"),
				encodeVarint(ownTrackAlias("user2")),
				hex("00 00 04 c04000 01 01 61"),
			]),
		);
		await flush();

		expect(s.cancelled).toBe(true);
		expect(client.isSubscribed("user2")).toBe(false);
		expect(onMessage).not.toHaveBeenCalled();
		expect(fake.closeCalls).toBe(0);
	});

	it("a hub PUBLISH with an unknown Mandatory Track Property is refused UNSUPPORTED_EXTENSION (3.7)", async () => {
		const { fake } = await connected23();
		const publish = (trackProperties: { type: bigint; num: bigint }[]) =>
			encodeControlFrame(
				MSG_PUBLISH,
				encodePublish({
					requestId: 1n,
					trackNamespace: [utf8ToBytes("wired")],
					trackName: utf8ToBytes("x"),
					trackAlias: 3n,
					parameters: [],
					trackProperties,
				}),
			);

		const mandatory = fake.pushHubRequest(
			publish([{ type: 0x4000n, num: 1n }]),
		);
		const plain = fake.pushHubRequest(publish([]));
		await flush();

		expect(decodeRequestError(mandatory.answer.body).errorCode).toBe(0x33n);
		expect(decodeRequestError(plain.answer.body).errorCode).toBe(0x3n);
	});
});
