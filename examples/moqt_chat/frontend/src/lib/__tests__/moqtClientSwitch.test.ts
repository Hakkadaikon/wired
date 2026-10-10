// MoqtChatClient's side of the track switching extension (draft-22 only,
// tasks/moqt-trackswitch-plan.md 1): it advertises SSTS_ALGORITHMS in its
// own SETUP, reads the hub's, and sends extension parameters only when the
// session is draft-22 AND the hub advertised the option.
import { afterEach, describe, expect, it, vi } from "vitest";
import { type MoqtChatCallbacks, MoqtChatClient } from "../moqtClient";
import {
	bytesToHex,
	concatBytes,
	decodeNamespace,
	decodeVarint,
	encodeControlFrame,
	encodeSubscribeOk,
	SSTS_ALGORITHM_BACKPRESSURE,
	SSTS_ALGORITHM_DEFAULT,
	SWITCH_MODE_SOFT,
	switchFromParam,
	switchingSetAssignmentParam,
	utf8ToBytes,
} from "../moqtWire";
import {
	FakeWebTransport,
	hubSetupBody,
	MSG_SUBSCRIBE,
	must,
	stubWebTransport,
} from "./fakeWebTransport";

const flush = () => vi.advanceTimersByTimeAsync(0);

async function connect(opts: {
	draft: 19 | 22;
	hubAlgs?: bigint[];
	callbacks?: Partial<MoqtChatCallbacks>;
}) {
	vi.useFakeTimers();
	const fake = new FakeWebTransport();
	stubWebTransport(() => fake);
	const client = new MoqtChatClient("user1", {
		onStatusChange: () => {},
		onMessage: () => {},
		...opts.callbacks,
	});
	const ready = client.connect("https://hub.example/", []);
	if (opts.draft === 22)
		fake.startD22Control("moqt-22", hubSetupBody(opts.hubAlgs));
	else fake.protocol = undefined;
	fake.resolveReady();
	await ready;
	await flush();
	return { fake, client };
}

const subscribeOk = () =>
	encodeControlFrame(
		0x4n,
		encodeSubscribeOk({ trackAlias: 9n, parameters: [], trackProperties: [] }),
	);

// The SUBSCRIBE's parameters as raw bytes: everything after the track name.
function subscribeParamsHex(body: Uint8Array): string {
	const rid = decodeVarint(body, 0);
	const ns = decodeNamespace(body, rid.len);
	const nameLen = decodeVarint(body, rid.len + ns.len);
	return bytesToHex(
		body.slice(rid.len + ns.len + nameLen.len + Number(nameLen.value)),
	);
}

const ssa = switchingSetAssignmentParam({
	setId: 1n,
	algorithmId: SSTS_ALGORITHM_BACKPRESSURE,
	thresholdKbps: 2000n,
	weight: 1n,
	activate: 2n,
});

describe("MoqtChatClient SSTS_ALGORITHMS negotiation", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.useRealTimers();
	});

	it("its own d22 SETUP advertises SSTS_ALGORITHMS [0xff01, 0] (backpressure preferred)", async () => {
		const { fake } = await connect({ draft: 22 });
		// Type 0x2F00, Length 6, option 0x09 Length 4 { c0ff01, 00 }.
		expect(bytesToHex(concatBytes(fake.uniStreams[0].written))).toBe(
			"af0000060904c0ff0100",
		);
	});

	it("reads the hub's SETUP: advertised ids, and the negotiated algorithm prefers backpressure", async () => {
		const onHubSetup = vi.fn();
		const { client } = await connect({
			draft: 22,
			hubAlgs: [0n, 0xff01n],
			callbacks: { onHubSetup },
		});
		expect(client.sstsAlgorithms).toEqual([0n, 0xff01n]);
		expect(client.trackSwitching).toBe(true);
		expect(client.sstsAlgorithm).toBe(SSTS_ALGORITHM_BACKPRESSURE);
		expect(onHubSetup).toHaveBeenCalledWith([0n, 0xff01n]);
	});

	it("a hub offering only the default algorithm negotiates 0", async () => {
		const { client } = await connect({ draft: 22, hubAlgs: [0n] });
		expect(client.sstsAlgorithm).toBe(SSTS_ALGORITHM_DEFAULT);
	});

	it("a hub offering no algorithm we know negotiates none, but the extension is on", async () => {
		const { client } = await connect({ draft: 22, hubAlgs: [7n] });
		expect(client.sstsAlgorithm).toBeUndefined();
		expect(client.trackSwitching).toBe(true);
	});

	it("an extension-less hub (no option): no algorithm, no track switching", async () => {
		const onHubSetup = vi.fn();
		const { client } = await connect({ draft: 22, callbacks: { onHubSetup } });
		expect(client.sstsAlgorithms).toEqual([]);
		expect(client.trackSwitching).toBe(false);
		expect(client.sstsAlgorithm).toBeUndefined();
		expect(onHubSetup).toHaveBeenCalledWith([]);
	});

	it("no protocol attribute: the hub's uni SETUP (read before the draft settles) still counts", async () => {
		vi.useFakeTimers();
		const fake = new FakeWebTransport();
		stubWebTransport(() => fake);
		const client = new MoqtChatClient("user1", {
			onStatusChange: () => {},
			onMessage: () => {},
		});
		const ready = client.connect("https://hub.example/", []);
		fake.startD22Control(null, hubSetupBody([0xff01n]));
		fake.resolveReady();
		await ready;
		await flush();
		expect(client.draft).toBe(22);
		expect(client.trackSwitching).toBe(true);
		expect(client.sstsAlgorithm).toBe(SSTS_ALGORITHM_BACKPRESSURE);
	});

	it("no protocol attribute: onHubSetup already sees the d22 session (algorithms and trackSwitching)", async () => {
		vi.useFakeTimers();
		const fake = new FakeWebTransport();
		stubWebTransport(() => fake);
		const seen: { algs: bigint[]; switching: boolean }[] = [];
		const client: MoqtChatClient = new MoqtChatClient("user1", {
			onStatusChange: () => {},
			onMessage: () => {},
			onHubSetup: (algs) =>
				seen.push({ algs, switching: client.trackSwitching }),
		});
		const ready = client.connect("https://hub.example/", []);
		fake.startD22Control(null, hubSetupBody([0xff01n]));
		fake.resolveReady();
		await ready;
		await flush();
		expect(seen).toEqual([{ algs: [0xff01n], switching: true }]);
	});

	it("F5: a d19 winner (bidi control first) is never reported as d22, whenever a stray uni SETUP lands", async () => {
		for (let ticks = 0; ticks < 10; ticks++) {
			vi.useFakeTimers();
			const fake = new FakeWebTransport(); // bidi control stream on offer
			stubWebTransport(() => fake);
			const client = new MoqtChatClient("user1", {
				onStatusChange: () => {},
				onMessage: () => {},
			});
			const ready = client.connect("https://hub.example/", []);
			fake.resolveReady();
			for (let i = 0; i < ticks; i++) await Promise.resolve();
			fake.serverControl.push(
				encodeControlFrame(0x2f00n, hubSetupBody([0xff01n])),
			);
			fake.incomingUnidirectionalStreams.pushStream(fake.serverControl);
			await ready;
			await flush();
			// d22 exactly when our own d22 control stream (uni SETUP) went out.
			const opened22 = fake.uniStreams.length === 1;
			expect({ ticks, draft: client.draft }).toEqual({
				ticks,
				draft: opened22 ? 22 : 19,
			});
			expect(client.trackSwitching).toBe(opened22);
			vi.unstubAllGlobals();
			vi.useRealTimers();
		}
	});

	it("N2: a SETUP on a stray uni stream after d19 won is not reported and changes nothing", async () => {
		// tick 1 is the ordering where the stray stream starts during the race
		// and d19 wins (see the F5 test).
		vi.useFakeTimers();
		const fake = new FakeWebTransport();
		stubWebTransport(() => fake);
		const onHubSetup = vi.fn();
		const client = new MoqtChatClient("user1", {
			onStatusChange: () => {},
			onMessage: () => {},
			onHubSetup,
		});
		const ready = client.connect("https://hub.example/", []);
		fake.resolveReady();
		await Promise.resolve();
		fake.serverControl.push(
			encodeControlFrame(0x2f00n, hubSetupBody([0xff01n])),
		);
		fake.incomingUnidirectionalStreams.pushStream(fake.serverControl);
		await ready;
		await flush();
		expect(client.draft).toBe(19);
		fake.serverControl.push(
			encodeControlFrame(0x2f00n, hubSetupBody([0xff01n])),
		); // more on that stream
		await flush();
		expect(onHubSetup).not.toHaveBeenCalled();
		expect(client.sstsAlgorithms).toEqual([]);
		expect(client.trackSwitching).toBe(false);
	});

	it("a d19 session never has track switching", async () => {
		const { client } = await connect({ draft: 19 });
		expect(client.draft).toBe(19);
		expect(client.trackSwitching).toBe(false);
		expect(client.sstsAlgorithm).toBeUndefined();
	});
});

describe("MoqtChatClient extension parameters on SUBSCRIBE", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.useRealTimers();
	});

	const history = () => ({
		joiningStart: 0n,
		onObject: () => {},
		onDone: () => {},
	});

	it("d22 + advertised: SWITCHING_SET_ASSIGNMENT goes after the fill, in ascending Type order", async () => {
		const { fake, client } = await connect({ draft: 22, hubAlgs: [0xff01n] });
		void client.subscribeTrack(
			utf8ToBytes("user2/screen"),
			"user2/screen",
			history(),
			{ params: [ssa] },
		);
		await flush();
		const [s] = fake.requestsOf(MSG_SUBSCRIBE);
		// 3 params: 0x21 Next Object, 0x23 fill Relative Start 1, 0x41 (delta 0x1e).
		expect(subscribeParamsHex(s.request.body)).toBe(
			"03" + "2105" + "020401210101" + "1e08" + "01c0ff0187d00102",
		);
	});

	it("d22 without the hub's option: extension parameters are not sent", async () => {
		const { fake, client } = await connect({ draft: 22 });
		void client.subscribeTrack(
			utf8ToBytes("user2/screen"),
			"user2/screen",
			history(),
			{ params: [ssa] },
		);
		await flush();
		expect(
			subscribeParamsHex(fake.requestsOf(MSG_SUBSCRIBE)[0].request.body),
		).toBe("022105020401210101");
	});

	it("d19: extension parameters are never sent (they would be unknown parameters there)", async () => {
		const { fake, client } = await connect({ draft: 19 });
		void client.subscribeTrack(
			utf8ToBytes("user2/screen"),
			"user2/screen",
			history(),
			{ params: [ssa] },
		);
		await flush();
		// d19 LOCATION_FILTER Largest Object (Length-prefixed), nothing else.
		expect(
			subscribeParamsHex(fake.requestsOf(MSG_SUBSCRIBE)[0].request.body),
		).toBe("01210102");
	});

	it("SWITCH_FROM names the old subscription's Request ID; forgetSubscription FINs (not resets) it", async () => {
		const { fake, client } = await connect({ draft: 22, hubAlgs: [0xff01n] });
		const first = client.subscribeTrack(
			utf8ToBytes("user2/screen-lo"),
			"user2/screen-lo",
		);
		await flush();
		const [lo] = fake.requestsOf(MSG_SUBSCRIBE);
		lo.replies.push(subscribeOk());
		await first;
		const rid = await client.subscriptionRequestId("user2/screen-lo");
		expect(rid).toBe(decodeVarint(lo.request.body, 0).value);

		const sf = switchFromParam({
			requestId: must(rid),
			mode: SWITCH_MODE_SOFT,
			publishDone: true,
		});
		const second = client.subscribeTrack(
			utf8ToBytes("user2/screen"),
			"user2/screen",
			undefined,
			{ params: [sf] },
		);
		await flush();
		const hi = fake.requestsOf(MSG_SUBSCRIBE)[1];
		expect(subscribeParamsHex(hi.request.body)).toBe(
			`012403${must(rid).toString(16).padStart(2, "0")}0180`,
		);
		hi.replies.push(subscribeOk());
		await second;
		client.forgetSubscription("user2/screen-lo");
		await flush();

		expect(client.isSubscribed("user2/screen-lo")).toBe(false);
		expect(lo.closed).toBe(true);
		expect(lo.aborted).toBe(false);
		expect(
			await client.subscriptionRequestId("user2/screen-lo"),
		).toBeUndefined();
	});

	it("a SUBSCRIBE_OK landing after its label was unsubscribed does not mark it subscribed", async () => {
		const { fake, client } = await connect({ draft: 22, hubAlgs: [0xff01n] });
		const sub = client.subscribeTrack(
			utf8ToBytes("user2/screen"),
			"user2/screen",
		);
		await flush();
		const [s] = fake.requestsOf(MSG_SUBSCRIBE);
		s.replies.push(subscribeOk()); // already on the wire...
		client.unsubscribe("user2/screen"); // ...when the caller gives the label up
		await sub;
		await flush();
		expect(client.isSubscribed("user2/screen")).toBe(false);
		expect(await client.subscriptionRequestId("user2/screen")).toBeUndefined();
		expect(s.aborted).toBe(true);
	});

	it("a stale answer does not clobber a newer SUBSCRIBE of the same label", async () => {
		const { fake, client } = await connect({ draft: 22, hubAlgs: [0xff01n] });
		const first = client.subscribeTrack(
			utf8ToBytes("user2/screen"),
			"user2/screen",
		);
		await flush();
		const [a] = fake.requestsOf(MSG_SUBSCRIBE);
		a.replies.push(subscribeOk());
		client.forgetSubscription("user2/screen"); // FIN only: the reply still reads
		const second = client.subscribeTrack(
			utf8ToBytes("user2/screen"),
			"user2/screen",
		);
		await first;
		await flush();
		expect(client.isSubscribed("user2/screen")).toBe(false); // only the newer one may set it
		const b = fake.requestsOf(MSG_SUBSCRIBE)[1];
		b.replies.push(subscribeOk());
		await second;
		expect(client.isSubscribed("user2/screen")).toBe(true);
		expect(await client.subscriptionRequestId("user2/screen")).toBe(
			decodeVarint(b.request.body, 0).value,
		);
	});

	it("unsubscribe cancels (resets) one label's request and lets it be subscribed again", async () => {
		const { fake, client } = await connect({ draft: 22, hubAlgs: [0xff01n] });
		const sub = client.subscribeTrack(
			utf8ToBytes("user2/screen"),
			"user2/screen",
		);
		await flush();
		const [s] = fake.requestsOf(MSG_SUBSCRIBE);
		s.replies.push(subscribeOk());
		await sub;
		client.unsubscribe("user2/screen");
		await flush();
		expect(s.cancelled).toBe(true);
		expect(client.isSubscribed("user2/screen")).toBe(false);

		void client.subscribeTrack(utf8ToBytes("user2/screen"), "user2/screen");
		await flush();
		expect(fake.requestsOf(MSG_SUBSCRIBE)).toHaveLength(2);
	});
});
