// The room session a connect uses (roomAuth.ts's roomSession): the
// WebTransport URL it names and the AUTHORIZATION TOKEN its SETUP carries;
// and the hub's close reason, read from `closed` in both the connected and
// the failed-connect path.
import { afterEach, describe, expect, it, vi } from "vitest";
import { authTokenOption } from "../moqtAuthWire";
import { MoqtChatClient } from "../moqtClient";
import {
	bytesToHex,
	encodeControlFrame,
	encodeSetup,
	encodeSstsAlgorithms,
	SETUP_OPTION_SSTS_ALGORITHMS,
	utf8ToBytes,
} from "../moqtWire";
import { FakeWebTransport, stubWebTransport } from "./fakeWebTransport";

const flush = () => vi.advanceTimersByTimeAsync(0);
const SSTS = {
	type: SETUP_OPTION_SSTS_ALGORITHMS,
	raw: encodeSstsAlgorithms([0xff01n, 0n]),
};
const setupHex = (options: ReturnType<typeof authTokenOption>[]) =>
	bytesToHex(
		encodeControlFrame(0x2f00n, encodeSetup({ setupOptions: options })),
	);

afterEach(() => {
	vi.useRealTimers();
	vi.unstubAllGlobals();
});

function start(
	session?: (url: string) => Promise<{ url: string; token?: string }>,
) {
	vi.useFakeTimers();
	const fakes: FakeWebTransport[] = [];
	const urls: string[] = [];
	stubWebTransport((url) => {
		urls.push(url);
		const f = new FakeWebTransport();
		fakes.push(f);
		return f;
	});
	const onCloseReason = vi.fn();
	const onStatusChange = vi.fn();
	const client = new MoqtChatClient(
		"user1",
		"room1",
		{ onStatusChange, onMessage: () => {}, onCloseReason },
		session,
	);
	return { client, fakes, urls, onCloseReason, onStatusChange };
}

async function connectOnce(t: ReturnType<typeof start>) {
	const done = t.client.connect("https://hub.example/", []);
	await flush();
	const fake = t.fakes[t.fakes.length - 1];
	fake.startControl();
	fake.resolveReady();
	await done;
	await flush();
	return fake;
}

describe("MoqtChatClient room session", () => {
	it("connects to the session's URL; SETUP carries its token ahead of SSTS", async () => {
		const t = start(async (url) => ({ url: `${url}?room=r`, token: "ev" }));
		const fake = await connectOnce(t);
		expect(t.urls).toEqual(["https://hub.example/?room=r"]);
		expect(bytesToHex(fake.uniStreams[0].written[0])).toBe(
			setupHex([authTokenOption(0n, utf8ToBytes("ev")), SSTS]),
		);
	});

	it("without a token the SETUP is unchanged (SSTS only)", async () => {
		const t = start(async (url) => ({ url }));
		const fake = await connectOnce(t);
		expect(bytesToHex(fake.uniStreams[0].written[0])).toBe(setupHex([SSTS]));
	});

	it("asks the session afresh on every connect", async () => {
		let n = 0;
		const t = start(async (url) => ({ url, token: `ev${++n}` }));
		await connectOnce(t);
		t.client.close();
		const second = await connectOnce(t);
		expect(bytesToHex(second.uniStreams[0].written[0])).toBe(
			setupHex([authTokenOption(0n, utf8ToBytes("ev2")), SSTS]),
		);
	});

	it("a failed signature fails the connect before any WebTransport", async () => {
		const t = start(async () => {
			throw new Error("declined");
		});
		await expect(t.client.connect("https://hub.example/", [])).rejects.toThrow(
			"declined",
		);
		expect(t.urls).toEqual([]);
	});

	it("close() while the extension signs: no WebTransport ever opens", async () => {
		let approve: (v: { url: string; token: string }) => void = () => {};
		const t = start(
			() =>
				new Promise((res) => {
					approve = res;
				}),
		);
		const done = t.client.connect("https://hub.example/", []);
		t.client.close();
		approve({ url: "https://hub.example/?room=r", token: "ev" });
		await expect(done).rejects.toThrow("closed");
		expect(t.urls).toEqual([]);
	});

	it("close() while ready is pending: connect stops, sends no SETUP", async () => {
		const t = start(async (url) => ({ url, token: "ev" }));
		const done = t.client.connect("https://hub.example/", []);
		await flush();
		t.client.close();
		t.fakes[0].resolveReady();
		await expect(done).rejects.toThrow("closed");
		expect(t.fakes[0].uniStreams).toEqual([]);
	});
});

describe("MoqtChatClient close reason", () => {
	it("connected: the hub's reason reaches onCloseReason before 'disconnected'", async () => {
		const t = start();
		const order: string[] = [];
		t.onCloseReason.mockImplementation((r) => order.push(r));
		t.onStatusChange.mockImplementation((s) => order.push(s));
		const fake = await connectOnce(t);
		fake.resolveClosed({ closeCode: 0, reason: "room-ended" });
		await flush();
		expect(order.slice(-2)).toEqual(["room-ended", "disconnected"]);
	});

	it("failed connect: a resolved close still reports its reason", async () => {
		const t = start();
		const done = t.client.connect("https://hub.example/", []);
		const fake = t.fakes[0];
		fake.resolveClosed({ closeCode: 2, reason: "unauthorized" });
		fake.rejectReady(new Error("closed"));
		await expect(done).rejects.toThrow();
		await flush();
		expect(t.onCloseReason).toHaveBeenCalledWith("unauthorized");
	});

	it("a reason for a session close()d since (a torn-down client) reports none", async () => {
		const t = start();
		const fake = await connectOnce(t);
		t.client.close();
		fake.resolveClosed({ closeCode: 0, reason: "room-ended" });
		await flush();
		expect(t.onCloseReason).not.toHaveBeenCalled();
	});

	it("a rejected close (network) or an empty reason reports none", async () => {
		const t = start();
		const fake = await connectOnce(t);
		fake.rejectClosed(new Error("network"));
		await flush();
		expect(t.onCloseReason).not.toHaveBeenCalled();
		expect(t.onStatusChange).toHaveBeenLastCalledWith("disconnected");
		const u = start();
		const f2 = await connectOnce(u);
		f2.resolveClosed({ closeCode: 0, reason: "" });
		await flush();
		expect(u.onCloseReason).not.toHaveBeenCalled();
	});
});
