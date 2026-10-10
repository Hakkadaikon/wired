// A WebTransport stand-in for driving MoqtChatClient's connection lifecycle
// from tests: `ready` and `closed` are deferred promises the test settles
// (resolveReady/rejectClosed/...), the incoming-bidi reader serves one fake
// control stream so connect() can complete, every client-opened bidi
// stream is a FakeRequestStream recorded in `requests`, and the
// incoming-uni reader parks forever. `protocol` is the negotiated
// WebTransport subprotocol (undefined: none, the draft-19 legacy session);
// with "moqt-22" a test pushes `serverControl` as the hub's draft-22 uni
// control stream (startD22Control) and every client-opened uni stream's
// writes land in `uniStreams`. Not a .test file, so vitest does not
// collect it.

import { vi } from "vitest";
import {
	concatBytes,
	decodeControlFrame,
	encodeControlFrame,
	encodeRequestOk,
	encodeSetup,
	encodeSstsAlgorithms,
	SETUP_OPTION_SSTS_ALGORITHMS,
} from "../moqtWire";

/** A hub SETUP body (startD22Control's setupBody) advertising the
 * SSTS_ALGORITHMS `algs`; undefined: no such option (an extension-less hub). */
export function hubSetupBody(algs?: bigint[]): Uint8Array {
	return encodeSetup({
		setupOptions: algs
			? [
					{
						type: SETUP_OPTION_SSTS_ALGORITHMS,
						raw: encodeSstsAlgorithms(algs),
					},
				]
			: [],
	});
}

type WriterLike = { write: () => Promise<void>; close: () => Promise<void> };

/** One stream's hub-to-client half: yields whatever a test push()es (the
 * hub's replies), parking between pushes; end() / a cancel finish it. */
export class FakeControlReplies {
	#queue: Uint8Array[] = [];
	#wake: (() => void) | undefined;
	#ended = false;
	cancelled = false;

	getReader() {
		return {
			read: async (): Promise<{ value?: Uint8Array; done: boolean }> => {
				for (;;) {
					const value = this.#queue.shift();
					if (value) return { value, done: false };
					if (this.#ended) return { value: undefined, done: true };
					await new Promise<void>((resolve) => {
						this.#wake = resolve;
					});
				}
			},
			cancel: async () => {
				this.cancelled = true;
				this.end();
			},
			releaseLock: () => {},
		};
	}

	push(frame: Uint8Array): void {
		this.#queue.push(frame);
		this.#wake?.();
		this.#wake = undefined;
	}

	end(): void {
		this.#ended = true;
		this.#wake?.();
		this.#wake = undefined;
	}
}

function fakeControlStream(readable: FakeControlReplies) {
	return {
		writable: {
			getWriter: (): WriterLike => ({
				write: async () => {},
				close: async () => {},
			}),
		},
		readable,
	};
}

export const MSG_PUBLISH = 0x1dn;
export const MSG_SUBSCRIBE = 0x3n;
export const MSG_FETCH = 0x16n;
export const MSG_PUBLISH_NAMESPACE = 0x6n;
export const MSG_SUBSCRIBE_NAMESPACE = 0x50n;

export const requestOk = () =>
	encodeControlFrame(
		0x7n,
		encodeRequestOk({ parameters: [], trackProperties: [] }),
	);

/** A client-opened bidi request stream (draft-ietf-moq-transport-22 6.4.2; d19 3.3):
 * records what the client wrote and whether it FINed or reset its side;
 * `replies` is the hub's half. */
export class FakeRequestStream {
	written: Uint8Array[] = [];
	closed = false;
	aborted = false;
	readonly replies = new FakeControlReplies();
	readonly readable = this.replies;
	readonly writable = {
		getWriter: () => ({
			write: async (chunk: Uint8Array) => {
				this.written.push(chunk);
				this.#onWrite(this);
			},
			close: async () => {
				this.closed = true;
			},
			abort: async () => {
				this.aborted = true;
			},
			releaseLock: () => {},
		}),
	};
	#onWrite: (s: FakeRequestStream) => void;

	constructor(onWrite: (s: FakeRequestStream) => void) {
		this.#onWrite = onWrite;
	}

	/** The request message: Type and body of the first control message. */
	get request() {
		return decodeControlFrame(concatBytes(this.written)).frame;
	}

	get cancelled(): boolean {
		return this.aborted && this.replies.cancelled;
	}
}

/** Fake wt.datagrams: the writable records what was written, the readable
 * serves whatever a test push()es (parking between pushes). */
export class FakeDatagrams {
	maxDatagramSize = 1200;
	written: Uint8Array[] = [];
	#queue: Uint8Array[] = [];
	#wake: (() => void) | undefined;

	writable = {
		getWriter: () => ({
			write: async (chunk: Uint8Array) => {
				this.written.push(chunk);
			},
			releaseLock: () => {},
		}),
	};

	readable = {
		getReader: () => ({
			read: async (): Promise<{ value?: Uint8Array; done: boolean }> => {
				for (;;) {
					const value = this.#queue.shift();
					if (value) return { value, done: false };
					await new Promise<void>((resolve) => {
						this.#wake = resolve;
					});
				}
			},
		}),
	};

	push(datagram: Uint8Array): void {
		this.#queue.push(datagram);
		this.#wake?.();
		this.#wake = undefined;
	}
}

/** One incoming uni stream whose entire wire payload is delivered in a
 * single reader.read() chunk (real streams may fragment, but every writer
 * in this codebase writes a whole message in one write() call, and
 * #readOneUniStream/readToEof only need done:false once then done:true). */
function fakeUniStream(wire: Uint8Array) {
	let delivered = false;
	return {
		getReader: () => ({
			read: async () => {
				if (delivered) return { value: undefined, done: true };
				delivered = true;
				return { value: wire, done: false };
			},
			cancel: async () => {},
			releaseLock: () => {},
		}),
	};
}

type UniStreamLike = { getReader: FakeControlReplies["getReader"] };

/** Incoming uni streams: readable.getReader().read() yields whatever a test
 * push()es, one fake stream per push, parking between pushes; pushStream()
 * hands over a long-lived stream (the draft-22 control stream) as is. */
class FakeIncomingUniStreams {
	#queue: UniStreamLike[] = [];
	#wake: (() => void) | undefined;

	getReader() {
		return {
			read: async () => {
				for (;;) {
					const stream = this.#queue.shift();
					if (stream) return { value: stream, done: false };
					await new Promise<void>((resolve) => {
						this.#wake = resolve;
					});
				}
			},
		};
	}

	push(wire: Uint8Array): void {
		this.pushStream(fakeUniStream(wire) as UniStreamLike);
	}

	pushStream(stream: UniStreamLike): void {
		this.#queue.push(stream);
		this.#wake?.();
		this.#wake = undefined;
	}
}

/** A client-opened uni stream: what the client wrote, and whether it FINed. */
export interface FakeUniWrite {
	written: Uint8Array[];
	closed: boolean;
}

export class FakeWebTransport {
	readonly ready: Promise<void>;
	readonly datagrams = new FakeDatagrams();
	/** Hub replies on the control stream: push() an encoded control frame. */
	readonly controlReplies = new FakeControlReplies();
	/** Incoming uni streams (chat/attachment Objects): push() one wire message. */
	readonly incomingUnidirectionalStreams = new FakeIncomingUniStreams();
	readonly closed: Promise<unknown>;
	/** WebTransport.draining: the test settles it (resolveDraining). */
	readonly draining = new Promise<void>((resolve, reject) => {
		this.resolveDraining = resolve;
		this.rejectDraining = reject;
	});
	resolveDraining!: () => void;
	rejectDraining!: (err: unknown) => void;
	closeCalls = 0;
	resolveReady!: () => void;
	rejectReady!: (err: unknown) => void;
	resolveClosed!: (info?: unknown) => void;
	rejectClosed!: (err: unknown) => void;

	/** WebTransport.protocol: the negotiated subprotocol, or undefined when
	 * none was (a browser without `protocols` support -> draft-19 legacy). */
	protocol: string | undefined = undefined;
	/** The options the client passed to the WebTransport constructor (set by
	 * a test's stub). */
	options: { protocols?: string[] } | undefined;
	/** How many times the client read incomingBidirectionalStreams. */
	bidiReads = 0;
	/** The hub's draft-22 uni control stream (SETUP, then GOAWAY ...):
	 * push() an encoded control frame. */
	readonly serverControl = new FakeControlReplies();

	/** false: the hub opens no bidi control stream (a draft-22 session) --
	 * a read of incomingBidirectionalStreams then parks forever. */
	bidiControl = true;

	/** Set once the client cancels its incomingBidirectionalStreams reader
	 * (a parked read then ends with done). */
	bidiCancelled = false;
	#unparkBidi: (() => void) | undefined;

	incomingBidirectionalStreams = {
		getReader: () => ({
			read: async () => {
				this.bidiReads += 1;
				if (!this.bidiControl) {
					await new Promise<void>((res) => {
						this.#unparkBidi = res;
					});
					return { value: undefined, done: true };
				}
				return { value: fakeControlStream(this.controlReplies), done: false };
			},
			cancel: async () => {
				this.bidiCancelled = true;
				this.#unparkBidi?.();
			},
			releaseLock: () => {},
		}),
	};

	/** Negotiates moqt-22 (or reports `protocol` as given; null leaves it
	 * undefined, a browser without the attribute) and opens the hub's uni control stream,
	 * whose first bytes are its SETUP (Type 0x2F00, empty options unless
	 * `setupBody` gives the encoded Setup Options); no bidi control stream
	 * comes. */
	startD22Control(
		protocol: string | null = "moqt-22",
		setupBody: Uint8Array = new Uint8Array(0),
	): void {
		this.protocol = protocol ?? undefined;
		this.bidiControl = false;
		this.serverControl.push(encodeControlFrame(0x2f00n, setupBody));
		this.incomingUnidirectionalStreams.pushStream(this.serverControl);
	}

	constructor() {
		this.ready = new Promise<void>((res, rej) => {
			this.resolveReady = res;
			this.rejectReady = rej;
		});
		this.closed = new Promise((res, rej) => {
			this.resolveClosed = res;
			this.rejectClosed = rej;
		});
		// No self-attached rejection handlers here, deliberately: a real
		// browser's WebTransport does not swallow its own closed rejection
		// either, so an attempt the production code leaves unhandled must
		// surface through vitest's unhandled-rejection reporting.
	}

	close(): void {
		this.closeCalls += 1;
	}

	/** Every uni stream the client opened, in order, with its writes. */
	readonly uniStreams: FakeUniWrite[] = [];

	createUnidirectionalStream = async () => {
		const rec: FakeUniWrite = { written: [], closed: false };
		this.uniStreams.push(rec);
		return {
			getWriter: () => ({
				write: async (chunk: Uint8Array) => {
					rec.written.push(chunk);
				},
				close: async () => {
					rec.closed = true;
				},
				releaseLock: () => {},
			}),
		};
	};

	/** Every bidi request stream the client opened, in order. */
	readonly requests: FakeRequestStream[] = [];

	/** The hub's automatic first answer to a request of this Type, or
	 * undefined to leave it for the test. Default: REQUEST_OK to a PUBLISH /
	 * PUBLISH_NAMESPACE / SUBSCRIBE_NAMESPACE, the requests a connect makes. */
	autoAnswer = (type: bigint): Uint8Array | undefined =>
		type === MSG_PUBLISH ||
		type === MSG_PUBLISH_NAMESPACE ||
		type === MSG_SUBSCRIBE_NAMESPACE
			? requestOk()
			: undefined;

	createBidirectionalStream = async () => {
		const stream = new FakeRequestStream((s) => {
			if (s.written.length !== 1) return;
			const answer = this.autoAnswer(s.request.type);
			if (answer) s.replies.push(answer);
		});
		this.requests.push(stream);
		return stream;
	};

	/** The request streams whose request has Type type. */
	requestsOf(type: bigint): FakeRequestStream[] {
		return this.requests.filter((s) => s.request.type === type);
	}
}

// Install `make` as the global WebTransport constructor: each
// `new WebTransport(url, options)` returns whatever `make(url, options)`
// returns.
export function stubWebTransport(
	make: (url: string, options: { protocols?: string[] }) => unknown,
): void {
	// A function declaration, not an arrow: the client calls it with `new`.
	function WebTransport(url: string, options: { protocols?: string[] }) {
		return make(url, options);
	}
	vi.stubGlobal("WebTransport", WebTransport);
}
