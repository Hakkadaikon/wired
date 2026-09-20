// A WebTransport stand-in for driving MoqtChatClient's connection lifecycle
// from tests: `ready` and `closed` are deferred promises the test settles
// (resolveReady/rejectClosed/...), the incoming-bidi reader serves one fake
// control stream so connect() can complete, and the incoming-uni reader
// parks forever. Not a .test file, so vitest does not collect it.

type WriterLike = { write: () => Promise<void>; close: () => Promise<void> };

function fakeControlStream() {
  return {
    writable: { getWriter: (): WriterLike => ({ write: async () => {}, close: async () => {} }) },
    readable: {
      // #readControlReplies iterates this; never yielding parks it forever.
      [Symbol.asyncIterator]: () => ({ next: () => new Promise<never>(() => {}) }),
    },
  };
}

export class FakeWebTransport {
  readonly ready: Promise<void>;
  readonly closed: Promise<unknown>;
  closeCalls = 0;
  resolveReady!: () => void;
  rejectReady!: (err: unknown) => void;
  resolveClosed!: (info?: unknown) => void;
  rejectClosed!: (err: unknown) => void;

  incomingBidirectionalStreams = {
    getReader: () => ({
      read: async () => ({ value: fakeControlStream(), done: false }),
      releaseLock: () => {},
    }),
  };
  incomingUnidirectionalStreams = {
    getReader: () => ({ read: () => new Promise<never>(() => {}) }),
  };

  constructor() {
    this.ready = new Promise<void>((res, rej) => {
      this.resolveReady = res;
      this.rejectReady = rej;
    });
    this.closed = new Promise((res, rej) => {
      this.resolveClosed = res;
      this.rejectClosed = rej;
    });
    // A test that rejects these before/without a listener must not trip
    // vitest's unhandled-rejection reporting.
    this.ready.catch(() => {});
    this.closed.catch(() => {});
  }

  close(): void {
    this.closeCalls += 1;
  }

  createUnidirectionalStream = async () => ({
    getWriter: (): WriterLike => ({ write: async () => {}, close: async () => {} }),
  });
}
