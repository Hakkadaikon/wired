// A WebTransport stand-in for driving MoqtChatClient's connection lifecycle
// from tests: `ready` and `closed` are deferred promises the test settles
// (resolveReady/rejectClosed/...), the incoming-bidi reader serves one fake
// control stream so connect() can complete, and the incoming-uni reader
// parks forever. Not a .test file, so vitest does not collect it.

type WriterLike = { write: () => Promise<void>; close: () => Promise<void> };

/** The control stream's hub-to-client half: yields whatever a test
 * push()es (the hub's replies), parking between pushes. */
class FakeControlReplies {
  #queue: Uint8Array[] = [];
  #wake: (() => void) | undefined;

  [Symbol.asyncIterator]() {
    return {
      next: async (): Promise<{ value: Uint8Array; done: false }> => {
        for (;;) {
          const value = this.#queue.shift();
          if (value) return { value, done: false };
          await new Promise<void>((resolve) => {
            this.#wake = resolve;
          });
        }
      },
    };
  }

  push(frame: Uint8Array): void {
    this.#queue.push(frame);
    this.#wake?.();
    this.#wake = undefined;
  }
}

function fakeControlStream(readable: FakeControlReplies) {
  return {
    writable: { getWriter: (): WriterLike => ({ write: async () => {}, close: async () => {} }) },
    readable,
  };
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

export class FakeWebTransport {
  readonly ready: Promise<void>;
  readonly datagrams = new FakeDatagrams();
  /** Hub replies on the control stream: push() an encoded control frame. */
  readonly controlReplies = new FakeControlReplies();
  readonly closed: Promise<unknown>;
  closeCalls = 0;
  resolveReady!: () => void;
  rejectReady!: (err: unknown) => void;
  resolveClosed!: (info?: unknown) => void;
  rejectClosed!: (err: unknown) => void;

  incomingBidirectionalStreams = {
    getReader: () => ({
      read: async () => ({ value: fakeControlStream(this.controlReplies), done: false }),
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
    // No self-attached rejection handlers here, deliberately: a real
    // browser's WebTransport does not swallow its own closed rejection
    // either, so an attempt the production code leaves unhandled must
    // surface through vitest's unhandled-rejection reporting.
  }

  close(): void {
    this.closeCalls += 1;
  }

  createUnidirectionalStream = async () => ({
    getWriter: (): WriterLike => ({ write: async () => {}, close: async () => {} }),
  });
}
