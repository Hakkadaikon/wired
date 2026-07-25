import { describe, expect, it, vi } from "vitest";
import { WebTransportClient } from "../webtransportClient";

// Minimal fake matching the shape of the WebTransport API surface this
// client depends on: .ready, .closed, .datagrams, .createBidirectionalStream.
function fakeTransport(overrides: Partial<Record<string, unknown>> = {}) {
  let resolveReady: () => void = () => {};
  let rejectReady: (e: unknown) => void = () => {};
  const ready = new Promise<void>((res, rej) => {
    resolveReady = res;
    rejectReady = rej;
  });
  let resolveClosed: () => void = () => {};
  let rejectClosed: (e: unknown) => void = () => {};
  const closed = new Promise<void>((res, rej) => {
    resolveClosed = res;
    rejectClosed = rej;
  });
  return {
    ready,
    closed,
    resolveReady,
    rejectReady,
    resolveClosed,
    rejectClosed,
    datagrams: { writable: undefined, readable: undefined },
    createBidirectionalStream: vi.fn(),
    close: vi.fn(),
    ...overrides,
  };
}

describe("WebTransportClient", () => {
  it("transitions to established once .ready resolves", async () => {
    const transport = fakeTransport();
    const client = new WebTransportClient(() => transport as never);
    expect(client.state).toBe("connecting");
    const connectDone = client.connect();
    transport.resolveReady();
    await connectDone;
    expect(client.state).toBe("established");
  });

  it("surfaces an error and stays unestablished when .ready rejects", async () => {
    const transport = fakeTransport();
    const onError = vi.fn();
    const client = new WebTransportClient(() => transport as never, {
      onError,
    });
    const connectDone = client.connect();
    transport.rejectReady(new Error("tls mismatch"));
    await connectDone;
    expect(client.state).not.toBe("established");
    expect(onError).toHaveBeenCalledTimes(1);
  });

  it("transitions to disconnected and stops I/O when .closed settles", async () => {
    const transport = fakeTransport();
    const client = new WebTransportClient(() => transport as never);
    const connectDone = client.connect();
    transport.resolveReady();
    await connectDone;
    expect(client.state).toBe("established");
    transport.resolveClosed();
    await Promise.resolve();
    await Promise.resolve();
    expect(client.state).toBe("disconnected");
  });

  it("treats an immediate .closed settlement before .ready as unestablished->disconnected without double cleanup", async () => {
    const transport = fakeTransport();
    const cleanup = vi.fn();
    const client = new WebTransportClient(() => transport as never, {
      onCleanup: cleanup,
    });
    const connectDone = client.connect();
    // closed decides first, before ready ever resolves.
    transport.resolveClosed();
    await Promise.resolve();
    await Promise.resolve();
    transport.resolveReady();
    await connectDone;
    await Promise.resolve();
    expect(client.state).toBe("disconnected");
    expect(cleanup).toHaveBeenCalledTimes(1);
  });
});
