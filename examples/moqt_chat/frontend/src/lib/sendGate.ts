// Serializes datagram sends against one WebTransport connection. Every
// caller (chat, presence, voice) must go through the SAME gate for a given
// transport: WebTransport's WritableStreamDefaultWriter throws
// "Cannot create writer when WritableStream is locked" if a second
// getWriter() happens while a first write() is still in flight -- two
// independent send paths racing the same stream hit this in practice, not
// just in theory.
//
// A send in flight blocks the gate; while blocked, only the most recently
// queued send is kept for when it frees up (latest-wins coalescing), never a
// growing backlog. A rejected send (stream error, peer gone) drops that one
// frame and the gate stays usable for the next.
export function createSendGate(
  send: (bytes: Uint8Array) => void | Promise<void>,
  onSendFailed?: (err: unknown) => void,
): (bytes: Uint8Array) => Promise<void> {
  let inFlight = false;
  let pending: { bytes: Uint8Array; resolve: () => void } | null = null;

  const pump = async (bytes: Uint8Array, resolve: () => void) => {
    inFlight = true;
    try {
      await send(bytes);
    } catch (err) {
      // Still a dropped frame, not a rethrow -- the gate must stay usable
      // for the next send either way. onSendFailed only adds visibility
      // (e.g. micPipeline.ts counting consecutive failures) on top of that.
      onSendFailed?.(err);
    }
    resolve();
    inFlight = false;
    if (pending) {
      const next = pending;
      pending = null;
      await pump(next.bytes, next.resolve);
    }
  };

  return (bytes: Uint8Array) =>
    new Promise<void>((resolve) => {
      if (inFlight) {
        pending?.resolve(); // superseded by this newer send
        pending = { bytes, resolve };
        return;
      }
      void pump(bytes, resolve);
    });
}
