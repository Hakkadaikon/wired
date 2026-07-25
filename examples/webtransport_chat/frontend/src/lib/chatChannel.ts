// Chat over a WebTransport bidirectional stream: JSON-serialize on write,
// JSON-parse on read, and surface stream failure as a send-unavailable
// state instead of leaving callers to discover it via an unhandled
// rejection.

export interface BidiStreamLike {
  writable: {
    getWriter: () => {
      write: (chunk: Uint8Array) => Promise<void>;
      close: () => Promise<void>;
    };
  };
  readable: {
    getReader: () => {
      read: () => Promise<{ value: Uint8Array | undefined; done: boolean }>;
    };
  };
  closed: Promise<void>;
}

export type ChatChannelOptions = {
  onMessage: (message: unknown) => void;
  onError: (err: unknown) => void;
  onSendUnavailable?: () => void;
};

export type ChatChannel = {
  send: (message: unknown) => Promise<void>;
};

async function readLoop(
  stream: BidiStreamLike,
  options: ChatChannelOptions,
): Promise<void> {
  const reader = stream.readable.getReader();
  const decoder = new TextDecoder();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    if (!value) continue;
    try {
      options.onMessage(JSON.parse(decoder.decode(value)));
    } catch (err) {
      options.onError(err);
    }
  }
}

export function openChatChannel(
  stream: BidiStreamLike,
  options: ChatChannelOptions,
): ChatChannel {
  let sendUnavailable = false;
  const markUnavailable = () => {
    if (sendUnavailable) return;
    sendUnavailable = true;
    options.onSendUnavailable?.();
  };
  stream.closed.then(markUnavailable, markUnavailable);
  readLoop(stream, options).catch(markUnavailable);

  return {
    send: async (message: unknown) => {
      if (sendUnavailable) {
        throw new Error("chat channel is send-unavailable");
      }
      const writer = stream.writable.getWriter();
      await writer.write(new TextEncoder().encode(JSON.stringify(message)));
    },
  };
}
