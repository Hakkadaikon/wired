// Reconnect orchestration: on disconnect, spin up a new transport, a new
// sender id, and a fresh bidi stream, reset the jitter buffer for the new
// session, and retry with capped exponential backoff up to a fixed attempt
// limit before handing control back to the user.

import type { JitterBufferManager } from "./jitterBuffer";
import { generateSenderId } from "./voiceProtocol";
import { senderIdKey } from "./voiceReceivePipeline";

const BASE_DELAY_MS = 1000;
const MAX_DELAY_MS = 30000;
const MAX_ATTEMPTS = 5;

export type ReconnectFlowDeps<T, S> = {
  makeTransport: () => { ready: Promise<void>; closed: Promise<unknown> };
  openBidiStream: (transport: T) => Promise<S>;
  jitterBuffer: JitterBufferManager;
  initialSenderId: Uint8Array;
  onGiveUp?: () => void;
  onAttemptFailed?: (attempt: number, err: unknown) => void;
};

export type ReconnectFlow = {
  senderId: Uint8Array;
  allSenderIds: Uint8Array[];
  reconnecting: boolean;
  reconnect: () => Promise<void>;
  reconnectWithBackoff: () => Promise<void>;
};

function delayFor(attempt: number): number {
  return Math.min(BASE_DELAY_MS * 2 ** (attempt - 1), MAX_DELAY_MS);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function createReconnectFlow<T, S>(
  deps: ReconnectFlowDeps<T, S>,
): ReconnectFlow {
  const state = {
    senderId: deps.initialSenderId,
    allSenderIds: [deps.initialSenderId],
    reconnecting: false,
  };

  async function attemptOnce(): Promise<void> {
    const transport = deps.makeTransport();
    await transport.ready;
    const newId = generateSenderId();
    state.senderId = newId;
    state.allSenderIds.push(newId);
    deps.jitterBuffer.reconnect(senderIdKey(newId));
    await deps.openBidiStream(transport as unknown as T);
  }

  return {
    get senderId() {
      return state.senderId;
    },
    get allSenderIds() {
      return state.allSenderIds;
    },
    get reconnecting() {
      return state.reconnecting;
    },
    reconnect: async () => {
      state.reconnecting = true;
      try {
        await attemptOnce();
      } finally {
        state.reconnecting = false;
      }
    },
    reconnectWithBackoff: async () => {
      state.reconnecting = true;
      try {
        for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
          try {
            await attemptOnce();
            return;
          } catch (err) {
            deps.onAttemptFailed?.(attempt, err);
            if (attempt === MAX_ATTEMPTS) {
              deps.onGiveUp?.();
              return;
            }
            await sleep(delayFor(attempt));
          }
        }
      } finally {
        state.reconnecting = false;
      }
    },
  };
}
