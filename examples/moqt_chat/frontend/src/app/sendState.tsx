"use client";

import type { ChatMessage } from "@/stores/moqtChatStore";
import { Icon } from "./icons";

export type Retry = (m: ChatMessage) => Promise<void>;

/** A failed message's line. Retry drops this bubble at once, and the
 * re-send shows its own pending one (retryMessage). */
function NotSent({ onRetry }: { onRetry: () => void }) {
	return (
		<span className="message__failed" role="alert">
			<Icon name="alert" />
			Not sent
			<button
				type="button"
				className="link"
				data-testid="message-retry"
				onClick={onRetry}
			>
				<Icon name="rejoin" />
				Retry
			</button>
		</span>
	);
}

/** An own message's send: a spinner while pending (D-24), Retry once failed. */
export function SendState({ m, onRetry }: { m: ChatMessage; onRetry: Retry }) {
	if (m.pending)
		return (
			<span className="message__pending" aria-live="polite">
				<Icon name="spinner" />
				<span className="sr-only">Sending</span>
			</span>
		);
	return m.failed ? <NotSent onRetry={() => void onRetry(m)} /> : null;
}
