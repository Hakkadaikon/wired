"use client";

import { useEffect, useRef, useState } from "react";
import { closeMessage, remaining } from "@/lib/roomAuth";
import { useMoqtChatStore } from "@/stores/moqtChatStore";

const nowSeconds = () => Date.now() / 1000;

/** The room's time left, from the host's meeting `ends`, ticking each
 * second; hidden once past or when `ends` is out of range. */
export function Countdown({ ends }: { ends: number }) {
	const [now, setNow] = useState(nowSeconds);
	useEffect(() => {
		const t = setInterval(() => setNow(nowSeconds()), 1000);
		return () => clearInterval(t);
	}, []);
	const left = remaining(ends, now);
	if (!left) return null;
	return (
		<span className="room-head__countdown" data-testid="room-countdown">
			{left} left
		</span>
	);
}

/** On a final close reason, calls end once, right away: the session, mic,
 * camera and screen capture stop without waiting for the user. */
export function useEndOnRoomClosed(end: () => void): void {
	const endRef = useRef(end);
	useEffect(() => {
		endRef.current = end;
	}, [end]);
	useEffect(
		() =>
			useMoqtChatStore.subscribe((s, prev) => {
				if (s.roomClosed && !prev.roomClosed) endRef.current();
			}),
		[],
	);
}

/** The final screen: the hub closed the session with a reason token
 * (roomAuth.ts). No automatic rejoin; Back returns to the join screen. Its
 * heading takes the focus, so a screen reader announces the change. */
export function RoomClosed({
	token,
	onBack,
}: {
	token: string;
	onBack: () => void;
}) {
	const heading = useRef<HTMLHeadingElement>(null);
	useEffect(() => heading.current?.focus(), []);
	return (
		<div className="cover" data-testid="room-closed" data-reason={token}>
			<div>
				<h1 ref={heading} tabIndex={-1}>
					Room closed
				</h1>
				<p
					className="cover__lede"
					role="alert"
					data-testid="room-closed-message"
				>
					{closeMessage(token)}
				</p>
			</div>
			<div>
				<button
					type="button"
					className="sign sign--outline"
					data-testid="room-closed-back"
					onClick={onBack}
				>
					← Back
				</button>
			</div>
		</div>
	);
}
