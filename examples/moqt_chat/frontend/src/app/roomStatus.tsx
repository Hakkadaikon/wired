"use client";

import { useEffect, useRef, useState } from "react";
import { closeMessage, remaining } from "@/lib/roomAuth";
import { activeRoom } from "@/lib/roomLink";
import { newlyRaised, timerLevel } from "@/lib/roomUi";
import { useMoqtChatStore } from "@/stores/moqtChatStore";
import { authorLabels } from "./rawNostrEvent";
import { showToast } from "./toast";

const nowSeconds = () => Date.now() / 1000;

/** The room's time left, from the host's meeting `ends`, ticking each
 * second; hidden once past or when `ends` is out of range. Yellow under
 * 30 min, red under 5 min, when it also toasts once. */
export function Countdown({ ends }: { ends: number }) {
	const [now, setNow] = useState(nowSeconds);
	useEffect(() => {
		const t = setInterval(() => setNow(nowSeconds()), 1000);
		return () => clearInterval(t);
	}, []);
	const left = remaining(ends, now);
	const level = timerLevel(ends - now);
	// Only the warn -> danger crossing toasts: not a join under 5 min, and
	// not once the time is past.
	const seen = useRef(level);
	useEffect(() => {
		if (seen.current === "warn" && level === "danger" && left)
			showToast("5 minutes left in this room");
		seen.current = level;
	}, [level, left]);
	if (!left) return null;
	return (
		<span
			className="room-head__countdown"
			data-testid="room-countdown"
			data-level={level}
		>
			{left} left
		</span>
	);
}

/** "<name> raised their hand" for each peer whose presence raises it. */
export function useHandToasts(): void {
	useEffect(
		() =>
			useMoqtChatStore.subscribe((s, prev) => {
				const raised = newlyRaised(
					prev.nostrRoom.presence,
					s.nostrRoom.presence,
					activeRoom.space,
					nowSeconds(),
				);
				for (const pk of raised.filter((pk) => pk !== s.nostrPubkey)) {
					const name = authorLabels(pk, s.nostrProfiles[pk] ?? {}).title;
					showToast(`${name} raised their hand`);
				}
			}),
		[],
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
