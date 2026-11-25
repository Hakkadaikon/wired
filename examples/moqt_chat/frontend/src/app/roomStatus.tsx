"use client";

import { useEffect, useRef, useState } from "react";
import { closeMessage, remaining } from "@/lib/roomAuth";
import { activeRoom } from "@/lib/roomLink";
import { newlyRaised, nextParticipantId, timerLevel } from "@/lib/roomUi";
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
				// id-taken is useIdTakenRetry's: it swaps the session instead.
				if (s.roomClosed && !prev.roomClosed && s.roomClosed !== "id-taken")
					endRef.current();
			}),
		[],
	);
}

/** id-taken (the id is held in an open room, or by another key): joins
 * again right away as the next free id and says so; the final screen
 * (end) only once every id was tried. current is the id the page joined
 * as. */
export function useIdTakenRetry(
	current: string,
	rejoin: (id: string) => void,
	end: () => void,
): void {
	const latest = useRef({
		current,
		rejoin,
		end,
		tried: [] as string[],
		room: activeRoom.id,
	});
	useEffect(() => {
		Object.assign(latest.current, { current, rejoin, end });
	}, [current, rejoin, end]);
	useEffect(
		() =>
			useMoqtChatStore.subscribe((s, prev) => {
				const l = latest.current;
				// The ids tried so far count only for this room, until a
				// connect holds: a stale list would skip ids that are free now.
				const held =
					s.connectionState === "connected" &&
					prev.connectionState !== "connected";
				if (held || l.room !== activeRoom.id) {
					l.tried = [];
					l.room = activeRoom.id;
				}
				if (s.roomClosed !== "id-taken" || prev.roomClosed === "id-taken")
					return;
				l.tried.push(l.current);
				const next = nextParticipantId(l.current, s.peers, l.tried);
				if (!next) {
					l.tried = [];
					l.end(); // the final screen, after a full teardown
					return;
				}
				showToast(`${l.current} is in use in this room: joined as ${next}`);
				l.current = next;
				s.setRoomClosed(null);
				// connect() replaces the closed session itself (mic, audio and
				// the room stay up): no Leave, so no 30313 ended either.
				l.rejoin(next);
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
