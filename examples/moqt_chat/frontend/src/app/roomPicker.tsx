"use client";

import { useState } from "react";
import { enterRoom, newRoomId, type RoomLink, withRoom } from "@/lib/roomLink";
import { useMoqtChatStore } from "@/stores/moqtChatStore";

/** The room being joined and its copyable share link (origin + path only:
 * the page's other parameters, e.g. ?relays=, are the user's own). */
function ShareLink({ room }: { room: RoomLink }) {
	const [copyFailed, setCopyFailed] = useState(false);
	const share = withRoom(`${location.origin}${location.pathname}`, room);
	// No clipboard (an insecure context) fails like a refused write.
	const copy = () =>
		(navigator.clipboard?.writeText(share) ?? Promise.reject()).then(
			() => setCopyFailed(false),
			() => setCopyFailed(true),
		);
	return (
		<div className="field">
			<span className="field__label" data-testid="room-joining">
				Joining room {room.id}
			</span>
			<input
				readOnly
				aria-label="Share link"
				value={share}
				data-testid="share-link"
			/>
			<button
				type="button"
				className="link"
				data-testid="copy-share-link"
				onClick={() => void copy()}
			>
				Copy share link
			</button>
			{copyFailed && (
				<span
					className="field__hint caption"
					role="alert"
					data-testid="copy-error"
				>
					Could not copy: select the link and copy it by hand.
				</span>
			)}
		</div>
	);
}

/** The join screen's room: the link's room and its share link, or (no
 * room in the URL) Create room -- the logged-in Nostr key becomes the host. */
export function RoomPicker({
	room,
	error,
	onRoom,
}: {
	room: RoomLink | null;
	error: string | null;
	onRoom: (link: RoomLink) => void;
}) {
	const pubkey = useMoqtChatStore((s) => s.nostrPubkey);
	if (room) return <ShareLink room={room} />;
	const create = () => {
		if (!pubkey) return;
		const link = { id: newRoomId(), host: pubkey };
		enterRoom(link);
		history.replaceState(null, "", withRoom(location.href, link));
		onRoom(link);
	};
	return (
		<div className="field">
			<span className="field__label">Room</span>
			{error && (
				<span
					className="field__hint caption"
					role="alert"
					data-testid="room-error"
				>
					{error}
				</span>
			)}
			<button
				type="button"
				className="sign"
				disabled={!pubkey}
				data-testid="create-room"
				onClick={create}
			>
				→ Create room
			</button>
			<span className="field__hint caption">
				{pubkey
					? "You host the new room. Share its link to invite others."
					: "Log in with Nostr to create a room: you become its host."}
			</span>
		</div>
	);
}
