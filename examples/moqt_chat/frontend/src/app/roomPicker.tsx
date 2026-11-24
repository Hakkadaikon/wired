"use client";

import { useState } from "react";
import type { RoomMode } from "@/lib/roomAuth";
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

const MODES: { mode: RoomMode; label: string }[] = [
	{ mode: "open", label: "Open" },
	{ mode: "auth", label: "Login required" },
];

function createHint(pubkey: string | null, nip05: string | undefined) {
	if (!pubkey)
		return "Log in with Nostr to create a room: you become its host.";
	if (!nip05) return "A NIP-05 address is required to create a room";
	return "You host the new room. Share its link to invite others.";
}

/** The join screen's room: the link's room and its share link, or (no
 * room in the URL) Create room -- the logged-in Nostr key with a kind 0
 * nip05 becomes the host; the hub verifies the address. */
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
	const nip05 = useMoqtChatStore((s) =>
		pubkey ? s.nostrProfiles[pubkey]?.nip05 : undefined,
	);
	const [mode, setMode] = useState<RoomMode>("open");
	if (room) return <ShareLink room={room} />;
	const create = () => {
		if (!pubkey || !nip05) return;
		const link = { id: newRoomId(), host: pubkey };
		enterRoom(link, { mode, nip05, created: Math.floor(Date.now() / 1000) });
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
			<fieldset className="tiles" aria-label="Who may join">
				{MODES.map((m) => (
					<button
						key={m.mode}
						type="button"
						className="tile"
						aria-pressed={m.mode === mode}
						data-testid={`room-mode-${m.mode}`}
						onClick={() => setMode(m.mode)}
					>
						{m.label}
					</button>
				))}
			</fieldset>
			<span className="field__hint caption">
				Open: anyone with the link joins. Login required: joining needs a Nostr
				login (an identity, not an invite list).
			</span>
			<button
				type="button"
				className="sign"
				disabled={!pubkey || !nip05}
				data-testid="create-room"
				onClick={create}
			>
				→ Create room
			</button>
			<span
				className="field__hint caption"
				data-testid={pubkey && !nip05 ? "nip05-required" : undefined}
			>
				{createHint(pubkey, nip05)}
			</span>
		</div>
	);
}
