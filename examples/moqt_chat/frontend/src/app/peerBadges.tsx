"use client";

import { useEffect, useState } from "react";
import { acceptPresence, handRaised, micMuted } from "@/lib/nostrRoom";
import { activeRoom } from "@/lib/roomLink";
import { useMoqtChatStore } from "@/stores/moqtChatStore";
import { Icon, type IconName } from "./icons";
import { Tooltip } from "./tooltip";

/** A raised hand in the Room list: the pubkey's fresh presence says so. */
// While a hand shows, re-check freshness every HAND_RECHECK_MS so a stale
// presence (its author gone silent) drops the badge.
const HAND_RECHECK_MS = 30_000;

function Hand({ pubkey, testId }: { pubkey?: string | null; testId: string }) {
	const presence = useMoqtChatStore((s) =>
		pubkey ? s.nostrRoom.presence[pubkey] : undefined,
	);
	const raised = presence !== undefined && handRaised(presence);
	const [, recheck] = useState(0);
	useEffect(() => {
		if (!raised) return;
		const t = setInterval(() => recheck((n) => n + 1), HAND_RECHECK_MS);
		return () => clearInterval(t);
	}, [raised]);
	const fresh = presence && acceptPresence(presence, activeRoom.space);
	if (!fresh || !handRaised(presence)) return null;
	return (
		<span
			className="hand"
			role="img"
			aria-label="Hand raised"
			data-testid={testId}
		>
			<Icon name="hand" />
		</span>
	);
}

export function Badge({ icon, label }: { icon: IconName; label: string }) {
	return (
		<Tooltip tip={label}>
			<span className="badge" role="img" aria-label={label}>
				<Icon name={icon} />
			</span>
		</Tooltip>
	);
}

/** A participant's mic / screen / hand state as icons ("own" = this page).
 * A peer's mute comes from its presence (D-15 / D-21). */
export function PeerBadges({
	id,
	handTestId,
}: {
	id: string;
	handTestId: string;
}) {
	const own = id === "own";
	const pubkey = useMoqtChatStore((s) =>
		own ? s.nostrPubkey : s.peerPubkeys[id],
	);
	const declared = useMoqtChatStore((s) => {
		if (own) return s.muted;
		const presence = pubkey ? s.nostrRoom.presence[pubkey] : undefined;
		return presence !== undefined && micMuted(presence);
	});
	const speaking = useMoqtChatStore((s) =>
		own ? s.localSpeaking : Boolean(s.speaking[id]),
	);
	// A peer's self-declared mute never hides speech we actually hear.
	const muted = declared && (own || !speaking);
	const sharing = useMoqtChatStore((s) =>
		own ? s.screenSharing : s.screenTiles.includes(id),
	);
	return (
		<span className="badges">
			{muted && <Badge icon="micOff" label="Muted" />}
			{speaking && !muted && <Badge icon="mic" label="Speaking" />}
			{sharing && <Badge icon="screen" label="Sharing screen" />}
			<Hand pubkey={pubkey} testId={handTestId} />
		</span>
	);
}
