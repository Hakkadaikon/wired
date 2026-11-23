"use client";

import { npubEncode } from "nostr-tools/nip19";
import { useId, useState } from "react";
import { shortNpub } from "@/lib/nostr";
import { useMoqtChatStore } from "@/stores/moqtChatStore";

/** A Nostr author: the profile name (if any) always next to the short npub
 * and a "verified Nostr" badge, the full npub in the title -- so a name or
 * a legacy nickname cannot pass for someone's Nostr identity. */
export function NostrAuthor({ pubkey }: { pubkey: string }) {
	const name = useMoqtChatStore((s) => s.nostrNames[pubkey]);
	return (
		<span className="nostr-author" title={npubEncode(pubkey)}>
			{name && <span className="nostr-author__name">{name} </span>}
			<span className="message__npub" data-testid="nostr-npub">
				{shortNpub(pubkey)}
			</span>{" "}
			<span className="nostr-author__badge caption">✓ verified Nostr</span>
		</span>
	);
}

const SIGNED_KEYS = new Set([
	"id",
	"pubkey",
	"created_at",
	"kind",
	"tags",
	"content",
	"sig",
]);

// Keys outside the NIP-01 event ride along unsigned.
function hasUnsignedKeys(raw: string): boolean {
	try {
		return Object.keys(JSON.parse(raw)).some((k) => !SIGNED_KEYS.has(k));
	} catch {
		return false;
	}
}

function pretty(raw: string): string {
	try {
		return JSON.stringify(JSON.parse(raw), null, 2);
	} catch {
		return raw;
	}
}

/** The "{ }" toggle on a Nostr chat message: the event JSON as carried in
 * the MoQ Object payload, rendered as text. Only verified events reach the
 * store, so it always reads "verified". */
export function RawNostrEvent({ raw, id }: { raw: string; id: string }) {
	const [open, setOpen] = useState(false);
	const panelId = useId();
	return (
		<>
			<button
				type="button"
				className="link message__raw-toggle"
				aria-label="Show raw Nostr event"
				aria-expanded={open}
				aria-controls={panelId}
				data-testid="nostr-raw-toggle"
				onClick={() => setOpen(!open)}
			>
				{"{ }"}
			</button>
			{open && (
				<div className="message__raw" id={panelId} data-testid="nostr-raw">
					<span className="caption">
						verified · id {id}
						{hasUnsignedKeys(raw) &&
							" · raw payload (unsigned extra keys are not covered by the signature)"}
					</span>
					<pre>{pretty(raw)}</pre>
					<button
						type="button"
						className="link"
						onClick={() => void navigator.clipboard?.writeText(raw)}
					>
						Copy raw
					</button>
				</div>
			)}
		</>
	);
}
