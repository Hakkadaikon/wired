"use client";

import { npubEncode } from "nostr-tools/nip19";
import { type ReactNode, useId, useState } from "react";
import { type NostrProfile, shortNpub } from "@/lib/nostr";
import { useMoqtChatStore } from "@/stores/moqtChatStore";
import { Tooltip } from "./tooltip";

/** A Nostr author: avatar, then the kind 0 display_name over "@name"
 * (NIP-24), falling back to name, then the short npub; the full npub is the
 * title. Only verified pubkeys reach here, so a nickname cannot pose as one. */
export function NostrAuthor({ pubkey }: { pubkey: string }) {
	const profile = useMoqtChatStore((s) => s.nostrProfiles[pubkey]) ?? {};
	const { title, handle, initial } = authorLabels(pubkey, profile);
	return (
		<span className="nostr-author" title={npubEncode(pubkey)}>
			<NostrAvatar
				key={profile.picture}
				pubkey={pubkey}
				picture={profile.picture}
				initial={initial}
			/>
			<span className="nostr-author__names">
				<span className="nostr-author__name">{title}</span>
				{handle && <span className="nostr-author__handle">@{handle}</span>}
			</span>
		</span>
	);
}

/** The same label as NostrAuthor's line 1, text only. */
export function NostrName({ pubkey }: { pubkey: string }) {
	const profile = useMoqtChatStore((s) => s.nostrProfiles[pubkey]) ?? {};
	return authorLabels(pubkey, profile).title;
}

// Line 1 (display_name, else name, else short npub), the line 2 handle
// when both names exist, and the placeholder's initial (names only).
export function authorLabels(pubkey: string, p: NostrProfile) {
	const named = p.displayName ?? p.name ?? "";
	return {
		title: named || shortNpub(pubkey),
		handle: p.displayName && p.name,
		initial: [...named][0] ?? "",
	};
}

const VERIFIED = "Verified Nostr event: id and BIP-340 signature checked";

/** The check under a Nostr post; its tooltip shows on hover and on focus. */
function VerifiedMark() {
	return (
		<Tooltip tip={VERIFIED}>
			<button
				type="button"
				className="verified__mark"
				aria-label="Verified Nostr event"
				data-testid="nostr-verified"
			>
				✓
			</button>
		</Tooltip>
	);
}

/** The author's kind 0 picture (already https-only, safePictureUrl), or a
 * placeholder coloured from the pubkey when it is missing or fails to load.
 * Decorative: the name/npub label sits right next to it. The initial is a
 * CSS attr() so it stays out of the label's text. */
export function NostrAvatar({
	pubkey,
	picture,
	initial,
}: {
	pubkey: string;
	picture?: string;
	initial: string;
}) {
	const [failed, setFailed] = useState(false);
	if (picture && !failed)
		return (
			// biome-ignore lint/performance/noImgElement: participant-chosen https host in a static export; next/image cannot optimize it
			<img
				className="nostr-avatar"
				src={picture}
				alt=""
				referrerPolicy="no-referrer"
				loading="lazy"
				decoding="async"
				onError={() => setFailed(true)}
			/>
		);
	const hue = Number.parseInt(pubkey.slice(0, 6), 16) % 360;
	return (
		<span
			className="nostr-avatar nostr-avatar--placeholder"
			aria-hidden="true"
			data-initial={initial.toUpperCase()}
			style={{ background: `hsl(${hue} 45% 45%)` }}
		/>
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

/** A Nostr post's foot: the verified check (then `children`: reactions),
 * and on the right `actions` then the "⋯" toggle opening the event JSON as
 * carried in the MoQ Object payload, as text, below the post. Only
 * verified events reach the store. */
export function RawNostrEvent({
	raw,
	id,
	children,
	actions,
}: {
	raw: string;
	id: string;
	children?: ReactNode;
	actions?: ReactNode;
}) {
	const [open, setOpen] = useState(false);
	const panelId = useId();
	return (
		<>
			<div className="message__foot">
				<span className="message__foot-start">
					<VerifiedMark />
					{children}
				</span>
				<span className="message__foot-end">
					{actions}
					<button
						type="button"
						className="link post-icon"
						aria-label={open ? "Hide raw Nostr event" : "Show raw Nostr event"}
						aria-expanded={open}
						aria-controls={panelId}
						data-testid="nostr-raw-toggle"
						onClick={() => setOpen(!open)}
					>
						⋯
					</button>
				</span>
			</div>
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
