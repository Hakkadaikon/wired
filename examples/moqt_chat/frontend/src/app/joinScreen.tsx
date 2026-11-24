"use client";

import { type ReactNode, useEffect, useRef, useState } from "react";
import {
	certHashError,
	joinBlocker,
	shortHash,
	urlError,
} from "@/lib/joinForm";
import { CANDIDATE_PARTICIPANT_IDS } from "@/lib/moqtClient";
import {
	DEFAULT_NOSTR_RELAYS,
	nostrLogin,
	parseRelayList,
	shortNpub,
} from "@/lib/nostr";
import type { RoomLink } from "@/lib/roomLink";
import { lookupNostrName, useMoqtChatStore } from "@/stores/moqtChatStore";
import { CopyButton } from "./copyButton";
import { Icon } from "./icons";
import { NostrAuthor } from "./rawNostrEvent";
import { RoomPicker } from "./roomPicker";
import { InfoTip, Tooltip } from "./tooltip";

export const DEFAULT_URL = "https://localhost:4433/";
export const DEFAULT_RELAYS_TEXT = DEFAULT_NOSTR_RELAYS.join("\n");
const LOGIN_TIMEOUT_MS = 30_000;

// NIP-07 login: the extension holds the key and signs; this page only learns
// the pubkey. Logged in, text messages go out as signed kind 1311 events.
// Lives in the join masthead's top right; errors sit under the button.
export function NostrAccount({
	setNickname,
}: {
	setNickname: (v: string) => void;
}) {
	const pubkey = useMoqtChatStore((s) => s.nostrPubkey);
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);
	// An extension prompt that is closed without an answer never settles:
	// coming back to the window (or 30 s) frees the button again.
	useEffect(() => {
		if (!busy) return;
		const free = () => setBusy(false);
		const t = window.setTimeout(free, LOGIN_TIMEOUT_MS);
		window.addEventListener("focus", free);
		return () => {
			window.clearTimeout(t);
			window.removeEventListener("focus", free);
		};
	}, [busy]);
	const login = async () => {
		setBusy(true);
		try {
			const pk = await nostrLogin();
			useMoqtChatStore.getState().setNostrPubkey(pk);
			setNickname(shortNpub(pk));
			setError(null);
			lookupNostrName(pk);
		} catch (e) {
			setError(e instanceof Error ? e.message : String(e));
		}
		setBusy(false);
	};
	const logout = () => {
		useMoqtChatStore.getState().setNostrPubkey(null);
		setNickname("");
	};
	return (
		<div className="account">
			{pubkey ? (
				<>
					<span className="account__who" data-testid="nostr-user">
						<span className="account__state">
							<Icon name="check" />
							Logged in
						</span>
						<NostrAuthor pubkey={pubkey} />
					</span>
					<button type="button" className="link" onClick={logout}>
						Log out
					</button>
				</>
			) : (
				<button
					type="button"
					className="sign sign--nostr"
					data-testid="nostr-login"
					disabled={busy}
					onClick={() => void login()}
				>
					<Icon name={busy ? "spinner" : "login"} />
					{busy ? "Connecting…" : "Log in with Nostr"}
				</button>
			)}
			<span
				className="field__error account__error"
				aria-live="polite"
				data-testid="nostr-login-error"
			>
				{error}
			</span>
		</div>
	);
}

/** A labelled text field with a copy button and its inline error. */
function CopyField({
	id,
	label,
	info,
	value,
	onChange,
	error,
	placeholder,
}: {
	id: string;
	label: string;
	info?: ReactNode;
	value: string;
	onChange: (v: string) => void;
	error: string | null;
	placeholder: string;
}) {
	const errId = `${id}-error`;
	return (
		<div className="field">
			<span className="field__label">
				<label htmlFor={id}>{label}</label>
				{info}
			</span>
			<span className="field__row">
				<input
					id={id}
					placeholder={placeholder}
					value={value}
					spellCheck={false}
					autoComplete="off"
					aria-invalid={error !== null}
					aria-describedby={error ? errId : undefined}
					data-testid={id}
					onChange={(e) => onChange(e.target.value)}
				/>
				<CopyButton
					value={value}
					label={`Copy ${label}`}
					testId={`copy-${id}`}
				/>
			</span>
			{error && (
				<span className="field__error" id={errId}>
					{error}
				</span>
			)}
		</div>
	);
}

function NostrRelays({
	relaysText,
	setRelaysText,
}: {
	relaysText: string;
	setRelaysText: (v: string) => void;
}) {
	return (
		<div className="field">
			<span className="field__label">
				<label htmlFor="nostr-relays">Profile relays</label>
				<InfoTip
					label="About profile relays"
					tip="Read-only, one wss:// URL per line. Only names (kind 0) are read from these; chat stays on the hub."
				/>
			</span>
			<span className="field__row">
				<textarea
					id="nostr-relays"
					rows={5}
					value={relaysText}
					data-testid="nostr-relays"
					onChange={(e) => setRelaysText(e.target.value)}
					onBlur={() => setRelaysText(parseRelayList(relaysText).join("\n"))}
				/>
				<CopyButton
					value={relaysText}
					label="Copy profile relays"
					testId="copy-relays"
				/>
			</span>
			<button
				type="button"
				className="link"
				onClick={() => setRelaysText(DEFAULT_RELAYS_TEXT)}
			>
				Reset relays to defaults
			</button>
		</div>
	);
}

type Connection = {
	url: string;
	setUrl: (v: string) => void;
	certHash: string;
	setCertHash: (v: string) => void;
	relaysText: string;
	setRelaysText: (v: string) => void;
};

/** Server URL, certificate hash and relays: closed until wanted, but while
 * a value is invalid it stays open (a collapse re-opens) so the error is
 * never hidden; the summary counts the errors. */
function Advanced(c: Connection & { errors: number }) {
	const [open, setOpen] = useState(false);
	return (
		<details
			className="advanced"
			open={open || c.errors > 0}
			onToggle={(e) => {
				const el = e.currentTarget;
				if (!el.open && c.errors > 0) el.open = true;
				else setOpen(el.open);
			}}
		>
			<summary data-testid="advanced">
				Advanced
				{c.errors > 0 && (
					<span className="advanced__errors">
						{c.errors === 1 ? "1 error" : `${c.errors} errors`}
					</span>
				)}
				<span className="advanced__summary">
					{c.url}
					{c.certHash && ` · ${shortHash(c.certHash)}`}
				</span>
			</summary>
			<CopyField
				id="url"
				label="Server URL"
				placeholder={DEFAULT_URL}
				value={c.url}
				onChange={c.setUrl}
				error={urlError(c.url)}
			/>
			<CopyField
				id="certHash"
				label="Certificate hash (SHA-256)"
				info={
					<InfoTip
						label="About the certificate hash"
						tip="Server certificate fingerprint. Copy it from the server's startup log; leave it empty for a CA-signed certificate."
					/>
				}
				placeholder="hex fingerprint"
				value={c.certHash}
				onChange={c.setCertHash}
				error={certHashError(c.certHash)}
			/>
			<NostrRelays relaysText={c.relaysText} setRelaysText={c.setRelaysText} />
		</details>
	);
}

function SlotPicker({
	participantId,
	setParticipantId,
}: {
	participantId: string;
	setParticipantId: (v: string) => void;
}) {
	return (
		<div className="field">
			<span className="field__label" id="slot-label">
				Choose a participant slot (max 4)
			</span>
			<fieldset
				className="tiles"
				aria-labelledby="slot-label"
				data-testid="author"
			>
				{CANDIDATE_PARTICIPANT_IDS.map((id) => (
					<Tooltip key={id} tip="Join in this slot">
						<button
							type="button"
							className="tile"
							aria-pressed={id === participantId}
							data-testid={`participant-${id}`}
							onClick={() => setParticipantId(id)}
						>
							{id === participantId && <Icon name="check" />}
							{id}
						</button>
					</Tooltip>
				))}
			</fieldset>
		</div>
	);
}

const SAVED_ITEMS =
	"server URL, certificate hash, participant slot, display name and profile relays";

/** An in-page confirm (window.confirm's buttons are in the browser's
 * language): modal where showModal exists, Esc cancels. */
function ClearSaved({ onConfirm }: { onConfirm: () => void }) {
	const [asking, setAsking] = useState(false);
	const ref = useRef<HTMLDialogElement>(null);
	const opener = useRef<HTMLButtonElement>(null);
	useEffect(() => {
		if (asking) ref.current?.showModal?.();
	}, [asking]);
	// Focus goes back to the button that opened the dialog.
	const done = (confirmed: boolean) => {
		setAsking(false);
		opener.current?.focus();
		if (confirmed) onConfirm();
	};
	return (
		<>
			<button
				type="button"
				className="link"
				ref={opener}
				data-testid="clear-saved"
				onClick={() => setAsking(true)}
			>
				<Icon name="trash" />
				Delete saved connection info
			</button>
			{asking && (
				<dialog
					ref={ref}
					className="confirm"
					aria-labelledby="clear-saved-title"
					data-testid="clear-saved-dialog"
					onClose={() => done(false)}
				>
					<h2 id="clear-saved-title">Delete saved connection info?</h2>
					<p>This removes the {SAVED_ITEMS} saved in this browser.</p>
					<div className="confirm__actions">
						<button
							type="button"
							className="sign sign--outline"
							data-testid="clear-saved-cancel"
							onClick={() => done(false)}
						>
							Cancel
						</button>
						<button
							type="button"
							className="sign sign--danger"
							data-testid="clear-saved-confirm"
							onClick={() => done(true)}
						>
							<Icon name="trash" />
							Delete
						</button>
					</div>
				</dialog>
			)}
		</>
	);
}

function JoinButton({
	connecting,
	blocker,
}: {
	connecting: boolean;
	blocker: string | null;
}) {
	return (
		<>
			<button
				type="submit"
				className="sign sign--primary"
				disabled={connecting || blocker !== null}
				data-testid="connect"
			>
				{connecting && <Icon name="spinner" />}
				{connecting ? "Connecting…" : "Join"}
				{!connecting && <Icon name="chevron" />}
			</button>
			{blocker && (
				<span className="field__reason" data-testid="join-blocker">
					{blocker}
				</span>
			)}
		</>
	);
}

export function JoinScreen(
	props: Connection & {
		nickname: string;
		setNickname: (v: string) => void;
		participantId: string;
		setParticipantId: (v: string) => void;
		connecting: boolean;
		onJoin: () => void;
		onClearSaved: () => void;
		room: RoomLink | null;
		roomError: string | null;
		setRoom: (v: RoomLink) => void;
	},
) {
	const errors = [urlError(props.url), certHashError(props.certHash)].filter(
		(e) => e !== null,
	).length;
	const blocker = joinBlocker(props.room !== null, errors);
	return (
		<div className="cover">
			<div className="card">
				<h1>Join the room</h1>
				<p className="cover__lede">
					Voice, screen sharing and text over one MOQT session.
				</p>
				<RoomPicker
					room={props.room}
					error={props.roomError}
					onRoom={props.setRoom}
				/>
				<form
					className="form"
					noValidate
					onSubmit={(e) => {
						e.preventDefault();
						if (!props.connecting && !blocker) props.onJoin();
					}}
				>
					<label className="field">
						<span className="field__label">Nickname (optional)</span>
						<input
							placeholder="Shown instead of your participant id"
							value={props.nickname}
							data-testid="nickname"
							onChange={(e) => props.setNickname(e.target.value)}
						/>
					</label>
					<SlotPicker
						participantId={props.participantId}
						setParticipantId={props.setParticipantId}
					/>
					<Advanced {...props} errors={errors} />
					<JoinButton connecting={props.connecting} blocker={blocker} />
					<ClearSaved onConfirm={props.onClearSaved} />
				</form>
			</div>
		</div>
	);
}
