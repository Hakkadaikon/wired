"use client";

import {
	useCallback,
	useEffect,
	useId,
	useLayoutEffect,
	useRef,
	useState,
} from "react";
import { deletePost, reactTo, toggleHand } from "@/hooks/nostrRoomSession";
import { useMoqtChat } from "@/hooks/useMoqtChat";
import { useObjectUrl } from "@/hooks/useObjectUrl";
import {
	ATTACHMENT_MAX_BYTES,
	validateAttachmentCandidate,
} from "@/lib/attachmentValidation";
import { clearJoinPrefs, loadJoinPrefs, saveJoinPrefs } from "@/lib/joinPrefs";
import {
	CANDIDATE_PARTICIPANT_IDS,
	type ChatAttachment as WireChatAttachment,
} from "@/lib/moqtClient";
import type { ScreenQuality } from "@/lib/moqtScreenClient";
import { nostrRelays, parseRelayList } from "@/lib/nostr";
import {
	acceptPresence,
	countReactions,
	handRaised,
	isDeleted,
	reactedWith,
	type Target,
	tag,
} from "@/lib/nostrRoom";
import { canPickOutput } from "@/lib/outputMixer";
import {
	activeRoom,
	enterRoom,
	exitRoom,
	parseRoomLink,
	type RoomLink,
	roomName,
} from "@/lib/roomLink";
import { retryMessage } from "@/lib/roomUi";
import { isMuteShortcut } from "@/lib/shortcuts";
import {
	clampSplit,
	gridColumns,
	loadSplit,
	saveSplit,
	splitKey,
	stageMode,
} from "@/lib/stageLayout";
import {
	type ChatMessage,
	type ConnectionState,
	resolveDisplayName,
	useMoqtChatStore,
} from "@/stores/moqtChatStore";
import { Icon, type IconName } from "./icons";
import {
	DEFAULT_RELAYS_TEXT,
	DEFAULT_URL,
	JoinScreen,
	NostrAccount,
} from "./joinScreen";
import {
	authorLabels,
	NostrAuthor,
	NostrAvatar,
	NostrName,
	RawNostrEvent,
} from "./rawNostrEvent";
import { RoomInvite } from "./roomPicker";
import {
	Countdown,
	RoomClosed,
	useEndOnRoomClosed,
	useHandToasts,
} from "./roomStatus";
import { RoomTabs, type RoomView, useEscToClose } from "./roomTabs";
import { Toast } from "./toast";
import { Tooltip } from "./tooltip";
import { VideoSection } from "./videoSection";
import { Wordmark } from "./wordmark";

const DEFAULT_PARTICIPANT_ID = CANDIDATE_PARTICIPANT_IDS[0];

const STATUS_LABEL: Record<string, string> = {
	connecting: "Connecting…",
	connected: "Connected",
	disconnected: "Disconnected",
};

/** The connection: a green / yellow / red dot and its word (never colour
 * alone). */
function Status() {
	const connectionState = useMoqtChatStore((s) => s.connectionState);
	return (
		<div className="status" role="status">
			<span
				className="status__dot"
				data-testid="status"
				data-status={connectionState}
			/>
			<span>{STATUS_LABEL[connectionState]}</span>
		</div>
	);
}

function MicToggle({ onToggleMute }: { onToggleMute: () => void }) {
	const muted = useMoqtChatStore((s) => s.muted);
	return (
		<Tooltip tip="Mute or unmute (M)">
			<button
				type="button"
				className="sign sign--outline"
				aria-pressed={!muted}
				data-testid="mic-toggle"
				onClick={onToggleMute}
			>
				<Icon name={muted ? "micOff" : "mic"} />
				Mic{" "}
				<span className="sign__state" aria-hidden="true">
					{muted ? "off" : "on"}
				</span>
			</button>
		</Tooltip>
	);
}

function NoiseSuppressionToggle() {
	const enabled = useMoqtChatStore((s) => s.noiseSuppressionEnabled);
	const setNoiseSuppressionEnabled = useMoqtChatStore(
		(s) => s.setNoiseSuppressionEnabled,
	);
	return (
		<button
			type="button"
			className="sign sign--outline"
			aria-pressed={enabled}
			data-testid="ns-toggle"
			onClick={() => setNoiseSuppressionEnabled(!enabled)}
		>
			<Icon name="wave" />
			Noise suppression{" "}
			<span className="sign__state" aria-hidden="true">
				{enabled ? "on" : "off"}
			</span>
		</button>
	);
}

// The room tool row's hand: shown once logged in with Nostr (it is a signed
// kind 10312 presence); pressed = raised.
function HandToggle() {
	const pubkey = useMoqtChatStore((s) => s.nostrPubkey);
	const hand = useMoqtChatStore((s) => s.nostrRoom.hand);
	if (!pubkey) return null;
	return (
		<button
			type="button"
			className="sign sign--outline"
			aria-pressed={hand}
			data-testid="hand-toggle"
			onClick={toggleHand}
		>
			<Icon name="hand" />
			Hand{" "}
			<span className="sign__state" aria-hidden="true">
				{hand ? "up" : "down"}
			</span>
		</button>
	);
}

/** NIP-53: the host's space name (else roomName of the link's id), then the
 * live meeting's title and status. */
function RoomHead({
	view,
	onView,
}: {
	view: RoomView;
	onView: (view: RoomView) => void;
}) {
	const space = useMoqtChatStore((s) => s.nostrRoom.space);
	const meeting = useMoqtChatStore((s) => s.nostrRoom.meeting);
	const status = meeting && tag(meeting, "status");
	const ends = meeting && tag(meeting, "ends");
	const unavailable = useMoqtChatStore((s) => s.nostrRoom.unavailable);
	return (
		<header className="room-head" data-testid="room-head">
			<h2 data-testid="space-name">
				{(space && tag(space, "room")) || roomName(activeRoom.id)}
			</h2>
			{meeting ? (
				<p className="room-head__meeting">
					<span data-testid="meeting-title">{tag(meeting, "title")}</span>
					<span
						className="room-head__status"
						data-testid="meeting-status"
						data-status={status}
					>
						{status}
					</span>
					{status === "live" && /^\d+$/.test(ends ?? "") && (
						<Countdown ends={Number(ends)} />
					)}
				</p>
			) : (
				<p className="caption">
					{unavailable
						? "Room events unavailable: the hub refused the Nostr tracks"
						: "No meeting announced"}
				</p>
			)}
			<RoomInvite room={activeRoom} />
			{/* Icon-only on a tablet (CSS) so it shares the head's row. */}
			<Tooltip tip="People & settings">
				<button
					type="button"
					id="room-drawer-toggle"
					className="sign sign--outline room-head__drawer"
					aria-label="People & settings"
					aria-expanded={view === "people"}
					aria-controls="room-rail"
					onClick={() => onView(view === "people" ? "video" : "people")}
				>
					<Icon name="users" />
					People & settings
				</button>
			</Tooltip>
		</header>
	);
}

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

function ScreenShareToggle({
	sharing,
	onStart,
	onStop,
}: {
	sharing: boolean;
	onStart: () => void;
	onStop: () => void;
}) {
	return (
		<button
			type="button"
			className="sign sign--outline"
			data-testid="screen-toggle"
			onClick={sharing ? onStop : onStart}
		>
			<Icon name="screen" />
			{sharing ? "Stop sharing" : "Start sharing"}
		</button>
	);
}

// A remote tile's quality choice (track switching only): "auto" lets the
// hub switch between the sender's variants, high/low pin one.
const SCREEN_QUALITIES: { value: ScreenQuality; label: string }[] = [
	{ value: "auto", label: "Auto" },
	{ value: "high", label: "High" },
	{ value: "low", label: "Low" },
];

function ScreenTiles({
	registerScreenCanvas,
	setScreenQuality,
}: {
	registerScreenCanvas: (id: string, el: HTMLCanvasElement | null) => void;
	setScreenQuality: (id: string, quality: ScreenQuality) => void;
}) {
	const screenTiles = useMoqtChatStore((s) => s.screenTiles);
	const screenSharing = useMoqtChatStore((s) => s.screenSharing);
	const stalledScreenTiles = useMoqtChatStore((s) => s.stalledScreenTiles);
	const nicknames = useMoqtChatStore((s) => s.nicknames);
	const maximized = useMoqtChatStore((s) => s.maximizedScreenTile);
	const setMaximized = useMoqtChatStore((s) => s.setMaximizedScreenTile);
	const switching = useMoqtChatStore((s) => s.screenSwitching);
	const variants = useMoqtChatStore((s) => s.screenTileVariants);
	const qualities = useMoqtChatStore((s) => s.screenTileQuality);
	// Esc (or the browser's own exit) leaves fullscreen without going
	// through the button, so follow the document's state, not the click.
	useEffect(() => {
		const onChange = () => {
			if (!document.fullscreenElement) setMaximized(null);
		};
		document.addEventListener("fullscreenchange", onChange);
		return () => document.removeEventListener("fullscreenchange", onChange);
	}, [setMaximized]);
	const toggleMaximize = (id: string, canvas: HTMLCanvasElement | null) => {
		if (maximized === id) {
			if (document.fullscreenElement)
				void document.exitFullscreen().catch(() => {});
			setMaximized(null);
			return;
		}
		setMaximized(id);
		// Without the Fullscreen API the tile alone filling the stage stands in.
		if (canvas?.requestFullscreen)
			void canvas.requestFullscreen().catch(() => {});
	};
	const remote = screenTiles.filter((id) => id !== "own");
	// While one tile is maximized the others hide but stay mounted, so their
	// canvases keep the last frame instead of starting black on restore.
	const solo = maximized && remote.includes(maximized) ? maximized : null;
	const hidden = (id: string) => solo !== null && solo !== id;
	const count = solo ? 1 : remote.length + (screenSharing ? 1 : 0);
	return (
		<StageGrid count={count}>
			{screenSharing && (
				<div className="vtile" hidden={hidden("own")}>
					<canvas
						ref={(el) => registerScreenCanvas("own", el)}
						data-testid="screen-tile-own"
						width={160}
						height={90}
					/>
					<span className="vtile__bar">
						<Icon name="screen" />
						Sharing screen
					</span>
					{stalledScreenTiles.own && (
						<span className="vtile__tools" data-testid="screen-stalled-own">
							Screen sharing seems to have stalled. Stop sharing, then share
							again.
						</span>
					)}
				</div>
			)}
			{remote.map((id) => (
				<div key={id} className="vtile" hidden={hidden(id)}>
					<canvas
						ref={(el) => registerScreenCanvas(id, el)}
						data-testid={`screen-tile-${id}`}
						width={320}
						height={180}
					/>
					<span className="vtile__bar">
						<Icon name="screen" />
						{resolveDisplayName(id, nicknames)}
					</span>
					<div className="vtile__tools">
						{/* The variant being decoded (follows each keyframe), so a
                  switch is observable: "HI" / "LO". */}
						{switching && variants[id] && (
							<span
								className="caption screen-tile__variant"
								data-testid={`screen-variant-${id}`}
							>
								{variants[id] === "lo" ? "LO" : "HI"}
							</span>
						)}
						{switching && (
							<select
								className="screen-tile__quality"
								data-testid={`screen-quality-${id}`}
								aria-label="Screen quality"
								value={qualities[id] ?? "auto"}
								onChange={(e) =>
									setScreenQuality(id, e.target.value as ScreenQuality)
								}
							>
								{SCREEN_QUALITIES.map((q) => (
									<option key={q.value} value={q.value}>
										{q.label}
									</option>
								))}
							</select>
						)}
						{stalledScreenTiles[id] && (
							<span className="caption" data-testid={`screen-stalled-${id}`}>
								Stalled
							</span>
						)}
						<button
							type="button"
							className="sign sign--outline sign--small"
							data-testid={`screen-maximize-${id}`}
							onClick={(e) =>
								toggleMaximize(
									id,
									e.currentTarget.closest(".vtile")?.querySelector("canvas") ??
										null,
								)
							}
						>
							<Icon name={maximized === id ? "minimize" : "maximize"} />
							{maximized === id ? "Restore" : "Maximize"}
						</button>
					</div>
				</div>
			))}
		</StageGrid>
	);
}

/** The element's content box, measured before the first paint (no
 * one-column frame) and on every resize. */
function useSize(ref: React.RefObject<HTMLElement | null>) {
	const [size, setSize] = useState({ w: 0, h: 0 });
	useLayoutEffect(() => {
		const el = ref.current;
		if (!el) return;
		setSize({ w: el.clientWidth, h: el.clientHeight });
		if (typeof ResizeObserver === "undefined") return;
		const ro = new ResizeObserver(([e]) =>
			setSize({ w: e.contentRect.width, h: e.contentRect.height }),
		);
		ro.observe(el);
		return () => ro.disconnect();
	}, [ref]);
	return size;
}

/** The stage's tiles in a grid whose column count makes each 16:9 tile
 * as large as the stage allows. */
function StageGrid({
	count,
	children,
}: {
	count: number;
	children: React.ReactNode;
}) {
	const ref = useRef<HTMLDivElement>(null);
	const size = useSize(ref);
	const cols = gridColumns(count, size.w, size.h);
	return (
		<div
			ref={ref}
			className="stage-grid"
			style={
				{
					"--cols": cols,
					"--rows": Math.max(1, Math.ceil(count / cols)),
				} as React.CSSProperties
			}
		>
			{children}
		</div>
	);
}

/** A participant with no Nostr name yet: a muted disc with the initial
 * (CSS attr, so it stays out of the row's text). */
function PeerAvatar({ name }: { name: string }) {
	return (
		<span
			className="nostr-avatar nostr-avatar--placeholder peer-avatar"
			aria-hidden="true"
			data-initial={([...name][0] ?? "").toUpperCase()}
		/>
	);
}

/** The avatar beside a participant's label, from the same source: the
 * Nostr picture / display name when the pubkey is known ("own" = this
 * page's login), else the nickname's initial. */
function ParticipantAvatar({ id }: { id: string }) {
	const pubkey = useMoqtChatStore((s) =>
		id === "own" ? s.nostrPubkey : s.peerPubkeys[id],
	);
	const profile = useMoqtChatStore((s) =>
		pubkey ? s.nostrProfiles[pubkey] : undefined,
	);
	const nicknames = useMoqtChatStore((s) => s.nicknames);
	if (!pubkey)
		return (
			<PeerAvatar
				name={id === "own" ? "You" : resolveDisplayName(id, nicknames)}
			/>
		);
	return (
		<NostrAvatar
			key={profile?.picture}
			pubkey={pubkey}
			picture={profile?.picture}
			initial={authorLabels(pubkey, profile ?? {}).initial}
		/>
	);
}

function PeerName({ id }: { id: string }) {
	const pubkey = useMoqtChatStore((s) => s.peerPubkeys[id]);
	const nicknames = useMoqtChatStore((s) => s.nicknames);
	return pubkey ? (
		<NostrName pubkey={pubkey} />
	) : (
		resolveDisplayName(id, nicknames)
	);
}

function Badge({ icon, label }: { icon: IconName; label: string }) {
	return (
		<Tooltip tip={label}>
			<span className="badge" role="img" aria-label={label}>
				<Icon name={icon} />
			</span>
		</Tooltip>
	);
}

/** A participant's mic / screen / hand state as icons ("own" = this page). */
function PeerBadges({ id, handTestId }: { id: string; handTestId: string }) {
	const own = id === "own";
	const pubkey = useMoqtChatStore((s) =>
		own ? s.nostrPubkey : s.peerPubkeys[id],
	);
	const muted = useMoqtChatStore((s) => own && s.muted);
	const speaking = useMoqtChatStore((s) =>
		own ? s.localSpeaking : Boolean(s.speaking[id]),
	);
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

/** The video grid: own tile then one per peer, the camera when it is
 * decoding, else the avatar and name. Name bar bottom-left over the tile. */
function VideoGrid({
	registerCameraCanvas,
}: {
	registerCameraCanvas: (id: string, el: HTMLCanvasElement | null) => void;
}) {
	const cameraTiles = useMoqtChatStore((s) => s.cameraTiles);
	const peers = useMoqtChatStore((s) => s.peers);
	const source = useMoqtChatStore((s) => s.video.source);
	const ids = [...new Set([...peers, ...cameraTiles])];
	return (
		<>
			<StageGrid count={ids.length + 1}>
				<div
					className="vtile"
					data-testid={source === "off" ? "avatar-tile-own" : "camera-tile-own"}
				>
					{source === "off" ? (
						<span className="vtile__avatar">
							<ParticipantAvatar id="own" />
						</span>
					) : (
						<canvas
							ref={(el) => registerCameraCanvas("own", el)}
							width={160}
							height={90}
						/>
					)}
					<span className="vtile__bar">
						{source === "file" && (
							<Badge icon="play" label="Playing a video file" />
						)}
						You
						<PeerBadges id="own" handTestId="tile-hand-you" />
					</span>
				</div>
				{ids.map((id) => (
					<div
						key={id}
						className="vtile"
						data-testid={
							cameraTiles.includes(id)
								? `camera-tile-${id}`
								: `avatar-tile-${id}`
						}
					>
						{cameraTiles.includes(id) ? (
							<canvas
								ref={(el) => registerCameraCanvas(id, el)}
								width={320}
								height={180}
							/>
						) : (
							<span className="vtile__avatar">
								<ParticipantAvatar id={id} />
							</span>
						)}
						<span className="vtile__bar">
							<PeerName id={id} />
							<PeerBadges id={id} handTestId={`tile-hand-${id}`} />
						</span>
					</div>
				))}
			</StageGrid>
			{ids.length === 0 && (
				<p className="caption stage__empty">No one has joined yet</p>
			)}
		</>
	);
}

/** Warning-sign panel: black panel, optional bold heading, light body. */
function Notice({
	title,
	message,
	children,
}: {
	title?: string;
	message: string | null;
	children?: React.ReactNode;
}) {
	if (!message) return null;
	return (
		<div className="notice" role="alert">
			<p>
				{title && <strong>{title}</strong>}
				{message}
			</p>
			{children}
		</div>
	);
}

function Peers() {
	const peers = useMoqtChatStore((s) => s.peers);
	const voiceQuality = useMoqtChatStore((s) => s.voiceQuality);
	const speaking = useMoqtChatStore((s) => s.speaking);
	const localSpeaking = useMoqtChatStore((s) => s.localSpeaking);
	const nicknames = useMoqtChatStore((s) => s.nicknames);
	const peerPubkeys = useMoqtChatStore((s) => s.peerPubkeys);
	return (
		<section>
			<h2>
				<Icon name="users" />
				Participants
			</h2>
			<p className="caption">{peers.length + 1} in room</p>
			<ul className="peers">
				<li className="you">
					<span
						className="status__block"
						data-testid="speaking-you"
						data-speaking={localSpeaking || undefined}
					/>
					<ParticipantAvatar id="own" />
					You
					<PeerBadges id="own" handTestId="hand-you" />
				</li>
				{peers.map((p) => (
					<li key={p}>
						<span
							className="status__block"
							data-testid={`quality-${p}`}
							data-quality={
								voiceQuality[p] === "none" ? undefined : voiceQuality[p]
							}
							data-speaking={speaking[p] || undefined}
						/>
						{peerPubkeys[p] ? (
							<NostrAuthor pubkey={peerPubkeys[p]} />
						) : (
							<>
								<ParticipantAvatar id={p} />
								{resolveDisplayName(p, nicknames)}
							</>
						)}
						<PeerBadges id={p} handTestId={`hand-${p}`} />
					</li>
				))}
			</ul>
		</section>
	);
}

/** A 0-1 volume slider; its 0-100 value sits outside the label, so the
 * slider's name stays the label alone. */
function VolumeSlider({
	label,
	value,
	testId,
	onChange,
}: {
	label: React.ReactNode;
	value: number;
	testId: string;
	onChange: (v: number) => void;
}) {
	const id = useId();
	return (
		<div className="volume">
			<span className="volume__head">
				<label className="volume__label" htmlFor={id}>
					{label}
				</label>
				<output htmlFor={id}>{Math.round(value * 100)}</output>
			</span>
			<input
				id={id}
				type="range"
				min={0}
				max={1}
				step={0.01}
				value={value}
				data-testid={testId}
				onChange={(e) => onChange(Number(e.target.value))}
			/>
		</div>
	);
}

function Volume() {
	const peers = useMoqtChatStore((s) => s.peers);
	const masterVolume = useMoqtChatStore((s) => s.masterVolume);
	const peerVolumes = useMoqtChatStore((s) => s.peerVolumes);
	const setMasterVolume = useMoqtChatStore((s) => s.setMasterVolume);
	const setPeerVolume = useMoqtChatStore((s) => s.setPeerVolume);
	return (
		<section>
			<h2>
				<Icon name="volume" />
				Volume
			</h2>
			<VolumeSlider
				label="Master"
				value={masterVolume}
				testId="master-volume"
				onChange={setMasterVolume}
			/>
			{peers.map((p) => (
				<VolumeSlider
					key={p}
					label={<PeerName id={p} />}
					value={peerVolumes[p] ?? 1}
					testId={`peer-volume-${p}`}
					onChange={(v) => setPeerVolume(p, v)}
				/>
			))}
		</section>
	);
}

function OutputDevice({ onSelect }: { onSelect: (deviceId: string) => void }) {
	const [devices, setDevices] = useState<MediaDeviceInfo[]>([]);
	useEffect(() => {
		const AudioContextCtor = window.AudioContext as unknown as {
			prototype: { setSinkId?: unknown };
		};
		if (!canPickOutput(AudioContextCtor.prototype)) return;
		navigator.mediaDevices
			.enumerateDevices()
			.then((all) => setDevices(all.filter((d) => d.kind === "audiooutput")))
			.catch(() => {});
	}, []);
	if (devices.length === 0) return null;
	return (
		<section>
			<h2>
				<Icon name="volume" />
				Output
			</h2>
			<select
				data-testid="output-device"
				onChange={(e) => onSelect(e.target.value)}
				defaultValue=""
			>
				<option value="" disabled>
					Default
				</option>
				{devices.map((d) => (
					<option key={d.deviceId} value={d.deviceId}>
						{d.label || d.deviceId}
					</option>
				))}
			</select>
		</section>
	);
}

// One attachment inside a sent/received message. The Blob URL already lives
// on the store's ChatAttachment (attachBlobUrls in useMoqtChat.ts creates it
// once per message), so this only picks image vs. video by MIME type --
// unlike DraftChip below, it does not own the URL's lifetime.
function MessageAttachment({
	mimeType,
	url,
	index,
}: {
	mimeType: string;
	url: string;
	index: number;
}) {
	// The Blob URL holds the original bytes, so a download link on it saves
	// the file at full size even though the preview is scaled by CSS.
	const fileName = `attachment-${index + 1}.${mimeType.split("/")[1] ?? "bin"}`;
	return (
		<figure className="message__attachment">
			{mimeType.startsWith("video/") ? (
				// biome-ignore lint/a11y/useMediaCaption: a peer's attached video file arrives as raw bytes with no caption track to offer
				<video src={url} controls data-testid="message-video" />
			) : (
				// biome-ignore lint/performance/noImgElement: blob: URL in a static export; next/image cannot optimize it
				<img src={url} data-testid="message-image" alt="" />
			)}
			<a className="caption" href={url} download={fileName}>
				download
			</a>
		</figure>
	);
}

function Sender({ m }: { m: ChatMessage }) {
	const nicknames = useMoqtChatStore((s) => s.nicknames);
	if (m.author) return <NostrAuthor pubkey={m.author} />;
	return (
		<>
			<ParticipantAvatar id={m.own ? "own" : m.senderId} />
			{m.own ? "You" : resolveDisplayName(m.senderId, nicknames)}
		</>
	);
}

const REACTIONS = ["+", "❤️", "😂", "🎉"];
const REACTION_LABEL: Record<string, string> = { "+": "Like", "-": "Dislike" };
const reactionLabel = (c: string) => REACTION_LABEL[c] ?? c;

/** NIP-25 counts under a Nostr post (one per author and content) and, once
 * logged in, a "React" toggle opening a few reactions inline. */
function Reactions({ target }: { target: Target }) {
	const reactions = useMoqtChatStore((s) => s.nostrRoom.reactions);
	const pubkey = useMoqtChatStore((s) => s.nostrPubkey);
	const canReact = pubkey !== null;
	const [open, setOpen] = useState(false);
	const counts = [...countReactions(target, reactions)];
	// One kind 7 per content: what we already sent stays pressed.
	const mine = reactedWith(target, reactions, pubkey ?? "");
	const react = (c: string) => {
		reactTo(target, c);
		setOpen(false);
	};
	return (
		<span className="reactions">
			{counts.map(([c, n]) => (
				<button
					type="button"
					key={c}
					className="reaction"
					data-testid="reaction-count"
					aria-label={`${reactionLabel(c)}: ${n}`}
					aria-pressed={mine.has(c)}
					disabled={!canReact || mine.has(c)}
					onClick={() => react(c)}
				>
					{c} {n}
				</button>
			))}
			{canReact && (
				<Tooltip tip="Add reaction">
					<button
						type="button"
						className="link post-icon"
						aria-expanded={open}
						aria-label="Add reaction"
						data-testid="reaction-add"
						onClick={() => setOpen(!open)}
					>
						<Icon name="reactAdd" />
					</button>
				</Tooltip>
			)}
			{open &&
				REACTIONS.map((c) => (
					<button
						type="button"
						key={c}
						className="reaction"
						aria-label={`React ${reactionLabel(c)}`}
						data-testid="reaction-pick"
						disabled={mine.has(c)}
						onClick={() => react(c)}
					>
						{c}
					</button>
				))}
		</span>
	);
}

/** A Nostr post's NIP-09 deletion check and its own author's Delete. */
function useNostrPost(m: ChatMessage) {
	const deletions = useMoqtChatStore((s) => s.nostrRoom.deletions);
	const own = useMoqtChatStore((s) => s.nostrPubkey === m.author);
	if (!m.author || !m.key) return undefined;
	const target = {
		id: m.key.slice("nostr:".length),
		pubkey: m.author,
		kind: 1311,
	};
	return {
		target,
		own,
		deleted: isDeleted(target, deletions[target.id] ?? []),
	};
}

function NostrFoot({ m }: { m: ChatMessage }) {
	const post = useNostrPost(m);
	if (!post || !m.raw) return null;
	// NIP-09: isDeleted only honours the author's own kind 5.
	if (post.deleted)
		return (
			<span className="message__deleted caption" data-testid="message-deleted">
				<Icon name="trash" />
				{post.own ? "You" : <NostrName pubkey={post.target.pubkey} />} deleted
				this message
			</span>
		);
	return (
		<RawNostrEvent
			raw={m.raw}
			id={post.target.id}
			actions={
				post.own && (
					<button
						type="button"
						className="link message__delete"
						data-testid="nostr-delete"
						onClick={() => deletePost(post.target)}
					>
						<Icon name="trash" />
						Delete
					</button>
				)
			}
		>
			<Reactions target={post.target} />
		</RawNostrEvent>
	);
}

/** A failed message's line: Retry keeps the bubble (disabled, "Retrying…")
 * until the re-send is done. */
function NotSent({ onRetry }: { onRetry: () => Promise<void> }) {
	const [busy, setBusy] = useState(false);
	return (
		<span className="message__failed" role="alert">
			<Icon name="alert" />
			Not sent
			<button
				type="button"
				className="link"
				data-testid="message-retry"
				disabled={busy}
				onClick={() => {
					setBusy(true);
					void onRetry().finally(() => setBusy(false));
				}}
			>
				<Icon name={busy ? "spinner" : "rejoin"} />
				{busy ? "Retrying…" : "Retry"}
			</button>
		</span>
	);
}

type Retry = (m: ChatMessage) => Promise<void>;

function Message({ m, onRetry }: { m: ChatMessage; onRetry: Retry }) {
	const deleted = useNostrPost(m)?.deleted;
	// A fixed English 24 h clock, not the browser's locale (D-29).
	const time = new Date(m.at).toLocaleTimeString("en", {
		hour: "2-digit",
		minute: "2-digit",
		hourCycle: "h23",
	});
	// The Blob URLs are created once (attachBlobUrls in useMoqtChat.ts) and
	// belong to this message instance for its whole lifetime, so revoke them
	// on unmount only -- capture the values the effect closed over, not a
	// fresh read of m.
	useEffect(() => {
		const urls = m.attachments?.map((a) => a.url) ?? [];
		if (urls.length === 0) return;
		return () => {
			for (const url of urls) URL.revokeObjectURL(url);
		};
	}, [m.attachments]);
	// DOM order is sender, time, text (the grid puts the time last): the e2e
	// load harness matches "msg:<tag>:<seq>" in textContent, and a time
	// directly after the text would extend the digits.
	return (
		<div
			className={`message${m.author ? " message--nostr" : ""}${m.own ? " message--own" : ""}`}
			data-testid="message"
			data-sender={m.senderId}
			data-failed={m.failed || undefined}
		>
			<span className={m.own ? "message__sender you" : "message__sender"}>
				<Sender m={m} />
			</span>
			<span className="message__time caption">{time}</span>
			{m.text && !deleted && <span className="message__text">{m.text}</span>}
			<NostrFoot m={m} />
			{m.attachments && m.attachments.length > 0 && (
				<div className="message__attachments">
					{m.attachments.map((a, i) => (
						<MessageAttachment
							key={a.url}
							mimeType={a.mimeType}
							url={a.url}
							index={i}
						/>
					))}
				</div>
			)}
			{m.failed && <NotSent onRetry={() => onRetry(m)} />}
		</div>
	);
}

function MessageList({ onRetry }: { onRetry: Retry }) {
	const messages = useMoqtChatStore((s) => s.messages);
	const listRef = useRef<HTMLDivElement>(null);

	// biome-ignore lint/correctness/useExhaustiveDependencies: messages.length is the trigger -- re-scroll to the bottom whenever a message is appended
	useEffect(() => {
		const el = listRef.current;
		if (el) el.scrollTop = el.scrollHeight;
	}, [messages.length]);

	// A list read to its end stays there when it gets shorter (a share
	// starting, the splitter moving); one scrolled back keeps its place.
	const pinned = useRef(true);
	useEffect(() => {
		const el = listRef.current;
		if (!el || typeof ResizeObserver === "undefined") return;
		const ro = new ResizeObserver(() => {
			if (pinned.current) el.scrollTop = el.scrollHeight;
		});
		ro.observe(el);
		return () => ro.disconnect();
	}, []);

	return (
		<div
			ref={listRef}
			className="messages"
			data-testid="messages"
			onScroll={(e) => {
				const el = e.currentTarget;
				pinned.current = el.scrollHeight - el.scrollTop - el.clientHeight < 2;
			}}
		>
			{messages.length === 0 && (
				<span className="caption">Send the first message</span>
			)}
			{messages.map((m) => (
				<Message key={m.id} m={m} onRetry={onRetry} />
			))}
		</div>
	);
}

type Draft = {
	id: string;
	bytes: Uint8Array;
	mimeType: string;
	fileName: string;
};

let nextDraftId = 1;

// One preview chip. Owns its Blob URL for the draft's whole lifetime via
// useObjectUrl -- removing the item from draftAttachments unmounts this
// component, which is what revokes the URL (no parent-managed URL map).
function DraftChip({
	draft,
	onRemove,
}: {
	draft: Draft;
	onRemove: () => void;
}) {
	const previewUrl = useObjectUrl(draft.bytes, draft.mimeType);
	return (
		<div className="draft-chip">
			{draft.mimeType.startsWith("video/") ? (
				<video
					src={previewUrl}
					muted
					preload="metadata"
					// Safari/WebKit doesn't decode a frame for the poster just from
					// preload="metadata"; nudging currentTime forces a decode so the
					// chip shows a real thumbnail instead of a blank rectangle.
					onLoadedMetadata={(e) => {
						e.currentTarget.currentTime = 0.1;
					}}
				/>
			) : (
				// biome-ignore lint/performance/noImgElement: blob: URL in a static export; next/image cannot optimize it
				<img src={previewUrl} alt={draft.fileName} />
			)}
			<Tooltip tip="Remove attachment">
				<button
					type="button"
					className="draft-chip__remove"
					aria-label="Remove attachment"
					data-testid="draft-remove"
					onClick={onRemove}
				>
					<Icon name="x" />
				</button>
			</Tooltip>
		</div>
	);
}

// Gave up reconnecting ("disconnected"): say so, not "Reconnecting…".
const COMPOSE_PLACEHOLDER: Record<ConnectionState, string> = {
	connected: "Type a message",
	connecting: "Reconnecting…",
	disconnected: "Disconnected",
};

function Compose({
	onSend,
	onAttachmentRejected,
	state,
}: {
	onSend: (text: string, attachments: WireChatAttachment[]) => void;
	onAttachmentRejected: (reason: string) => void;
	state: ConnectionState;
}) {
	const disabled = state !== "connected";
	const [draft, setDraft] = useState("");
	const [draftAttachments, setDraftAttachments] = useState<Draft[]>([]);
	const fileInputRef = useRef<HTMLInputElement>(null);

	const tryAddFile = (
		file: File,
		bytes: Uint8Array,
		existingCount: number,
	): Draft | null => {
		const result = validateAttachmentCandidate(
			{ byteLength: bytes.byteLength, mimeType: file.type },
			existingCount,
		);
		if (!result.ok) {
			onAttachmentRejected(
				result.reason === "too-large"
					? `attachment too large (max ${ATTACHMENT_MAX_BYTES / (1024 * 1024)}MB)`
					: result.reason === "too-many"
						? "too many attachments (max 4)"
						: "unsupported attachment type",
			);
			return null;
		}
		return {
			id: String(nextDraftId++),
			bytes,
			mimeType: file.type,
			fileName: file.name,
		};
	};

	const addFiles = async (files: File[]) => {
		let count = draftAttachments.length;
		const added: Draft[] = [];
		for (const file of files) {
			const bytes = new Uint8Array(await file.arrayBuffer());
			const item = tryAddFile(file, bytes, count);
			if (!item) continue;
			added.push(item);
			count += 1;
		}
		if (added.length > 0) setDraftAttachments((prev) => [...prev, ...added]);
	};

	const pickFiles = async (e: React.ChangeEvent<HTMLInputElement>) => {
		const files = Array.from(e.target.files ?? []);
		e.target.value = "";
		if (files.length === 0) return;
		await addFiles(files);
	};

	// Pasted images/videos are picked up the same way as a file-picker
	// selection; plain-text paste (item.kind === "string") is left completely
	// alone -- no preventDefault, so the browser's normal paste-into-input
	// still happens. When a file WAS picked up, preventDefault stops the
	// browser from also inserting the file's name/a raw data URL into the
	// text input alongside the draft chip this creates.
	const onPaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
		const files = Array.from(e.clipboardData.items)
			.filter(
				(item) =>
					item.kind === "file" &&
					(item.type.startsWith("image/") || item.type.startsWith("video/")),
			)
			.map((item) => item.getAsFile())
			.filter((f): f is File => f !== null);
		if (files.length === 0) return;
		e.preventDefault();
		void addFiles(files);
	};

	const canSend = draft.trim().length > 0 || draftAttachments.length > 0;
	const submit = () => {
		if (!canSend) return;
		onSend(
			draft.trim(),
			draftAttachments.map((d) => ({ bytes: d.bytes, mimeType: d.mimeType })),
		);
		setDraft("");
		setDraftAttachments([]);
	};
	// Enter is handled on keydown rather than via a <form>: the e2e load
	// harness dispatches a synthetic keydown, which never submits a form.
	return (
		<div className="compose" data-testid="chat-form">
			{draftAttachments.length > 0 && (
				<div className="draft-row">
					{draftAttachments.map((d) => (
						<DraftChip
							key={d.id}
							draft={d}
							onRemove={() =>
								setDraftAttachments((prev) => prev.filter((x) => x.id !== d.id))
							}
						/>
					))}
				</div>
			)}
			<input
				name="chat-message"
				placeholder={COMPOSE_PLACEHOLDER[state]}
				value={draft}
				disabled={disabled}
				data-testid="text"
				onChange={(e) => setDraft(e.target.value)}
				onPaste={onPaste}
				onKeyDown={(e) => {
					if (e.key === "Enter") submit();
				}}
			/>
			<input
				type="file"
				accept="image/*,video/*"
				multiple
				data-testid="attachment-file"
				hidden
				ref={fileInputRef}
				onChange={(e) => void pickFiles(e)}
			/>
			<Tooltip tip="Attach images or videos">
				<button
					type="button"
					className="sign sign--outline sign--icon"
					aria-label="Attach images or videos"
					disabled={disabled}
					onClick={() => fileInputRef.current?.click()}
				>
					<Icon name="paperclip" />
				</button>
			</Tooltip>
			<button
				type="button"
				className="sign sign--primary"
				disabled={disabled || !canSend}
				onClick={submit}
			>
				<Icon name="send" />
				Send
			</button>
		</div>
	);
}

/** The logged-in identity at the end of the room masthead's tool row. */
function NostrIdentity() {
	const pubkey = useMoqtChatStore((s) => s.nostrPubkey);
	if (!pubkey) return null;
	return (
		<span className="account__who" data-testid="nostr-identity">
			<NostrAuthor pubkey={pubkey} />
		</span>
	);
}

/** The video area's placeholder until the session is (back) up. */
function Connecting() {
	const state = useMoqtChatStore((s) => s.connectionState);
	if (state === "connected") return null;
	const lost = state === "disconnected";
	return (
		<p className="skeleton" data-testid="video-connecting" data-status={state}>
			<Icon name={lost ? "alert" : "spinner"} />
			{lost ? "Disconnected" : "Connecting…"}
		</p>
	);
}

// The minimum pane heights the splitter keeps: --control-h (44px) times
// φ² for the stage, φ³ for the chat (the composer and two posts).
const STAGE_MIN_PX = 44 * 2.618;
const CHAT_MIN_PX = 44 * 4.236;

/** The main column: the stage on top (the share while one is live, else
 * the cameras), the chat below, both full width, split by a separator
 * that drags (pointer) or steps (arrows, Home / End). The phone shows one
 * pane at a time and hides the separator (CSS). */
function RoomMain({
	stage,
	children,
}: {
	stage: (share: boolean) => React.ReactNode;
	children: React.ReactNode;
}) {
	const mode = useMoqtChatStore((s) =>
		stageMode(s.screenSharing, s.screenTiles, s.stalledScreenTiles),
	);
	const [ratios, setRatios] = useState(() => ({
		share: loadSplit("share"),
		camera: loadSplit("camera"),
	}));
	const ref = useRef<HTMLDivElement>(null);
	// The stage and chat share the column less the splitter (--s-3, 16px).
	// Clamped on every render: a loaded ratio, a resize, a mode switch.
	const total = useSize(ref).h - 16;
	const keep = (r: number) =>
		total > 0 ? clampSplit(r, total, STAGE_MIN_PX, CHAT_MIN_PX) : r;
	const ratio = keep(ratios[mode]);
	const latest = useRef(ratio);
	latest.current = ratio;
	const grab = useRef(0);
	const set = (r: number) => {
		latest.current = keep(r);
		setRatios((p) => ({ ...p, [mode]: latest.current }));
	};
	const start = (e: React.PointerEvent<HTMLDivElement>) => {
		if (e.button !== 0) return;
		e.preventDefault();
		grab.current = e.clientY - e.currentTarget.getBoundingClientRect().top;
		e.currentTarget.setPointerCapture(e.pointerId);
		ref.current?.setAttribute("data-dragging", "");
	};
	const drag = (e: React.PointerEvent<HTMLDivElement>) => {
		const top = ref.current?.getBoundingClientRect().top ?? 0;
		if (e.currentTarget.hasPointerCapture(e.pointerId))
			set((e.clientY - grab.current - top) / total);
	};
	const end = () => {
		ref.current?.removeAttribute("data-dragging");
		saveSplit(mode, latest.current);
	};
	return (
		<div ref={ref} className="room-main">
			<section className="stage" aria-label="Video" style={{ flexGrow: ratio }}>
				{stage(mode === "share")}
			</section>
			{/* biome-ignore lint/a11y/useSemanticElements: a focusable WAI-ARIA window splitter, not a thematic <hr> */}
			<div
				role="separator"
				tabIndex={0}
				className="splitter"
				data-testid="splitter"
				aria-label="Resize video and chat"
				aria-orientation="horizontal"
				aria-valuemin={Math.round(keep(0) * 100)}
				aria-valuemax={Math.round(keep(1) * 100)}
				aria-valuenow={Math.round(ratio * 100)}
				onPointerDown={start}
				onPointerMove={drag}
				onPointerUp={end}
				onPointerCancel={end}
				onKeyDown={(e) => {
					const r = splitKey(ratio, e.key);
					if (r === null) return;
					e.preventDefault();
					set(r);
					saveSplit(mode, latest.current);
				}}
			/>
			<section
				className="chat"
				aria-label="Chat"
				style={{ flexGrow: 1 - ratio }}
			>
				{children}
			</section>
		</div>
	);
}

// A final screen (roomClosed) replaces the connect error notice.
const whileOpen = <T,>(roomClosed: string | null, v: T) =>
	roomClosed ? null : v;

export default function Home() {
	const [url, setUrl] = useState(DEFAULT_URL);
	const [certHash, setCertHash] = useState("");
	const [nickname, setNickname] = useState("");
	const [participantId, setParticipantId] = useState(DEFAULT_PARTICIPANT_ID);
	const [joined, setJoined] = useState(false);
	const [relaysText, setRelaysText] = useState(DEFAULT_RELAYS_TEXT);
	const [room, setRoom] = useState<RoomLink | null>(null);
	const [roomError, setRoomError] = useState<string | null>(null);
	const {
		connect,
		sendMessage,
		toggleMute,
		leave,
		micError,
		connectError,
		startScreenShare,
		stopScreenShare,
		registerScreenCanvas,
		setOutputDevice,
		setScreenQuality,
		toggleVideoSource,
		pickVideoFile,
		setVideoBackground,
		registerCameraCanvas,
	} = useMoqtChat();
	const connectionState = useMoqtChatStore((s) => s.connectionState);
	const screenSharing = useMoqtChatStore((s) => s.screenSharing);
	const screenShareError = useMoqtChatStore((s) => s.screenShareError);
	const messageSendError = useMoqtChatStore((s) => s.messageSendError);
	const roomClosed = useMoqtChatStore((s) => s.roomClosed);
	const [view, setView] = useState<RoomView>("video");
	useHandToasts();

	// Switch to the chat screen once the connection is established.
	useEffect(
		() =>
			useMoqtChatStore.subscribe((s) => {
				if (s.connectionState === "connected") setJoined(true);
			}),
		[],
	);

	// Restore the join form from the last visit. Deferred a tick, not in the
	// initial state: the page is statically prerendered (no localStorage until
	// hydration), and a synchronous setState inside the effect would both
	// trip the react-hooks rule and risk a hydration mismatch.
	useEffect(() => {
		const t = window.setTimeout(() => {
			const saved = loadJoinPrefs();
			if (!saved) return;
			setUrl(saved.url);
			setCertHash(saved.certHash);
			if (saved.name) setParticipantId(saved.name);
			if (saved.nickname) setNickname(saved.nickname);
			if (saved.relays) setRelaysText(saved.relays.join("\n"));
		}, 0);
		return () => window.clearTimeout(t);
	}, []);

	// The room comes from the page URL (?room=&host=), read once after
	// hydration like the saved prefs above; without one, Create room.
	useEffect(() => {
		const t = window.setTimeout(() => {
			const { link, error } = parseRoomLink(window.location.search);
			if (link) enterRoom(link);
			setRoom(link ?? null);
			setRoomError(error ?? null);
		}, 0);
		return () => window.clearTimeout(t);
	}, []);

	// The profile relays in effect: ?relays= (e2e) wins over the user's list.
	useEffect(() => {
		useMoqtChatStore
			.getState()
			.setNostrRelays(
				nostrRelays(window.location.search, parseRelayList(relaysText)),
			);
	}, [relaysText]);

	const clearSaved = () => {
		clearJoinPrefs();
		setUrl(DEFAULT_URL);
		setCertHash("");
		setNickname("");
		setParticipantId(DEFAULT_PARTICIPANT_ID);
		setRelaysText(DEFAULT_RELAYS_TEXT);
	};

	const connecting = connectionState === "connecting";
	const pins = certHash.trim() ? [certHash.trim()] : [];
	const lost = joined && connectionState === "disconnected";
	// Leave, or a final close reason (at once, not on Back): the session,
	// mic, camera and screen capture stop and the room tools go.
	const exit = () => {
		leave();
		setJoined(false);
		setView("video");
		exitRoom();
	};
	// The tablet drawer closes on Esc or its Close, focus back on its toggle.
	// On a phone the toggle is hidden and People is a tab: Esc leaves it be.
	const closeDrawer = useCallback(() => {
		const toggle = document.getElementById("room-drawer-toggle");
		if (!toggle?.getClientRects().length) return;
		setView("video");
		toggle.focus();
	}, []);
	useEscToClose(view === "people", closeDrawer);
	useEndOnRoomClosed(exit);

	useEffect(() => {
		if (!joined) return;
		const onKey = (e: KeyboardEvent) => {
			if (isMuteShortcut(e)) toggleMute();
		};
		window.addEventListener("keydown", onKey);
		return () => window.removeEventListener("keydown", onKey);
	}, [joined, toggleMute]);

	return (
		<main className={joined ? "page page--room" : "page"}>
			<header className="masthead">
				<div className="masthead__brand">
					<Wordmark height="2em" />
					<span className="masthead__stem">Chat</span>
				</div>
				{joined ? (
					<div className="masthead__tools">
						<Status />
						<MicToggle onToggleMute={toggleMute} />
						<NoiseSuppressionToggle />
						<HandToggle />
						<ScreenShareToggle
							sharing={screenSharing}
							onStart={() => void startScreenShare()}
							onStop={stopScreenShare}
						/>
						<button type="button" className="sign sign--outline" onClick={exit}>
							<Icon name="leave" />
							Leave
						</button>
						<NostrIdentity />
					</div>
				) : (
					<div className="masthead__end">
						<p className="masthead__id">
							Media over QUIC Transport
							<br />
							draft-ietf-moq-transport-23
						</p>
						<NostrAccount setNickname={setNickname} />
					</div>
				)}
			</header>
			<hr className="rule" />

			<Notice
				title="Connection lost"
				message={lost ? "The session to the hub was closed." : null}
			>
				<button
					type="button"
					className="sign sign--outline"
					onClick={() => void connect(url, participantId, pins, nickname)}
				>
					<Icon name="rejoin" />
					Rejoin
				</button>
			</Notice>
			<Notice
				title="Could not connect"
				message={whileOpen(roomClosed, connectError)}
			/>
			<Notice message={micError} />
			{/* Here, not in the stage: an auto-stop that removed the last share
          tile also unmounts the share stage, and the message must stay. */}
			<Notice message={screenShareError} />
			<Notice message={messageSendError} />

			{roomClosed ? (
				<RoomClosed
					token={roomClosed}
					onBack={() => useMoqtChatStore.getState().setRoomClosed(null)}
				/>
			) : joined ? (
				<div className="room" data-view={view}>
					<RoomHead view={view} onView={setView} />
					<aside className="rail" id="room-rail">
						<button
							type="button"
							className="sign sign--outline rail__close"
							onClick={closeDrawer}
						>
							<Icon name="x" />
							Close
						</button>
						<Peers />
						<Volume />
						<details className="settings" data-testid="settings">
							<summary>
								<Icon name="settings" />
								Settings
								<Icon name="chevron" />
							</summary>
							<VideoSection
								connected={connectionState === "connected"}
								onToggle={toggleVideoSource}
								onBackground={setVideoBackground}
								onPickFile={pickVideoFile}
							/>
							<OutputDevice onSelect={setOutputDevice} />
						</details>
					</aside>
					<RoomMain
						stage={(share) => (
							<>
								<Connecting />
								{share ? (
									<ScreenTiles
										registerScreenCanvas={registerScreenCanvas}
										setScreenQuality={setScreenQuality}
									/>
								) : (
									<VideoGrid registerCameraCanvas={registerCameraCanvas} />
								)}
							</>
						)}
					>
						<MessageList
							onRetry={(m) =>
								retryMessage(m, sendMessage, useMoqtChatStore.getState())
							}
						/>
						<Compose
							onSend={(text, attachments) =>
								void sendMessage(text, attachments)
							}
							onAttachmentRejected={(reason) =>
								useMoqtChatStore.getState().setMessageSendError(reason)
							}
							state={connectionState}
						/>
					</RoomMain>
					<RoomTabs view={view} onView={setView} />
				</div>
			) : (
				<JoinScreen
					url={url}
					setUrl={setUrl}
					certHash={certHash}
					setCertHash={setCertHash}
					nickname={nickname}
					setNickname={setNickname}
					participantId={participantId}
					setParticipantId={setParticipantId}
					connecting={connecting}
					onJoin={() => {
						saveJoinPrefs({
							url,
							certHash,
							name: participantId,
							nickname,
							relays: parseRelayList(relaysText),
						});
						void connect(url, participantId, pins, nickname);
					}}
					onClearSaved={clearSaved}
					relaysText={relaysText}
					setRelaysText={setRelaysText}
					room={room}
					roomError={roomError}
					setRoom={setRoom}
				/>
			)}
			<Toast />
			<footer className="folio">MOQT Chat · wired</footer>
		</main>
	);
}
