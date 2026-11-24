// The join form's pure checks: what the card shows and why Join or Create
// room stays disabled.
import { parseCertHash } from "./certHash";

/** A fingerprint as its first 8 … last 8 hex digits (colons dropped). */
export function shortHash(hash: string): string {
	const hex = hash.replace(/[:\s]/g, "");
	return hex.length <= 16 ? hex : `${hex.slice(0, 8)}…${hex.slice(-8)}`;
}

/** Why the server URL cannot be joined, or null when it can. */
export function urlError(url: string): string | null {
	if (!url.trim()) return "Enter the server URL";
	if (!URL.canParse(url)) return "Enter a full URL, e.g. https://host:4433/";
	// new URL().hash is "" for a bare "#", which WebTransport still refuses.
	if (url.includes("#")) return "Remove the #fragment from the URL";
	if (new URL(url).protocol !== "https:")
		return "WebTransport needs an https:// URL";
	return null;
}

/** Why the certificate hash is unusable, or null (empty = CA-signed). */
export function certHashError(hash: string): string | null {
	if (!hash.trim()) return null;
	if (!/^[0-9a-fA-F:\s]+$/.test(hash)) return "Use hex digits 0-9 and a-f only";
	if (parseCertHash(hash)?.length !== 32)
		return "A SHA-256 hash is 64 hex digits (32 bytes)";
	return null;
}

/** What Create room still needs (a NIP-07 login whose kind 0 has nip05),
 * or null when it may create. */
export function createRoomBlocker(
	pubkey: string | null,
	nip05: string | undefined,
): string | null {
	if (!pubkey)
		return "Log in with Nostr to create a room: you become its host.";
	if (!nip05) return "A NIP-05 address is required to create a room";
	return null;
}

/** Why Join is disabled (no room, or fields to fix), or null. */
export function joinBlocker(hasRoom: boolean, errors: number): string | null {
	if (!hasRoom) return "Create a room or open a room link first";
	if (errors === 0) return null;
	return `Fix ${errors} ${errors === 1 ? "field" : "fields"} in Advanced`;
}
