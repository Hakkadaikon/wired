// Nostr helpers shared by the s24/s25/s26 scenarios: fixed test keys, a
// the short-npub label, a mocked NIP-07 extension and the
// chat input.

import { npubEncode } from "nostr-tools/nip19";
import { finalizeEvent, getPublicKey } from "nostr-tools/pure";

export const WAIT_MS = 15000;

// Fixed test-only keys: user1 = 0x01.., user2 = 0x02..
export const keyOf = (n) => new Uint8Array(32).fill(n);
export const pubkeyOf = (n) => getPublicKey(keyOf(n));

/** The sender label of a Nostr author with no profile name (?relays=). */
export function shortNpub(pk) {
	const npub = npubEncode(pk);
	return `${npub.slice(0, 11)}…${npub.slice(-4)}`;
}

/** Mocks a NIP-07 extension injected late (after load), then logs in;
 * signing happens here in Node with sk (page.exposeFunction). */
export function nostrLogin(sk) {
	const pk = getPublicKey(sk);
	return async (page) => {
		await page.exposeFunction("__e2eNostrSign", (t) => finalizeEvent(t, sk));
		await page.evaluate((pubkey) => {
			window.nostr = {
				getPublicKey: async () => pubkey,
				signEvent: (t) => window.__e2eNostrSign(t),
			};
		}, pk);
		await page.click('[data-testid="nostr-login"]');
		await page.waitForSelector('[data-testid="nostr-user"]', {
			timeout: WAIT_MS,
		});
	};
}

/** Types text into the chat input and presses Enter. */
export async function sendChat(client, text) {
	await client.page.evaluate((t) => {
		const input = document.querySelector('input[data-testid="text"]');
		const setter = Object.getOwnPropertyDescriptor(
			window.HTMLInputElement.prototype,
			"value",
		).set;
		setter.call(input, t);
		input.dispatchEvent(new Event("input", { bubbles: true }));
		input.dispatchEvent(
			new KeyboardEvent("keydown", { key: "Enter", bubbles: true }),
		);
	}, text);
}
