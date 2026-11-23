// S24 nostr-chat: NIP-07 login and kind 1311 chat over the MoQ hub. user1
// and user2 get a mocked window.nostr (signing happens here in Node with a
// fixed test key per user, via page.exposeFunction), log in, and exchange
// messages; each must show the other's message with the author's short
// npub. user3 has no extension: it still sends in the old format (shown
// under its participant id) and still sees the Nostr messages. `?relays=`
// keeps every page off the public profile relays, so names stay npubs. The
// "{ }" toggle on a received message shows the verified event JSON.
//
//   just e2e-stability s24-nostr-chat

import { npubEncode } from "nostr-tools/nip19";
import { finalizeEvent, getPublicKey } from "nostr-tools/pure";
import { closeClient, joinStabilityClient } from "../lib/stabilityClient.mjs";

const WAIT_MS = 15000;

// Fixed test-only keys: user1 = 0x01.., user2 = 0x02..
const keyOf = (n) => new Uint8Array(32).fill(n);
const shortNpub = (pk) => {
	const npub = npubEncode(pk);
	return `${npub.slice(0, 11)}…${npub.slice(-4)}`;
};
// The sender label of a Nostr message with no profile name (?relays=).
const nostrLabel = (pk) => `${shortNpub(pk)} ✓ verified Nostr`;

// Mocks a NIP-07 extension injected late (after load), then logs in.
function nostrLogin(sk) {
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

async function sendChat(client, text) {
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

// Waits for a message bubble from `sender` (data-sender) containing `text`
// and returns its whole sender label, or null on timeout.
async function labelOf(client, sender, text) {
	try {
		const h = await client.page.waitForFunction(
			(s, t) =>
				Array.from(
					document.querySelectorAll(
						`[data-testid="message"][data-sender="${s}"]`,
					),
				)
					.find((m) => m.textContent.includes(t))
					?.querySelector(".message__sender")?.textContent,
			// A Nostr author shows "<short npub> ✓ verified Nostr"; a legacy
			// sender just its id.
			{ timeout: WAIT_MS },
			sender,
			text,
		);
		return await h.jsonValue();
	} catch {
		return null;
	}
}

export async function run({ pageUrl, serverUrl, server, log }) {
	const url = new URL(pageUrl);
	url.searchParams.set("relays", "");
	const opts = (tag, beforeConnect) => ({
		pageUrl: url.href,
		serverUrl,
		certHash: server.certHash,
		participantId: tag,
		beforeConnect,
	});
	const pk1 = getPublicKey(keyOf(1));
	const pk2 = getPublicKey(keyOf(2));
	const stamp = Date.now();
	const failures = [];
	const report = {};
	const clients = [];
	const expectLabel = async (name, who, sender, text, want) => {
		const got = await labelOf(who, sender, text);
		report[name] = got;
		if (got !== want) failures.push(`${name}: want ${want}, got ${got}`);
	};
	try {
		log("user1, user2 log in with NIP-07; user3 has no extension");
		const user1 = await joinStabilityClient(
			opts("user1", nostrLogin(keyOf(1))),
		);
		clients.push(user1);
		const user2 = await joinStabilityClient(
			opts("user2", nostrLogin(keyOf(2))),
		);
		clients.push(user2);
		const user3 = await joinStabilityClient(opts("user3"));
		clients.push(user3);
		await new Promise((r) => setTimeout(r, 1000));

		const m1 = `nostr-from-1-${stamp}`;
		const m2 = `nostr-from-2-${stamp}`;
		const m3 = `legacy-from-3-${stamp}`;
		await sendChat(user1, m1);
		await sendChat(user2, m2);
		await sendChat(user3, m3);

		await expectLabel("user2 sees user1", user2, pk1, m1, nostrLabel(pk1));
		await expectLabel("user1 sees user2", user1, pk2, m2, nostrLabel(pk2));
		await expectLabel("legacy sees user1", user3, pk1, m1, nostrLabel(pk1));
		await expectLabel("user1 sees legacy", user1, "user3", m3, "user3");
		await expectLabel("own nostr label", user1, "user1", m1, nostrLabel(pk1));

		// The "{ }" toggle shows the verified event as carried on the wire.
		report.rawPanel = await user2.page.evaluate(
			(s, t) => {
				const m = Array.from(
					document.querySelectorAll(
						`[data-testid="message"][data-sender="${s}"]`,
					),
				).find((x) => x.textContent.includes(t));
				m?.querySelector('[data-testid="nostr-raw-toggle"]')?.click();
				return new Promise((r) =>
					setTimeout(
						() => r(m?.querySelector('[data-testid="nostr-raw"]')?.textContent),
						100,
					),
				);
			},
			pk1,
			m1,
		);
		const raw = report.rawPanel ?? "";
		if (!raw.includes("verified") || !raw.includes(`"content": "${m1}"`))
			failures.push(`raw panel missing the event: ${raw}`);

		for (const c of clients) {
			if (c.errors.length > 0)
				failures.push(`${c.tag} page errors: ${c.errors.join("; ")}`);
		}
	} finally {
		for (const c of clients) await closeClient(c);
	}
	return { report, failures };
}
