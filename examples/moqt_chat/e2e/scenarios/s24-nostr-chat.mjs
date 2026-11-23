// S24 nostr-chat: NIP-07 login and kind 1311 chat over the MoQ hub. user1
// and user2 get a mocked window.nostr (signing happens here in Node with a
// fixed test key per user, via page.exposeFunction), log in, and exchange
// messages; each must show the other's message with the author's short
// npub (the name fallback) and the Room list must name the other by the
// pubkey of its verified event. user3 has no extension: it still sends in
// the old format (shown under its participant id) and still sees the Nostr
// messages. `?relays=` keeps every page off the public profile relays, so
// names stay npubs. A received message carries the verified check, and its
// "⋯" toggle shows the verified event JSON.
//
//   just e2e-stability s24-nostr-chat

import { getPublicKey } from "nostr-tools/pure";
import {
	keyOf,
	nostrLogin,
	sendChat,
	shortNpub,
	WAIT_MS,
} from "../lib/nostrE2e.mjs";
import { closeClient, joinStabilityClient } from "../lib/stabilityClient.mjs";

// The sender label of a Nostr message with no profile name (?relays=).
const nostrLabel = (pk) => shortNpub(pk);

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
			// A Nostr author with no profile shows its short npub; a legacy
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

// The Room list names the peer by its verified event's pubkey.
async function checkRoomList(client, pk, report) {
	report.roomList = await client.page
		.waitForFunction(
			(want) =>
				Array.from(document.querySelectorAll(".peers .nostr-author"))
					.map((a) => a.textContent)
					.find((t) => t === want),
			{ timeout: WAIT_MS },
			nostrLabel(pk),
		)
		.then((h) => h.jsonValue())
		.catch(() => null);
	return report.roomList === nostrLabel(pk)
		? []
		: [`room list lacks ${nostrLabel(pk)}`];
}

// The check is labelled; "⋯" opens, relabels, and closes the raw panel.
async function checkFoot(client, sender, text, report) {
	const foot = await client.page.evaluate(
		async (s, t) => {
			const m = Array.from(
				document.querySelectorAll(
					`[data-testid="message"][data-sender="${s}"]`,
				),
			).find((x) => x.textContent.includes(t));
			const mark = m?.querySelector('[data-testid="nostr-verified"]');
			const btn = m?.querySelector('[data-testid="nostr-raw-toggle"]');
			const tick = () => new Promise((r) => setTimeout(r, 100));
			const panel = () =>
				m?.querySelector('[data-testid="nostr-raw"]')?.textContent ?? null;
			btn?.click();
			await tick();
			const open = [btn?.getAttribute("aria-label"), panel()];
			btn?.click();
			await tick();
			return {
				mark: mark?.getAttribute("aria-label"),
				text: btn?.textContent,
				openLabel: open[0],
				rawPanel: open[1],
				closed: panel() === null,
			};
		},
		sender,
		text,
	);
	Object.assign(report, foot);
	const failures = [];
	const raw = foot.rawPanel ?? "";
	if (!raw.includes("verified") || !raw.includes(`"content": "${text}"`))
		failures.push(`raw panel missing the event: ${raw}`);
	if (foot.mark !== "Verified Nostr event")
		failures.push(`verified check label: ${foot.mark}`);
	const toggles =
		foot.text === "⋯" && foot.openLabel === "Hide raw Nostr event";
	if (!toggles || !foot.closed)
		failures.push(`⋯ toggle: ${JSON.stringify(foot)}`);
	return failures;
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

		failures.push(...(await checkRoomList(user2, pk1, report)));
		failures.push(...(await checkFoot(user2, pk1, m1, report)));

		for (const c of clients) {
			if (c.errors.length > 0)
				failures.push(`${c.tag} page errors: ${c.errors.join("; ")}`);
		}
	} finally {
		for (const c of clients) await closeClient(c);
	}
	return { report, failures };
}
