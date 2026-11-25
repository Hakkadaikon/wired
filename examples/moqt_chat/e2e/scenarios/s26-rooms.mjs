// S26 rooms: two rooms on one hub stay apart, in two cases run one after
// the other (each room's first id creates it with its host's key; case 1's
// rooms must end -- the host's Leave ends its room -- before case 2 creates
// rooms with the same hosts: one room per creator, three per hub):
//   distinct ids  room A = user1 + user2, room B = user3 + user4
//   same ids      room C = user1 + user2, room D = user1 + user2
// Each client must see its own peer in the roster and its message, never
// the other room's messages, and (distinct ids) never the other room's
// participants; every client stays connected with no page errors.
//
// Each client stays under its room's namespace wired/moqt_chat/<room>/...,
// and the hub confines every session to its own room (room_hooks.c).
//
//   just e2e-stability s26-rooms

import { sendChat, WAIT_MS } from "../lib/nostrE2e.mjs";
import { leave, waitRoomLog } from "../lib/roomsE2e.mjs";
import {
	closeClient,
	createRoomClient,
	joinStabilityClient,
} from "../lib/stabilityClient.mjs";

// Time given to a leak (a NAMESPACE or a message from the other room) to
// show up after the own room's traffic already did.
const SETTLE_MS = 3000;

const CASES = [
	[
		{ name: "A", ids: ["user1", "user2"], host: 1 },
		{ name: "B", ids: ["user3", "user4"], host: 3 },
	],
	[
		{ name: "C", ids: ["user1", "user2"], host: 1 },
		{ name: "D", ids: ["user1", "user2"], host: 2 },
	],
];

const hasMessage = (client, text) =>
	client.page.evaluate(
		(t) =>
			[...document.querySelectorAll('[data-testid="message"]')].some((m) =>
				m.textContent.includes(t),
			),
		text,
	);

const inRoster = (client, id) =>
	client.page.evaluate(
		(p) => document.querySelector(`[data-testid="quality-${p}"]`) !== null,
		id,
	);

const status = (client) =>
	client.page.evaluate(() =>
		document
			.querySelector('[data-testid="status"]')
			?.getAttribute("data-status"),
	);

async function waitMessage(client, text) {
	try {
		await client.page.waitForFunction(
			(t) =>
				[...document.querySelectorAll('[data-testid="message"]')].some((m) =>
					m.textContent.includes(t),
				),
			{ timeout: WAIT_MS },
			text,
		);
		return true;
	} catch {
		return false;
	}
}

const textOf = (room, id, stamp) => `room-${room.name}-${id}-${stamp}`;

// What `c` must see (its peer, the peer's text, connected) and must not
// (the other room's texts; its ids too when they differ from ours).
async function checkClient(c, other, stamp, failures) {
	const where = `${c.room.name}/${c.tag}`;
	const peer = c.room.ids.find((id) => id !== c.tag);
	if (!(await inRoster(c, peer)))
		failures.push(`${where}: roster lacks ${peer}`);
	if (!(await waitMessage(c, textOf(c.room, peer, stamp))))
		failures.push(`${where}: no message from ${peer}`);
	for (const id of other.ids) {
		if (!c.room.ids.includes(id) && (await inRoster(c, id)))
			failures.push(`${where}: sees ${other.name}/${id}`);
		if (await hasMessage(c, textOf(other, id, stamp)))
			failures.push(`${where}: got ${other.name}/${id}'s text`);
	}
	const s = await status(c);
	if (s !== "connected") failures.push(`${where}: status ${s}`);
	if (c.errors.length > 0)
		failures.push(`${where} page errors: ${c.errors.join("; ")}`);
}

async function runCase(rooms, ctx, report, failures) {
	const { pageUrl, serverUrl, server, log } = ctx;
	const stamp = Date.now();
	const clients = [];
	try {
		for (const room of rooms) {
			for (const id of room.ids) {
				log(`${id} ${room.url ? "joins" : "creates"} room ${room.name}`);
				const opts = {
					pageUrl: room.url ?? pageUrl,
					serverUrl,
					certHash: server.certHash,
					participantId: id,
				};
				const c = room.url
					? await joinStabilityClient(opts)
					: await createRoomClient(opts, room.host);
				room.url ??= c.link;
				c.room = room;
				clients.push(c);
			}
			report[`room${room.name}`] = new URL(room.url).searchParams.get("room");
		}
		for (const c of clients) await sendChat(c, textOf(c.room, c.tag, stamp));
		await new Promise((r) => setTimeout(r, SETTLE_MS));
		for (const c of clients)
			await checkClient(
				c,
				rooms.find((r) => r !== c.room),
				stamp,
				failures,
			);
		for (const c of clients) await leave(c);
	} finally {
		for (const c of clients) await closeClient(c);
	}
	for (const room of rooms)
		if (!(await waitRoomLog(room.url, "end")))
			failures.push(`room ${room.name} did not end`);
}

export async function run(ctx) {
	const failures = [];
	const report = {};
	for (const rooms of CASES) await runCase(rooms, ctx, report, failures);
	return { report, failures };
}
