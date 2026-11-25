// S4 voice-outage-reconnect: 3 voice clients, each through its own UDP
// proxy flow. One client suffers a burst outage (its packets dropped both
// ways), crashes during it (browser SIGKILL -- the close can never reach
// the server), and rejoins the moment the outage lifts. Gates: the two
// survivors keep decoding each other throughout, and the rejoin is decoding
// audio again within the budget.

import { E2E_PORT } from "../lib/args.mjs";
import {
	clientMetrics,
	closeClient,
	crashClient,
	joinStabilityClient,
	waitFirstDecode,
} from "../lib/stabilityClient.mjs";
import { startUdpProxy } from "../lib/udpProxy.mjs";

const PROXY_BASE = 24433;
// The default room's creator joins through flow 0: the hub's --public-url.
export const publicUrl = `https://127.0.0.1:${PROXY_BASE}`;
const SERVER_PORT = E2E_PORT;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// The crashed user3's session holds its id until the idle timeout, so the
// rejoin is closed id-taken and joins again as the next free id by itself.
// (A login-required room's same-key takeover does not fit here: every
// client signs its own proxy flow's URL, and the hub has one --public-url.)

export async function run({ pageUrl, server, arg, log }) {
	const outageMs = Number(arg("outage-ms", "3000"));
	const rejoinMaxMs = Number(arg("rejoin-max-ms", "5000"));
	const failures = [];
	const proxy = await startUdpProxy({
		listenBase: PROXY_BASE,
		upstreamPort: SERVER_PORT,
		flowCount: 4, // flow 3 is the rejoin's fresh flow
	});
	const opts = (tag, flow) => ({
		pageUrl,
		serverUrl: `https://127.0.0.1:${proxy.port(flow)}/`,
		certHash: server.certHash,
		participantId: tag,
	});

	const survivors = [];
	try {
		for (const [i, tag] of [
			["0", "user1"],
			["1", "user2"],
		].map(([f, t]) => [Number(f), t])) {
			log(`joining ${tag} via proxy flow ${i}`);
			survivors.push(await joinStabilityClient(opts(tag, i)));
		}
		let victim = await joinStabilityClient(opts("user3", 2));
		for (const c of [...survivors, victim]) await waitFirstDecode(c);
		log("room live; starting outage on user3's flow");

		const before = await Promise.all(survivors.map((c) => clientMetrics(c)));
		proxy.outage(2, outageMs);
		await sleep(1000);
		log("crashing user3 mid-outage");
		await crashClient(victim);
		await sleep(outageMs); // let the outage window fully lapse
		log("outage over; user3 rejoins immediately on a fresh flow");
		const t0 = Date.now();
		const report = { metrics: {} };
		victim = await joinStabilityClient(opts("user3", 3));
		let rejoinMs = null;
		try {
			await waitFirstDecode(victim, { timeoutMs: rejoinMaxMs + 10000 });
			rejoinMs = Date.now() - t0;
		} catch {
			failures.push("rejoined user3 never decoded audio");
			// What the rejoined page did: its voice tap by direction, and the
			// notices it shows (a mic / playback error says startVoice failed).
			report.victimProbe = await victim.page
				.evaluate(() => ({
					tap: Object.fromEntries(
						Object.entries(
							Object.groupBy(window.__wiredVoiceTapBuf ?? [], (e) => e.dir),
						).map(([dir, es]) => [dir, es.length]),
					),
					status: document
						.querySelector('[data-testid="status"]')
						?.getAttribute("data-status"),
					notices: [...document.querySelectorAll('[role="alert"]')].map(
						(e) => e.textContent,
					),
				}))
				.catch((e) => String(e));
		}
		if (rejoinMs !== null && rejoinMs > rejoinMaxMs) {
			failures.push(`rejoin ${rejoinMs}ms > ${rejoinMaxMs}ms`);
		}
		await sleep(2000);
		const after = await Promise.all(survivors.map((c) => clientMetrics(c)));
		for (let i = 0; i < survivors.length; i++) {
			if (after[i].decodedFrameCount <= before[i].decodedFrameCount) {
				failures.push(
					`survivor ${survivors[i].tag} stopped decoding across the outage`,
				);
			}
		}

		Object.assign(report, { rejoinMs, proxyStats: proxy.stats() });
		for (const c of [...survivors, victim]) {
			const m = await clientMetrics(c);
			if (m) delete m.voiceTapEvents;
			report.metrics[c.tag] = m;
			for (const e of c.errors) failures.push(`${c.tag} page error: ${e}`);
			await closeClient(c);
		}
		return { report, failures };
	} finally {
		proxy.close();
	}
}
