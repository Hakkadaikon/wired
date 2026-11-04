// S23 voice-stream: user1's session has no datagram path, so its voice
// falls back to the long-lived uni stream (moqtVoiceClient.ts) and reaches
// user2 through the room's uni-stream routing rather than as datagrams.
// user2 must decode it. Only user1 is forced onto the stream: with every
// client sending voice that way the hub drops stream opens and starves
// other tracks, which is not what this checks.
//
//   just e2e-stability s23-voice-stream

import {
	closeClient,
	joinStabilityClient,
	waitFirstDecode,
} from "../lib/stabilityClient.mjs";

const VOICE_ON_STREAM_SCRIPT = `{
	const D = window.WebTransportDatagramDuplexStream;
	if (D) Object.defineProperty(D.prototype, "maxDatagramSize", { get: () => undefined });
}`;

export async function run({ pageUrl, serverUrl, server, log }) {
	const opts = (tag, initScripts) => ({
		pageUrl,
		serverUrl,
		certHash: server.certHash,
		participantId: tag,
		initScripts,
	});
	const failures = [];
	const report = {};
	const clients = [];
	try {
		log("user1 joins without datagrams; user2 joins");
		clients.push(
			await joinStabilityClient(opts("user1", [VOICE_ON_STREAM_SCRIPT])),
		);
		const user2 = await joinStabilityClient(opts("user2", []));
		clients.push(user2);
		log("user2 hears user1");
		report.voiceOnStream = await waitFirstDecode(user2, {
			timeoutMs: 20000,
		}).then(
			() => true,
			() => false,
		);
		if (!report.voiceOnStream)
			failures.push("user2 never decoded user1's voice sent on the stream");
		for (const c of clients)
			if (c.errors.length)
				failures.push(`${c.tag} page errors: ${c.errors.join("; ")}`);
		return { report, failures };
	} finally {
		for (const c of clients) await closeClient(c);
	}
}
