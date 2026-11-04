// S23 voice-stream: user1's page reports no usable datagram size, so
// moqtVoiceClient.ts sends its voice on the long-lived uni stream instead
// of as datagrams, and user2 receives it through the room's uni-stream
// routing (useMoqtChat.ts's onUnknownUniStream). user2 must decode it.
// Only user1 is moved onto the stream: with every client's voice on
// streams, the run also saw the hub drop stream opens (open_dropped in its
// relay stats) and other tracks starve. That load is outside what this
// scenario checks, and it is not investigated here.
//
//   just e2e-stability s23-voice-stream

import {
	clientMetrics,
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
		const user1 = await joinStabilityClient(
			opts("user1", [VOICE_ON_STREAM_SCRIPT]),
		);
		clients.push(user1);
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
		// The voice really left on a stream: chat streams close right after
		// one message, the voice stream stays open and keeps growing.
		const out = (await clientMetrics(user1))?.wtOutUniStreams ?? [];
		report.voiceStreamBytes = Math.max(
			0,
			...out.filter((s) => s.closed === null).map((s) => s.bytes),
		);
		if (report.voiceStreamBytes < 1000)
			failures.push(
				`user1 sent no voice on a stream (${report.voiceStreamBytes} bytes)`,
			);
		for (const c of clients)
			if (c.errors.length)
				failures.push(`${c.tag} page errors: ${c.errors.join("; ")}`);
		return { report, failures };
	} finally {
		for (const c of clients) await closeClient(c);
	}
}
