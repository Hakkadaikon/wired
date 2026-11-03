// S22 camera: user1 turns the camera on, picks the image background,
// switches to the bundled mp4, and turns it off. user2 watches the whole
// time; user3 joins while the mp4 is streaming.
//
// Chrome's fake camera shows no person, so with the image background the
// segmenter keeps none of the frame and the tile turns the bundled
// image's blue; without a background the fake camera's green shows. The
// mp4 is 480x270, unlike the fake camera, so its frames are told apart by
// size.
//
//   just e2e-stability s22-camera

import { closeClient, joinStabilityClient } from "../lib/stabilityClient.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const TAP_SCRIPT = "window.__wiredCameraTap = [];";
const MP4 = { width: 480, height: 270 };

const tileSelector = (sender) => `[data-testid="camera-tile-${sender}"] canvas`;

// Mean RGB of the sender's camera tile as the viewer sees it.
const tileColour = (client, sender) =>
	client.page.evaluate((sel) => {
		const canvas = document.querySelector(sel);
		if (!canvas?.width) return null;
		const ctx = canvas.getContext("2d");
		const { data } = ctx.getImageData(0, 0, canvas.width, canvas.height);
		const sum = [0, 0, 0];
		for (let i = 0; i < data.length; i += 4)
			for (let c = 0; c < 3; c++) sum[c] += data[i + c];
		const n = data.length / 4;
		return sum.map((s) => Math.round(s / n));
	}, tileSelector(sender));

const framesSince = (client, sender, t0) =>
	client.page.evaluate(
		(s, t) =>
			(window.__wiredCameraTap ?? []).filter(
				(e) => e.senderId === s && e.t >= t,
			),
		sender,
		t0,
	);

const now = (client) => client.page.evaluate(() => performance.now());

async function waitFor(check, timeoutMs) {
	const end = Date.now() + timeoutMs;
	for (;;) {
		const v = await check();
		if (v) return v;
		if (Date.now() > end) return null;
		await sleep(250);
	}
}

const isBlue = (rgb) => rgb && rgb[2] > rgb[1] + 30 && rgb[2] > rgb[0] + 30;
const isGreen = (rgb) => rgb && rgb[1] > rgb[2] + 30 && rgb[1] > rgb[0] + 30;
const isMp4 = (e) => e.width === MP4.width && e.height === MP4.height;

async function lastFrameSize(viewer, sender, t0) {
	const frames = await framesSince(viewer, sender, t0);
	return frames.at(-1);
}

export async function run({ pageUrl, serverUrl, server, log }) {
	const opts = (tag) => ({
		pageUrl,
		serverUrl,
		certHash: server.certHash,
		participantId: tag,
		initScripts: [TAP_SCRIPT],
	});
	const failures = [];
	const report = {};
	const clients = [];
	const select = (c, value) =>
		c.page.select('[data-testid="background-select"]', value);
	try {
		const user1 = await joinStabilityClient(opts("user1"));
		const user2 = await joinStabilityClient(opts("user2"));
		clients.push(user1, user2);
		await sleep(1000);

		log("user1 turns the camera on");
		let t0 = await now(user2);
		await user1.page.click('[data-testid="camera-toggle"]');
		const first = await waitFor(() => lastFrameSize(user2, "user1", t0), 15000);
		if (!first) failures.push("user2 never decoded user1's camera");
		else report.cameraSize = `${first.width}x${first.height}`;
		if (first && isMp4(first))
			failures.push("camera frames already have the mp4's size");
		report.rawColour = await waitFor(async () => {
			const rgb = await tileColour(user2, "user1");
			return isGreen(rgb) ? rgb : null;
		}, 5000);
		if (!report.rawColour)
			failures.push(
				`raw camera tile is not the fake camera's green: ${await tileColour(user2, "user1")}`,
			);

		log("user1 picks the image background");
		await select(user1, "image");
		report.imageColour = await waitFor(async () => {
			const rgb = await tileColour(user2, "user1");
			return isBlue(rgb) ? rgb : null;
		}, 30000);
		if (!report.imageColour)
			failures.push(
				`image background never reached user2: ${await tileColour(user2, "user1")}`,
			);

		log("user1 switches to the video file");
		t0 = await now(user2);
		await user1.page.click('[data-testid="video-file-toggle"]');
		const mp4 = await waitFor(async () => {
			const f = await lastFrameSize(user2, "user1", t0);
			return f && isMp4(f) ? f : null;
		}, 15000);
		if (!mp4)
			failures.push(
				`user2 never got mp4-sized frames: ${JSON.stringify(await lastFrameSize(user2, "user1", t0))}`,
			);
		report.cameraOffAfterSwitch = await user1.page.evaluate(
			() =>
				document
					.querySelector('[data-testid="camera-toggle"]')
					?.getAttribute("aria-pressed") !== "true",
		);
		if (!report.cameraOffAfterSwitch)
			failures.push("camera toggle still on after switching to the file");

		log("user3 joins while the file streams");
		const user3 = await joinStabilityClient(opts("user3"));
		clients.push(user3);
		const late = await waitFor(async () => {
			const f = await lastFrameSize(user3, "user1", 0);
			return f && isMp4(f) ? f : null;
		}, 15000);
		if (!late) failures.push("late joiner never decoded the mp4 stream");

		log("user1 turns the video file off");
		const tOff = await now(user2);
		await user1.page.click('[data-testid="video-file-toggle"]');
		const gone = await waitFor(
			() =>
				user2.page.evaluate(
					() => !document.querySelector('[data-testid="camera-tile-user1"]'),
				),
			10000,
		);
		if (!gone) failures.push("user1's camera tile stayed after off");
		// Frames still decoded a second after off mean the sender kept sending.
		report.framesAfterOff = (
			await framesSince(user2, "user1", tOff + 1000)
		).length;
		if (report.framesAfterOff)
			failures.push(`${report.framesAfterOff} frames arrived after off`);

		for (const c of clients)
			if (c.errors.length)
				failures.push(`${c.tag} page errors: ${c.errors.join("; ")}`);
	} finally {
		for (const c of clients) await closeClient(c);
	}
	return { report, failures };
}
