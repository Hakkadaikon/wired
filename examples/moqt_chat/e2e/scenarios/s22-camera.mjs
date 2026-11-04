// S22 camera: user1 turns the camera on, picks the blur and then the image
// background, switches to the bundled mp4, and turns it off. user2 watches
// the whole time; user3 joins while the mp4 is streaming, then shows its
// own camera and crashes. Last, user1's camera is live when the hub dies.
//
// Chrome's fake camera shows no person, so with the image background the
// segmenter keeps none of the frame and the tile turns the bundled
// image's blue; without a background, or blurred, the fake camera's green
// shows. The mp4 is 480x270, unlike the fake camera, so its frames are
// told apart by size.
//
//   just e2e-stability s22-camera

import {
	closeClient,
	crashClient,
	joinStabilityClient,
} from "../lib/stabilityClient.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const TAP_SCRIPT = "window.__wiredCameraTap = [];";
const MP4 = { width: 480, height: 270 };

const tileSelector = (sender) => `[data-testid="camera-tile-${sender}"] canvas`;

// Mean RGB of a canvas: a sender's camera tile, or the own preview.
const canvasColour = (client, selector) =>
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
	}, selector);
const tileColour = (client, sender) =>
	canvasColour(client, tileSelector(sender));

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

const select = (c, value) =>
	c.page.select('[data-testid="background-select"]', value);

// Blur keeps frames flowing and, with no person, the camera's green. Raw
// frames stop the moment blur is picked, so a frame decoded well after it
// (past the in-flight ones) can only be a blurred one.
async function blurStep({ user1, user2, report, failures, log }) {
	log("user1 picks the blur background");
	const tBlur = await now(user2);
	await select(user1, "blur");
	const framesAfterBlur = await waitFor(
		async () => (await framesSince(user2, "user1", tBlur + 3000)).length > 0,
		30000,
	);
	if (!framesAfterBlur)
		failures.push("user2 got no blurred frames after the blur switch");
	// the fake camera blurred is still green; blue would be the image
	// The tile may have stalled out while the segmenter loaded; a fresh
	// tile's canvas is blank until its next frame is drawn.
	report.blurColour = await waitFor(async () => {
		const rgb = await tileColour(user2, "user1");
		return isGreen(rgb) ? rgb : null;
	}, 15000);
	if (!report.blurColour)
		failures.push(
			`blur tile is not green: ${await tileColour(user2, "user1")}`,
		);
}

// A dropped connection releases the camera at once: the badge turning
// "disconnected" and the camera toggle going off land in the same render,
// a second before the first automatic rejoin would tear the session down.
async function dropStep({ user1, user2, server, report, failures, log }) {
	log("user1 turns the camera on again; the hub dies");
	const t0 = await now(user2);
	await user1.page.click('[data-testid="camera-toggle"]');
	if (!(await waitFor(() => lastFrameSize(user2, "user1", t0), 15000)))
		failures.push("user2 never decoded user1's camera before the drop");
	await server.stop("SIGKILL");
	try {
		await user1.page.waitForFunction(
			() =>
				document
					.querySelector('[data-testid="status"]')
					?.getAttribute("data-status") === "disconnected",
			{ timeout: 30000, polling: 50 },
		);
	} catch {
		failures.push("user1 never saw the connection drop");
		return;
	}
	report.cameraOffOnDrop = await user1.page.evaluate(
		() =>
			document
				.querySelector('[data-testid="camera-toggle"]')
				?.getAttribute("aria-pressed") === "false",
	);
	if (!report.cameraOffOnDrop)
		failures.push("camera still on right after the connection dropped");
	// Turning a source on needs a connection; the off source's toggle locks.
	report.toggleLockedOnDrop = await user1.page.evaluate(
		() =>
			document.querySelector('[data-testid="camera-toggle"]')?.disabled ===
			true,
	);
	if (!report.toggleLockedOnDrop)
		failures.push("camera toggle still enabled while disconnected");
}

// The sender sees its own preview, and the viewer's tile names the sender.
async function previewStep({ user1, user2, report, failures }) {
	report.ownPreview = await waitFor(async () => {
		const rgb = await canvasColour(
			user1,
			'[data-testid="camera-tile-own"] canvas',
		);
		return isGreen(rgb) ? rgb : null;
	}, 5000);
	if (!report.ownPreview) failures.push("user1's own preview shows no camera");
	report.tileLabel = await user2.page.evaluate(
		() =>
			document.querySelector('[data-testid="camera-tile-user1"]')?.textContent,
	);
	if (!report.tileLabel?.includes("user1"))
		failures.push(`user1's tile is not labelled: ${report.tileLabel}`);
}

// A sender that vanishes without withdrawing its namespace (its browser is
// killed; the hub only notices at its idle timeout) loses its tile once its
// frames stall, a few seconds after the last one.
async function stallStep({ user2, user3, report, failures, log }) {
	log("user3 turns the camera on, then its browser dies");
	const t0 = await now(user2);
	await user3.page.click('[data-testid="camera-toggle"]');
	if (!(await waitFor(() => lastFrameSize(user2, "user3", t0), 15000))) {
		failures.push("user2 never decoded user3's camera");
		return;
	}
	await crashClient(user3);
	const crashAt = Date.now();
	const gone = await waitFor(
		() =>
			user2.page.evaluate(
				() => !document.querySelector('[data-testid="camera-tile-user3"]'),
			),
		15000,
	);
	report.stallRemovalMs = gone ? Date.now() - crashAt : null;
	// 3 s stall threshold + the drain tick + slack; the hub's 30 s idle
	// timeout (the withdrawal path) is far past it.
	if (!gone || report.stallRemovalMs > 8000)
		failures.push(
			`user3's stalled tile stayed ${report.stallRemovalMs ?? ">15000"}ms`,
		);
}

// Off removes the tile, and no frame is decoded a second after it.
async function offStep({ user1, user2, report, failures, log }) {
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
	// Frames still decoded a second after off mean the sender kept sending;
	// give that second and more time to pass before counting.
	await waitFor(async () => (await now(user2)) > tOff + 2500, 10000);
	report.framesAfterOff = (
		await framesSince(user2, "user1", tOff + 1000)
	).length;
	if (report.framesAfterOff)
		failures.push(`${report.framesAfterOff} frames arrived after off`);
	const back = await user2.page.evaluate(
		() => !!document.querySelector('[data-testid="camera-tile-user1"]'),
	);
	if (back) failures.push("user1's camera tile came back after off");
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
	try {
		const user1 = await joinStabilityClient(opts("user1"));
		const user2 = await joinStabilityClient(opts("user2"));
		clients.push(user1, user2);
		const ctx = { user1, user2, report, failures, log };
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
		await previewStep(ctx);

		await blurStep(ctx);

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
		await stallStep({ ...ctx, user3 });

		await offStep(ctx);
		await dropStep({ ...ctx, server });

		for (const c of clients)
			if (c.errors.length)
				failures.push(`${c.tag} page errors: ${c.errors.join("; ")}`);
	} finally {
		for (const c of clients) await closeClient(c);
	}
	return { report, failures };
}
