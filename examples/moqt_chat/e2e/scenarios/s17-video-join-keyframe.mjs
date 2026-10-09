// S17 video-join-keyframe: a late viewer decodes a running screen share
// at once instead of waiting for the next keyframe. user1 shares (a fake
// screen, 10 fps, a keyframe -- and with it a new Group -- every 2 s);
// user2 joins mid-Group. Its screen subscription carries a fill
// (draft-ietf-moq-transport-22 3.4-3.5: FILL_PARAMETERS, RelativeStart 1;
// draft-19 fallback 10.12.2: Relative Joining FETCH, Joining Start 0),
// which hands it the current Group from its keyframe, so the
// first frame decodes well before the next keyframe would arrive.
//
//   just e2e-stability s17-video-join-keyframe

import { FAKE_DISPLAY_MEDIA_SCRIPT } from "../lib/screenShareFake.mjs";
import { joinStabilityClient, closeClient } from "../lib/stabilityClient.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const framesFrom = (client, sender) =>
  client.page.evaluate((s) => (window.__wiredScreenTap ?? []).filter((e) => e.senderId === s).length, sender);

export async function run({ pageUrl, serverUrl, server, arg, log }) {
  const firstFrameMaxMs = Number(arg("first-frame-max-ms", "1500"));
  const opts = (tag) => ({
    pageUrl,
    serverUrl,
    certHash: server.certHash,
    participantId: tag,
    initScripts: [FAKE_DISPLAY_MEDIA_SCRIPT],
  });
  const failures = [];
  const report = { firstFrameMaxMs };
  const clients = [];
  try {
    const user1 = await joinStabilityClient(opts("user1"));
    clients.push(user1);
    await sleep(1000); // let the session's requests settle before sharing
    log("user1 shares");
    await user1.page.click('[data-testid="screen-toggle"]');
    // Land mid-Group: 1 s into a 2 s keyframe interval, after a few Groups.
    await sleep(5000);

    log("user2 joins late");
    const user2 = await joinStabilityClient(opts("user2"));
    clients.push(user2);
    const start = Date.now();
    try {
      await user2.page.waitForFunction(
        () => (window.__wiredScreenTap ?? []).some((e) => e.senderId === "user1"),
        { timeout: 15000 },
      );
      report.firstFrameMs = Date.now() - start;
    } catch {
      failures.push("late viewer never decoded user1's share");
    }
    if (report.firstFrameMs > firstFrameMaxMs)
      failures.push(`first frame after ${report.firstFrameMs}ms > ${firstFrameMaxMs}ms`);
    await sleep(2000);
    report.framesAfter2s = await framesFrom(user2, "user1");
    if (report.framesAfter2s < 5) failures.push(`only ${report.framesAfter2s} frames in the 2 s after the first`);

    for (const c of clients) if (c.errors.length) failures.push(`${c.tag} page errors: ${c.errors.join("; ")}`);
  } finally {
    for (const c of clients) await closeClient(c);
  }
  return { report, failures };
}
