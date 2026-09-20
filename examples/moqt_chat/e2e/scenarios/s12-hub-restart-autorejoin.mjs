// S12 hub-restart auto-rejoin: 2 voice clients mid-call, hub SIGKILLed and
// restarted, and -- unlike s5b, where the runner reconnects each page by
// hand -- the pages must recover on their OWN. Gates: (1) each page's status
// badge flips to data-status="disconnected" within 3 s of the kill
// (transport-close detection); (2) after the restart, both pages return to
// data-status="connected" within 15 s with no manual rejoin (back-off
// auto-rejoin), audio decode resumes, and each client opened at least one
// more outgoing uni stream (the rejoined session's audio stream).
//
// Caveat this scenario checks explicitly: the hub's cert fingerprint is
// anchored to its boot time, so a restart can change it -- and a page that
// pinned the OLD hash can then never complete the rejoin handshake. A
// changed hash is reported as its own named failure instead of a mystery
// timeout.

import {
  joinStabilityClient,
  waitFirstDecode,
  clientMetrics,
  closeClient,
} from "../lib/stabilityClient.mjs";

export async function run({ pageUrl, server, arg, log }) {
  const detectMaxMs = Number(arg("detect-max-ms", "3000"));
  const rejoinMaxMs = Number(arg("rejoin-max-ms", "15000"));
  const failures = [];
  const clients = [];
  for (const tag of ["user1", "user2"]) {
    log(`joining ${tag}`);
    clients.push(
      await joinStabilityClient({ pageUrl, serverUrl: "", certHash: server.certHash, participantId: tag }),
    );
  }
  for (const c of clients) await waitFirstDecode(c);
  const before = {};
  for (const c of clients) {
    before[c.tag] = await c.page.evaluate(() => ({
      decoded: window.__decodedFrameCount ?? 0,
      uniOpens: window.__uniStreamOpenCount ?? 0,
    }));
  }
  const hashBeforeKill = server.certHash;

  const statusIs = (c, status, timeout) =>
    c.page.waitForFunction(
      (s) =>
        document.querySelector('[data-testid="status"]')?.getAttribute("data-status") === s,
      { timeout, polling: 100 },
      status,
    );

  log("both clients decoding; SIGKILL the hub");
  const killAt = Date.now();
  await server.stop("SIGKILL");
  const detection = await Promise.all(
    clients.map(async (c) => {
      try {
        await statusIs(c, "disconnected", detectMaxMs);
        return { tag: c.tag, detectMs: Date.now() - killAt };
      } catch {
        return { tag: c.tag, detectMs: null };
      }
    }),
  );
  for (const d of detection) {
    if (d.detectMs === null)
      failures.push(`${d.tag}: badge not disconnected within ${detectMaxMs}ms of the kill`);
  }

  log("restarting the hub; waiting for auto-rejoin (no manual reconnect)");
  await server.restart("SIGKILL");
  if (server.certHash !== hashBeforeKill) {
    failures.push(
      "hub cert fingerprint changed across the restart; the pages pinned the old " +
        "hash, so the auto-rejoin handshake cannot succeed",
    );
  }
  const restartAt = Date.now();
  const rejoins = await Promise.all(
    clients.map(async (c) => {
      try {
        await statusIs(c, "connected", rejoinMaxMs);
        return { tag: c.tag, rejoinMs: Date.now() - restartAt };
      } catch {
        return { tag: c.tag, rejoinMs: null };
      }
    }),
  );
  for (const r of rejoins) {
    if (r.rejoinMs === null)
      failures.push(`${r.tag}: not connected again within ${rejoinMaxMs}ms of the restart`);
  }

  const after = {};
  for (const c of clients) {
    try {
      await waitFirstDecode(c, { past: before[c.tag].decoded, timeoutMs: 10000 });
    } catch {
      failures.push(`${c.tag}: audio decode did not resume after the auto-rejoin`);
    }
    after[c.tag] = await c.page.evaluate(() => ({
      decoded: window.__decodedFrameCount ?? 0,
      uniOpens: window.__uniStreamOpenCount ?? 0,
    }));
    if (after[c.tag].uniOpens < before[c.tag].uniOpens + 1) {
      failures.push(
        `${c.tag}: no new outgoing uni stream after the rejoin ` +
          `(${before[c.tag].uniOpens} -> ${after[c.tag].uniOpens})`,
      );
    }
  }

  const report = { detection, rejoins, before, after, metrics: {} };
  for (const c of clients) {
    report.metrics[c.tag] = await clientMetrics(c);
    delete report.metrics[c.tag]?.voiceTapEvents; // bulky; not graded here
  }
  for (const c of clients) {
    // "Connection lost." is the app's own legitimate reaction to the hub
    // dying -- this scenario CAUSES that; only other page errors gate.
    for (const e of c.errors.filter((m) => !m.includes("Connection lost")))
      failures.push(`${c.tag} page error: ${e}`);
    await closeClient(c);
  }
  return { report, failures };
}
