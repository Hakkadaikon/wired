// S5b server-restart: 2 voice clients mid-call, server SIGKILLed and
// immediately restarted. Gates: (1) each client's WebTransport detects the
// dead connection fast (fail-fast <= 3s -- needs the server to answer
// unknown-DCID short headers with a stateless reset instead of silently
// dropping them); (2) rejoin against the restarted server completes and
// audio flows again within the rejoin budget.

import {
  joinStabilityClient,
  connectClient,
  waitFirstDecode,
  clientMetrics,
  closeClient,
} from "../lib/stabilityClient.mjs";

export async function run({ pageUrl, server, arg, log }) {
  const failFastMaxMs = Number(arg("fail-fast-max-ms", "3000"));
  const rejoinMaxMs = Number(arg("rejoin-max-ms", "5000"));
  const detectTimeoutMs = Number(arg("detect-timeout-ms", "45000"));
  const failures = [];
  const clients = [];
  for (const tag of ["user1", "user2"]) {
    log(`joining ${tag}`);
    clients.push(
      await joinStabilityClient({ pageUrl, serverUrl: "", certHash: server.certHash, participantId: tag }),
    );
  }
  for (const c of clients) await waitFirstDecode(c);
  log("both clients decoding; SIGKILL + restart server");
  const killAt = Date.now();
  await server.restart("SIGKILL");
  log(`server back (pid ${server.pid}); waiting for clients to notice`);

  const detection = await Promise.all(
    clients.map(async (c) => {
      try {
        await c.page.waitForFunction(
          () => (window.__wtEvents ?? []).some((e) => e.closedAt !== null),
          { timeout: detectTimeoutMs },
        );
        const closedAt = await c.page.evaluate(() =>
          Math.min(...window.__wtEvents.filter((e) => e.closedAt).map((e) => e.closedAt)),
        );
        return { tag: c.tag, detectMs: closedAt - killAt };
      } catch {
        return { tag: c.tag, detectMs: null };
      }
    }),
  );
  for (const d of detection) {
    if (d.detectMs === null) {
      failures.push(`${d.tag}: transport never noticed the dead connection within ${detectTimeoutMs}ms`);
    } else if (d.detectMs > failFastMaxMs) {
      failures.push(`${d.tag}: fail-fast ${d.detectMs}ms > ${failFastMaxMs}ms`);
    }
  }

  const rejoins = [];
  for (const c of clients) {
    await c.page.close().catch(() => {});
    const start = Date.now();
    await connectClient(c, { pageUrl, serverUrl: "", certHash: server.certHash, participantId: c.tag });
    rejoins.push({ tag: c.tag, connectMs: Date.now() - start });
  }
  const redecodeStart = Date.now();
  for (const c of clients) {
    try {
      await waitFirstDecode(c, { timeoutMs: rejoinMaxMs + 10000 });
    } catch {
      failures.push(`${c.tag}: no audio after rejoin`);
    }
  }
  const redecodeMs = Date.now() - redecodeStart;
  for (const r of rejoins) {
    if (r.connectMs > rejoinMaxMs) failures.push(`${r.tag}: rejoin connect ${r.connectMs}ms > ${rejoinMaxMs}ms`);
  }

  const report = { detection, rejoins, redecodeMs, metrics: {} };
  for (const c of clients) {
    report.metrics[c.tag] = await clientMetrics(c);
    delete report.metrics[c.tag]?.voiceTapEvents; // bulky; not graded here
  }
  for (const c of clients) {
    // "Connection lost." is the app's own legitimate reaction to the server
    // dying -- this scenario CAUSES that; only other page errors gate.
    for (const e of c.errors.filter((m) => !m.includes("Connection lost")))
      failures.push(`${c.tag} page error: ${e}`);
    await closeClient(c);
  }
  return { report, failures };
}
