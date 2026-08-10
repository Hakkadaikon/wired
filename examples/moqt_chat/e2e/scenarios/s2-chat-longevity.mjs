// S2 chat-longevity: 2 clients, 120 chat messages each, on one connection.
// Every chat message is one client->server WT uni stream, so this drives a
// single connection well past 100 uni streams; the gate is zero chat loss
// (the relay retains busy rounds, so steady-state chat loss should be 0).

import { runChatLoadTest } from "../lib/loadTest.mjs";

export async function run({ browser, pageUrl, server, arg, log }) {
  const messagesPerClient = Number(arg("messages", "120"));
  log(`2 clients x ${messagesPerClient} messages`);
  const report = await runChatLoadTest({
    browser,
    pageUrl,
    certHash: server.certHash,
    clientCount: 2,
    messagesPerClient,
    sendIntervalMs: Number(arg("interval-ms", "200")),
    settleMs: Number(arg("settle-ms", "10000")),
  });

  const failures = [];
  if (report.lossRate > 0) {
    failures.push(
      `chat lossRate ${report.lossRate.toFixed(4)} > 0 ` +
        `(${report.actualDeliveries}/${report.expectedDeliveries} delivered)`,
    );
  }
  for (const [tag, errs] of Object.entries(report.pageErrors)) {
    if (errs.length > 0) failures.push(`client ${tag} page errors: ${errs.join("; ")}`);
  }
  return { report, failures };
}
