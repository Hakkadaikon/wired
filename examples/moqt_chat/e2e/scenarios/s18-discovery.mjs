// S18 discovery: room membership follows namespace discovery
// (draft-ietf-moq-transport-19 6.1-6.2), not polling. user1 joins alone;
// user2 joins and both rosters show the other within roster-max-ms
// (NAMESPACE); user2 leaves and user1's roster drops it within the same
// bound (NAMESPACE_DONE once the hub sees the session end). Nobody sends
// a chat message, so nothing but discovery can put a peer on the roster.
//
//   just e2e-stability s18-discovery

import { joinStabilityClient, closeClient } from "../lib/stabilityClient.mjs";

async function rosterHas(client, peer, want, timeoutMs) {
  const start = Date.now();
  try {
    await client.page.waitForFunction(
      (p, w) => (document.querySelector(`[data-testid="quality-${p}"]`) !== null) === w,
      { timeout: timeoutMs },
      peer,
      want,
    );
    return Date.now() - start;
  } catch {
    return null;
  }
}

export async function run({ pageUrl, serverUrl, server, arg, log }) {
  const rosterMaxMs = Number(arg("roster-max-ms", "5000"));
  const opts = (tag) => ({ pageUrl, serverUrl, certHash: server.certHash, participantId: tag });
  const failures = [];
  const report = { rosterMaxMs };
  const clients = [];
  try {
    const user1 = await joinStabilityClient(opts("user1"));
    clients.push(user1);
    log("user2 joins");
    const user2 = await joinStabilityClient(opts("user2"));
    clients.push(user2);
    report.user1SeesJoinMs = await rosterHas(user1, "user2", true, rosterMaxMs);
    report.user2SeesUser1Ms = await rosterHas(user2, "user1", true, rosterMaxMs);
    if (report.user1SeesJoinMs === null) failures.push("user1's roster never showed user2");
    if (report.user2SeesUser1Ms === null) failures.push("user2's roster never showed user1");

    log("user2 leaves (closes its tab)");
    await user2.page.close({ runBeforeUnload: true });
    report.user1SeesLeaveMs = await rosterHas(user1, "user2", false, rosterMaxMs);
    if (report.user1SeesLeaveMs === null) failures.push("user1's roster still shows user2 after it left");

    for (const c of clients) if (c.errors.length) failures.push(`${c.tag} page errors: ${c.errors.join("; ")}`);
  } finally {
    for (const c of clients) await closeClient(c);
  }
  return { report, failures };
}
