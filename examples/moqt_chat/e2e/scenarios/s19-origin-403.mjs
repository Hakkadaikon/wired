// S19 origin-403: the hub started with an Origin allow-list
// (WIRED_ALLOWED_ORIGINS, wired_server.c's origin_allowed) answers a
// WebTransport CONNECT from any other Origin with 403
// (draft-ietf-webtrans-http3-15 3.1). The same static page is loaded under
// two Origins: http://127.0.0.1:<port> is on the list and must connect,
// http://localhost:<port> is not and must never reach "connected".
//
//   just e2e-stability s19-origin-403

import { joinStabilityClient, connectClient, closeClient } from "../lib/stabilityClient.mjs";

const PAGE_PORT = 8093; // run-stability.sh's static frontend
export const serverEnv = { WIRED_ALLOWED_ORIGINS: `https://elsewhere.example,http://127.0.0.1:${PAGE_PORT}` };

export async function run({ browser, pageUrl, serverUrl, server, log }) {
  const allowed = new URL(pageUrl);
  allowed.hostname = "127.0.0.1";
  const refused = new URL(pageUrl);
  refused.hostname = "localhost";
  const failures = [];
  const report = {};
  const clients = [];
  try {
    log(`allowed Origin ${allowed.origin}`);
    clients.push(
      await joinStabilityClient({ pageUrl: allowed.href, serverUrl, certHash: server.certHash, participantId: "user1" }),
    );
    report.allowedConnected = true;

    log(`refused Origin ${refused.origin}`);
    // On the runner's shared browser, so a refused join leaves no Chrome
    // behind (joinStabilityClient launches its own and throws before
    // handing it back).
    const probe = { tag: "user2", browser, page: null, errors: [] };
    try {
      await connectClient(probe, { pageUrl: refused.href, serverUrl, certHash: server.certHash, participantId: "user2" });
      failures.push(`a page from ${refused.origin} connected despite the allow-list`);
    } catch (err) {
      const msg = String(err);
      report.refusedHandshakeFailed = /Opening handshake failed/.test(msg);
      if (!report.refusedHandshakeFailed) failures.push(`refused Origin failed for another reason: ${msg.slice(0, 300)}`);
    } finally {
      await probe.page?.close().catch(() => {});
    }
  } catch (err) {
    failures.push(`allowed Origin did not connect: ${err}`);
  } finally {
    for (const c of clients) await closeClient(c);
  }
  return { report, failures };
}
