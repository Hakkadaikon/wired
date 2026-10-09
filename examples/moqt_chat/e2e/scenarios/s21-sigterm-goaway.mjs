// S21 sigterm-goaway: a hub restart by SIGTERM is announced, not just
// suffered. On SIGTERM the hub sends every session MOQT GOAWAY
// (draft-ietf-moq-transport-22 6.6.1 / 9.2; draft-19 3.6 / 10.4, wired_server.c
// goaway_on_shutdown) and drains; the browser reconnects as soon as the
// GOAWAY lands (useMoqtChat.ts handleGoaway) instead of waiting for the
// connection to die, then retries through the auto-rejoin back-off until
// the restarted hub answers. Gates:
//   A -- each client's first new connect attempt starts within
//        goaway-react-max-ms of the SIGTERM (the old connection is still
//        up then: the hub drains for ~5 s);
//   B -- both are "connected" again within rejoin-max-ms of the restart;
//   C -- chat flows both ways afterwards (publishes, namespaces and
//        subscriptions were re-established by the reconnect).
//
//   just e2e-stability s21-sigterm-goaway

import { joinStabilityClient, closeClient } from "../lib/stabilityClient.mjs";

async function sendChat(client, text) {
  await client.page.evaluate((t) => {
    const input = document.querySelector('input[data-testid="text"]');
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
    setter.call(input, t);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
  }, text);
}

async function sawChat(client, text, timeoutMs) {
  try {
    await client.page.waitForFunction(
      (t) => document.querySelector('[data-testid="messages"]')?.textContent?.includes(t),
      { timeout: timeoutMs },
      text,
    );
    return true;
  } catch {
    return false;
  }
}

const firstOpenAfter = (client, t) =>
  client.page.evaluate((since) => (window.__wtEvents ?? []).find((e) => e.openedAt >= since)?.openedAt ?? null, t);

export async function run({ pageUrl, serverUrl, server, arg, log }) {
  const reactMaxMs = Number(arg("goaway-react-max-ms", "2000"));
  const rejoinMaxMs = Number(arg("rejoin-max-ms", "20000"));
  const opts = (tag) => ({ pageUrl, serverUrl, certHash: server.certHash, participantId: tag });
  const failures = [];
  const report = { reactMaxMs, rejoinMaxMs };
  const clients = [];
  try {
    for (const tag of ["user1", "user2"]) clients.push(await joinStabilityClient(opts(tag)));
    const [user1, user2] = clients;
    await user1.page.waitForSelector('[data-testid="quality-user2"]', { timeout: 10000 });

    log("SIGTERM the hub, then start it again");
    const sigtermAt = Date.now();
    await server.restart("SIGTERM");
    const restartedAt = Date.now();
    report.hubDownMs = restartedAt - sigtermAt;

    for (const c of clients) {
      const opened = await firstOpenAfter(c, sigtermAt);
      report[`${c.tag}ReconnectStartMs`] = opened === null ? null : opened - sigtermAt;
      if (opened === null || opened - sigtermAt > reactMaxMs)
        failures.push(`gate A: ${c.tag} did not start reconnecting within ${reactMaxMs}ms of SIGTERM (${opened === null ? "never" : opened - sigtermAt + "ms"})`);
    }

    for (const c of clients) {
      try {
        await c.page.waitForFunction(
          (since) =>
            document.querySelector('[data-testid="status"]')?.getAttribute("data-status") === "connected" &&
            (window.__wtEvents ?? []).some((e) => e.readyAt !== null && e.readyAt >= since),
          { timeout: rejoinMaxMs },
          restartedAt,
        );
        report[`${c.tag}RejoinedMs`] = Date.now() - restartedAt;
      } catch {
        failures.push(`gate B: ${c.tag} not connected to the restarted hub within ${rejoinMaxMs}ms`);
      }
    }

    const a = `after-restart-a-${Date.now()}`;
    const b = `after-restart-b-${Date.now()}`;
    await user1.page.waitForSelector('[data-testid="quality-user2"]', { timeout: 10000 }).catch(() => {});
    await sendChat(user1, a);
    await sendChat(user2, b);
    if (!(await sawChat(user2, a, 10000))) failures.push("gate C: user2 never got user1's chat after the restart");
    if (!(await sawChat(user1, b, 10000))) failures.push("gate C: user1 never got user2's chat after the restart");
  } finally {
    for (const c of clients) await closeClient(c);
  }
  return { report, failures };
}
