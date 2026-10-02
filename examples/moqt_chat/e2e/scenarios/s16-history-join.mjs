// S16 history-join: chat history reaches a late joiner. user1 joins alone
// and sends a few messages; user2 joins afterwards and must show all of
// them without user1 sending anything more -- its subscription to user1's
// chat track carries a Joining FETCH (draft-ietf-moq-transport-19 10.12.2)
// served from the hub's object cache. Then user2 leaves and rejoins on a
// fresh page: the history is fetched again, each message exactly once.
//
//   just e2e-stability s16-history-join

import { joinStabilityClient, connectClient, closeClient } from "../lib/stabilityClient.mjs";

const HISTORY_TIMEOUT_MS = 15000;

async function sendChat(client, text) {
  await client.page.evaluate((t) => {
    const input = document.querySelector('input[data-testid="text"]');
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
    setter.call(input, t);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
  }, text);
}

// How many received bubbles from `sender` contain each of `texts`.
const countsFrom = (client, sender, texts) =>
  client.page.evaluate(
    (s, want) =>
      want.map(
        (t) =>
          Array.from(document.querySelectorAll(`[data-testid="message"][data-sender="${s}"]`)).filter((m) =>
            m.textContent.includes(t),
          ).length,
      ),
    sender,
    texts,
  );

async function waitAll(client, sender, texts) {
  try {
    await client.page.waitForFunction(
      (s, want) => {
        const msgs = Array.from(document.querySelectorAll(`[data-testid="message"][data-sender="${s}"]`));
        return want.every((t) => msgs.some((m) => m.textContent.includes(t)));
      },
      { timeout: HISTORY_TIMEOUT_MS },
      sender,
      texts,
    );
    return true;
  } catch {
    return false;
  }
}

export async function run({ pageUrl, serverUrl, server, arg, log }) {
  const count = Number(arg("messages", "5"));
  const opts = (tag) => ({ pageUrl, serverUrl, certHash: server.certHash, participantId: tag });
  const texts = Array.from({ length: count }, (_, i) => `history-${i}-${Date.now()}`);
  const failures = [];
  const report = { messages: count };
  const clients = [];
  try {
    log("user1 joins alone and sends its messages");
    const user1 = await joinStabilityClient(opts("user1"));
    clients.push(user1);
    for (const t of texts) {
      await sendChat(user1, t);
      await new Promise((r) => setTimeout(r, 200));
    }

    log("user2 joins late");
    const user2 = await joinStabilityClient(opts("user2"));
    clients.push(user2);
    const start = Date.now();
    report.historyArrived = await waitAll(user2, "user1", texts);
    report.historyMs = Date.now() - start;
    if (!report.historyArrived) {
      const got = await countsFrom(user2, "user1", texts);
      failures.push(`late joiner missing history: per-message counts ${JSON.stringify(got)}`);
    }

    log("user2 rejoins: history again, each message once");
    await user2.page.close();
    await connectClient(user2, opts("user2"));
    if (!(await waitAll(user2, "user1", texts))) failures.push("rejoined user2 missing history");
    const counts = await countsFrom(user2, "user1", texts);
    report.countsAfterRejoin = counts;
    if (counts.some((n) => n !== 1)) failures.push(`history shown more than once: ${JSON.stringify(counts)}`);

    for (const c of clients) {
      if (c.errors.length > 0) failures.push(`${c.tag} page errors: ${c.errors.join("; ")}`);
    }
  } finally {
    for (const c of clients) await closeClient(c);
  }
  return { report, failures };
}
