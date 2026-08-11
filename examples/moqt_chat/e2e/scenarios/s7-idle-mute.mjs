// S7 idle-mute: every participant mutes for 45s (no voice frames, no chat
// -- genuinely silent in both directions), then unmutes. Gate: the
// connections survive the silence and audio flows again. 45s deliberately
// exceeds the 30s idle timeout, so this run decides whether the SDK needs
// an application-level keepalive or the idle machinery already copes.

import {
  joinStabilityClient,
  waitFirstDecode,
  clientMetrics,
  closeClient,
} from "../lib/stabilityClient.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function run({ pageUrl, server, arg, log }) {
  const muteMs = Number(arg("mute-ms", "45000"));
  const failures = [];
  const clients = [];
  for (const tag of ["user1", "user2"]) {
    log(`joining ${tag}`);
    clients.push(
      await joinStabilityClient({ pageUrl, serverUrl: "", certHash: server.certHash, participantId: tag }),
    );
  }
  for (const c of clients) await waitFirstDecode(c);
  log(`both decoding; muting everyone for ${muteMs}ms`);
  for (const c of clients) await c.page.click('[data-testid="mic-toggle"]');
  await sleep(muteMs);

  const aliveAfterMute = {};
  for (const c of clients) {
    const m = await clientMetrics(c);
    const dead = (m?.wtEvents ?? []).filter((e) => e.closedAt !== null);
    aliveAfterMute[c.tag] = dead.length === 0;
    if (dead.length > 0) {
      failures.push(
        `${c.tag}: connection died during the mute (${dead[0].closeInfo})`,
      );
    }
  }
  log("unmuting");
  for (const c of clients) await c.page.click('[data-testid="mic-toggle"]').catch(() => {});
  const resumed = {};
  for (const c of clients) {
    const m = await clientMetrics(c);
    try {
      await waitFirstDecode(c, { past: m?.decodedFrameCount ?? 0, timeoutMs: 10000 });
      resumed[c.tag] = true;
    } catch {
      resumed[c.tag] = false;
      failures.push(`${c.tag}: no audio after unmute`);
    }
  }

  const report = { muteMs, aliveAfterMute, resumed };
  for (const c of clients) {
    for (const e of c.errors.filter((m) => !m.includes("Connection lost")))
      failures.push(`${c.tag} page error: ${e}`);
    await closeClient(c);
  }
  return { report, failures };
}
