// S8 late-join: three participants talk for a while, then a fourth joins
// mid-call. Gate: the latecomer decodes its first audio frame within 2s of
// reaching connected, and the incumbents keep decoding -- a regression
// guard on the subscribe/announce path for peers that were already
// publishing before the newcomer arrived.

import {
  joinStabilityClient,
  waitFirstDecode,
  clientMetrics,
  closeClient,
} from "../lib/stabilityClient.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function run({ pageUrl, server, arg, log }) {
  const preTalkMs = Number(arg("pre-talk-ms", "10000"));
  const firstFrameMaxMs = Number(arg("first-frame-max-ms", "2000"));
  const failures = [];
  const opts = (tag) => ({ pageUrl, serverUrl: "", certHash: server.certHash, participantId: tag });
  const incumbents = [];
  for (const tag of ["user1", "user2", "user3"]) {
    log(`joining ${tag}`);
    incumbents.push(await joinStabilityClient(opts(tag)));
  }
  for (const c of incumbents) await waitFirstDecode(c);
  log(`room live (3 clients); talking ${preTalkMs}ms before the late join`);
  await sleep(preTalkMs);

  const before = await Promise.all(incumbents.map((c) => clientMetrics(c)));
  log("user4 joins late");
  const late = await joinStabilityClient(opts("user4"));
  let firstFrameMs = null;
  try {
    const at = await waitFirstDecode(late, { timeoutMs: firstFrameMaxMs + 10000 });
    firstFrameMs = at - late.joinedAt;
  } catch {
    failures.push("late joiner never decoded audio");
  }
  if (firstFrameMs !== null && firstFrameMs > firstFrameMaxMs) {
    failures.push(`late join first frame ${firstFrameMs}ms > ${firstFrameMaxMs}ms`);
  }
  await sleep(2000);
  const after = await Promise.all(incumbents.map((c) => clientMetrics(c)));
  for (let i = 0; i < incumbents.length; i++) {
    if (after[i].decodedFrameCount <= before[i].decodedFrameCount) {
      failures.push(`incumbent ${incumbents[i].tag} stopped decoding across the late join`);
    }
  }

  const report = { firstFrameMs };
  for (const c of [...incumbents, late]) {
    for (const e of c.errors) failures.push(`${c.tag} page error: ${e}`);
    await closeClient(c);
  }
  return { report, failures };
}
