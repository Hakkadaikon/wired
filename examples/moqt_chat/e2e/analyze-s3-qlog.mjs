// Thin driver over lib/qlogStreamForensics.mjs: reads an s3-voice-loss
// run's evidence (report.json + server.qlog), attaches a server-side
// stream-frame verdict to every missing chat delivery, and writes
// qlog-verdicts.json next to them.
//
//   node e2e/analyze-s3-qlog.mjs --evidence-dir=tasks/voice-stability/<id>

import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  parseJsonSeq,
  groupIdsInOrder,
  groupStreams,
  splitOneShotVsKeepOpen,
  chatUploadSeq,
  dispatchOrder,
  verdictForMissing,
  alignRelays,
} from "./lib/qlogStreamForensics.mjs";

const TAGS = ["user1", "user2", "user3", "user4"];
const dirArg = process.argv.find((a) => a.startsWith("--evidence-dir="));
if (!dirArg) {
  console.error("usage: node analyze-s3-qlog.mjs --evidence-dir=<dir>");
  process.exit(2);
}
const dir = dirArg.slice("--evidence-dir=".length);
const report = JSON.parse(readFileSync(path.join(dir, "report.json"), "utf8"));
const records = parseJsonSeq(readFileSync(path.join(dir, "server.qlog"), "utf8"));

// group_id = connection slot; first appearance in the qlog = join order =
// the scenario's fixed user1..user4 join sequence.
const gids = groupIdsInOrder(records);
if (gids.length !== TAGS.length) {
  console.error(`expected ${TAGS.length} connections in qlog, found ${gids.length} -- refusing to map tags`);
  process.exit(1);
}
const byTag = {};
TAGS.forEach((tag, i) => {
  byTag[tag] = groupStreams(records, gids[i]);
});

const uploadsByTag = {};
const relaysByTag = {};
for (const tag of TAGS) {
  uploadsByTag[tag] = chatUploadSeq(byTag[tag]);
  relaysByTag[tag] = splitOneShotVsKeepOpen(byTag[tag])
    .oneShot.filter((s) => s.streamId % 4 === 3 && s.sent.length > 0)
    .sort((a, b) => a.streamId - b.streamId);
}
const dispatch = dispatchOrder(uploadsByTag);

// Transport-level arrivals per receiver, from the persisted taps' heads.
const arrivedIdsFor = (tag) =>
  (report.uniStreamTaps?.[tag] ?? [])
    .flatMap((s) => s.head?.match(/msg:[A-Za-z0-9]+:\d+/g) ?? []);

const missingPairs = Object.keys(report.missingTransport ?? {});
const missingIdsFor = (tag) =>
  missingPairs.filter((p) => p.endsWith(`->${tag}`)).map((p) => p.split("->")[0]);

const alignByTag = {};
for (const tag of TAGS) {
  alignByTag[tag] = alignRelays({
    expectedIds: dispatch.filter((o) => o.tag !== tag).map((o) => o.id),
    relayStreams: relaysByTag[tag],
    arrivedIds: arrivedIdsFor(tag),
    missingIds: missingIdsFor(tag),
  });
}

const verdicts = {};
for (const pair of missingPairs) {
  const [id, receiver] = pair.split("->");
  const [, sender, seqStr] = id.split(":");
  const k = Number(seqStr);
  const uploads = uploadsByTag[sender] ?? [];
  const upload = uploads[k];
  const align = alignByTag[receiver];
  const relayStream = align.ok ? align.byId[id] : null;
  verdicts[pair] = {
    scenarioVerdict: report.missingTransport[pair],
    upload: upload
      ? {
          received: true,
          streamId: upload.streamId,
          // index k = message k only holds when every upload landed
          exactIndex: uploads.length === 15,
          frames: upload.received,
        }
      : { received: false, uploadCount: uploads.length },
    relay: align.ok
      ? { ...verdictForMissing({ relayStream }), streamId: relayStream?.streamId, sent: relayStream?.sent, lost: relayStream?.lost }
      : { verdict: align.reason },
  };
}

const summary = {};
for (const v of Object.values(verdicts)) {
  const key = v.relay.verdict;
  summary[key] = (summary[key] ?? 0) + 1;
}
const out = {
  evidenceDir: dir,
  connections: Object.fromEntries(TAGS.map((t, i) => [t, gids[i]])),
  uploadCounts: Object.fromEntries(TAGS.map((t) => [t, uploadsByTag[t].length])),
  relayCounts: Object.fromEntries(TAGS.map((t) => [t, relaysByTag[t].length])),
  alignment: Object.fromEntries(TAGS.map((t) => [t, alignByTag[t].ok ? "ok" : alignByTag[t].reason])),
  summary,
  verdicts,
};
writeFileSync(path.join(dir, "qlog-verdicts.json"), JSON.stringify(out, null, 2));
console.log(JSON.stringify(out, null, 2));
