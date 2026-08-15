import test from "node:test";
import assert from "node:assert/strict";
import {
  parseBenchLine,
  meanSd,
  summarizeSpeed,
  parseSizeB,
  parseUsageLine,
  summarizeUsage,
  renderSpeedTable,
  renderSectionsTable,
  renderUsageTable,
} from "../lib/aggregate.mjs";

// Test list (comparison bench aggregation):
// 1. parseBenchLine: one run-lane speed line -> typed record; garbage -> null
// 2. meanSd: sample stdev over rounds; a single value has no spread (sd null)
// 3. summarizeSpeed: rounds grouped per server+mode, failures totaled
// 4. parseSizeB: Berkeley `size` output -> text/data/bss per binary
// 5. parseUsageLine: raw ticks/kB/hz line -> derived cpu us/req and cpu%
//    (derivation lives here, not in the shell, so it is testable)
// 6. summarizeUsage: load rounds -> cpu stats + peak RSS max; idle line -> idle RSS
// 7. renderers: markdown tables carry the computed values

const SPEED_LINES = [
  "wired r1 mode=load n=10000 fails=0 reqps=27067.0 p50=0.61 p99=3.26 cpu%=117",
  "wired r2 mode=load n=10000 fails=0 reqps=25174.4 p50=0.66 p99=3.16 cpu%=132",
  "wired r1 mode=ttfb n=100 fails=0 reqps=426.3 p50=2.17 p99=4.92 cpu%=73",
  "quiche r1 mode=load n=10000 fails=2 reqps=22767.1 p50=0.81 p99=2.13 cpu%=118",
];

test("parseBenchLine extracts one speed record", () => {
  const r = parseBenchLine(SPEED_LINES[0]);
  assert.equal(r.server, "wired");
  assert.equal(r.run, "r1");
  assert.equal(r.mode, "load");
  assert.equal(r.n, 10000);
  assert.equal(r.fails, 0);
  assert.equal(r.reqps, 27067.0);
  assert.equal(r.p50, 0.61);
  assert.equal(r.p99, 3.26);
  assert.equal(r.cpu, 117);
});

test("parseBenchLine returns null on non-matching lines", () => {
  assert.equal(parseBenchLine("=== quiche"), null);
  assert.equal(parseBenchLine(""), null);
});

test("meanSd is sample stdev; single sample has no spread", () => {
  const { mean, sd } = meanSd([2, 4, 6]);
  assert.equal(mean, 4);
  assert.equal(sd, 2);
  assert.equal(meanSd([5]).sd, null);
});

test("summarizeSpeed groups per server+mode and totals failures", () => {
  const s = summarizeSpeed(SPEED_LINES);
  const wiredLoad = s.find((e) => e.server === "wired" && e.mode === "load");
  assert.equal(wiredLoad.rounds, 2);
  assert.equal(wiredLoad.fails, 0);
  assert.equal(wiredLoad.requests, 20000);
  assert.ok(Math.abs(wiredLoad.reqps.mean - 26120.7) < 0.1);
  const quicheLoad = s.find((e) => e.server === "quiche" && e.mode === "load");
  assert.equal(quicheLoad.fails, 2);
});

test("parseSizeB reads Berkeley size output", () => {
  const out = [
    "   text\t   data\t    bss\t    dec\t    hex\tfilename",
    " 234567\t   1234\t9876543\t10112344\t 9a4c58\tbuild/wired_server",
    "  11111\t    222\t    333\t  11666\t   2d92\tbench/qgserver/qgserver",
  ].join("\n");
  const rows = parseSizeB(out);
  assert.equal(rows.length, 2);
  assert.deepEqual(rows[0], {
    text: 234567,
    data: 1234,
    bss: 9876543,
    filename: "build/wired_server",
  });
});

test("parseUsageLine derives cpu us/req and cpu% from raw ticks", () => {
  // 380 ticks at hz=100 over 10000 requests in 1900ms of wall time:
  // cpu time = 3.8s?? no -- 380/100 = 3.8s. Use smaller: 38 ticks = 0.38s
  // -> 38 us/req, and 0.38s over 1.9s wall = 20%.
  const u = parseUsageLine(
    "wired r1 usage kind=load reqs=10000 dticks=38 wall_ms=1900 hz=100 vmhwm_kb=12345 vmrss_kb=11111",
  );
  assert.equal(u.server, "wired");
  assert.equal(u.kind, "load");
  assert.equal(u.cpuUsPerReq, 38);
  assert.ok(Math.abs(u.cpuPct - 20) < 0.001);
  assert.equal(u.vmhwmKb, 12345);
  assert.equal(u.vmrssKb, 11111);
});

test("parseUsageLine handles idle lines (no requests, no rate)", () => {
  const u = parseUsageLine(
    "wired r0 usage kind=idle reqs=0 dticks=0 wall_ms=0 hz=100 vmhwm_kb=900 vmrss_kb=800",
  );
  assert.equal(u.kind, "idle");
  assert.equal(u.cpuUsPerReq, null);
  assert.equal(u.cpuPct, null);
});

test("summarizeUsage: cpu stats over load rounds, peak RSS max, idle RSS", () => {
  const s = summarizeUsage([
    "wired r0 usage kind=idle reqs=0 dticks=0 wall_ms=0 hz=100 vmhwm_kb=900 vmrss_kb=800",
    "wired r1 usage kind=load reqs=10000 dticks=38 wall_ms=1900 hz=100 vmhwm_kb=1000 vmrss_kb=950",
    "wired r2 usage kind=load reqs=10000 dticks=42 wall_ms=2100 hz=100 vmhwm_kb=1100 vmrss_kb=960",
  ]);
  const w = s.find((e) => e.server === "wired");
  assert.equal(w.idleRssKb, 800);
  assert.equal(w.peakRssKb, 1100);
  assert.equal(w.rounds, 2);
  assert.ok(Math.abs(w.cpuUsPerReq.mean - 40) < 0.001);
});

test("renderers produce markdown rows with the computed values", () => {
  const speed = renderSpeedTable(summarizeSpeed(SPEED_LINES));
  assert.match(speed, /\| wired \|/);
  assert.match(speed, /26,121|26120/);
  const sections = renderSectionsTable(
    parseSizeB("   text\tdata\tbss\tdec\thex\tfilename\n100\t2\t3\t105\t69\ta/b"),
  );
  assert.match(sections, /\| b \| 100 \| 2 \| 3 \|/);
  const usage = renderUsageTable(
    summarizeUsage([
      "wired r0 usage kind=idle reqs=0 dticks=0 wall_ms=0 hz=100 vmhwm_kb=900 vmrss_kb=800",
      "wired r1 usage kind=load reqs=10000 dticks=38 wall_ms=1900 hz=100 vmhwm_kb=1000 vmrss_kb=950",
    ]),
  );
  assert.match(usage, /\| wired \|/);
  assert.match(usage, /38/);
});
