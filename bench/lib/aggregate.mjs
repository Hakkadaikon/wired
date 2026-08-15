// Pure aggregation for the comparison bench lanes: parses run-lane.sh's
// speed/usage lines and Berkeley `size` output, computes the statistics,
// and renders the markdown tables the workflow summary and comparison.md
// use. No I/O here -- the shell stays a thin driver and every derivation
// (mean/sd, ticks -> us/req, kB -> MiB) is testable.

/** "wired r1 mode=load n=10000 fails=0 reqps=27067.0 p50=0.61 p99=3.26 cpu%=117" */
export function parseBenchLine(line) {
  const m = line.match(
    /^(\S+) (r\d+) mode=(\w+) n=(\d+) fails=(\d+) reqps=([\d.]+) p50=([\d.]+) p99=([\d.]+) cpu%=(\d+)/,
  );
  if (!m) return null;
  return {
    server: m[1],
    run: m[2],
    mode: m[3],
    n: Number(m[4]),
    fails: Number(m[5]),
    reqps: Number(m[6]),
    p50: Number(m[7]),
    p99: Number(m[8]),
    cpu: Number(m[9]),
  };
}

/** Sample mean and stdev (n-1); a single sample has no spread (sd null). */
export function meanSd(values) {
  const n = values.length;
  const mean = values.reduce((a, b) => a + b, 0) / n;
  if (n < 2) return { mean, sd: null };
  const varSum = values.reduce((a, b) => a + (b - mean) ** 2, 0);
  return { mean, sd: Math.sqrt(varSum / (n - 1)) };
}

function groupBy(records, keyFn) {
  const map = new Map();
  for (const r of records) {
    const k = keyFn(r);
    if (!map.has(k)) map.set(k, []);
    map.get(k).push(r);
  }
  return map;
}

/** Speed lines -> per server+mode stats. */
export function summarizeSpeed(lines) {
  const recs = lines.map(parseBenchLine).filter(Boolean);
  const out = [];
  for (const [, rs] of groupBy(recs, (r) => `${r.server}\0${r.mode}`)) {
    out.push({
      server: rs[0].server,
      mode: rs[0].mode,
      rounds: rs.length,
      requests: rs.reduce((a, r) => a + r.n, 0),
      fails: rs.reduce((a, r) => a + r.fails, 0),
      reqps: meanSd(rs.map((r) => r.reqps)),
      p50: meanSd(rs.map((r) => r.p50)),
      p99: meanSd(rs.map((r) => r.p99)),
      clientCpuMax: Math.max(...rs.map((r) => r.cpu)),
    });
  }
  return out;
}

/** Berkeley `size` output -> [{text, data, bss, filename}]. */
export function parseSizeB(output) {
  const rows = [];
  for (const line of output.split("\n")) {
    const m = line.trim().match(/^(\d+)\s+(\d+)\s+(\d+)\s+\d+\s+[0-9a-fA-F]+\s+(\S+)$/);
    if (m) {
      rows.push({
        text: Number(m[1]),
        data: Number(m[2]),
        bss: Number(m[3]),
        filename: m[4],
      });
    }
  }
  return rows;
}

/**
 * "wired r1 usage kind=load reqs=10000 dticks=38 wall_ms=1900 hz=100
 *  vmhwm_kb=12345 vmrss_kb=11111" -> derived record. The shell emits only
 * raw counters (ticks, kB, hz); us/req and cpu% are derived here.
 */
export function parseUsageLine(line) {
  const m = line.match(
    /^(\S+) (r\d+) usage kind=(\w+) reqs=(\d+) dticks=(\d+) wall_ms=(\d+) hz=(\d+) vmhwm_kb=(\d+) vmrss_kb=(\d+)/,
  );
  if (!m) return null;
  const reqs = Number(m[4]);
  const dticks = Number(m[5]);
  const wallMs = Number(m[6]);
  const hz = Number(m[7]);
  const cpuUs = (dticks * 1e6) / hz;
  return {
    server: m[1],
    run: m[2],
    kind: m[3],
    reqs,
    cpuUsPerReq: reqs > 0 ? cpuUs / reqs : null,
    cpuPct: wallMs > 0 ? (cpuUs / 1000 / wallMs) * 100 : null,
    vmhwmKb: Number(m[8]),
    vmrssKb: Number(m[9]),
  };
}

/** Usage lines -> per server: cpu stats over load rounds, peak/idle RSS. */
export function summarizeUsage(lines) {
  const recs = lines.map(parseUsageLine).filter(Boolean);
  const out = [];
  for (const [, rs] of groupBy(recs, (r) => r.server)) {
    const load = rs.filter((r) => r.kind === "load");
    const idle = rs.find((r) => r.kind === "idle");
    out.push({
      server: rs[0].server,
      rounds: load.length,
      idleRssKb: idle ? idle.vmrssKb : null,
      peakRssKb: rs.reduce((a, r) => Math.max(a, r.vmhwmKb), 0),
      cpuUsPerReq: meanSd(load.map((r) => r.cpuUsPerReq)),
      cpuPct: meanSd(load.map((r) => r.cpuPct)),
    });
  }
  return out;
}

function fmt(stat, decimals = 1) {
  if (stat.sd === null) return stat.mean.toFixed(decimals);
  return `${stat.mean.toFixed(decimals)} ± ${stat.sd.toFixed(decimals)}`;
}

function fmtInt(stat) {
  const f = (v) => Math.round(v).toLocaleString("en-US");
  if (stat.sd === null) return f(stat.mean);
  return `${f(stat.mean)} ± ${f(stat.sd)}`;
}

/** Markdown: one row per server, split by mode columns (ttfb + load). */
export function renderSpeedTable(summary) {
  const servers = [...new Set(summary.map((e) => e.server))];
  const rows = [
    "| Server | TTFB p50 (ms) | load req/s | load p50 (ms) | load p99 (ms) | failures | client CPU max % |",
    "|---|---|---|---|---|---|---|",
  ];
  for (const s of servers) {
    const ttfb = summary.find((e) => e.server === s && e.mode === "ttfb");
    const load = summary.find((e) => e.server === s && e.mode === "load");
    const fails = (ttfb?.fails ?? 0) + (load?.fails ?? 0);
    const total = (ttfb?.requests ?? 0) + (load?.requests ?? 0);
    rows.push(
      `| ${s} | ${ttfb ? fmt(ttfb.p50, 2) : "—"} | ${load ? fmtInt(load.reqps) : "—"} | ` +
        `${load ? fmt(load.p50, 2) : "—"} | ${load ? fmt(load.p99, 2) : "—"} | ` +
        `${fails} / ${total.toLocaleString("en-US")} | ${load?.clientCpuMax ?? "—"} |`,
    );
  }
  return rows.join("\n");
}

/** Markdown: text/data/bss per binary. */
export function renderSectionsTable(rows) {
  const out = [
    "| Binary | text (B) | data (B) | bss (B) |",
    "|---|---|---|---|",
  ];
  for (const r of rows) {
    const base = r.filename.split("/").pop();
    out.push(`| ${base} | ${r.text} | ${r.data} | ${r.bss} |`);
  }
  return out.join("\n");
}

/** Markdown: idle/peak RSS + server CPU per request. */
export function renderUsageTable(summary) {
  const out = [
    "| Server | idle RSS (KiB) | peak RSS (KiB) | server CPU (µs/req) | server CPU (%) | rounds |",
    "|---|---|---|---|---|---|",
  ];
  for (const s of summary) {
    out.push(
      `| ${s.server} | ${s.idleRssKb ?? "—"} | ${s.peakRssKb} | ` +
        `${fmt(s.cpuUsPerReq, 1)} | ${fmt(s.cpuPct, 1)} | ${s.rounds} |`,
    );
  }
  return out.join("\n");
}
