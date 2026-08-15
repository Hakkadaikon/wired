// CLI over lib/aggregate.mjs: turn captured lane output into markdown.
//   node bench/report.mjs speed    <lines-file>
//   node bench/report.mjs usage    <lines-file>
//   node bench/report.mjs sections <size-output-file>
import { readFileSync } from "node:fs";
import {
  summarizeSpeed,
  summarizeUsage,
  parseSizeB,
  renderSpeedTable,
  renderUsageTable,
  renderSectionsTable,
} from "./lib/aggregate.mjs";

const [mode, file] = process.argv.slice(2);
if (!mode || !file) {
  console.error("usage: report.mjs speed|usage|sections <file>");
  process.exit(2);
}
const text = readFileSync(file, "utf8");
const lines = text.split("\n");
const out = {
  speed: () => renderSpeedTable(summarizeSpeed(lines)),
  usage: () => renderUsageTable(summarizeUsage(lines)),
  sections: () => renderSectionsTable(parseSizeB(text)),
}[mode];
if (!out) {
  console.error(`unknown mode: ${mode}`);
  process.exit(2);
}
console.log(out());
