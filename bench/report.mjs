// CLI over lib/aggregate.mjs: turn captured lane output into markdown.
//   node bench/report.mjs speed    <lines-file>
//   node bench/report.mjs usage    <lines-file>
import { readFileSync } from "node:fs";
import {
  summarizeSpeed,
  summarizeUsage,
  renderSpeedTable,
  renderUsageTable,
} from "./lib/aggregate.mjs";

const [mode, file] = process.argv.slice(2);
if (!mode || !file) {
  console.error("usage: report.mjs speed|usage <file>");
  process.exit(2);
}
const text = readFileSync(file, "utf8");
const lines = text.split("\n");
const out = {
  speed: () => renderSpeedTable(summarizeSpeed(lines)),
  usage: () => renderUsageTable(summarizeUsage(lines)),
}[mode];
if (!out) {
  console.error(`unknown mode: ${mode}`);
  process.exit(2);
}
console.log(out());
