// Resolves the puppeteer-managed Chrome binary and its LD_LIBRARY_PATH. This
// sandbox's Chrome for Testing download is missing several shared libs
// (atk, cups, cairo, pango, alsa, ...) that ship on a desktop but not this
// container; `just e2e-deps` (justfile) provisions them via `nix-shell -p`
// once and this module just locates the resulting profile.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";

const CACHE_ROOT = path.join(
  process.env.HOME ?? "",
  ".cache/puppeteer/chrome",
);
const LIB_PROFILE = path.join(
  path.dirname(new URL(import.meta.url).pathname),
  "..",
  ".chrome-libs-profile",
);

function findChromeBinary() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  if (!existsSync(CACHE_ROOT)) return null;
  const dirs = readdirSync(CACHE_ROOT).filter((d) => d.startsWith("linux-"));
  if (dirs.length === 0) return null;
  const newest = dirs.sort().at(-1);
  return path.join(CACHE_ROOT, newest, "chrome-linux64", "chrome");
}

function nixLdLibraryPath() {
  if (!existsSync(LIB_PROFILE)) return null;
  try {
    return readFileSync(LIB_PROFILE, "utf8").trim() || null;
  } catch {
    return null;
  }
}

/** @returns {{executablePath: string, env: object}} launch args for puppeteer */
export function resolveChromeLaunch() {
  const executablePath = findChromeBinary();
  if (!executablePath) {
    throw new Error(
      "no Chrome for Testing binary found under ~/.cache/puppeteer/chrome; " +
        "run: npx puppeteer browsers install chrome",
    );
  }
  const ldPath = nixLdLibraryPath();
  const env = ldPath
    ? { ...process.env, LD_LIBRARY_PATH: ldPath }
    : process.env;
  return { executablePath, env };
}
