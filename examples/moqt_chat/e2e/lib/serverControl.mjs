// Owns the wired_server process for stability scenarios: spawn, scrape the
// cert fingerprint from stdout, and support kill/restart mid-scenario (the
// restart re-scrapes the fingerprint -- cert validity dates depend on boot
// time, so the hash can change across restarts even with fixed keys).
// run.sh/run-voice.sh manage the server from bash; scenarios need the
// lifecycle under the test's own control, hence this module.

import { spawn } from "node:child_process";
import { appendFileSync } from "node:fs";

const FINGERPRINT_RE = /cert sha-256 fingerprint: ([0-9A-Fa-f:]+)/;
const FINGERPRINT_TIMEOUT_MS = 5000;

function launch(binPath, args, logPath) {
  const proc = spawn(binPath, args, { stdio: ["ignore", "pipe", "pipe"] });
  let buffered = "";
  let notify = () => {};
  // The fingerprint goes to the server's stderr; log and scan both streams
  // so this module does not care which one carries it.
  const onData = (chunk) => {
    appendFileSync(logPath, chunk);
    buffered += chunk.toString();
    notify();
  };
  proc.stdout.on("data", onData);
  proc.stderr.on("data", onData);

  const certHash = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`no cert fingerprint within ${FINGERPRINT_TIMEOUT_MS}ms; log: ${logPath}`));
    }, FINGERPRINT_TIMEOUT_MS);
    notify = () => {
      const m = buffered.match(FINGERPRINT_RE);
      if (!m) return;
      clearTimeout(timer);
      notify = () => {};
      resolve(m[1]);
    };
    proc.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`server exited (code ${code}) before printing a fingerprint`));
    });
    notify();
  });
  return { proc, certHash };
}

function waitExit(proc) {
  if (proc.exitCode !== null || proc.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => proc.once("exit", resolve));
}

/**
 * @param {object} opts
 * @param {string} opts.binPath   path to wired_server
 * @param {string} opts.logPath   file to append all server output to
 * @param {string[]} [opts.args]  extra argv for the server
 */
export async function startServer({ binPath, logPath, args = [] }) {
  let current = launch(binPath, args, logPath);
  let certHash = await current.certHash;

  return {
    get pid() {
      return current.proc.pid;
    },
    get certHash() {
      return certHash;
    },
    /** SIGKILL simulates a crash (S-restart scenarios); SIGTERM is a clean stop. */
    async stop(signal = "SIGTERM") {
      current.proc.kill(signal);
      await waitExit(current.proc);
    },
    async restart(signal = "SIGKILL") {
      await this.stop(signal);
      current = launch(binPath, args, logPath);
      certHash = await current.certHash;
      return certHash;
    },
  };
}
