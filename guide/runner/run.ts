// Run every guide snippet for real and compare its normalized output with the
// committed golden.txt. Usage: node runner/run.ts [--update] [id...]
// Expects build/guide/<id> to exist (`just ninja guide`); builds the Go clients.
import { spawn, execFileSync, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { normalize } from '../src/lib/normalize.ts';
import { expandSteps, type Run, type Step } from '../src/lib/steps.ts';

const guide = join(import.meta.dirname, '..');
const root = join(guide, '..');
const bin = join(root, 'build/guide');
const port = Number(process.env.GUIDE_PORT ?? 4433);
const addr = `127.0.0.1:${port}`;

interface Proc {
  child: ChildProcess;
  out: Promise<{ stdout: string; stderr: string; code: number | null }>;
}

function start(cmd: string, args: string[], cwd: string): Proc {
  // detached = own process group, so a server that forks workers stops as a whole.
  const child = spawn(cmd, args, { cwd, detached: true });
  let stdout = '';
  let stderr = '';
  child.stdout?.on('data', (d) => (stdout += d));
  child.stderr?.on('data', (d) => (stderr += d));
  const out = new Promise<{ stdout: string; stderr: string; code: number | null }>((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code) => resolve({ stdout, stderr, code }));
  });
  return { child, out };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function within<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what}: timed out after ${ms}ms`)), ms);
  });
  try {
    return await Promise.race([p, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/** Whether something has UDP port `port` bound (the server is ready once it does). */
function udpBound(): boolean {
  const hex = `:${port.toString(16).toUpperCase().padStart(4, '0')} `;
  return ['/proc/net/udp', '/proc/net/udp6'].some(
    (f) => existsSync(f) && readFileSync(f, 'utf8').includes(hex),
  );
}

async function waitBound(server: Proc): Promise<void> {
  for (let i = 0; i < 50; i++) {
    if (udpBound()) return;
    if (server.child.exitCode !== null) throw new Error('server exited before binding');
    await sleep(100);
  }
  throw new Error(`server did not bind udp ${port} within 5s`);
}

function signal(p: Proc, sig: NodeJS.Signals) {
  try {
    process.kill(-p.child.pid!, sig);
  } catch {
    // already gone
  }
}

async function stop(server: Proc) {
  signal(server, 'SIGTERM');
  const kill = setTimeout(() => signal(server, 'SIGKILL'), 3000);
  const res = await server.out;
  clearTimeout(kill);
  return res;
}

type ClientStep = Extract<Step, { client: string }>;

function client(id: string, step: ClientStep): { shown: string; cmd: string; args: string[] } {
  const rest = step.args ?? [];
  if (step.client === 'probe')
    return { shown: ['probe', rest[0], addr, ...rest.slice(1)].join(' '), cmd: join(bin, 'probe'), args: [rest[0], addr, ...rest.slice(1)] };
  return { shown: `go run . https://${addr}`, cmd: join(bin, `${id}-client`), args: [`https://${addr}`, ...rest] };
}

/** Run one step against the live server; returns the text to append to the
 * transcript (empty for signal/sleep, which act but print nothing). */
async function runStep(id: string, dir: string, srv: Proc, step: Step): Promise<string> {
  if ('sleep' in step) {
    await sleep(step.sleep);
    return '';
  }
  if ('signal' in step) {
    signal(srv, step.signal);
    await sleep(200);
    return '';
  }
  const c = client(id, step);
  const res = await within(start(c.cmd, c.args, dir).out, 10000, `${id} client`);
  if (res.code !== 0) throw new Error(`${id} client exited ${res.code}\n${res.stderr}`);
  return `$ ${c.shown}\n${res.stdout}`;
}

async function execute(id: string, run: Run): Promise<string> {
  const server = join(bin, id);
  // Run in the snippet's own directory so it can read files committed next to it.
  const dir = join(guide, 'snippets', id);
  if (!existsSync(server)) throw new Error(`${server} missing: run \`just ninja guide\` first`);
  if (run.client === 'none') {
    const p = start(server, run.serverArgs ?? [], dir);
    const res = await within(p.out, 5000, id);
    return `$ ${['./' + id, ...(run.serverArgs ?? [])].join(' ')}\n${res.stderr}${res.stdout}`;
  }
  if (udpBound()) throw new Error(`udp ${port} already in use (set GUIDE_PORT)`);
  const sargs = ['--port', String(port), ...(run.serverArgs ?? [])];
  const srv = start(server, sargs, dir);
  try {
    await waitBound(srv);
    let out = '';
    for (const step of expandSteps(run)) out += await runStep(id, dir, srv, step);
    const s = await stop(srv);
    return `$ ./${id} ${sargs.join(' ')}\n${s.stderr}${out}`;
  } finally {
    signal(srv, 'SIGKILL');
  }
}

function buildGo(ids: string[], runs: Map<string, Run>) {
  const go = (out: string, pkg: string) => execFileSync('go', ['build', '-o', join(bin, out), pkg], { cwd: guide, stdio: 'inherit' });
  const clientSteps = (id: string) => expandSteps(runs.get(id)!).filter((s): s is ClientStep => 'client' in s);
  if (ids.some((id) => clientSteps(id).some((s) => s.client === 'probe'))) go('probe', './probe');
  for (const id of ids) if (clientSteps(id).some((s) => s.client === 'go')) go(`${id}-client`, `./snippets/${id}/client.go`);
}

function diff(goldenPath: string, got: string): string {
  const tmp = join(mkdtempSync(join(tmpdir(), 'guide-')), 'got.txt');
  writeFileSync(tmp, got);
  try {
    execFileSync('diff', ['-u', '--label', 'golden.txt', '--label', 'actual', goldenPath, tmp]);
    return '';
  } catch (e) {
    return String((e as { stdout?: Buffer }).stdout ?? e);
  }
}

async function main() {
  const argv = process.argv.slice(2);
  const update = argv.includes('--update');
  const snippets = join(guide, 'snippets');
  const all = readdirSync(snippets).filter((d) => existsSync(join(snippets, d, 'main.c'))).sort();
  const ids = argv.filter((a) => a !== '--update');
  for (const id of ids) if (!all.includes(id)) throw new Error(`unknown snippet: ${id}`);
  const todo = ids.length ? ids : all;
  const runs = new Map<string, Run>(
    todo.map((id) => [id, JSON.parse(readFileSync(join(snippets, id, 'run.json'), 'utf8')) as Run]),
  );
  buildGo(todo, runs);
  let failed = 0;
  for (const id of todo) {
    const goldenPath = join(snippets, id, 'golden.txt');
    try {
      const got = normalize(await execute(id, runs.get(id)!), port);
      const want = existsSync(goldenPath) ? readFileSync(goldenPath, 'utf8') : '';
      if (got === want) {
        console.log(`ok   ${id}`);
      } else if (update) {
        writeFileSync(goldenPath, got);
        console.log(`upd  ${id}`);
      } else {
        failed++;
        console.log(`FAIL ${id}\n${diff(goldenPath, got)}`);
      }
    } catch (e) {
      failed++;
      console.log(`FAIL ${id}: ${(e as Error).message}`);
    }
  }
  process.exit(failed ? 1 : 0);
}

await main();
