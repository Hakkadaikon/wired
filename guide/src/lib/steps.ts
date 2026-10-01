/** One action executed while a snippet's server runs. */
export type Step =
  | { client: 'probe' | 'go'; args?: string[] }
  | { signal: NodeJS.Signals }
  | { sleep: number };

/** run.json shape: a server (`client: 'none'`) or a single legacy client
 * run, optionally replaced by an ordered `steps` list (see runner/run.ts). */
export interface Run {
  client: 'none' | 'probe' | 'go';
  args?: string[];
  serverArgs?: string[];
  steps?: Step[];
}

/** Normalize a run into the ordered steps to execute against the live
 * server: `steps` verbatim when present, else the single legacy client run. */
export function expandSteps(run: Run): Step[] {
  return run.steps ?? [{ client: run.client as 'probe' | 'go', args: run.args }];
}
