---
description: Implementation may run in parallel, but git add/commit, tests/run.c wiring, and justfile edits are serialized to one worker; commits are conventional micro-commits.
appliesTo: when running parallel coders/subagents, when wiring run.c or justfile, when committing changes
alwaysApply: true
---

# Parallelism & commit discipline

## What may run in parallel, what may not

Parallelize ONLY the editing of distinct new files. Serialize anything that
touches a shared resource to a single worker:

- `tests/run.c` and `justfile` are shared files — wiring them from multiple
  coders guarantees conflict (#2/#18). One coordinator wires, last, in one pass.
- **The git index is a single repo-wide resource** (#21). Even when coders touch
  different files, parallel `git add`/`git commit` collide: coder A stages
  `chacha20.c`, coder B's `commit` sweeps A's staged diff into B's commit, and
  A's own commit comes up empty ("no changes added"). "Different files" does NOT
  imply "independent index".

So the pipeline is fixed:

1. Implementation coders run in parallel — **edit their own new files only, do
   NOT commit.** Leave changes in the worktree.
2. ONE aggregation worker wires `run.c`/`justfile`, runs the three-point gate
   (build-and-verify.md), and commits everything.

If parallel commits are truly unavoidable, give each worker its own
`git worktree` — but (1)+(2) is lighter and is the default.

## Subagent instructions (always include these)

When delegating to coders/subagents, state explicitly:

- "Edit only your assigned new files. Do NOT `git add`/`commit`/wire `run.c` or
  `justfile`." (#18/#21)
- "Verify in `$TMPDIR`. Public API names must be globally unique — grep `src/`
  first." (#16/#17 — isolated green is necessary, not sufficient; integration
  green is the real gate.)
- "Emit tool calls as structured calls. Never write a tool-markup prefix or
  preamble in prose." Tool-markup leaks happen in subagents too and burn
  thousands of seconds in a retry loop (#22).
- When a subagent adds temporary diagnostics (hex dumps, per-layer ok/fail
  probes), tell it up front: ONE file or ONE commit, a fixed location, and remove
  them the moment the cause is confirmed (#31/#32). Otherwise uncommitted probes
  pile up across agents and the real fix gets lost among them — sweep `git status`
  for stray diffs periodically.
- For a long verify-then-commit flow, have the subagent write intermediate
  results to a file (a probe log) and make the final commit its own separate
  step, so a mid-flow stop loses nothing (#20).
- "Do NOT push. Assume you have no credential-helper permission." A subagent
  once pushed to `origin/main` despite a no-push instruction (2026-07-03).
  Saying it is not enough — when collecting a subagent's work, run
  `git ls-remote origin main` and compare against the local base to DETECT an
  unintended push instead of discovering it later.
- A subagent working in its own worktree starts from a stale base: make its
  FIRST step `git merge main` plus an explicit check that the base sha matches
  current `main` (2026-07-03 — an agent built on a base several days old).

## Detecting stalled / leaking background subagents

Judge progress by ARTIFACTS, not notifications (#19/#22):

- A completion notice can be lost; absence of a notice does NOT mean "still
  working". Check the output file's size/mtime and whether `src/<dir>/` exists.
- A background coder producing no file for a long time has stalled — kill and
  re-launch it.
- Thousands of seconds + three-digit tool_uses + repeated same-task-id notices =
  a tool-markup leak loop, not progress. Verify with `git log` / file existence.
- When you kill a runaway subagent: (a) salvage only the facts it confirmed,
  (b) `git stash` its uncommitted diff to get a clean tree, (c) finish the rest
  by reading the code directly rather than re-launching into the same loop (#31).
- A subagent that died on a session/token limit produced nothing and must be
  re-launched — but an earlier coder may have left unwired `src/` behind. On
  resume, don't trust notifications: `comm` the source list against `tests/run.c`
  to find generated-but-unwired files and pick them up before moving on (#27).

## Commits: conventional micro-commits

- Split changes into ~30–50 line logical units; one conventional commit each
  (`feat:`, `fix:`, `test:`, `build:`, …) with an RFC section reference where
  relevant.
- End every commit message with the trailer used across this history:
  ```
  Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
  ```
  Confirm the exact current form with `git log -1 --format=%B` before committing.
- Never commit a red gate (build-and-verify.md). Never `;`-chain gate and commit.
