import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

// Snippets use the public API only: wired.h, plus the handful of headers
// an application legitimately includes directly (each added here by the
// first sample that needed it).
const allowed = new Set([
  'wired.h',
  'app/moqt/run/moqtrun.h',
  'app/moqt/data/moqdata.h',
  'app/moqt/dgram/moqdg.h',
  'crypto/symmetric/hash/hash/sha256.h',
  'app/media/mp4frag/mp4frag.h',
  'common/platform/clock/mono.h',
]);
const ids = readdirSync(new URL('../snippets/', import.meta.url));

describe('snippet includes', () => {
  it.each(ids)('%s/main.c includes only public headers', (id) => {
    const src = readFileSync(new URL(`../snippets/${id}/main.c`, import.meta.url), 'utf8');
    const incs = [...src.matchAll(/^#include\s+["<]([^">]+)[">]/gm)].map((m) => m[1]);
    expect(incs).toContain('wired.h');
    for (const inc of incs) expect(allowed).toContain(inc);
  });
  // api-stability.md: these are reachable from wired.h but not application API.
  it.each(ids)('%s/main.c calls no internal helpers', (id) => {
    const src = readFileSync(new URL(`../snippets/${id}/main.c`, import.meta.url), 'utf8');
    expect(src.match(/\b(bytes_\w+|wired_cstr_len|wired_die)\s*\(/g) ?? []).toEqual([]);
  });
});
