import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

// Snippets use the public API only: everything is reachable from wired.h.
const allowed = new Set(['wired.h']);
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
