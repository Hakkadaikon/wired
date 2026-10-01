import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

// Snippets use the public API only: wired.h, plus the two documented
// headers that live outside it (see docs/api-stability.md).
const allowed = new Set(['wired.h', 'app/moqt/run/moqtrun.h', 'crypto/symmetric/hash/hash/sha256.h']);
const ids = readdirSync(new URL('../snippets/', import.meta.url));

describe('snippet includes', () => {
  it.each(ids)('%s/main.c includes only public headers', (id) => {
    const src = readFileSync(new URL(`../snippets/${id}/main.c`, import.meta.url), 'utf8');
    const incs = [...src.matchAll(/^#include\s+["<]([^">]+)[">]/gm)].map((m) => m[1]);
    expect(incs).toContain('wired.h');
    for (const inc of incs) expect(allowed).toContain(inc);
  });
});
