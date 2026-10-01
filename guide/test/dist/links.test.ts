import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const dist = new URL('../../dist/', import.meta.url);
const base = '/wired/guide/';
const html = (readdirSync(dist, { recursive: true }) as string[]).filter((f) => f.endsWith('.html'));

function resolves(href: string): boolean {
  const path = decodeURI(href.slice(base.length).split(/[?#]/)[0]);
  const target = new URL(path, dist);
  return path === '' || path.endsWith('/') ? existsSync(new URL('index.html', target)) : existsSync(target);
}

describe('internal links', () => {
  it.each(html)('%s links only to pages that exist', (file) => {
    const text = readFileSync(new URL(file, dist), 'utf8');
    const hrefs = [...text.matchAll(/(?:href|src)="([^"]+)"/g)].map((m) => m[1]).filter((h) => h.startsWith(base));
    expect(hrefs.filter((h) => !resolves(h))).toEqual([]);
  });
});
