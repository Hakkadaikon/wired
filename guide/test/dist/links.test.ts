import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const dist = new URL('../../dist/', import.meta.url);
const origin = 'https://hakkadaikon.github.io';
const base = '/wired/guide/';
// 404.html is skipped: Starlight links it to per-locale 404 pages it never builds.
const html = (readdirSync(dist, { recursive: true }) as string[]).filter((f) => f.endsWith('.html') && f !== '404.html');

/** The site-absolute path a link on `file` points at, or null if it leaves the guide. */
function target(file: string, href: string): string | null {
  const page = new URL(base + file.replace(/index\.html$/, ''), origin);
  const url = new URL(href, page);
  return url.origin === origin && url.pathname.startsWith(base) ? url.pathname : null;
}

function exists(pathname: string): boolean {
  const rel = decodeURI(pathname.slice(base.length));
  return rel === '' || rel.endsWith('/') ? existsSync(new URL(`${rel}index.html`, dist)) : existsSync(new URL(rel, dist));
}

describe('internal links', () => {
  it.each(html)('%s links only to pages that exist', (file) => {
    const text = readFileSync(new URL(file, dist), 'utf8');
    const broken = [...text.matchAll(/(?:href|src)="([^"#][^"]*)"/g)]
      .map((m) => target(file, m[1].replaceAll('&amp;', '&')))
      .filter((p): p is string => p !== null && !exists(p));
    expect(broken).toEqual([]);
  });
});
