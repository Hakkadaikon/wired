import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const page = (p: string) => readFileSync(new URL(`../../dist/${p}`, import.meta.url), 'utf8');

describe('built site', () => {
  it.each([
    ['en', 'en'],
    ['ja', 'ja'],
  ])('/%s/ exists with <html lang="%s">', (dir, lang) => {
    expect(existsSync(new URL(`../../dist/${dir}/index.html`, import.meta.url))).toBe(true);
    expect(page(`${dir}/index.html`)).toMatch(new RegExp(`<html[^>]*lang="${lang}"`));
  });

  it('root redirects to en/', () => {
    expect(page('index.html')).toMatch(/http-equiv="refresh"[^>]*\/wired\/guide\/en\//);
  });
});
