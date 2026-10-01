import { existsSync, readdirSync, readFileSync } from 'node:fs';
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

const pages = (readdirSync(new URL('../../dist/', import.meta.url), { recursive: true }) as string[]).filter(
  (f) => /^(en|ja)\/.+\/index\.html$/.test(f),
);

describe.each(pages)('%s', (file) => {
  const text = page(file);
  it('has the locale\'s <html lang>', () => {
    expect(text).toMatch(new RegExp(`<html[^>]*lang="${file.slice(0, 2)}"`));
  });
  it('shows copyable code next to its real output when it has an example', () => {
    if (!text.includes('data-example=')) return;
    expect(text).toContain('data-example-result');
    expect(text).toMatch(/<button[^>]*data-copied/);
  });
});
