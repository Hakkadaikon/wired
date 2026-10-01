import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const docs = new URL('../src/content/docs/', import.meta.url);
const pages = (lang: string) =>
  (readdirSync(new URL(`${lang}/`, docs), { recursive: true }) as string[])
    .filter((f) => f.endsWith('.mdx') || f.endsWith('.md'))
    .sort();
const exampleIds = (lang: string) =>
  new Set(
    pages(lang).flatMap((p) =>
      [...readFileSync(new URL(`${lang}/${p}`, docs), 'utf8').matchAll(/<Example id="([^"]+)"/g)].map((m) => m[1]),
    ),
  );
const snippets = readdirSync(new URL('../snippets/', import.meta.url)).sort();

describe('en/ja parity', () => {
  it('both locales have the same pages', () => {
    expect(pages('ja')).toEqual(pages('en'));
  });
  it.each(['en', 'ja'])('every <Example id> in %s names a snippet', (lang) => {
    for (const id of exampleIds(lang)) expect(snippets).toContain(id);
  });
  it.each(['en', 'ja'])('every snippet is shown in %s', (lang) => {
    expect([...exampleIds(lang)].sort()).toEqual(snippets);
  });
});
