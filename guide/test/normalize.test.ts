import { describe, expect, it } from 'vitest';
import { normalize } from '../src/lib/normalize.ts';

describe('normalize', () => {
  it('turns CRLF into LF', () => {
    expect(normalize('a\r\nb\r\n', 4433)).toBe('a\nb\n');
  });
  it('masks wired_log_ts timestamps', () => {
    expect(normalize('1790448263.123456789 listening\n', 4433)).toBe('<ts> listening\n');
  });
  it('rewrites the run port to 4433', () => {
    expect(normalize('https://127.0.0.1:14433/\n', 14433)).toBe('https://127.0.0.1:4433/\n');
  });
  it('rewrites a --port flag to 4433', () => {
    expect(normalize('$ ./srv --port 14433\n', 14433)).toBe('$ ./srv --port 4433\n');
  });
  it('keeps deterministic hex (digests are the point of some pages)', () => {
    const d = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n';
    expect(normalize(d, 4433)).toBe(d);
  });
  it('strips trailing spaces and ends with exactly one newline', () => {
    expect(normalize('a  \nb\n\n\n', 4433)).toBe('a\nb\n');
    expect(normalize('', 4433)).toBe('');
  });
  it('is idempotent', () => {
    const once = normalize('1.000000001 x  \r\n127.0.0.1:14433\n\n', 14433);
    expect(normalize(once, 14433)).toBe(once);
  });
});
