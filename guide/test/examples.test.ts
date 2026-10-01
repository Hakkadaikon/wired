import { describe, expect, it } from 'vitest';
import { getExample, splitGolden } from '../src/lib/examples.ts';

describe('getExample', () => {
  it('loads code and golden for a known id', () => {
    const ex = getExample('hello');
    expect(typeof ex.code).toBe('string');
    expect(ex.golden).toContain('$ ./hello');
    expect(ex.client).toBeUndefined();
  });
  it('throws for an unknown id', () => {
    expect(() => getExample('no-such-snippet')).toThrow(/no-such-snippet/);
  });
});

describe('splitGolden', () => {
  it('splits on "$ " lines into command + output sections', () => {
    expect(splitGolden('$ ./server --port 4433\nup\n$ probe h3get x\nstatus=200\nbody\n')).toEqual([
      { cmd: './server --port 4433', out: 'up' },
      { cmd: 'probe h3get x', out: 'status=200\nbody' },
    ]);
  });
  it('keeps a section with empty output', () => {
    expect(splitGolden('$ ./a\n$ ./b\nx\n')).toEqual([
      { cmd: './a', out: '' },
      { cmd: './b', out: 'x' },
    ]);
  });
});
