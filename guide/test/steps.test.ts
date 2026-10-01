import { describe, expect, it } from 'vitest';
import { expandSteps } from '../src/lib/steps.ts';

describe('expandSteps', () => {
  it('wraps a legacy client+args run into a single client step', () => {
    expect(expandSteps({ client: 'probe', args: ['tls', '3'] })).toEqual([
      { client: 'probe', args: ['tls', '3'] },
    ]);
  });
  it('wraps a legacy run with no args', () => {
    expect(expandSteps({ client: 'go' })).toEqual([{ client: 'go', args: undefined }]);
  });
  it('returns steps verbatim when present, ignoring top-level client/args', () => {
    const steps = [{ client: 'probe' as const, args: ['h3get', '/'] }, { sleep: 50 }, { signal: 'SIGHUP' as const }];
    expect(expandSteps({ client: 'go', args: ['ignored'], steps })).toEqual(steps);
  });
});
