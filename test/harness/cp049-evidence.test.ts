import { beforeAll, describe, it } from 'vitest';
import { FULL_CONTROL_TIMEOUT_MS, prepareFullControl } from './cp050-full.js';

const timeout = FULL_CONTROL_TIMEOUT_MS + 30_000;

describe('CP-049/B3 selective oracle control', () => {
  let verify: () => void;
  beforeAll(() => { verify = prepareFullControl('selective-as-full'); }, timeout);
  it('CP-049/B3 selective oracle results cannot establish full validation', () => {
    verify();
  });
});

describe('CP-049/B3 changed candidate control', () => {
  let verify: () => void;
  beforeAll(() => { verify = prepareFullControl('changed-candidate'); }, timeout);
  it('CP-049/B3 changed candidate inputs cannot establish frozen full validation', () => {
    verify();
  });
});

describe('CP-049/B4 complete validation control', () => {
  let verify: () => void;
  beforeAll(() => { verify = prepareFullControl('complete'); }, timeout);
  it('CP-049/B4 complete synthetic validation retains original candidate input and report identities', () => {
    verify();
  });
});
