import { inspect } from 'node:util';
import { expect, it } from 'vitest';
import { decodeMacaroon, encodeMacaroon } from '../src/decode/index.js';
import { Secret } from '../src/secret.js';
import { fingerprint, vector } from './support/cp039-audit.js';

it('CP-039/B12-canonical-encoding encodes copied facts with independently pinned identity', () => {
  for (const name of ['default-readonly', 'duplicate-ops', 'third-party', 'trailing-bytes']) {
    const v = vector(name), facts = decodeMacaroon(new Secret(v.bytes));
    expect(facts.fingerprint, name).toBe(v.fingerprint);
    expect(facts.permissions, name).toEqual(v.printed.permissions);
    const copy = { ...facts, permissions: [...facts.permissions], caveats: facts.caveats.map(c => ({ ...c })),
      warnings: [...facts.warnings] };
    const encoded = encodeMacaroon(copy);
    expect(encoded.toString(), `${name} canonical byte hash`).toBe(`[redacted ${v.fingerprint}]`);
    expect(decodeMacaroon(encoded).rootKeyId, name).toBe(BigInt(v.printed.root_key_id));
    expect(decodeMacaroon(encoded).permissions, name).toEqual(v.printed.permissions);
    expect(decodeMacaroon(encoded).warnings.includes('trailing-bytes'), name).toBe(false);
  }
});
it('CP-039/B12-canonical-encoding valid trailing-byte Secret markers retain independent canonical identity', () => {
  const v = vector('trailing-bytes'), secret = new Secret(v.bytes);
  const canonical = `[redacted ${fingerprint(v.bytes.subarray(0, v.canonicalLength))}]`;
  expect(v.bytes.length > v.canonicalLength, 'reference includes trailing data').toBe(true);
  expect(fingerprint(v.bytes.subarray(0, v.canonicalLength))).toBe(v.fingerprint);
  expect(decodeMacaroon(secret).fingerprint).toBe(v.fingerprint);
  expect(secret.toString()).toBe(canonical); expect(secret.toJSON()).toBe(canonical); expect(inspect(secret)).toBe(canonical);
  expect(fingerprint(v.bytes) === v.fingerprint, 'trailing bytes change the raw hash but not public identity').toBe(false);
});
it('CP-039/A7-capabilities public Secret reflection exposes no credential byte accessor or storage', () => {
  const secret = new Secret(vector('default-readonly').bytes);
  const descriptors = Object.getOwnPropertyDescriptors(Secret.prototype);
  expect(Object.hasOwn(descriptors, 'reveal'), 'no public reveal capability').toBe(false);
  expect(Reflect.ownKeys(secret).every(key => key === 'fingerprint'), 'only safe fingerprint metadata is publicly stored').toBe(true);
  const allowed = new Set(['constructor', 'toString', 'toJSON', 'fingerprint', inspect.custom]);
  expect(Reflect.ownKeys(Secret.prototype).every(key => allowed.has(key)), 'only safe public methods').toBe(true);
  expect(inspect(secret).startsWith('[redacted fp:')).toBe(true);
});
