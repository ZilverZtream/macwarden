import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { inspect } from 'node:util';
import { expect, it } from 'vitest';
import { Secret } from '../src/secret.js';
import { addFirstPartyCaveat, decodeMacaroon, encodeMacaroon } from '../src/decode/index.js';
import { builtInspect, fingerprint, independentCaveat, noEcho, register, scratch, variants, vector } from './support/cp041-controls.js';

it('CP-041/B2-canonical-secret-fingerprint valid trailing variants have one public identity through built inspect', () => scratch(dir => {
  const v = vector(); expect(fingerprint(v.canonical)).toBe(v.fingerprint);
  for (const [index, bytes] of variants().entries()) {
    register(bytes); const secret = new Secret(bytes), facts = decodeMacaroon(secret);
    expect.soft(secret.fingerprint, 'public canonical identity').toBe(v.fingerprint);
    for (const value of [String(secret), secret.toJSON(), inspect(secret), JSON.stringify(secret)]) {
      expect.soft(value.includes(v.fingerprint), 'safe canonical marker').toBe(true); noEcho(value, bytes);
    }
    expect(facts.fingerprint).toBe(v.fingerprint); expect(facts.permissions).toEqual(v.printed.permissions);
    expect(encodeMacaroon({ ...facts }).fingerprint).toBe(v.fingerprint);
    const path = join(dir, `variant-${index}.macaroon`); writeFileSync(path, bytes);
    const doc = builtInspect(path);
    expect(doc.schema === 1 && doc.ok && doc.error === null, 'one success envelope').toBe(true);
    expect(doc.result.fingerprint).toBe(v.fingerprint);
    expect(doc.result.warnings.includes('trailing-bytes')).toBe(index > 0);
  }
}));
it('CP-041/B2-canonical-secret-fingerprint genuine caveat changes independently computed canonical identity', () => {
  const v = vector(), reference = independentCaveat(); register(reference.bytes);
  const product = addFirstPartyCaveat(new Secret(v.canonical), reference.condition);
  expect(reference.fingerprint === v.fingerprint).toBe(false);
  expect(product.fingerprint).toBe(reference.fingerprint);
  expect(decodeMacaroon(product).caveats).toEqual([{ type: 'time-before', value: '2030-01-01T00:00:00Z' }]);
});
it('CP-041/B2-canonical-secret-fingerprint malformed containers retain exact safe marker and decoding stage', () => {
  const bytes = Buffer.from([2, 127, 1, 42]), secret = new Secret(bytes);
  expect(secret.fingerprint).toBe(fingerprint(bytes));
  let caught: unknown; try { decodeMacaroon(secret); } catch (error) { caught = error; }
  expect((caught as { stage: string }).stage).toBe('packet');
  for (const value of [String(secret), inspect(secret), JSON.stringify(secret), String(caught)]) noEcho(value, bytes);
});
