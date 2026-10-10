// rotate --finish re-checks the staged replacement after the confirmation prompt: a replacement
// whose time-before caveat passes while the prompt is open must never let the old root key be
// deleted (1.2.1).
import { readFileSync } from 'node:fs';
import { expect, it, vi } from 'vitest';
import { register } from './helpers/cp026-revoke-support.mjs';
import { absent, failure, invoke, instant, oldId, released, save, scratch, unchanged, type Fixture } from './helpers/cp029-rotate-support.js';
import { addFirstPartyCaveat, decodeMacaroon, timeBeforeCondition } from '../src/decode/index.js';
import { Secret } from '../src/secret.js';
import { revealSecret } from './helpers/secret-bytes.js';

vi.setConfig({ testTimeout: 60_000 });

/** Replaces the staged file with one expiring a minute after `instant`; returns the clock setter. */
function expiringReplacement(f: Fixture): (iso: string) => void {
  const base = new Secret(readFileSync(f.next.outPath));
  const mac = addFirstPartyCaveat(base, timeBeforeCondition('1m', () => new Date(instant)));
  const facts = decodeMacaroon(mac);
  const bytes = Buffer.from(revealSecret(mac));
  Object.assign(f.next, { outPath: register(bytes), fingerprint: facts.fingerprint,
    caveats: facts.caveats.map(({ type, value }) => ({ type, value })) });
  save(f);
  let now = new Date(instant);
  f.deps.clock = () => now;
  return iso => { now = new Date(iso); };
}

for (const repaired of [false, true]) {
  it(`rotate --finish refuses when the replacement expires during confirmation${repaired ? ' (absent-old repair)' : ''}`,
    async () => scratch(async f => {
      const setClock = expiringReplacement(f);
      if (repaired) absent(f);
      f.prompt.mockImplementation(async () => { setClock('2026-10-05T09:02:00.000Z'); return 'Alice'; });
      const before = readFileSync(f.registry), ids = [...f.ids];
      const result = await invoke(f, []);
      failure(result, 5, 'F7');
      expect(result.error!.message).toMatch(/expired while waiting for confirmation/);
      expect(result.error!.message).toContain(`macwarden revoke ${f.next.rootKeyId}`);
      expect(f.prompt).toHaveBeenCalledTimes(1);
      expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled();
      expect(f.ids).toEqual(ids); if (!repaired) expect(f.ids).toContain(oldId);
      unchanged(f, before); released(f);
    }));
}

it('rotate --finish --yes refuses an already expired replacement before deletion', async () => scratch(async f => {
  const setClock = expiringReplacement(f);
  setClock('2026-10-05T09:05:00.000Z');
  const before = readFileSync(f.registry), result = await invoke(f, ['--yes']);
  failure(result, 5, 'F7');
  expect(result.error!.message).toContain('new credential is not accepted');
  expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled(); expect(f.ids).toContain(oldId);
  unchanged(f, before); released(f);
}));

it('rotate --finish still finishes when the replacement is valid after confirmation', async () => scratch(async f => {
  const setClock = expiringReplacement(f);
  f.prompt.mockImplementation(async () => { setClock('2026-10-05T09:00:30.000Z'); return 'Alice'; });
  const result = await invoke(f, []);
  expect(result.error).toBeNull(); expect(f.lnd.deleteMacaroonId).toHaveBeenCalledTimes(1); released(f);
}));
