// rotate --finish re-reads the staged replacement file after the confirmation prompt (pre-1.4
// audit): the operator confirms that the app uses N's file, so a file removed or overwritten while
// the prompt was open must not let O be deleted. The re-read is local and adds no LND call.
import { readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { expect, it, vi } from 'vitest';
import { absent, failure, newId, oldId, prefix, released, scratch, unchanged, type Envelope, type Fixture } from './helpers/cp029-rotate-support.js';
import { wireFixture } from './helpers/cp026-revoke-support.mjs';
import { expectSchemaValid } from './helpers/output-schema.js';
import { revealSecret } from './helpers/secret-bytes.js';
import { decodeMacaroon } from '../src/decode/index.js';
import type { Secret } from '../src/secret.js';

vi.setConfig({ testTimeout: 60_000 });

async function finish(f: Fixture, change: (path: string) => void): Promise<Envelope> {
  const path = f.next.outPath, original = readFileSync(path);
  // Acceptance by root key ID only: the fixture's default also compares the file, which this test changes.
  f.lnd.checkMacaroon.mockImplementation(async (mac: Secret) => {
    const id = String(decodeMacaroon(mac).rootKeyId); f.calls.push(`Check:${id}`);
    expect(revealSecret(mac).length).toBeGreaterThan(0);
    return f.ids.includes(id) ? { valid: true as const }
      : { valid: false as const, reason: 'root-key-missing' as const, message: `root key with id ${id} doesn't exist` };
  });
  let before = -1;
  f.prompt.mockImplementation(async () => { before = f.calls.length; change(path); return 'Alice'; });
  const module = await import('../src/commands/rotate.js');
  const stdout = vi.spyOn(process.stdout, 'write').mockImplementation((() => true) as typeof process.stdout.write);
  try {
    const result = await module.run(f.args, f.deps) as Envelope;
    expectSchemaValid(result);
    // Nothing reached LND after the prompt: the refusal precedes every post-prompt call.
    if (result.error) expect(f.calls.slice(before)).toEqual([]);
    return result;
  } finally { stdout.mockRestore(); writeFileSync(path, original, { mode: 0o600 }); }
}

const changes: Array<[string, (path: string) => void]> = [
  ['removed', path => unlinkSync(path)],
  ['overwritten with garbage', path => writeFileSync(path, 'garbage')],
  ['replaced by another macaroon on the same root key ID', path => writeFileSync(path, wireFixture('preset-invoice-only', newId))],
];

for (const repaired of [false, true]) {
  for (const [name, change] of changes) {
    it(`rotate --finish refuses at F7 when the replacement file is ${name} during confirmation${repaired ? ' (absent-old repair)' : ''}`,
      async () => scratch(async f => {
        if (repaired) absent(f);
        const before = readFileSync(f.registry), ids = [...f.ids];
        const result = await finish(f, change);
        failure(result, 3, 'F7');
        expect(result.error!.message).toContain('staged replacement file was removed or changed while waiting for confirmation; nothing changed');
        expect(result.error!.message).toContain(`macwarden revoke ${newId}`);
        expect(f.lnd.deleteMacaroonId).not.toHaveBeenCalled(); expect(f.deps.fs.rename).not.toHaveBeenCalled();
        expect(f.ids).toEqual(ids); if (!repaired) expect(f.ids).toContain(oldId);
        expect(f.calls.slice(0, 4)).toEqual([...prefix, `Check:${newId}`]);
        unchanged(f, before); released(f);
      }));
  }
}

it('rotate --finish proceeds when the replacement file is rewritten with the same bytes during confirmation', async () => scratch(async f => {
  const result = await finish(f, path => writeFileSync(path, readFileSync(path)));
  expect(result.error).toBeNull();
  expect(f.lnd.deleteMacaroonId).toHaveBeenCalledTimes(1); expect(f.ids).not.toContain(oldId);
  released(f);
}));
