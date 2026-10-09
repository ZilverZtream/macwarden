import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { run as inventory } from '../src/commands/inventory.js';
import { run as runRespond } from '../src/commands/respond.js';
import { run as rotate } from '../src/commands/rotate.js';
import { replacementLinkProblems } from '../src/registry/index.js';
import { render } from '../src/output/index.js';
import { expectSchemaValid } from './helpers/output-schema.js';
import { entry, fixture, oldId, ownId, type Entry, type Fixture, declareStagedFiles, declareStaging } from './helpers/cp038-online.js';

// Fresh audit (2026-10-08): two active entries naming each other in `replaces` passed the
// per-link check, and respond's originals() then dropped both, hiding live credentials.
const respond = async (...args: Parameters<typeof runRespond>) => {
  const output = await runRespond(...args);
  expectSchemaValid(output);
  return output;
};
const xId = 4294967460n, yId = 4294967461n, zId = 4294967462n;

function setup(entries: (f: Fixture) => Entry[], extra: bigint[]) {
  const f = fixture();
  f.save(entries(f));
  f.lnd.ids = [0n, ownId, oldId, ...extra];
  return { f, outDir: declareStaging(join(f.dir, 'replacements')) };
}
const mutations = (f: Fixture) => f.lnd.calls.filter(call => call === 'BakeMacaroon' || call === 'DeleteMacaroonID');

const shapes: [string, (f: Fixture) => Entry[], bigint[]][] = [
  // The audit's probe: equal creation times, each naming the other.
  ['a two-entry cycle with one label', f => [f.old, entry(xId, 'Pay', String(yId)), entry(yId, 'Pay', String(xId))], [xId, yId]],
  // Z replaces Y, which is itself a staged replacement of X.
  ['a chain with one label', f => [f.old, entry(xId, 'Pay'), entry(yId, 'Pay', String(xId)), entry(zId, 'Pay', String(yId))], [xId, yId, zId]],
  // Two active entries both claim to replace the same original.
  ['two claimants with one label', f => [f.old, entry(xId, 'Pay'), entry(yId, 'Pay', String(xId)), entry(zId, 'Pay', String(xId))], [xId, yId, zId]],
];

it.each(shapes)('RT/replacement-links %s is refused by respond, rotate and inventory, and nothing changes', async (_name, entries, extra) => {
  const { f, outDir } = setup(entries, extra);
  for (const args of [['--dry-run'], ['--out-dir', outDir, '--yes'], ['--finish', '--dry-run']]) {
    const output = await respond([...args, ...f.flags], f.deps);
    expect(output.ok).toBe(false);
    expect(output.error?.code).toBe(3);
  }
  for (const args of [['Pay', '--out', join(f.dir, 'next.macaroon')], ['Pay', '--finish', '--yes'], ['Alice', '--out', join(f.dir, 'a.macaroon')]]) {
    const rotated = await rotate([...args, ...f.flags], f.deps);
    expect(rotated.error?.code).toBe(3);
  }
  const listed = await inventory(f.flags, f.deps);
  expect(listed.error?.code).toBe(3);
  expect(mutations(f)).toEqual([]);
});

// Different labels pass the registry's per-label rule, so the shared link check is the
// layer that must catch them: respond and rotate refuse, inventory flags without hiding.
const mixed: [string, (f: Fixture) => Entry[], bigint[]][] = [
  ['a cycle across labels', f => [f.old, entry(xId, 'Pay', String(yId)), entry(yId, 'Shop', String(xId))], [xId, yId]],
  ['a chain across labels', f => [f.old, entry(xId, 'Pay'), entry(yId, 'Shop', String(xId)), entry(zId, 'Till', String(yId))], [xId, yId, zId]],
];

it.each(mixed)('RT/replacement-links %s is tampering for respond and rotate and flagged by inventory', async (_name, entries, extra) => {
  const { f, outDir } = setup(entries, extra);
  for (const args of [['--dry-run'], ['--out-dir', outDir, '--yes'], ['--finish', '--dry-run']]) {
    const output = await respond([...args, ...f.flags], f.deps);
    expect(output.error).toMatchObject({ code: 3, step: 'P5' });
    expect(output.error!.message).toMatch(/registry tampering: root key ID \d+ claims to replace \d+/);
  }
  const rotated = await rotate(['Alice', '--out', join(f.dir, 'a.macaroon'), ...f.flags], f.deps);
  expect(rotated.error?.code).toBe(3);
  expect(rotated.error!.message).toMatch(/registry tampering/);
  expect(mutations(f)).toEqual([]);
  const listed = await inventory(f.flags, f.deps);
  expectSchemaValid(listed);
  expect(listed.error).toBeNull();
  const rows = (listed.result as { rootKeys: { rootKeyId: string; flags: string[] }[] }).rootKeys;
  for (const id of extra) expect(rows.map(row => row.rootKeyId)).toContain(String(id));
  expect(rows.some(row => row.flags.includes('invalid-replacement'))).toBe(true);
  expect(render(listed, 'text')).toMatch(/invalid replacement link \(registry tampering\?\)/);
});

// Replacement credentials written into the staging directory are intended outputs.
afterEach(() => { declareStagedFiles(); });

it('RT/replacement-links the shared check names chains, cycles and second claimants', () => {
  const x = entry(xId, 'Pay'), y = entry(yId, 'Pay', String(xId)), z = entry(zId, 'Pay', String(yId));
  expect(replacementLinkProblems([x, y, z]).map(problem => [problem.rootKeyId, problem.problem]))
    .toEqual([[String(zId), 'the credential it replaces is itself a staged replacement (a chain or a cycle)']]);
  const cycle = replacementLinkProblems([entry(xId, 'Pay', String(yId)), entry(yId, 'Pay', String(xId))]);
  expect(cycle.length).toBe(2);
  const claimants = replacementLinkProblems([x, y, entry(zId, 'Pay', String(xId))]);
  expect(claimants.map(problem => problem.problem)).toEqual([`root key ID ${yId} also claims to replace it`]);
});

it('RT/replacement-links a genuine staged rotation and a finished one are not tampering', () => {
  const original = entry(xId, 'Pay');
  const staged = { ...entry(yId, 'Pay', String(xId)), createdAt: '2026-10-08T12:00:00.000Z' };
  // A finished rotation: the old entry is revoked, so the link is history, not a pending claim.
  const revoked = { ...entry(zId, 'Done'), status: 'revoked' as const, revokedAt: '2026-10-01T00:00:00.000Z', revokeEvidence: 'rejected' as const };
  const finished = { ...entry(oldId, 'Done', String(zId)), createdAt: '2026-10-08T12:00:00.000Z' };
  // Rotating that finished replacement again: its own link points at a revoked entry.
  const again = { ...entry(4294967463n, 'Done', String(oldId)), createdAt: '2026-10-09T12:00:00.000Z' };
  expect(replacementLinkProblems([original, staged, revoked, finished, again])).toEqual([]);
});
