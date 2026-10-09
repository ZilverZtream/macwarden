import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { run as runRespond } from '../src/commands/respond.js';
import { run as rotate } from '../src/commands/rotate.js';
import type { RespondResult } from '../src/command-result.js';
import { render } from '../src/output/index.js';
import { expectSchemaValid } from './helpers/output-schema.js';
import { createHash } from 'node:crypto';
import { entry, fixture, oldId, ownId, register, responseBytes, vector, type Entry, type Fixture, declareStagedFiles, declareStaging } from './helpers/cp038-online.js';

// Red-team scenarios (2026-10-08): an attacker may hold leaked credentials, may have
// modified or restored the registry, and acts between stage and finish.
const respond = async (...args: Parameters<typeof runRespond>) => {
  const output = await runRespond(...args);
  expectSchemaValid(output);
  return output;
};
const bobId = 4294967400n, malloryId = 4294967450n;
const canaryCaveat = [{ type: 'lnd-custom', value: 'region-a1a2f213 3a1e61423be44eaf' }];

function setup(entries: (f: Fixture) => Entry[], extraIds: bigint[] = []) {
  const f = fixture();
  f.save(entries(f));
  f.lnd.ids = [0n, ownId, oldId, bobId, ...extraIds];
  return { f, outDir: declareStaging(join(f.dir, 'replacements')) };
}
const mutations = (f: Fixture) => f.lnd.calls.filter(call => call === 'BakeMacaroon' || call === 'DeleteMacaroonID');

// Replacement credentials written into the staging directory are intended outputs.
afterEach(() => { declareStagedFiles(); });

it('RT/respond-canary a canary is never rotated into an ordinary credential, and rotate refuses it', async () => {
  const { f, outDir } = setup(f => [{ ...f.old, caveats: canaryCaveat }]);
  const staged = await respond(['--out-dir', outDir, '--yes', ...f.flags], f.deps);
  expect(staged.error).toBeNull();
  const item = (staged.result as RespondResult).items.find(candidate => candidate.label === 'Alice')!;
  expect(item).toMatchObject({ action: 'manual', status: 'manual', replacementRootKeyId: null });
  expect(item.note).toMatch(/custom caveat .* not rotated/);
  expect(item.note).toContain('macwarden bake --canary');
  expect(mutations(f)).toEqual([]);
  const rotated = await rotate(['Alice', '--out', join(f.dir, 'next.macaroon'), ...f.flags], f.deps);
  expect(rotated.error).toMatchObject({ code: 2, step: 'S3' });
  expect(rotated.error!.message).toMatch(/custom caveat/);
  expect(mutations(f)).toEqual([]);
});

it('RT/respond-revoked-present an ID the registry calls revoked but LND still holds is listed as needing action', async () => {
  const { f } = setup(f => [f.old, { ...entry(bobId, 'Bob'), status: 'revoked', revokedAt: '2026-09-01T00:00:00.000Z', revokeEvidence: 'by-id-only' }]);
  const output = await respond(['--dry-run', ...f.flags], f.deps);
  const plan = output.result as RespondResult;
  expect(plan.revokedButPresent.rootKeyIds).toEqual([String(bobId)]);
  expect(plan.revokedButPresent.guidance).toMatch(/Treat them as live and revoke each/);
  expect(plan.unknown.rootKeyIds).not.toContain(String(bobId));
  expect(output.warnings.map(item => (typeof item === 'string' ? item : item.code))).toContain('revoked-but-present');
  expect(render(output, 'text')).toContain(`REVOKED BUT STILL IN LND  ${bobId}`);
});

it.each([
  ['a different label', (f: Fixture) => ({ ...entry(malloryId, 'Mallory', String(oldId)), createdAt: f.old.createdAt })],
  ['an earlier creation time', () => ({ ...entry(malloryId, 'Alice', String(oldId)), createdAt: '2020-01-01T00:00:00.000Z' })],
])('RT/replaces-tamper a replacement link with %s is reported as tampering, never trusted', async (_name, forged) => {
  const { f, outDir } = setup(f => [f.old, forged(f)], [malloryId]);
  const output = await respond(['--out-dir', outDir, '--yes', ...f.flags], f.deps);
  expect(output.error).toMatchObject({ code: 3, step: 'P5' });
  expect(output.error!.message).toMatch(/registry tampering: root key ID 4294967450 claims to replace/);
  for (const args of [['Alice', '--out', join(f.dir, 'next.macaroon')], ['Alice', '--finish', '--yes']]) {
    const rotated = await rotate([...args, ...f.flags], f.deps);
    expect(rotated.error).toMatchObject({ code: 3 });
    expect(rotated.error!.message).toMatch(/registry tampering/);
  }
  expect(mutations(f)).toEqual([]);
});

it('RT/baking-risk credentials that can bake are flagged, finished first, and every proof is scoped to its credential', async () => {
  // Bob's credential file really carries macaroon:generate, so registry and file agree.
  const baker = (): Entry => {
    const permissions = [...vector('preset-invoice-only').permissions, 'macaroon:generate'];
    const bytes = responseBytes(bobId, permissions) as Buffer;
    return { ...entry(bobId, 'Bob'), grade: 'ADMIN', permissions, outPath: register(bytes),
      fingerprint: 'fp:' + createHash('sha256').update(bytes).digest('hex').slice(0, 16) };
  };
  const { f, outDir } = setup(f => [f.old, baker()]);
  const plan = (await respond(['--dry-run', ...f.flags], f.deps)).result as RespondResult;
  expect(plan.bakingRisk.rootKeyIds).toEqual([String(bobId)]);
  expect(plan.bakingRisk.guidance.join(' ')).toMatch(/regenerate all root keys/);
  expect(plan.bakingRisk.guidance.join(' ')).toMatch(/covers that credential only/);
  const staged = await respond(['--out-dir', outDir, '--allow-admin', '--yes', ...f.flags], f.deps);
  expect(staged.error).toBeNull();
  for (const item of (staged.result as RespondResult).items) expect(item.replacementFingerprint).toMatch(/^fp:[0-9a-f]{16}$/);
  const finished = (await respond(['--finish', '--yes', ...f.flags], f.deps)).result as RespondResult;
  // The credential that can bake is revoked first, shortening the window a leaked one has.
  expect(f.lnd.deleted[0]).toBe(bobId);
  for (const item of finished.items) expect(item.proof).toMatchObject({ scope: 'this-credential' });
});

it('RT/MW110-06 baking risk is baking authority (macaroon:generate, BakeMacaroon URI, or unassessed), not the ADMIN grade', async () => {
  const writer = { ...entry(bobId, 'Bob'), grade: 'ADMIN', permissions: ['info:read', 'macaroon:write'] };
  const uri = { ...entry(malloryId, 'Mallory'), grade: 'ADMIN', permissions: ['info:read', 'uri:/lnrpc.Lightning/BakeMacaroon'] };
  const unknown = { ...entry(4294967460n, 'Carol'), grade: 'UNASSESSED', permissions: ['info:read', 'future:bake'] };
  // A recorded grade cannot hide baking authority the permissions show.
  const downgraded = { ...entry(4294967470n, 'Dave'), grade: 'READ', permissions: ['info:read', 'macaroon:generate'] };
  const { f } = setup(f => [f.old, writer, uri, unknown, downgraded], [malloryId, 4294967460n, 4294967470n]);
  const output = await respond(['--dry-run', ...f.flags], f.deps);
  expect(output.error).toBeNull();
  const plan = output.result as RespondResult;
  expect(plan.bakingRisk.rootKeyIds).toEqual([String(malloryId), '4294967460', '4294967470']);
  expect(plan.items.find(item => item.label === 'Bob')).toMatchObject({ grade: 'ADMIN' });
});
