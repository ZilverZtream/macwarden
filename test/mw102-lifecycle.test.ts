import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { run as runRespond } from '../src/commands/respond.js';
import { run as runRotate } from '../src/commands/rotate.js';
import { run as runRevoke } from '../src/commands/revoke.js';
import { decodeMacaroon } from '../src/decode/index.js';
import { Secret } from '../src/secret.js';
import type { RespondResult } from '../src/command-result.js';
import { expectSchemaValid } from './helpers/output-schema.js';
import { wireFixture } from './helpers/cp026-revoke-support.mjs';
import { declare, declareStagedFiles, declareStaging, entry, fixture, nextId, oldId, ownId, register,
  type Entry, type Fixture } from './helpers/cp038-online.js';

// Audit 2026-10-08 of 1.0.1 (docs/reviews/2026-10-08-audit-1.0.1.md): lifecycle findings.
const respond = async (...args: Parameters<typeof runRespond>) => {
  const output = await runRespond(...args);
  expectSchemaValid(output);
  return output;
};
const rotate = async (...args: Parameters<typeof runRotate>) => {
  const output = await runRotate(...args);
  expectSchemaValid(output);
  return output;
};
const bobId = 4294967400n;
const mutations = (f: Fixture) => f.lnd.calls.filter(call => call === 'BakeMacaroon' || call === 'DeleteMacaroonID');

/** A registry entry whose file carries an lnd-custom caveat (a canary) but whose recorded caveats were cleared. */
function strippedCanary(): Entry {
  const bytes = wireFixture('lnd-custom', String(oldId), ['info:read']) as Buffer;
  const facts = decodeMacaroon(new Secret(bytes));
  expect(facts.caveats.some(caveat => caveat.type === 'lnd-custom')).toBe(true);
  return { ...entry(oldId), permissions: ['info:read'], grade: 'READ', caveats: [],
    fingerprint: facts.fingerprint, outPath: register(bytes) };
}

afterEach(() => { declareStagedFiles(); });

it('MW102-01/rotate a canary whose registry caveats were cleared is refused from its decoded file, before any mutation', async () => {
  const f = fixture();
  f.save([strippedCanary()]);
  f.lnd.ids = [0n, ownId, oldId];
  const before = readFileSync(f.registry);
  for (const extra of [['--dry-run'], []]) {
    const output = await rotate(['Alice', '--out', f.out, ...extra, ...f.flags], f.deps);
    expect(output.error).toMatchObject({ code: 3, step: 'S4' });
    expect(output.error!.message).toMatch(/custom caveat/);
  }
  expect(mutations(f)).toEqual([]);
  expect(f.lnd.calls).toEqual([]);
  expect(existsSync(f.out)).toBe(false);
  expect(readFileSync(f.registry).equals(before)).toBe(true);
});

it('MW102-01/respond the batch refuses a registry whose canary caveats disagree with the credential file', async () => {
  const f = fixture();
  f.save([strippedCanary(), entry(bobId, 'Bob')]);
  f.lnd.ids = [0n, ownId, oldId, bobId];
  const before = readFileSync(f.registry);
  const outDir = declareStaging(join(f.dir, 'replacements'));
  for (const args of [['--dry-run'], ['--out-dir', outDir, '--yes'], ['--finish', '--yes']]) {
    const output = await respond([...args, ...f.flags], f.deps);
    expect(output.error).toMatchObject({ code: 3, step: 'P5' });
    expect(output.error!.message).toMatch(new RegExp(`root key ID ${oldId}.*custom caveat`));
  }
  expect(mutations(f)).toEqual([]);
  expect(existsSync(join(outDir, 'Bob.macaroon'))).toBe(false);
  expect(readFileSync(f.registry).equals(before)).toBe(true);
});

it('MW102-01/control a canary recorded with its caveat stays manual, and ordinary credentials still stage', async () => {
  const f = fixture();
  const canary = strippedCanary();
  const bytes = readFileSync(canary.outPath!);
  canary.caveats = decodeMacaroon(new Secret(bytes)).caveats.map(({ type, value }) => ({ type, value }));
  f.save([canary, entry(bobId, 'Bob')]);
  f.lnd.ids = [0n, ownId, oldId, bobId];
  const outDir = declareStaging(join(f.dir, 'replacements'));
  const output = await respond(['--out-dir', outDir, '--yes', ...f.flags], f.deps);
  const result = output.result as RespondResult;
  expect(output.error).toBeNull();
  expect(result.items.map(item => [item.label, item.action, item.status])).toEqual([['Alice', 'manual', 'manual'], ['Bob', 'stage', 'staged']]);
  expect(f.lnd.baked).toHaveLength(1);
  declare(join(outDir, 'Bob.macaroon'));
});

it('MW102-02/respond finish resumes after the old root key was deleted but the registry was not saved, through rotate F6', async () => {
  const f = fixture();
  f.save([f.old]);
  f.lnd.ids = [0n, ownId, oldId];
  const outDir = declareStaging(join(f.dir, 'replacements'));
  const staged = await respond(['--out-dir', outDir, '--yes', ...f.flags], f.deps);
  expect((staged.result as RespondResult).items[0].status).toBe('staged');
  const replacement = f.rows().find(row => row.replaces === String(oldId))!;
  // Deletion succeeded, then the process died before F12 saved the registry.
  f.lnd.ids = f.lnd.ids.filter(id => id !== oldId);
  const registryBefore = readFileSync(f.registry);

  const rerunStage = await respond(['--out-dir', declareStaging(join(f.dir, 'again')), '--yes', ...f.flags], f.deps);
  const stageItem = (rerunStage.result as RespondResult).items[0];
  expect(stageItem).toMatchObject({ action: 'finish', status: 'staged-earlier', replacementRootKeyId: replacement.rootKeyId });
  expect(stageItem.note).toMatch(/already absent from LND.*respond --finish/);
  const plan = (await respond(['--finish', '--dry-run', ...f.flags], f.deps)).result as RespondResult;
  expect(plan.items[0]).toMatchObject({ action: 'finish', status: 'planned' });
  expect(readFileSync(f.registry).equals(registryBefore)).toBe(true);

  const output = await respond(['--finish', '--yes', ...f.flags], f.deps);
  expect(output.error).toBeNull();
  expect(output.exitCode).toBeUndefined();
  const finished = output.result as RespondResult;
  expect(finished.items[0]).toMatchObject({ action: 'finish', status: 'finished', replacementRootKeyId: replacement.rootKeyId,
    proof: { oldRootKeyIdAbsent: true, oldCredential: 'rejected', newCredential: 'accepted', proven: true } });
  expect(finished.unproven).toEqual([]);
  // F6 repair: no second delete, the replacement was proven accepted, the registry records the revocation and link.
  expect(f.lnd.deleted).toEqual([]);
  const checks = f.lnd.calls.filter(call => call === 'CheckMacaroonPermissions');
  expect(checks.length).toBeGreaterThanOrEqual(2);
  const rows = f.rows();
  expect(rows.find(row => row.rootKeyId === String(oldId))).toMatchObject({ status: 'revoked', revokeEvidence: 'by-id-only',
    replacedBy: replacement.rootKeyId });
  expect(rows.find(row => row.rootKeyId === replacement.rootKeyId)).toMatchObject({ status: 'active' });
});

it('MW102-02/respond finish does not repair the registry when the staged replacement is not accepted', async () => {
  const f = fixture();
  f.save([f.old]);
  f.lnd.ids = [0n, ownId, oldId];
  const outDir = declareStaging(join(f.dir, 'replacements'));
  await respond(['--out-dir', outDir, '--yes', ...f.flags], f.deps);
  f.lnd.ids = f.lnd.ids.filter(id => id !== oldId);
  f.lnd.verifyValid = false;
  const before = readFileSync(f.registry);
  const output = await respond(['--finish', '--yes', ...f.flags], f.deps);
  const finished = output.result as RespondResult;
  expect(finished.items[0]).toMatchObject({ status: 'failed', error: { code: 5, step: 'F7' } });
  expect(finished.unproven).toHaveLength(1);
  expect(output.exitCode).toBe(5);
  expect(readFileSync(f.registry).equals(before)).toBe(true);
});

it('MW102-02/advice where a label names two active entries, respond advice names the numeric root key ID, and that command works', async () => {
  // The registry allows two active entries with one label only as an original and its staged
  // replacement; revoke <label> then exits 2 at V6, so advice must use the root key ID.
  const f = fixture();
  const canary = { ...f.old, caveats: [{ type: 'lnd-custom', value: 'region-a1a2f213 3a1e61423be44eaf' }] };
  f.save([canary, f.next]);
  f.lnd.ids = [0n, ownId, oldId, nextId];
  const plan = (await respond(['--dry-run', ...f.flags], f.deps)).result as RespondResult;
  expect(plan.items).toHaveLength(1);
  expect(plan.items[0]).toMatchObject({ action: 'manual', status: 'manual' });
  expect(plan.items[0].note).toContain(`macwarden revoke ${oldId}`);
  expect(plan.items[0].note).not.toContain('revoke Alice');
  const byLabel = await runRevoke(['Alice', '--yes', ...f.flags], f.deps);
  expect(byLabel.error).toMatchObject({ code: 2, step: 'V6' });
  const byId = await runRevoke([String(oldId), '--yes', ...f.flags], f.deps);
  expect(byId.error).toBeNull();
  expect(f.lnd.deleted).toEqual([oldId]);
  expect(f.rows().find(row => row.rootKeyId === String(oldId))).toMatchObject({ status: 'revoked' });
});

/** The registry after a stage that allocated a replacement but never verified or wrote it (S10 uncertain, S11, S12, S13). */
function incompleteStage(f: Fixture, listed: boolean): Entry {
  const pendingNext = { ...f.next, fingerprint: null as unknown as string, outPath: null, verified: false };
  f.save([f.old, pendingNext]);
  f.lnd.ids = [0n, ownId, oldId, ...(listed ? [nextId] : [])];
  return pendingNext;
}

it.each([true, false])('MW102-10/stage an allocated but incomplete replacement (listed in LND: %s) is unresolved work, never a usable earlier stage', async listed => {
  const f = fixture();
  incompleteStage(f, listed);
  const before = readFileSync(f.registry);
  const outDir = declareStaging(join(f.dir, 'replacements'));
  const output = await respond(['--out-dir', outDir, '--yes', ...f.flags], f.deps);
  const result = output.result as RespondResult;
  const item = result.items[0];
  expect(item.status).not.toBe('staged-earlier');
  expect(item).toMatchObject({ action: 'repair', status: 'failed', replacementRootKeyId: String(nextId), outPath: null,
    error: { code: 7, step: 'P5' } });
  expect(item.note).not.toMatch(/switch the app/);
  expect(item.error!.message).toContain(`macwarden revoke ${nextId}`);
  expect(item.error!.message).toMatch(listed ? /LND lists it/ : /LND does not list it, but may still create it/);
  expect(item.error!.message).toMatch(/not retried automatically/);
  expect(result.unproven).toEqual([{ label: 'Alice', rootKeyId: String(oldId), reason: expect.stringContaining(`replacement root key ID ${nextId} incomplete`) }]);
  expect(output.exitCode).toBe(7);
  // Nothing is retried: no bake, no deletion, no file, the pending record is kept.
  expect(mutations(f)).toEqual([]);
  expect(existsSync(join(outDir, 'Alice.macaroon'))).toBe(false);
  expect(readFileSync(f.registry).equals(before)).toBe(true);
});

it('MW102-10/finish and dry run report the incomplete replacement the same way, and the printed recovery clears it', async () => {
  const f = fixture();
  incompleteStage(f, true);
  const plan = await respond(['--finish', '--dry-run', ...f.flags], f.deps);
  expect((plan.result as RespondResult).items[0]).toMatchObject({ action: 'repair', status: 'failed', error: { code: 7, step: 'P5' } });
  expect(plan.exitCode).toBeUndefined();
  const finish = await respond(['--finish', '--yes', ...f.flags], f.deps);
  expect((finish.result as RespondResult).items[0]).toMatchObject({ action: 'repair', status: 'failed' });
  expect(finish.exitCode).toBe(7);
  expect(mutations(f)).toEqual([]);
  // The recovery the message names (revoke the replacement by its numeric ID) works, and a rerun stages afresh.
  const revoked = await runRevoke([String(nextId), '--yes', ...f.flags], f.deps);
  expect(revoked.error).toBeNull();
  expect(f.lnd.deleted).toEqual([nextId]);
  const outDir = declareStaging(join(f.dir, 'replacements'));
  const again = await respond(['--out-dir', outDir, '--yes', ...f.flags], f.deps);
  expect(again.exitCode).toBeUndefined();
  expect((again.result as RespondResult).items[0]).toMatchObject({ action: 'stage', status: 'staged' });
});
