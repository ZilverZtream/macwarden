import { existsSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { withCancellation } from '../src/cancellation.js';
import { aggregateExit, run as runRespond } from '../src/commands/respond.js';
import { LndError } from '../src/errors.js';
import { expectSchemaValid } from './helpers/output-schema.js';
import type { RespondResult } from '../src/command-result.js';
import { render } from '../src/output/index.js';
import { entry, fixture, oldId, ownId, register, responseBytes, vector, type Entry, type Fixture, declareStagedFiles, declareStaging } from './helpers/cp038-online.js';

// Every real respond output, refusals and failed batches included, must match the published schema.
const respond = async (...args: Parameters<typeof runRespond>) => {
  const output = await runRespond(...args);
  expectSchemaValid(output);
  return output;
};

const bobId = 4294967400n, missingId = 4294967500n, unknownId = 777777n;

function setup(entries?: (f: Fixture) => Entry[]) {
  const f = fixture();
  const bob = entry(bobId, 'Bob');
  f.save(entries ? entries(f) : [f.old, bob]);
  f.lnd.ids = [0n, ownId, oldId, bobId, unknownId];
  const outDir = declareStaging(join(f.dir, 'replacements'));
  const answers: string[] = [];
  const prompt = Object.assign(async (question: string) => { answers.push(question); return confirm; }, { isTTY: true });
  let confirm = '';
  f.deps.prompt = prompt;
  return { f, bob, outDir, answers, say: (value: string) => { confirm = value; } };
}
const result = (output: Awaited<ReturnType<typeof respond>>) => {
  expect(output.error).toBeNull();
  return output.result as RespondResult;
};
const mutations = (f: Fixture) => f.lnd.calls.filter(call => call === 'BakeMacaroon' || call === 'DeleteMacaroonID');

// Replacement credentials written into the staging directory are intended outputs.
afterEach(() => { declareStagedFiles(); });

it('RESPOND/plan dry run classifies every credential and changes nothing', async () => {
  const { f } = setup(f => [f.old, entry(bobId, 'Bob'), entry(missingId, 'Carol')]);
  const before = readFileSync(f.registry);
  const plan = result(await respond(['--dry-run', ...f.flags], f.deps));
  expect(plan.items.map(item => [item.rootKeyId, item.label, item.action, item.status])).toEqual([
    [String(oldId), 'Alice', 'stage', 'planned'],
    [String(bobId), 'Bob', 'stage', 'planned'],
    [String(missingId), 'Carol', 'repair', 'manual'],
  ]);
  expect(plan.items[2].note).toContain('macwarden revoke Carol');
  // Root key 0 and macwarden's own ID are never "unknown"; the stranger ID is listed, never touched.
  expect(plan.unknown.rootKeyIds).toEqual([String(unknownId)]);
  expect(plan.unknown.guidance).toMatch(/never revokes them automatically/);
  expect(plan.rootKey0.present).toBe(true);
  expect(plan.rootKey0.guidance.join(' ')).toContain('lncli changepassword --new_mac_root_key');
  // LND regenerates every root key, so the guidance must say so and order it before staging.
  expect(plan.rootKey0.guidance.join(' ')).toMatch(/regenerates EVERY root key, not only ID 0/);
  expect(plan.rootKey0.guidance.join(' ')).toMatch(/Do not stage replacements with respond --out-dir before it/);
  expect(plan.rootKey0.ownOnRootKey0).toBe(false);
  expect(mutations(f)).toEqual([]);
  expect(readFileSync(f.registry).equals(before)).toBe(true);
});

it('RESPOND/stage needs an output directory and a typed batch confirmation', async () => {
  const { f, outDir, say, answers } = setup();
  expect((await respond(f.flags, f.deps)).error).toMatchObject({ code: 2, step: 'P1' });
  f.deps.stdin = Object.assign(f.deps.stdin, { isTTY: false });
  expect((await respond(['--out-dir', outDir, ...f.flags], f.deps)).error).toMatchObject({ code: 6, step: 'P7' });
  f.deps.stdin = Object.assign(f.deps.stdin, { isTTY: true });
  say('yes');
  expect((await respond(['--out-dir', outDir, ...f.flags], f.deps)).error).toMatchObject({ code: 6, step: 'P7' });
  expect(answers.at(-1)).toContain('Type "stage 2" to confirm');
  expect(mutations(f)).toEqual([]);
});

it('RESPOND/stage writes owner-only replacements for every credential and records them as pending', async () => {
  const { f, outDir, say } = setup();
  say('stage 2');
  const staged = result(await respond(['--out-dir', outDir, ...f.flags], f.deps));
  expect(staged.items.map(item => [item.label, item.status])).toEqual([['Alice', 'staged'], ['Bob', 'staged']]);
  expect(f.lnd.calls.filter(call => call === 'BakeMacaroon')).toHaveLength(2);
  expect(f.lnd.deleted).toEqual([]);
  for (const label of ['Alice', 'Bob']) {
    const path = join(outDir, `${label}.macaroon`);
    expect(existsSync(path)).toBe(true);
    if (process.platform !== 'win32') expect(readFileSync(path).length).toBeGreaterThan(0);
  }
  const rows = f.rows();
  for (const old of [oldId, bobId]) {
    const replacement = rows.find(row => row.replaces === String(old));
    expect(replacement).toMatchObject({ status: 'active', verified: true });
    expect(staged.items.find(item => item.rootKeyId === String(old))!.replacementRootKeyId).toBe(replacement!.rootKeyId);
  }
  // Rerunning is safe: staged credentials are reported, not staged again.
  const again = result(await respond(['--out-dir', declareStaging(join(f.dir, 'other')), '--yes', ...f.flags], f.deps));
  expect(again.items.map(item => item.status)).toEqual(['staged-earlier', 'staged-earlier']);
  expect(f.lnd.calls.filter(call => call === 'BakeMacaroon')).toHaveLength(2);
});

it('RESPOND/finish revokes every staged credential and proves old rejected and new accepted', async () => {
  const { f, outDir } = setup();
  result(await respond(['--out-dir', outDir, '--yes', ...f.flags], f.deps));
  const finished = result(await respond(['--finish', '--yes', ...f.flags], f.deps));
  expect([...f.lnd.deleted].sort()).toEqual([oldId, bobId].sort());
  expect(f.lnd.deleted).not.toContain(unknownId);
  for (const item of finished.items) {
    expect(item.status).toBe('finished');
    expect(item.proof).toMatchObject({ oldRootKeyIdAbsent: true, oldCredential: 'rejected', newCredential: 'accepted',
      proven: true, strength: 'credential-rejected' });
  }
  expect(finished.unproven).toEqual([]);
  const rows = f.rows();
  for (const old of [oldId, bobId]) expect(rows.find(row => row.rootKeyId === String(old))).toMatchObject({ status: 'revoked' });
  const text = render({ ...(await respond(['--finish', '--dry-run', ...f.flags], f.deps)) }, 'text');
  expect(text).not.toContain('NOT PROVEN');
});

it('RESPOND/finish without the old file proves by root key ID absence only', async () => {
  const { f, outDir } = setup(f => [f.old]);
  result(await respond(['--out-dir', outDir, '--yes', ...f.flags], f.deps));
  rmSync(f.old.outPath!);
  const finished = result(await respond(['--finish', '--yes', ...f.flags], f.deps));
  expect(finished.items[0].proof).toMatchObject({ oldRootKeyIdAbsent: true, oldCredential: 'not-tested',
    newCredential: 'accepted', proven: true, strength: 'root-key-id-absent' });
});

it('RESPOND/finish lists a credential it cannot prove and exits with its code', async () => {
  const { f, outDir } = setup(f => [f.old]);
  result(await respond(['--out-dir', outDir, '--yes', ...f.flags], f.deps));
  f.lnd.verifyValid = false;
  const output = await respond(['--finish', '--yes', ...f.flags], f.deps);
  const finished = result(output);
  expect(finished.items[0]).toMatchObject({ status: 'failed', error: { code: 5, step: 'F7' } });
  expect(finished.unproven).toEqual([{ label: 'Alice', rootKeyId: String(oldId), reason: 'failed at F7 (exit 5)' }]);
  expect(output.exitCode).toBe(5);
  expect(f.lnd.deleted).toEqual([]);
  expect(render(output, 'text')).toMatch(/not proven {2}Alice \(root key ID 4294967341\): failed at F7/);
});

it('RESPOND/resume an interrupted batch stops before the next credential and the rerun completes it', async () => {
  const { f, outDir } = setup();
  const controller = new AbortController();
  f.lnd.onBake = () => { controller.abort(); };
  const output = await withCancellation(controller.signal, () => respond(['--out-dir', outDir, '--yes', ...f.flags], f.deps));
  const interrupted = result(output);
  expect(output.exitCode).toBe(7);
  expect(interrupted.items.find(item => item.label === 'Bob')).toMatchObject({ status: 'not-run' });
  expect(output.warnings).toContainEqual(expect.objectContaining({ code: 'interrupted' }));
  expect(f.lnd.calls.filter(call => call === 'BakeMacaroon')).toHaveLength(1);
  f.lnd.onBake = null;
  const resumed = result(await respond(['--out-dir', declareStaging(join(f.dir, 'resume')), '--yes', ...f.flags], f.deps));
  expect(resumed.items.find(item => item.label === 'Bob')).toMatchObject({ status: 'staged' });
  expect(f.lnd.calls.filter(call => call === 'BakeMacaroon')).toHaveLength(2);
});

it('RESPOND/root-key-0 an own credential on root key 0 gets the warning and changepassword is only advice', async () => {
  const { f } = setup();
  const ownZero = register(responseBytes(0n, vector('default-admin').permissions) as Buffer);
  const flags = f.flags.map(value => value === f.own ? ownZero : value);
  const output = await respond(['--dry-run', ...flags], f.deps);
  const plan = result(output);
  expect(plan.rootKey0.ownOnRootKey0).toBe(true);
  expect(plan.rootKey0.guidance.at(-1)).toMatch(/own credential is on root key ID 0/);
  expect(output.warnings.map(item => typeof item === 'string' ? item : item.code)).toContain('own-root-key-0');
  expect(f.lnd.calls.every(call => ['GetInfo', 'ListPermissions', 'ListMacaroonIDs'].includes(call))).toBe(true);
});

it('RESPOND/leak output names files and IDs but never credential bytes', async () => {
  const { f, outDir } = setup();
  const staged = await respond(['--out-dir', outDir, '--yes', ...f.flags], f.deps);
  const finished = await respond(['--finish', '--yes', ...f.flags], f.deps);
  const secrets = [readFileSync(f.old.outPath!), readFileSync(join(outDir, 'Alice.macaroon')), readFileSync(join(outDir, 'Bob.macaroon'))];
  for (const output of [staged, finished]) for (const mode of ['text', 'json'] as const) {
    const text = render(output, mode);
    for (const bytes of secrets) for (const form of [bytes.toString('hex'), bytes.toString('base64'), bytes.toString('base64url')])
      expect(text).not.toContain(form.slice(0, 40));
  }
});

it('RESPOND/exit a possible LND change outranks every other failure', () => {
  expect(aggregateExit([0, 0])).toBe(0);
  expect(aggregateExit([0, 5, 3])).toBe(5);
  expect(aggregateExit([3, 7, 5])).toBe(7);
  expect(aggregateExit([6, 2])).toBe(6);
});

it('RESPOND/finish-unproven LND unreadable after the deletions means the result is not proven: exit 7, never 0', async () => {
  // Count the ListMacaroonIDs calls of an identical, healthy finish; the last one is the P9 proof.
  const healthy = setup(f => [f.old]);
  result(await respond(['--out-dir', healthy.outDir, '--yes', ...healthy.f.flags], healthy.f.deps));
  let lists = 0;
  const list = healthy.f.lnd.listMacaroonIds.bind(healthy.f.lnd);
  healthy.f.lnd.listMacaroonIds = async () => { lists += 1; return list(); };
  result(await respond(['--finish', '--yes', ...healthy.f.flags], healthy.f.deps));
  expect(lists).toBeGreaterThan(1);

  const { f, outDir } = setup(f => [f.old]);
  result(await respond(['--out-dir', outDir, '--yes', ...f.flags], f.deps));
  let seen = 0;
  const original = f.lnd.listMacaroonIds.bind(f.lnd);
  f.lnd.listMacaroonIds = async () => { seen += 1; if (seen === lists) throw new Error('connection reset'); return original(); };
  const output = await respond(['--finish', '--yes', ...f.flags], f.deps);
  const finished = result(output);
  expect(f.lnd.deleted).toEqual([oldId]);
  expect(finished.items[0]).toMatchObject({ status: 'finished', proof: { oldRootKeyIdAbsent: null, proven: false } });
  expect(finished.unproven).toEqual([{ label: 'Alice', rootKeyId: String(oldId), reason: 'old root key ID still listed or LND unreachable' }]);
  expect(output.exitCode).toBe(7);
});

it('RESPOND/finished-earlier a rerun of --finish does not ask to stage credentials that already replaced a revoked one', async () => {
  const { f, outDir } = setup(f => [f.old]);
  result(await respond(['--out-dir', outDir, '--yes', ...f.flags], f.deps));
  result(await respond(['--finish', '--yes', ...f.flags], f.deps));
  const again = result(await respond(['--finish', '--dry-run', ...f.flags], f.deps));
  expect(again.items).toHaveLength(1);
  expect(again.items[0]).toMatchObject({ status: 'finished-earlier', note: `replaces root key ID ${oldId}, already revoked: nothing to finish` });
});

it('RESPOND/table the text table columns line up under their headers', async () => {
  // Found in the live field check: the rows were joined with three spaces under a fixed header.
  const { f } = setup(f => [f.old, entry(bobId, 'Bob'), entry(missingId, 'Carol')]);
  const text = render(await respond(['--dry-run', ...f.flags], f.deps), 'text');
  const lines = text.split('\n');
  const header = lines.findIndex(line => line.startsWith('ROOT KEY ID'));
  const columns = ['ROOT KEY ID', 'LABEL', 'GRADE', 'ACTION', 'STATUS'].map(name => lines[header].indexOf(name));
  expect(lines[header + 1]).toBe(`${String(oldId).padEnd(columns[1] - 2)}  Alice  ${'RECEIVE'.padEnd(columns[3] - columns[2] - 2)}  stage   planned`);
  for (const line of lines.slice(header + 1, header + 4))
    for (const start of columns.slice(1)) expect(line[start - 1]).toBe(' ');
});

it('RESPOND/MW110-09 planning checks ListPermissions for snapshot drift itself, in a dry run with nothing to rotate too', async () => {
  const { f } = setup(() => []);
  // FakeLnd's permission map differs from the bundled snapshot.
  const drifted = await respond(['--dry-run', ...f.flags], f.deps);
  expect(drifted.error).toBeNull();
  expect(drifted.warnings).toContainEqual({ code: 'snapshot-drift', message: 'LND permissions differ from the bundled snapshot' });
  expect(f.lnd.calls).toEqual(['GetInfo', 'ListPermissions', 'ListMacaroonIDs']);
  // A matching map gives no warning.
  const snapshot = JSON.parse(readFileSync('src/grade/lnd-permissions.json', 'utf8')).methods as Record<string, string[]>;
  f.lnd.listPermissions = async () => { f.lnd.calls.push('ListPermissions'); return snapshot; };
  const clean = await respond(['--dry-run', ...f.flags], f.deps);
  expect(clean.warnings.map(warning => typeof warning === 'string' ? warning : warning.code)).not.toContain('snapshot-drift');
  // Normal failure handling: LND failing the call stops planning at P4.
  f.lnd.listPermissions = async () => { throw new LndError(5, 'list-permissions', 'invalid LND response'); };
  expect((await respond(['--dry-run', ...f.flags], f.deps)).error).toMatchObject({ code: 5, step: 'P4' });
  // The own credential must hold what ListPermissions needs (info:read or its uri:).
  const narrow = register(responseBytes(4294967600n, ['macaroon:read']));
  const flags = [...f.flags]; flags[flags.indexOf('--macaroon') + 1] = narrow;
  f.lnd.calls.length = 0;
  expect((await respond(['--dry-run', ...flags], f.deps)).error).toMatchObject({ code: 4, step: 'P2' });
  expect(f.lnd.calls).toEqual([]);
});
