import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { expect, it } from 'vitest';
import { run as verifyRun } from '../../src/commands/verify.js';
import { addFirstPartyCaveat } from '../../src/decode/index.js';
import { createLndAdapter } from '../../src/lnd/index.js';
import { revealSecret } from '../../src/secret-capability.js';
import { Secret } from '../../src/secret.js';
import { ids, probe, scenario } from '../helpers/cp038-live.js';
import { register, root } from '../helpers/cp038-online.js';
import { expectSchemaValid } from '../helpers/output-schema.js';
import { childEnvironment } from '../helpers/environment.js';
import { fixtureCopies } from '../helpers/fixture-copies.js';
import { findLeaks } from '../helpers/leak-check.js';
import { expectDocumentValid } from '../helpers/output-schema.js';

// Owner request 2026-10-08 (macwarden 1.1.0): verify asks the pinned regtest LND whether one
// credential file is still accepted, before and after its root key ID is revoked.
const repo = resolve();
function cli(command: string, args: string[], flags: string[], json = true) {
  return spawnSync(process.execPath, [resolve('dist/bin.js'), command, ...args, ...flags, ...(json ? ['--json'] : [])],
    { env: childEnvironment(), encoding: 'utf8', timeout: 60_000, windowsHide: true });
}
function document(run: ReturnType<typeof cli>) {
  const parsed = JSON.parse(run.stdout) as { command: string; ok: boolean; result: Record<string, unknown> | null };
  expectDocumentValid(parsed);
  return parsed;
}

it('VERIFY/live a baked credential verifies accepted (exit 1), and rejected (exit 0) after macwarden revoke', async () => scenario(async f => {
  const output: string[] = [];
  const target = f.old.outPath!;
  // Independent lncli evidence first: LND accepts the credential.
  expect(probe(target)).toBe('accepted');
  const before = cli('verify', [target], f.flags);
  output.push(before.stdout, before.stderr);
  expect(before.status, before.stderr).toBe(1);
  expect(document(before)).toMatchObject({ command: 'verify', ok: true, result: {
    status: 'accepted', rejection: null, conclusive: true, rootKeyId: f.old.rootKeyId, rootKeyListed: true,
    fingerprint: f.old.fingerprint, ownCredential: false, registry: { label: 'Alice', status: 'active', match: 'fingerprint' } } });
  const text = cli('verify', [target], f.flags, false);
  output.push(text.stdout, text.stderr);
  expect(text.status, text.stderr).toBe(1);
  expect(text.stdout).toContain('status       ACCEPTED by LND: this credential is live');
  expect(text.stdout).toContain(`macwarden revoke ${f.old.rootKeyId} (registered as Alice`);

  const revoked = cli('revoke', ['Alice', '--yes'], f.flags);
  output.push(revoked.stdout, revoked.stderr);
  expect(revoked.status, revoked.stderr).toBe(0);
  expect(ids()).not.toContain(f.old.rootKeyId);
  expect(probe(target)).toBe('rejected');

  const after = cli('verify', [target], f.flags);
  output.push(after.stdout, after.stderr);
  expect(after.status, after.stderr).toBe(0);
  expect(document(after)).toMatchObject({ ok: true, result: {
    status: 'rejected', rejection: 'root-key-missing', conclusive: true, rootKeyListed: false,
    registry: { label: 'Alice', status: 'revoked', match: 'fingerprint' } } });
  // A credential on another root key ID is untouched by the revoke.
  expect(probe(f.next.outPath!)).toBe('accepted');
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir: root('MACWARDEN_SENTINEL_DIR'),
    paths: [f.dir], testTmp: root('MACWARDEN_TEST_TMP'), root: repo, commandOutput: output.join('\n') })).toBeNull();
}), 180_000);

it('VERIFY/live-root-key-0 the fixture admin.macaroon verifies accepted on root key ID 0 with regeneration guidance and no revoke command', async () => scenario(async f => {
  const admin = join(await fixtureCopies(), 'admin.macaroon');
  const run = cli('verify', [admin], f.flags);
  expect(run.status, run.stderr).toBe(1);
  const result = document(run).result as { status: string; rootKeyId: string; canBake: boolean; guidance: string[] };
  expect(result).toMatchObject({ status: 'accepted', rootKeyId: '0', canBake: true });
  const guidance = result.guidance.join('\n');
  expect(guidance).toContain('lncli changepassword --new_mac_root_key');
  expect(guidance).not.toMatch(/macwarden revoke 0\b/);
  // Read-only: root key IDs are unchanged.
  expect(ids()).toEqual(expect.arrayContaining(['0', f.old.rootKeyId, f.next.rootKeyId]));
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir: root('MACWARDEN_SENTINEL_DIR'),
    paths: [f.dir], testTmp: root('MACWARDEN_TEST_TMP'), root: repo, commandOutput: run.stdout + run.stderr })).toBeNull();
}), 180_000);

// MW110-02 (audit of 1.1.0): only node-side evidence makes a rejection conclusive. An IP lock
// LND refuses for this caller stays inconclusive even when the local clock says a time-before
// caveat has passed; an expiry LND itself reports is conclusive.
it('VERIFY/live-context an IP-locked rejection stays inconclusive (exit 1), also with the local clock a day ahead; LND-reported expiry is conclusive (exit 0)', async () => scenario(async f => {
  const output: string[] = [];
  const parent = new Secret(readFileSync(f.next.outPath!));
  const derive = (...caveats: string[]) => register(revealSecret(caveats.reduce(addFirstPartyCaveat, parent)));
  // Wall-clock instants for caveat values only; no elapsed time is measured.
  const soon = new Date(Date.now() + 12 * 3_600_000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const ipLocked = derive('ipaddr 203.0.113.9', `time-before ${soon}`);
  const correct = cli('verify', [ipLocked], f.flags);
  output.push(correct.stdout, correct.stderr);
  expect(correct.status, correct.stderr).toBe(1);
  expect(document(correct)).toMatchObject({ ok: true, result: { status: 'rejected', rejection: 'other', conclusive: false,
    rootKeyListed: true, rootKeyId: f.next.rootKeyId } });

  // The same bytes through the real adapter and node, with only the injected local clock a day ahead.
  const skewed = await verifyRun([ipLocked, ...f.flags], { createAdapter: createLndAdapter, fs: { ...fs }, env: {},
    clock: () => new Date(Date.now() + 86_400_000), stdin: Object.assign(Readable.from([]), { isTTY: true }) });
  expectSchemaValid(skewed);
  expect(skewed.exitCode).toBe(1);
  expect(skewed.result).toMatchObject({ status: 'rejected', rejection: 'other', conclusive: false });
  expect((skewed.result as { caveats: unknown[] }).caveats).toContainEqual({ type: 'time-before', value: soon, expired: true });

  // LND reports the first caveat that fails: an expired time-before before the IP lock is node evidence.
  const expiredFirst = cli('verify', [derive('time-before 2020-01-01T00:00:00Z', 'ipaddr 203.0.113.9')], f.flags);
  output.push(expiredFirst.stdout, expiredFirst.stderr);
  expect(expiredFirst.status, expiredFirst.stderr).toBe(0);
  expect(document(expiredFirst)).toMatchObject({ ok: true, result: { status: 'rejected', rejection: 'expired', conclusive: true } });
  // The IP lock first: LND names it, so the verdict stays inconclusive although the file has expired.
  const ipFirst = cli('verify', [derive('ipaddr 203.0.113.9', 'time-before 2020-01-01T00:00:00Z')], f.flags);
  output.push(ipFirst.stdout, ipFirst.stderr);
  expect(ipFirst.status, ipFirst.stderr).toBe(1);
  expect(document(ipFirst)).toMatchObject({ ok: true, result: { status: 'rejected', rejection: 'other', conclusive: false } });
  // The parent is untouched: LND still accepts it.
  const accepted = cli('verify', [f.next.outPath!], f.flags);
  expect(accepted.status, accepted.stderr).toBe(1);
  expect(document(accepted)).toMatchObject({ result: { status: 'accepted' } });
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir: root('MACWARDEN_SENTINEL_DIR'),
    paths: [f.dir], testTmp: root('MACWARDEN_TEST_TMP'), root: repo, commandOutput: output.join('\n') })).toBeNull();
}), 180_000);
