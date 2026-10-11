import { createHmac } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { run } from '../src/commands/bake/index.js';
import { Secret } from '../src/secret.js';
import { directory, fixture } from './helpers/cp025-bake-support.mjs';
import { expectSchemaValid } from './helpers/output-schema.js';

function canaryArgs(args: string[], extra: string[] = []): string[] {
  const at = args.indexOf('--preset');
  return [...args.slice(0, at), ...args.slice(at + 2), '--canary', ...extra];
}

it('CANARY/bake a canary is verified first, then gets its custom caveat by the HMAC chain, and is recorded', async () => {
  const dir = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'canary-bake-'));
  const f = fixture(dir, Secret, 'decoy');
  const result = await run(canaryArgs(f.args), f.deps);
  expect(result).toMatchObject({ ok: true, command: 'bake' });
  expect(result.warnings).toContainEqual({ code: 'canary-requires-watch', message: expect.stringContaining('macwarden watch') });
  const config = JSON.parse(readFileSync(`${f.registry}.canary.json`, 'utf8')) as { schema: number; caveatName: string };
  expect(config.schema).toBe(1);
  expect(config.caveatName).toMatch(/^(tenant|scope|profile|policy|region|cluster)-[0-9a-f]{8}$/);
  expect(config.caveatName).not.toMatch(/canary/i);
  if (process.platform !== 'win32') expect(statSync(`${f.registry}.canary.json`).mode & 0o777).toBe(0o600);
  // LND verified the credential before the canary caveat existed.
  const checked = f.state.checked!;
  expect(checked.toString('latin1')).not.toContain('lnd-custom');
  const written = readFileSync(f.out);
  const condition = `lnd-custom ${config.caveatName} `;
  const at = written.toString('latin1').indexOf(condition);
  expect(at).toBeGreaterThan(0);
  const caveat = written.subarray(at, at + condition.length + 16).toString('utf8');
  expect(caveat).toMatch(/^lnd-custom \S+ [0-9a-f]{16}$/);
  // Independent HMAC chain: new signature = HMAC-SHA256(previous signature, caveat).
  expect(written.subarray(written.length - 32).equals(createHmac('sha256', checked.subarray(checked.length - 32)).update(caveat).digest())).toBe(true);
  const registry = JSON.parse(readFileSync(f.registry, 'utf8')) as { entries: { label: string; caveats: { type: string; value: string }[];
    permissions: string[]; verified: boolean }[] };
  const recorded = registry.entries.find(item => item.label === 'decoy')!;
  expect(recorded.caveats).toContainEqual({ type: 'lnd-custom', value: caveat.slice('lnd-custom '.length) });
  // A canary looks like an ordinary read-only credential covering the reconnaissance calls
  // a thief makes first (only permitted calls reach the guard).
  expect(recorded.permissions.sort()).toEqual(['address:read', 'info:read', 'invoices:read', 'offchain:read', 'onchain:read', 'peers:read']);
});

it.each([
  ['ADMIN', ['--permissions', 'macaroon:generate', '--allow-admin']],
  ['SPEND', ['--permissions', 'offchain:write']],
  ['OPERATE', ['--permissions', 'info:read,offchain:read,peers:write']],
] as const)('CANARY/admin a canary never carries %s permissions, even with --allow-admin', async (expected, extra) => {
  const dir = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'canary-admin-'));
  const f = fixture(dir, Secret, 'decoy');
  const result = await run(canaryArgs(f.args, [...extra]), f.deps);
  // LND runs a call with the macaroon's own permissions if the guard drops at the wrong
  // moment, so anything beyond READ or RECEIVE is refused before LND is contacted.
  expect(result).toMatchObject({ ok: false, error: { code: 2, step: 'B3',
    message: `a canary carries only READ or RECEIVE permissions (this set is ${expected})` } });
  expect(f.state.calls).toEqual([]);
  expect(existsSync(`${f.registry}.canary.json`)).toBe(false);
});

it('CANARY/receive a RECEIVE-grade canary (invoices:write) is allowed', async () => {
  const dir = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'canary-receive-'));
  const f = fixture(dir, Secret, 'decoy');
  const result = await run(canaryArgs(f.args, ['--permissions', 'info:read,invoices:read,invoices:write']), f.deps);
  expect(result).toMatchObject({ ok: true, command: 'bake', result: { grade: 'RECEIVE' } });
});

it('CANARY/dry-run plans a canary without creating its configuration or contacting LND for a key', async () => {
  const dir = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'canary-dry-'));
  const f = fixture(dir, Secret, 'decoy');
  // The shared fixture asserts the registry lock inside getInfo; a dry run takes no lock.
  f.lnd.getInfo = async () => { f.state.calls.push('GetInfo'); return { alias: 'fixture', version: '0.21.4-beta', pubkey: `02${'ab'.repeat(32)}`, network: 'regtest' }; };
  const result = await run(canaryArgs(f.args, ['--dry-run']), f.deps);
  expect(result).toMatchObject({ ok: true, result: { dryRun: true, canary: true, grade: 'READ' } });
  // The --json document of a canary plan matches schemas/output/bake.schema.json.
  expectSchemaValid(result);
  expect(existsSync(`${f.registry}.canary.json`)).toBe(false);
  expect(f.state.calls).not.toContain('BakeMacaroon');
});
