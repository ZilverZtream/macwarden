import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';
import type { LndAdapter } from '../src/lnd/index.js';
import { render, type OutputResult } from '../src/output/index.js';
import { adapter } from './helpers/adapter.js';
import { expectSchemaValid } from './helpers/output-schema.js';

// Fixed clock and hand-written caveat instants: every expected flag and date below is
// worked out from these values, not from the implementation.
const now = '2026-10-04T00:00:00Z';
const pubkey = '02' + 'ab'.repeat(32);
const cert = resolve('test/fixture/wrong-tls.cert');
const own = resolve('test/vectors/default-readonly.macaroon');
const before = (instant: string) => ({ type: 'time-before', value: instant });

function entry(rootKeyId: string, label: string, caveats: { type: string; value: string }[], status: 'active' | 'revoked' = 'active') {
  return { nodePubkey: pubkey, label, rootKeyId, permissions: ['info:read'], caveats, grade: 'READ',
    fingerprint: `fp:${rootKeyId.padStart(16, '0')}`, outPath: null, createdAt: '2026-09-01T00:00:00Z', verified: true,
    status, revokedAt: status === 'revoked' ? '2026-09-02T00:00:00Z' : null, revokeEvidence: status === 'revoked' ? 'by-id-only' : null,
    replaces: null, replacedBy: null };
}

const entries = [
  entry('10', 'Expired', [before('2026-10-01T00:00:00Z')]),
  entry('11', 'Soon', [before('2026-10-06T12:00:00Z')]),
  entry('12', 'Later', [before('2026-12-01T00:00:00Z')]),
  // LND enforces every caveat, so the earlier of two expiries is the effective one.
  entry('13', 'TwoCaveats', [before('2027-01-01T00:00:00Z'), before('2026-10-05T00:00:00Z')]),
  entry('14', 'NoExpiry', []),
  entry('15', 'Revoked', [before('2026-10-01T00:00:00Z')], 'revoked'),
  entry('16', 'Gone', [before('2026-10-01T00:00:00Z')]),
];

type Row = { rootKeyId: string; flags: string[]; expires: string | null };
type Envelope = OutputResult & { exitCode?: number; result: { rootKeys: Row[]; expiring?: { within: string; count: number } } | null };

async function inventory(extra: string[]): Promise<Envelope> {
  const base = process.env.MACWARDEN_TEST_TMP!;
  mkdirSync(base, { recursive: true, mode: 0o700 });
  const dir = mkdtempSync(join(base, 'inventory-expiry-'));
  try {
    const registry = join(dir, 'registry.json');
    writeFileSync(registry, JSON.stringify({ schema: 1, entries }), { mode: 0o600 });
    const permissions = JSON.parse(readFileSync(resolve('src/grade/lnd-permissions.json'), 'utf8')) as { methods: Record<string, string[]> };
    const lnd = { ...adapter({}),
      getInfo: vi.fn(async () => ({ alias: 'alice', version: '0.21.4-beta', pubkey, network: 'regtest' })),
      listPermissions: vi.fn(async () => permissions.methods),
      listMacaroonIds: vi.fn(async () => ['0', '10', '11', '12', '13', '14', '15'].map(BigInt)),
    } satisfies LndAdapter;
    const { run } = await import('../src/commands/inventory.js');
    const output = await run(['--lnd-rest', '127.0.0.1:1', '--tls-cert', cert, '--macaroon', own, '--registry', registry, ...extra],
      { lnd, fs, env: {}, clock: () => new Date(now) }) as unknown as Envelope;
    // Every inventory document this file produces must match the published schema.
    expectSchemaValid(output);
    return output;
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

const row = (output: Envelope, id: string) => output.result!.rootKeys.find(item => item.rootKeyId === id)!;

it('UX/inventory-expiry active credentials LND holds show their effective expiry and are flagged', async () => {
  const output = await inventory([]);
  expect(output.error).toBeNull();
  expect(row(output, '10')).toMatchObject({ expires: '2026-10-01T00:00:00Z' });
  expect(row(output, '10').flags).toContain('expired');
  expect(row(output, '11')).toMatchObject({ expires: '2026-10-06T12:00:00Z' });
  expect(row(output, '11').flags).toContain('expiring');
  expect(row(output, '12')).toMatchObject({ expires: '2026-12-01T00:00:00Z' });
  expect(row(output, '12').flags).not.toEqual(expect.arrayContaining(['expired']));
  expect(row(output, '12').flags).not.toEqual(expect.arrayContaining(['expiring']));
  expect(row(output, '13')).toMatchObject({ expires: '2026-10-05T00:00:00Z' });
  expect(row(output, '13').flags).toContain('expiring');
  expect(row(output, '14')).toMatchObject({ expires: null });
  // A revoked entry and an active entry LND no longer holds are not live credentials.
  for (const id of ['15', '16']) {
    expect(row(output, id).expires).toBeNull();
    expect(row(output, id).flags).not.toEqual(expect.arrayContaining(['expired']));
  }
  expect(output.exitCode ?? 0).toBe(0);
  expect(output.result!.expiring).toBeUndefined();
});

it('UX/inventory-expiry text output has an EXPIRES column and an actionable hint', async () => {
  const text = render(await inventory([]), 'text');
  expect(text).toMatch(/^ROOT KEY ID +LABEL +GRADE +AGE +EXPIRES +STATUS$/m);
  expect(text).toMatch(/^10 +Expired +READ +33d +2026-10-01 +active; expired; revoke with: macwarden revoke Expired$/m);
  // SPEC 3 changed in 1.1.1 (RL-05): rotate requires --out, so the advice carries a default.
  expect(text).toMatch(/^11 +Soon +READ +33d +2026-10-06 +active; expires in 2d; rotate with: macwarden rotate Soon --out Soon-2026-10-04\.macaroon$/m);
  expect(text).toMatch(/^14 +NoExpiry +READ +33d +— +active$/m);
});

it.each([
  ['1d', 2], // 10 expired; 13 expires exactly 1 day after the clock
  ['30d', 3], // also 11
  ['90d', 4], // also 12
])('UX/inventory-expiry --expiring-within %s exits 1 and counts %i active credentials', async (window, count) => {
  const output = await inventory(['--expiring-within', window]);
  expect(output.error).toBeNull();
  expect(output.result!.expiring).toEqual({ within: window, count });
  expect(output.exitCode).toBe(1);
  expect(render(output, 'text')).toContain(`${count} active credential(s) expired or expiring within ${window}`);
});

it('UX/inventory-expiry an invalid window is refused with the rule', async () => {
  const output = await inventory(['--expiring-within', '7']);
  expect(output.error).toMatchObject({ code: 2 });
  expect(output.error!.message).toMatch(/--expiring-within must be 1 to 99999 followed by m/);
});

it('UX/inventory-expiry scan text marks a finding whose time-before is past, like inspect', async () => {
  const { spawnSync } = await import('node:child_process');
  const { childEnvironment } = await import('./helpers/environment.js');
  const printed = JSON.parse(readFileSync(resolve('test/vectors/time-before.printmacaroon.json'), 'utf8')) as { caveats: string[] };
  const instant = Date.parse(printed.caveats[0].replace(/^time-before /, '').replace(/(\.\d{3})\d+Z$/, '$1Z'));
  const run = spawnSync(process.execPath, [resolve('dist/bin.js'), 'scan', resolve('test/vectors/time-before.macaroon')],
    { env: childEnvironment(), encoding: 'utf8', timeout: 30_000, windowsHide: true });
  const line = run.stdout.split('\n')[0];
  if (Date.now() >= instant) expect(line).toMatch(/ root key 0 \(expired\)$/);
  else expect(line).not.toContain('(expired)');
  const fresh = spawnSync(process.execPath, [resolve('dist/bin.js'), 'scan', resolve('test/vectors/default-readonly.macaroon')],
    { env: childEnvironment(), encoding: 'utf8', timeout: 30_000, windowsHide: true });
  expect(fresh.stdout).not.toContain('(expired)');
});
