import { adapter } from './helpers/adapter.js';
import type { LndAdapter } from '../src/lnd/index.js';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';
import { render } from './helpers/render-adversarial.js';
import { decodeMacaroon } from '../src/decode/index.js';
import { Secret } from '../src/secret.js';
import { register, responseBytes } from './helpers/cp038-online.js';

type Entry = {
  nodePubkey: string; label: string; rootKeyId: string; permissions: string[]; caveats: unknown[];
  grade: string; fingerprint: string; outPath: string | null; createdAt: string;
  verified: boolean; status: 'active' | 'revoked'; revokedAt: string | null;
  revokeEvidence: string | null; replaces: string | null; replacedBy: string | null;
};
type Row = { rootKeyId: string; verify: string; flags: string[] };
type Envelope = { ok: boolean; error: { code: number } | null;
  result: { rootKeys: Row[] } | null };
const repo = resolve();
const pubkey = '02' + 'ab'.repeat(32);
const otherPubkey = '03' + 'bc'.repeat(32);
const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as {
  vectors: Array<{ name: string; fingerprint: string; expectedGrade: string }> };
const snapshot = JSON.parse(readFileSync(join(repo, 'src/grade/lnd-permissions.json'), 'utf8')) as {
  methods: Record<string, string[]> };
const facts = (name: string) => {
  const item = manifest.vectors.find(value => value.name === name);
  if (!item) throw new Error(`Missing vector metadata for ${name}`);
  return item;
};
const printed = (name: string) => JSON.parse(readFileSync(
  join(repo, `test/vectors/${name}.printmacaroon.json`), 'utf8')) as { permissions: string[] };

async function temp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  const base = process.env.MACWARDEN_TEST_TMP;
  if (!base) throw new Error('MACWARDEN_TEST_TMP is required');
  mkdirSync(base, { recursive: true, mode: 0o700 });
  const dir = mkdtempSync(join(base, 'cp020-unit-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}
function credential(dir: string, name: string, target = name): string {
  const path = join(dir, `${target}.macaroon`);
  copyFileSync(join(repo, `test/vectors/${name}.macaroon`), path);
  return path;
}
function entry(id: string, outPath: string | null, name = 'default-readonly', changes: Partial<Entry> = {}): Entry {
  return { nodePubkey: pubkey, label: `row${id}`, rootKeyId: id,
    permissions: printed(name).permissions, caveats: [], grade: facts(name).expectedGrade,
    fingerprint: facts(name).fingerprint, outPath, createdAt: '2026-10-02T09:00:00Z',
    verified: true, status: 'active', revokedAt: null, revokeEvidence: null,
    replaces: null, replacedBy: null, ...changes };
}
// A row's file is baked on the row's own root key ID: inventory --verify checks a file only when
// both its root key ID and its fingerprint are the row's (audit 1.3.2).
function issued(dir: string, id: string, name = 'default-readonly', changes: Partial<Entry> = {}): Entry {
  const bytes = responseBytes(BigInt(id), printed(name).permissions);
  const path = join(dir, `${id}.macaroon`);
  writeFileSync(path, bytes, { mode: 0o600 });
  return entry(id, path, name, { fingerprint: decodeMacaroon(new Secret(bytes)).fingerprint, ...changes });
}
function registry(dir: string, entries: Entry[]): string {
  const path = join(dir, 'registry.json');
  writeFileSync(path, JSON.stringify({ schema: 1, entries }), { mode: 0o600 });
  return path;
}
type Verification = Awaited<ReturnType<LndAdapter['checkMacaroon']>>;
function fixture(ids: string[], check: (index: number) => Verification | Promise<Verification> = () => ({ valid: true })) {
  const calls: string[] = [];
  let checked = 0;
  const verification = vi.fn<LndAdapter['checkMacaroon']>(async (...args) => {
    void args;
    calls.push('CheckMacaroonPermissions');
    return check(checked++);
  });
  const lnd = {
    ...adapter({}),
    getInfo: vi.fn(async () => { calls.push('GetInfo'); return { alias: 'alice', version: '0.21.4-beta', pubkey: pubkey, network: 'regtest' }; }),
    listPermissions: vi.fn(async () => { calls.push('ListPermissions'); return snapshot.methods; }),
    listMacaroonIds: vi.fn(async () => { calls.push('ListMacaroonIDs'); return (ids).map(BigInt); }),

    checkMacaroon: verification,
  } satisfies LndAdapter;
  const deps = { lnd, fs: { ...fs }, env: {} as Record<string, string>,
    clock: () => new Date('2026-10-04T00:00:00Z') };
  return { calls, verification, deps };
}
async function invoke(path: string, deps: ReturnType<typeof fixture>['deps']): Promise<Envelope> {
  const command = await import('../src/commands/inventory.js') as unknown as {
    run: (args: string[], deps: unknown) => Promise<Envelope> };
  const output = await command.run(['--verify', '--lnd-rest', '127.0.0.1:1',
    '--tls-cert', join(repo, 'test/fixture/wrong-tls.cert'),
    '--macaroon', join(repo, 'test/vectors/default-readonly.macaroon'), '--registry', path], deps);
  expect(output.error, '--verify must complete inventory').toBeNull();
  return output;
}
function row(output: Envelope, id: string): Row {
  const found = output.result?.rootKeys.find(value => value.rootKeyId === id);
  expect(found, `row ${id}`).toBeDefined();
  return found!;
}
function count(calls: string[]) { return calls.filter(value => value === 'CheckMacaroonPermissions').length; }

it('CP-020/B1 valid, root-missing and signature-mismatch reject while other and auth failures error', async () => temp(async dir => {
  const ids = ['9', '10', '11', '12', '13', '14'];
  const entries = ids.map(id => issued(dir, id));
  const path = registry(dir, entries);
  // LND reports a missing root key consistently: ID 10 is absent from ListMacaroonIDs too.
  const { calls, deps } = fixture(['0', ...ids.filter(id => id !== '10')], index => {
    if (index === 0) return { valid: true as const };
    if (index === 1) return { valid: false, reason: 'root-key-missing', message: "root key with id 10 doesn't exist" };
    if (index === 2) return { valid: false as const, reason: 'signature-mismatch', message: 'signature mismatch' };
    if (index === 3) return { valid: false as const, reason: 'other' as const, message: 'permission denied' };
    throw Object.assign(new Error('OWN authentication failure'), { code: 4,
      status: index === 4 ? 401 : 403 });
  });
  const output = await invoke(path, deps);
  expect(output.error).toBeNull();
  expect(output.ok).toBe(true);
  expect(ids.map(id => row(output, id).verify))
    .toEqual(['accepted', 'rejected', 'rejected', 'error', 'error', 'error']);
  for (const id of ['10', '11']) expect(row(output, id).flags).toContain('rejected');
  for (const id of ['9', '12', '13', '14']) expect(row(output, id).flags).not.toContain('rejected');
  expect(count(calls)).toBe(ids.length);
}));

it('CP-020/B2 ineligible rows never send a verification request', async () => temp(async dir => {
  const good = credential(dir, 'default-readonly', 'eligible');
  const mismatch = credential(dir, 'default-invoice', 'mismatch');
  const entries = [issued(dir, '9'), entry('10', null), entry('11', join(dir, 'absent.macaroon')),
    entry('12', mismatch), entry('13', good, 'default-readonly', { status: 'revoked',
      revokedAt: '2026-10-03T00:00:00Z', revokeEvidence: 'rejected' }),
    entry('14', good, 'default-readonly', { nodePubkey: otherPubkey })];
  const path = registry(dir, entries);
  const { calls, deps } = fixture(['0', '9', '10', '11', '12', '13', '14', '15']);
  const output = await invoke(path, deps);
  expect(row(output, '9').verify).toBe('accepted');
  for (const id of ['0', '10', '11', '12', '13', '14', '15'])
    expect(row(output, id).verify, id).toBe('not-checked');
  expect(count(calls)).toBe(1);
  expect(JSON.stringify(output)).not.toContain(readFileSync(mismatch).toString('hex'));
}));

it('CP-020/B3 a failed row does not stop later checks or mutate registry and LND IDs', async () => temp(async dir => {
  const entries = ['9', '10', '11'].map(id => issued(dir, id));
  const path = registry(dir, entries);
  const before = readFileSync(path), mtime = statSync(path).mtimeMs;
  const ids = ['0', '9', '10', '11'];
  const { calls, deps } = fixture(ids, index => index === 1 ? Promise.reject(new Error('transient refusal')) : { valid: true as const });
  const output = await invoke(path, deps);
  expect(output.ok).toBe(true);
  expect(output.error).toBeNull();
  expect(['9', '10', '11'].map(id => row(output, id).verify)).toEqual(['accepted', 'error', 'accepted']);
  expect(count(calls)).toBe(3);
  expect(ids).toEqual(['0', '9', '10', '11']);
  expect(readFileSync(path).equals(before)).toBe(true);
  expect(statSync(path).mtimeMs).toBe(mtime);
  expect(existsSync(`${path}.lock`)).toBe(false);
}));

it('CP-020/B4 verification uses the file decoded ordinary and exact URI permissions', async () => temp(async dir => {
  const name = 'grade-invoice-send';
  const path = registry(dir, [issued(dir, '9', name, { permissions: ['info:read'] })]);
  const { verification, deps } = fixture(['0', '9']);
  const output = await invoke(path, deps);
  expect(row(output, '9').verify).toBe('accepted');
  expect(verification).toHaveBeenCalledTimes(1);
  const args = verification.mock.calls[0] as unknown[];
  const request = args.length === 1 ? args[0] as Record<string, unknown> : null;
  const perms = request ? request.permissions : args[1];
  const expected = printed(name).permissions;
  expect(expected).toContain('invoices:read');
  expect(expected).toContain('uri:/routerrpc.Router/SendPaymentV2');
  expect(expected.length).toBeGreaterThan(0);
  expect(perms).toEqual(request ? expected.map(permission => {
    const at = permission.indexOf(':');
    return { entity: permission.slice(0, at), action: permission.slice(at + 1) };
  }) : expected);
  if (request) {
    expect(request.fullMethod).toBeUndefined();
    expect(request.check_default_perms_from_full_method).toBeUndefined();
  }
}));

it('CP-020/B5 credential forms and request headers stay absent in accepted, rejected and error output', async () => temp(async dir => {
  const sentinelDir = process.env.MACWARDEN_SENTINEL_DIR;
  if (!sentinelDir) throw new Error('MACWARDEN_SENTINEL_DIR is required');
  mkdirSync(sentinelDir, { recursive: true, mode: 0o700 });
  const sentinels = new Map(['9', '10', '11'].map(id => [id, register(responseBytes(BigInt(id), printed('default-readonly').permissions))]));
  const path = registry(dir, [...sentinels].map(([id, sentinel]) => entry(id, sentinel, 'default-readonly',
    { fingerprint: decodeMacaroon(new Secret(readFileSync(sentinel))).fingerprint })));
  // ID 10's root key is missing, so ListMacaroonIDs does not list it either.
  const { deps } = fixture(['0', '9', '11'], index => {
    if (index === 0) return { valid: true as const };
    if (index === 1) return { valid: false, reason: 'root-key-missing', message: "root key with id 10 doesn't exist" };
    throw new Error('Grpc-Metadata-macaroon header rejected');
  });
  const output = await invoke(path, deps);
  const rendered = render(output as Parameters<typeof render>[0], 'json') +
    render(output as Parameters<typeof render>[0], 'text');
  for (const bytes of [...sentinels.values()].map(sentinel => readFileSync(sentinel))) for (const form of [bytes.toString('utf8'), bytes.toString('latin1'),
    bytes.toString('hex'), bytes.toString('hex').toUpperCase(), bytes.toString('base64'),
    bytes.toString('base64url'), bytes.toString('base64').replace(/=+$/, ''),
    bytes.toString('base64url').replace(/=+$/, '')]) expect(rendered).not.toContain(form);
  expect(rendered).not.toContain('Grpc-Metadata-macaroon');
  expect(['9', '10', '11'].map(id => row(output, id).verify)).toEqual(['accepted', 'rejected', 'error']);
}));

it('CP-020/B6 previously accepted rows become rejected after a simulated root-key-missing response', async () => temp(async dir => {
  const path = registry(dir, ['9', '10'].map(id => issued(dir, id)));
  let regenerated = false;
  const listed = ['0', '9', '10'];
  const { deps } = fixture(listed, () => {
    if (regenerated) return { valid: false, reason: 'root-key-missing', message: "root key with id 9 doesn't exist" };
    return { valid: true as const };
  });
  const before = await invoke(path, deps);
  expect(['9', '10'].map(id => row(before, id).verify)).toEqual(['accepted', 'accepted']);
  // The root keys are gone: LND no longer lists their IDs either.
  regenerated = true;
  listed.splice(1);
  const after = await invoke(path, deps);
  for (const id of ['9', '10']) {
    expect(row(after, id).verify).toBe('rejected');
    expect(row(after, id).flags).toContain('rejected');
  }
}));

// Audit 1.4.0 (as verify, 1.2.1): "root key missing" contradicted by ListMacaroonIDs is an error, never a rejection.
it('CP-020/B1 root-key-missing while ListMacaroonIDs still lists the ID is an error, not rejected', async () => temp(async dir => {
  const path = registry(dir, [issued(dir, '9')]);
  const { deps } = fixture(['0', '9'], () => ({ valid: false, reason: 'root-key-missing', message: "root key with id 9 doesn't exist" }));
  const output = await invoke(path, deps);
  expect(row(output, '9')).toMatchObject({ inLnd: true, verify: 'error' });
  expect(row(output, '9').flags).not.toContain('rejected');
}));

it('CP-020/B7 repeated verification has identical result and leaves registry bytes and mtime unchanged', async () => temp(async dir => {
  const path = registry(dir, [issued(dir, '9')]);
  const before = readFileSync(path), mtime = statSync(path).mtimeMs;
  const { calls, deps } = fixture(['0', '9']);
  const first = await invoke(path, deps), second = await invoke(path, deps);
  expect(first.result).toEqual(second.result);
  expect(row(first, '9').verify).toBe('accepted');
  expect(count(calls)).toBe(2);
  expect(readFileSync(path).equals(before)).toBe(true);
  expect(statSync(path).mtimeMs).toBe(mtime);
  expect(existsSync(`${path}.lock`)).toBe(false);
}));
