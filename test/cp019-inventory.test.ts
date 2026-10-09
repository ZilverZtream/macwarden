import { adapter } from './helpers/adapter.js';
import type { LndAdapter } from '../src/lnd/index.js';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';
import { render } from './helpers/render-adversarial.js';

type Entry = {
  nodePubkey: string; label: string | null; rootKeyId: string; permissions: string[];
  caveats: Array<{ type: string; value: string; requested?: string }>;
  grade: string; fingerprint: string; outPath: string | null; createdAt: string;
  verified: boolean; status: 'active' | 'revoked'; revokedAt: string | null;
  revokeEvidence: string | null; replaces: string | null; replacedBy: string | null;
};
type Row = { rootKeyId: string; inLnd: boolean; flags: string[]; verify: string;
  entry: Record<string, unknown> | null };
type Envelope = { schema: number; command: string; ok: boolean; warnings: Array<string | {code:string;message?:string}>;
  result: { node: { pubkey: string; alias: string; network: string; version: string };
    rootKeys: Row[] } | null;
  error: { code: number; step: string | null; message: string } | null };

const pubkey = '02' + 'ab'.repeat(32);
const otherPubkey = '03' + 'bc'.repeat(32);
const cert = resolve('test/fixture/wrong-tls.cert');
const own = resolve('test/vectors/default-readonly.macaroon');
const ownFacts = JSON.parse(readFileSync(resolve('test/vectors/default-readonly.printmacaroon.json'), 'utf8')) as { root_key_id: string };
const manifest = JSON.parse(readFileSync(resolve('test/vectors/manifest.json'), 'utf8')) as {
  vectors: Array<{ name: string; fingerprint: string; expectedGrade: string }> };
const vector = (name: string) => {
  const found = manifest.vectors.find(item => item.name === name);
  if (!found) throw new Error(`Missing vector metadata: ${name}`);
  return found;
};
const readVector = vector('default-readonly');
const invoiceVector = vector('default-invoice');
const flags = ['--lnd-rest', '127.0.0.1:1', '--tls-cert', cert, '--macaroon', own];

function entry(rootKeyId: string, label: string | null, changes: Partial<Entry> = {}): Entry {
  return {
    nodePubkey: pubkey, label, rootKeyId, permissions: ['info:read'], caveats: [],
    grade: readVector.expectedGrade, fingerprint: readVector.fingerprint,
    outPath: null, createdAt: '2026-10-02T09:00:00Z', verified: true,
    status: 'active', revokedAt: null, revokeEvidence: null,
    replaces: null, replacedBy: null, ...changes,
  };
}

function view(value: Entry): Record<string, unknown> {
  return {
    label: value.label, grade: value.grade, permissions: value.permissions,
    caveats: value.caveats, createdAt: value.createdAt, status: value.status,
    fingerprint: value.fingerprint, outPath: value.outPath,
    replaces: value.replaces, replacedBy: value.replacedBy,
  };
}

function temp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  const base = process.env.MACWARDEN_TEST_TMP;
  if (!base) throw new Error('MACWARDEN_TEST_TMP is required');
  mkdirSync(base, { recursive: true, mode: 0o700 });
  const dir = mkdtempSync(join(base, 'cp019-inventory-'));
  return work(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}

function registry(dir: string, entries: Entry[]) {
  const path = join(dir, 'registry.json');
  writeFileSync(path, JSON.stringify({ schema: 1, entries }), { mode: 0o600 });
  return path;
}

function fixture(ids: string[] = ['0']) {
  const calls: string[] = [];
  const permissions = JSON.parse(readFileSync(resolve('src/grade/lnd-permissions.json'), 'utf8')) as {
    methods: Record<string, string[]> };
  const lnd = {
    ...adapter({}),
    getInfo: vi.fn(async () => {
      calls.push('GetInfo');
      return { alias: 'alice', version: '0.21.4-beta', pubkey: pubkey, network: 'regtest' };
    }),
    listPermissions: vi.fn(async () => {
      calls.push('ListPermissions');
      return permissions.methods;
    }),
    listMacaroonIds: vi.fn(async () => {
      calls.push('ListMacaroonIDs');
      return (ids).map(BigInt);
    }),
  } satisfies LndAdapter;
  const deps = { lnd, fs: { ...fs, readFile: vi.fn((...args: Parameters<typeof fs.readFile>) => fs.readFile(...args)) },
    env: {} as Record<string, string>, clock: () => new Date('2026-10-04T00:00:00Z') };
  return { calls, lnd, deps };
}

async function invoke(path: string, deps: ReturnType<typeof fixture>['deps']): Promise<Envelope> {
  const module = await import('../src/commands/inventory.js') as unknown as {
    run: (args: string[], deps: unknown) => Promise<Envelope> };
  return module.run([...flags, '--registry', path], deps);
}

function row(result: Envelope, id: string): Row {
  const found = result.result?.rootKeys.find(item => item.rootKeyId === id);
  expect(found, `row ${id}`).toBeDefined();
  return found!;
}

it('CP-019/B1 missing registry is empty and creates no file or lock', async () => temp(async dir => {
  const path = join(dir, 'absent.json');
  const { calls, deps } = fixture();
  const output = await invoke(path, deps);
  expect(output.error).toBeNull();
  expect(output.result?.rootKeys.map(item => item.rootKeyId)).toEqual(['0']);
  expect(calls).toEqual(['GetInfo', 'ListPermissions', 'ListMacaroonIDs']);
  expect(existsSync(path)).toBe(false);
  expect(existsSync(`${path}.lock`)).toBe(false);
}));

it.each(['invalid', 'unknown schema', 'unreadable'] as const)(
  'CP-019/B1 %s registry exits at N3 before every LND call and takes no lock',
  async kind => temp(async dir => {
    const path = join(dir, 'registry.json');
    writeFileSync(path, kind === 'invalid' ? '{' : JSON.stringify({
      schema: kind === 'unknown schema' ? 2 : 1, entries: [],
    }));
    const { calls, deps } = fixture();
    if (kind === 'unreadable') deps.fs.readFile.mockImplementation(async (file, ...options) => {
      if (String(file) === path) throw Object.assign(new Error('private path detail'), { code: 'EACCES' });
      return fs.readFile(file, ...options);
    });
    const before = readFileSync(path);
    const output = await invoke(path, deps);
    expect(output.error).toMatchObject({ code: 3, step: 'N3' });
    expect(calls).toEqual([]);
    expect(readFileSync(path).equals(before)).toBe(true);
    expect(existsSync(`${path}.lock`)).toBe(false);
  }));

it('CP-019/B1 a held mutation lock is ignored and inventory leaves it untouched', async () => temp(async dir => {
  const path = registry(dir, []);
  const lock = `${path}.lock`;
  writeFileSync(lock, JSON.stringify({ pid: process.pid, hostname: 'holder', startedAt: '2026-10-04T00:00:00Z' }));
  const lockBytes = readFileSync(lock);
  const { deps } = fixture();
  const output = await invoke(path, deps);
  expect(output.error).toBeNull();
  expect(readFileSync(lock).equals(lockBytes)).toBe(true);
}));

it('CP-019/B2 joins only this node, omits absent revoked rows and sorts exact uint64 IDs', async () => temp(async dir => {
  const entries = [entry('18446744073709551615', 'maximum'),
    entry('10', 'ten'), entry('9', 'nine'),
    entry('11', 'revoked', { status: 'revoked', revokedAt: '2026-10-03T00:00:00Z', revokeEvidence: 'rejected' }),
    entry('12', 'foreign', { nodePubkey: otherPubkey })];
  const path = registry(dir, entries);
  const { deps } = fixture(['18446744073709551615', '10', '0', '9']);
  const output = await invoke(path, deps);
  expect(output.error).toBeNull();
  expect(output.result?.rootKeys.map(item => item.rootKeyId)).toEqual([
    '0', '9', '10', '18446744073709551615']);
  expect(output.result?.rootKeys.map(item => item.inLnd)).toEqual([true, true, true, true]);
  expect(output.result?.rootKeys.some(item => item.rootKeyId === '11' || item.rootKeyId === '12')).toBe(false);
}));

it('CP-019/B3 joins default, own, unknown, missing, revoked and staged rotation flags', async () => temp(async dir => {
  const old = entry('9', 'btcpay', { replacedBy: '10' });
  const replacement = entry('10', 'btcpay', { replaces: '9',
    fingerprint: invoiceVector.fingerprint, grade: invoiceVector.expectedGrade });
  const missing = entry('14', 'rtl');
  const revoked = entry('15', 'retired', { status: 'revoked',
    revokedAt: '2026-10-03T00:00:00Z', revokeEvidence: 'rejected' });
  const path = registry(dir, [old, replacement, missing, revoked]);
  const { deps } = fixture(['15', '10', '9', '0', '13']);
  const output = await invoke(path, deps);
  expect(output.error).toBeNull();
  expect(ownFacts.root_key_id).toBe('0');
  expect(row(output, '0').flags).toEqual(['default-root-key', 'own-credential']);
  expect(row(output, '9').flags).toContain('pending-replacement');
  expect(row(output, '10').flags).toContain('replacement');
  expect(row(output, '13')).toMatchObject({ inLnd: true, flags: ['unknown'], entry: null });
  expect(row(output, '14')).toMatchObject({ inLnd: false, flags: ['missing-in-lnd'] });
  expect(row(output, '15').flags).toContain('revoked-but-present');
  expect(output.result?.rootKeys.map(item => item.rootKeyId)).toEqual(['0', '9', '10', '13', '14', '15']);
}));

it('CP-019/B4 no verify leaves every row not-checked and exposes only the documented entry view', async () => temp(async dir => {
  const known = entry('9', 'read', { outPath: '/operator/read.macaroon' });
  const path = registry(dir, [known]);
  const { deps } = fixture(['0', '9', '10']);
  const output = await invoke(path, deps);
  expect(output.error).toBeNull();
  expect(output.result?.rootKeys.every(item => item.verify === 'not-checked')).toBe(true);
  expect(row(output, '10').entry).toBeNull();
  expect(row(output, '9').entry).toEqual(view(known));
  expect(JSON.stringify(output)).not.toContain('revokeEvidence');
}));

it('CP-019/B5 JSON is one credential-free document with exact node and row shape', async () => temp(async dir => {
  const known = entry('18446744073709551615', 'maximum');
  const path = registry(dir, [known]);
  const { deps } = fixture(['0', '18446744073709551615']);
  const output = await invoke(path, deps);
  const rendered = render(output, 'json');
  const parsed = JSON.parse(rendered) as Envelope;
  expect(parsed).toEqual({ schema: output.schema, command: output.command, ok: output.ok,
    warnings: output.warnings, result: output.result, error: output.error });
  expect(parsed).not.toHaveProperty('display');
  expect(parsed).not.toHaveProperty('exitCode');
  expect(parsed.result?.node).toEqual({ pubkey, alias: 'alice', network: 'regtest', version: '0.21.4-beta' });
  expect(Object.keys(row(parsed, '18446744073709551615')).sort()).toEqual(
    ['rootKeyId', 'inLnd', 'flags', 'verify', 'expires', 'entry'].sort());
  expect(row(parsed, '18446744073709551615').entry).toEqual(view(known));
  expect(rendered).not.toContain('nodePubkey');
  expect(rendered).not.toContain('verified');
  const ownBytes = readFileSync(own);
  for (const form of [ownBytes.toString('hex'), ownBytes.toString('base64'),
    ownBytes.toString('base64url')]) expect(rendered.includes(form)).toBe(false);
}));

it('CP-019/B6 text renders default, unknown, missing and staged rotation statuses', async () => temp(async dir => {
  const path = registry(dir, [entry('9', 'btcpay', { replacedBy: '10' }),
    entry('10', 'btcpay', { replaces: '9' }), entry('14', 'rtl')]);
  const { deps } = fixture(['0', '9', '10', '13']);
  const output = await invoke(path, deps);
  const text = render(output, 'text');
  expect(text).toContain('default root key: cannot be individually revoked');
  expect(text).toContain('unknown — not in this registry (another tool or operator may own it)');
  expect(text).toContain('missing in LND (registry says active)');
  expect(text).toContain('rotation staged -> 10');
}));

it('CP-019/B7 repeat reads preserve result, registry bytes and mtime without a lock', async () => temp(async dir => {
  const path = registry(dir, [entry('9', 'read')]);
  const before = readFileSync(path);
  const mtime = statSync(path).mtimeMs;
  const { deps, calls } = fixture(['0', '9']);
  const first = await invoke(path, deps);
  const second = await invoke(path, deps);
  expect(first.result).toEqual(second.result);
  expect(readFileSync(path).equals(before)).toBe(true);
  expect(statSync(path).mtimeMs).toBe(mtime);
  expect(existsSync(`${path}.lock`)).toBe(false);
  expect(calls).toEqual(['GetInfo', 'ListPermissions', 'ListMacaroonIDs',
    'GetInfo', 'ListPermissions', 'ListMacaroonIDs']);
}));

it('CP-019/B8 discrepancy rows still return a successful inventory', async () => temp(async dir => {
  const path = registry(dir, [entry('9', 'missing')]);
  const { deps } = fixture(['0', '10']);
  const output = await invoke(path, deps);
  expect(output.ok).toBe(true);
  expect(output.error).toBeNull();
  expect(row(output, '9').flags).toContain('missing-in-lnd');
  expect(row(output, '10').flags).toContain('unknown');
}));
