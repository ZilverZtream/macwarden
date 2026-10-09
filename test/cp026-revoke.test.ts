import { adapter } from './helpers/adapter.js';
import { LndError } from '../src/errors.js';
import type { LndAdapter } from '../src/lnd/index.js';
import type { Secret } from '../src/secret.js';
import { revealSecret } from './helpers/secret-bytes.js';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { Readable } from 'node:stream';
import { join, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';
import { render } from './helpers/render-adversarial.js';
import { findLeaks } from "./helpers/leak-check.js";
import { directory, entry, maxId, otherPubkey, ownId, permissionsResponse, pubkey,
  register, snapshot, vector, wireFixture } from './helpers/cp026-revoke-support.mjs';

type Envelope = { schema: number; command: string; ok: boolean;
  warnings: Array<string | { code: string }>; result: Record<string, unknown> | null;
  error: { code: number; step: string; message: string } | null };
const repo = resolve();
const modulePath = '../src/commands/revoke.js';
const fault = (kind: string) => new LndError(kind === 'transport' || kind === 'TLS' || kind === '401' || kind === '403' ? 4 : 5, kind === 'transport' || kind === 'TLS' ? 'transport' : 'lnd', 'injected online failure');

function fixture(dir: string) {
  const registry = join(dir, 'registry.json');
  const target = entry();
  const own = register(wireFixture('default-admin', ownId));
  const calls: string[] = [], io: string[] = [], output: string[] = [];
  const ids = ['0', maxId];
  const prompt = Object.assign(vi.fn(async (question: string) => {
    expect(existsSync(`${registry}.lock`)).toBe(false);
    output.push(question);
    return 'Alice' as string | null;
  }), { isTTY: true });
  const stdin = Object.assign(Readable.from(['Alice\n']), { isTTY: true });
  const mutation = vi.fn<(id: bigint) => Promise<{ deleted: boolean }>>(async () => {
    calls.push('MUTATION'); throw new Error('Mutation outside CP-026');
  });
  const lnd = {
    ...adapter({}),
    getInfo: vi.fn(async () => { calls.push('GetInfo'); return { alias: 'fixture', network: 'regtest', version: '0.21.4-beta', pubkey: pubkey }; }),
    listPermissions: vi.fn(async () => { calls.push('ListPermissions'); return permissionsResponse(); }),
    listMacaroonIds: vi.fn(async () => { calls.push('ListMacaroonIDs'); return ([...ids]).map(BigInt); }),
    checkMacaroon: vi.fn<LndAdapter['checkMacaroon']>(async (mac: Secret, requested: string[], ...extra: unknown[]) => {
      calls.push('CheckMacaroonPermissions');
      register(Buffer.from(revealSecret(mac)));
      expect(requested.length).toBeGreaterThan(0);
      expect(extra).toEqual([]);
      return { valid: true as const };
    }),
    deleteMacaroonId: mutation, bakeMacaroon: vi.fn(async () => { throw new Error('Unexpected bake'); }),
  } satisfies LndAdapter;

  const deps = { lnd: { ...lnd }, fs: { ...fs }, env: {} as Record<string, string>,
    clock: () => new Date('2026-10-05T00:00:00Z'), prompt, stdin,
    stdout: { write: (text: string) => { output.push(text); return true; } } };
  deps.fs.readFile = vi.fn(async (...args: Parameters<typeof fs.readFile>) => {
    io.push(`read:${String(args[0])}`); return fs.readFile(...args);
  }) as typeof fs.readFile;
  deps.fs.open = vi.fn(async (...args: Parameters<typeof fs.open>) => {
    io.push(`open:${String(args[0])}:${String(args[1])}`);
    return fs.open(...args);
  });
  writeFileSync(registry, JSON.stringify({ schema: 1, entries: [target] }), { mode: 0o600 });
  const args = ['Alice', '--registry', registry, '--lnd-rest', '127.0.0.1:1',
    '--tls-cert', resolve('test/fixture/wrong-tls.cert'), '--macaroon', own];
  return { registry, target, own, calls, io, output, ids, prompt, stdin, mutation, lnd, deps, args };
}
type Fixture = ReturnType<typeof fixture>;
async function scratch(work: (f: Fixture) => Promise<void>) {
  const dir = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'cp026-unit-'));
  try { await work(fixture(dir)); }
  finally { rmSync(dir, { recursive: true, force: true }); }
}
function save(f: Fixture, entries: Array<Record<string, unknown>>) {
  writeFileSync(f.registry, JSON.stringify({ schema: 1, entries }), { mode: 0o600 });
}
function flag(f: Fixture, name: string, value: string) { f.args[f.args.indexOf(name) + 1] = value; }
async function invoke(f: Fixture, flags: string[] = [], target = 'Alice', completed = false): Promise<Envelope> {
  const before = readFileSync(f.registry), mtime = statSync(f.registry).mtimeMs, ids = [...f.ids];
  const lock = existsSync(`${f.registry}.lock`) ? readFileSync(`${f.registry}.lock`) : null;
  if (completed) {
    const deletion = vi.fn(async (id: bigint) => {
      f.calls.push('DeleteMacaroonID');
      expect(typeof id).toBe('bigint'); expect(id).toBe(BigInt(f.target.rootKeyId)); expect(id).not.toBe(0n);
      expect(existsSync(`${f.registry}.lock`)).toBe(true);
      expect(f.ids).toContain(String(id));
      f.ids.splice(f.ids.indexOf(String(id)), 1);
      return { deleted: true };
    });
    f.deps.lnd.deleteMacaroonId = deletion; f.deps.lnd.deleteMacaroonId = deletion;
    f.lnd.checkMacaroon.mockImplementation(async (mac, requested, ...extra) => {
      f.calls.push('CheckMacaroonPermissions'); register(Buffer.from(revealSecret(mac)));
      expect(requested.length).toBeGreaterThan(0); expect(extra).toEqual([]);
      return f.ids.includes(f.target.rootKeyId) ? { valid: true as const } : {
        valid: false as const, reason: 'root-key-missing' as const, message: `root key with id ${f.target.rootKeyId} doesn't exist`,
      };
    });
  }
  const command = await import(/* @vite-ignore */ modulePath) as {
    run(args: string[], deps: unknown): Promise<Envelope>;
  };
  expect(typeof command.run).toBe('function');
  const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(((text: unknown) => {
    f.output.push(String(text)); return true;
  }) as typeof process.stdout.write);
  const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(((text: unknown) => {
    f.output.push(String(text)); return true;
  }) as typeof process.stderr.write);
  let result: Envelope;
  try { result = await command.run([target, ...f.args.slice(1), ...flags], f.deps); }
  finally { stdout.mockRestore(); stderr.mockRestore(); }
  expect(result).toMatchObject({ schema: 1, command: 'revoke' });
  expect(result.ok).toBe(result.error === null);
  expect(f.mutation).not.toHaveBeenCalled();
  if (completed) expect(f.deps.lnd.deleteMacaroonId).toHaveBeenCalledTimes(1);
  for (const [mac, requested] of f.lnd.checkMacaroon.mock.calls) {
    const path = flags.includes('--target-file') ? flags[flags.indexOf('--target-file') + 1] : f.target.outPath;
    expect(Buffer.from(revealSecret(mac)).equals(readFileSync(path))).toBe(true);
    expect(requested).toEqual(f.target.permissions);
  }
  if (completed) {
    const label = flags.includes('--unregistered') ? null : f.target.label;
    const evidence = label === null ? 'by-id-only' : 'rejected';
    expect(f.ids).toEqual(ids.filter(id => id !== f.target.rootKeyId));
    expect(result.error).toBeNull();
    expect(result.result).toEqual({ rootKeyId: f.target.rootKeyId, label, evidence, repaired: false,
      entry: expect.objectContaining({ nodePubkey: pubkey, rootKeyId: f.target.rootKeyId,
        label, status: 'revoked', revokedAt: '2026-10-05T00:00:00.000Z', revokeEvidence: evidence }) });
    expect(JSON.parse(readFileSync(f.registry, 'utf8'))).toEqual({ schema: 1, entries: [result.result!.entry] });
    if (label !== null) expect(result.result!.entry).toEqual({ ...f.target, status: 'revoked',
      revokedAt: '2026-10-05T00:00:00.000Z', revokeEvidence: evidence });
  } else {
    expect(f.ids).toEqual(ids);
    expect(readFileSync(f.registry).equals(before)).toBe(true);
    expect(statSync(f.registry).mtimeMs).toBe(mtime);
    expect(f.io.some(call => call.startsWith('open:') && /[wax+]/.test(call.split(':').at(-1)!))).toBe(false);
  }
  expect(existsSync(`${f.registry}.lock`)).toBe(lock !== null);
  if (lock) expect(readFileSync(`${f.registry}.lock`).equals(lock)).toBe(true);
  expect(findLeaks({ root: repo, sentinels: join(repo, 'test/sentinels.json'),
    sentinelDir: directory('MACWARDEN_SENTINEL_DIR'), testTmp: directory('MACWARDEN_TEST_TMP'),
    commandOutput: f.output.join('') + render(result, 'text') + render(result, 'json'),
    paths: [f.registry] })).toBeNull();
  return result;
}
function refused(result: Envelope, code: number, step: string) {
  expect(result.error).toMatchObject({ code, step });
  expect(result.error!.message.length).toBeGreaterThan(0);
  expect(result.result).toBeNull();
}
function plan(result: Envelope, f: Fixture, proof = 'rejected', label: string | null = 'Alice') {
  expect(result.error).toBeNull();
  expect(result.result).toMatchObject({ dryRun: true, rootKeyId: f.target.rootKeyId,
    label, grade: f.target.grade, proof });
  const text = render(result, 'text');
  for (const value of [label, f.target.rootKeyId, f.target.grade].filter(Boolean)) expect(text).toContain(value);
  expect(text).toMatch(proof === 'rejected' ? /reject/i : /by.?id.?only|by ID only/i);
}

it.each(['0', '007', '-1', '+5', '0x10', '18446744073709551616', 'bad label',
  '_bad', 'A'.repeat(65), '', '１２'])('CP-026/V1 invalid target %s wins before ENV, files and LND',
  async target => scratch(async f => {
    f.deps.env.NODE_DEBUG = 'https';
    flag(f, '--tls-cert', join(repo, 'test/nonexistent-cp026.cert'));
    refused(await invoke(f, ['--target-file', join(repo, 'test/nonexistent-cp026.macaroon')], target), 2, 'V1');
    expect(f.calls).toEqual([]); expect(f.io).toEqual([]);
  }));
it('CP-026/V1 canonical uint64 maximum passes parsing and keeps its decimal identity', async () => scratch(async f => {
  plan(await invoke(f, ['--dry-run'], maxId), f);
  expect(f.calls).toEqual(['GetInfo', 'ListPermissions', 'ListMacaroonIDs', 'CheckMacaroonPermissions']);
}));
it.each([['NODE_DEBUG', 'http'], ['NODE_DEBUG', 'https'], ['NODE_DEBUG', 'tls'],
  ['NODE_DEBUG', 'net'], ['NODE_DEBUG', 'fs,NET'], ['NODE_OPTIONS', '--report-on-fatalerror'],
  ['NODE_OPTIONS', '--report-directory=test']])('CP-026/V2 %s %s wins before target-file and OWN',
  async (key, value) => scratch(async f => {
    f.deps.env[key] = value;
    refused(await invoke(f, ['--target-file', join(repo, 'test/nonexistent-cp026.macaroon')]), 2, 'V2');
    expect(f.calls).toEqual([]); expect(f.io).toEqual([]);
  }));
it('CP-026/V2 harmless NODE_DEBUG passes the environment guard', async () => scratch(async f => {
  f.deps.env.NODE_DEBUG = 'fs'; plan(await invoke(f, ['--dry-run']), f);
}));
it.each(['unreadable', 'undecodable', 'root zero', 'numeric mismatch']) (
  'CP-026/V3 %s explicit target is refused before OWN and networking', async kind => scratch(async f => {
    const path = kind === 'unreadable' ? f.target.outPath : kind === 'undecodable'
      ? resolve('test/vectors/negative/truncated-protobuf.macaroon') : kind === 'root zero'
        ? resolve('test/vectors/default-invoice.macaroon') : register(wireFixture('root-max', '9007199254740993'));
    if (kind === 'unreadable') f.deps.fs.open = vi.fn(async (...args: Parameters<typeof fs.open>) => {
      if (args[0] === path) throw Object.assign(new Error('injected target read failure'), { code: 'EACCES' });
      return fs.open(...args);
    }) as typeof fs.open;
    flag(f, '--tls-cert', join(repo, 'test/nonexistent-cp026.cert'));
    refused(await invoke(f, ['--target-file', path], maxId),
      kind === 'root zero' || kind === 'numeric mismatch' ? 2 : 3, 'V3');
    expect(f.calls).toEqual([]);
  }));
it.each(['TLS unreadable', 'own unreadable', 'own undecodable', 'missing info:read',
  'missing macaroon:read', 'missing macaroon:write', 'numeric own ID']) (
  'CP-026/V4 %s is refused before registry resolution and LND', async kind => scratch(async f => {
    if (kind === 'TLS unreadable') flag(f, '--tls-cert', join(repo, 'test/nonexistent-cp026.cert'));
    else if (kind === 'own unreadable') flag(f, '--macaroon', join(repo, 'test/nonexistent-cp026.macaroon'));
    else if (kind === 'own undecodable') flag(f, '--macaroon', resolve('test/vectors/negative/truncated-protobuf.macaroon'));
    else if (kind.startsWith('missing ')) flag(f, '--macaroon', register(wireFixture('default-admin', ownId,
      vector('default-admin').printed.permissions.filter((permission: string) => permission !== kind.slice(8)))));
    writeFileSync(f.registry, '{invalid');
    refused(await invoke(f, [], kind === 'numeric own ID' ? ownId : 'Alice'),
      kind === 'numeric own ID' ? 2 : 4, 'V4');
    expect(f.calls).toEqual([]);
    expect(f.io).not.toContain(`read:${f.registry}`);
  }));
it('CP-026/V4 exact method URI permissions satisfy OWN without granting a different method', async () => scratch(async f => {
  const methods = ['GetInfo', 'ListPermissions', 'ListMacaroonIDs', 'CheckMacaroonPermissions', 'DeleteMacaroonID'];
  flag(f, '--macaroon', register(wireFixture('default-admin', ownId,
    methods.map(method => `uri:/lnrpc.Lightning/${method}`))));
  plan(await invoke(f, ['--dry-run']), f);
}));
it.each(['GetInfo', 'ListPermissions', 'ListMacaroonIDs', 'CheckMacaroonPermissions', 'DeleteMacaroonID']) (
  'CP-026/V4 URI OWN missing exact %s permission fails offline', async missing => scratch(async f => {
    const methods = ['GetInfo', 'ListPermissions', 'ListMacaroonIDs', 'CheckMacaroonPermissions', 'DeleteMacaroonID'];
    flag(f, '--macaroon', register(wireFixture('default-admin', ownId,
      methods.filter(method => method !== missing).map(method => `uri:/lnrpc.Lightning/${method}`))));
    refused(await invoke(f, ['--dry-run']), 4, 'V4');
    expect(f.calls).toEqual([]);
  }));
it('CP-026/V4 failed OWN wins over a numeric own-ID refusal', async () => scratch(async f => {
  flag(f, '--tls-cert', join(repo, 'test/nonexistent-cp026.cert'));
  refused(await invoke(f, [], ownId), 4, 'V4');
  expect(f.calls).toEqual([]);
}));
it('CP-026/V4 own root-zero warning permits planning a nonzero target', async () => scratch(async f => {
  flag(f, '--macaroon', resolve('test/vectors/default-admin.macaroon'));
  const result = await invoke(f, ['--dry-run']); plan(result, f);
  expect(result.warnings.map(value => typeof value === 'string' ? value : value.code)).toContain('own-root-key-0');
}));
it.each(['transport', 'TLS', '401', '403', '500']) (
  'CP-026/V5 GetInfo %s failure wins before invalid registry and is classified safely', async kind => scratch(async f => {
    f.lnd.getInfo.mockImplementationOnce(async () => { f.calls.push('GetInfo'); throw fault(kind); });
    writeFileSync(f.registry, '{invalid');
    refused(await invoke(f), kind === '500' ? 5 : 4, 'V5');
    expect(f.calls[0]).toBe('GetInfo');
    expect(f.calls.slice(1).every(call => call === 'ListMacaroonIDs')).toBe(true);
    expect(f.calls.filter(call => call === 'ListMacaroonIDs').length).toBeLessThanOrEqual(1);
    expect(f.io).not.toContain(`read:${f.registry}`);
  }));
it.each(['added method', 'removed method', 'changed permission', 'unchanged']) (
  'CP-026/V5 %s snapshot is compared once while the stored vector grade stays fixed', async kind => scratch(async f => {
    const methods = structuredClone(snapshot.methods);
    if (kind === 'added method') methods['/cp026.Extra/Read'] = ['info:read'];
    if (kind === 'removed method') delete methods['/lnrpc.Lightning/GetInfo'];
    if (kind === 'changed permission') methods['/lnrpc.Lightning/GetInfo'] = ['info:write'];
    f.lnd.listPermissions.mockImplementationOnce(async () => { f.calls.push('ListPermissions'); return permissionsResponse(methods); });
    const result = await invoke(f, ['--dry-run']); plan(result, f);
    expect(result.warnings.map(value => typeof value === 'string' ? value : value.code).includes('snapshot-drift'))
      .toBe(kind !== 'unchanged');
    expect(f.lnd.listPermissions).toHaveBeenCalledTimes(1);
  }));
it.each(['malformed JSON', 'invalid schema', 'unreadable registry']) (
  'CP-026/V6 %s stops after node identification without mutation', async kind => scratch(async f => {
    if (kind === 'malformed JSON') writeFileSync(f.registry, '{invalid');
    if (kind === 'invalid schema') writeFileSync(f.registry, '{"schema":99,"entries":[]}');
    if (kind === 'unreadable registry') f.deps.fs.readFile = vi.fn(async (...args: Parameters<typeof fs.readFile>) => {
      if (args[0] === f.registry) throw Object.assign(new Error('injected registry read failure'), { code: 'EACCES' });
      return fs.readFile(...args);
    }) as typeof fs.readFile;
    refused(await invoke(f), 3, 'V6');
    expect(f.calls).toEqual(['GetInfo', 'ListPermissions']);
  }));
it.each(['absent label', 'revoked label', 'other-node label', 'ambiguous label', 'other-node numeric',
  'unknown numeric', 'resolved own ID', 'explicit label target mismatch', 'wrong default ID']) (
  'CP-026/V6 %s is refused with node-scoped resolution before listing IDs', async kind => scratch(async f => {
    let rows = [f.target], target = 'Alice', flags: string[] = [];
    if (kind === 'absent label' || kind === 'unknown numeric') rows = [];
    if (kind === 'revoked label') rows = [{ ...f.target, status: 'revoked',
      revokedAt: '2026-10-04T00:00:00Z', revokeEvidence: 'by-id-only' }];
    if (kind.startsWith('other-node')) rows = [{ ...f.target, nodePubkey: otherPubkey }];
    if (kind === 'ambiguous label') rows.push(entry('root-max', '9007199254740993', { replaces: f.target.rootKeyId }));
    if (kind === 'resolved own ID') rows = [{ ...f.target, rootKeyId: ownId, outPath: f.own }];
    if (kind === 'explicit label target mismatch') flags = ['--target-file', register(wireFixture('root-max', '9007199254740993'))];
    // RL-01 (1.1.1): a default file on another root key ID is refused only when it carries the
    // entry's fingerprint (the entry was edited); another credential at a reused path is proven by ID.
    if (kind === 'wrong default ID') {
      const path = register(wireFixture('root-max', '9007199254740993'));
      rows = [{ ...f.target, outPath: path,
        fingerprint: 'fp:' + createHash('sha256').update(readFileSync(path)).digest('hex').slice(0, 16) }];
    }
    // SPEC 5 V6 changed in 1.1.1 (RL-04): an ID registered only for another node is refused
    // without --unregistered; with it, this node's ID is revoked (test/respond-multi-node.test.ts).
    if (kind === 'unknown numeric' || kind === 'other-node numeric') { target = maxId; flags = []; }
    save(f, rows);
    const result = await invoke(f, flags, target); refused(result, kind === 'wrong default ID' ? 3 : 2, 'V6');
    expect(f.calls).toEqual(['GetInfo', 'ListPermissions']);
    if (kind === 'ambiguous label') for (const row of rows) expect(result.error!.message).toContain(row.rootKeyId);
    if (kind === 'other-node numeric') expect(result.error!.message).toMatch(/another node.*--unregistered/);
    if (kind === 'unknown numeric') {
      expect(result.error!.message).toMatch(/other tools/i);
      expect(result.error!.message).toMatch(/other operators/i);
      expect(result.error!.message).toMatch(/same.*store|shar.*store/i);
    }
  }));
it.each(['label', 'numeric'])('CP-026/V6 %s selects only this node among identical cross-node entries',
  async kind => scratch(async f => {
    save(f, [{ ...f.target, nodePubkey: otherPubkey, grade: 'ADMIN', outPath: null }, f.target]);
    plan(await invoke(f, ['--dry-run'], kind === 'label' ? 'Alice' : maxId), f);
  }));
it('CP-026/V6 revoked duplicate does not make an active label ambiguous', async () => scratch(async f => {
  save(f, [entry('root-max', '9007199254740993', { status: 'revoked',
    revokedAt: '2026-10-04T00:00:00Z', revokeEvidence: 'by-id-only' }), f.target]);
  plan(await invoke(f, ['--dry-run']), f);
}));
it('CP-026/V6 label matching is exact and case-sensitive', async () => scratch(async f => {
  refused(await invoke(f, [], 'alice'), 2, 'V6');
  expect(f.calls).toEqual(['GetInfo', 'ListPermissions']);
}));
it('CP-026/V6 numeric resolution can plan an entry marked revoked when its ID is still present', async () => scratch(async f => {
  save(f, [{ ...f.target, status: 'revoked', revokedAt: '2026-10-04T00:00:00Z', revokeEvidence: 'by-id-only' }]);
  plan(await invoke(f, ['--dry-run'], maxId), f);
}));
it('CP-026/V6 unregistered ID is allowed explicitly with null label and grade', async () => scratch(async f => {
  save(f, []);
  const result = await invoke(f, ['--unregistered', '--dry-run'], maxId);
  expect(result.error).toBeNull();
  expect(result.result).toEqual({ dryRun: true, rootKeyId: maxId, label: null, grade: null, proof: 'by-id-only' });
  expect(f.calls).toEqual(['GetInfo', 'ListPermissions', 'ListMacaroonIDs']);
}));
it.each(['transport', 'TLS', '401', '403', '500']) (
  'CP-026/V7-present ListMacaroonIDs %s stops before baseline and confirmation', async kind => scratch(async f => {
    f.lnd.listMacaroonIds.mockImplementationOnce(async () => { f.calls.push('ListMacaroonIDs'); throw fault(kind); });
    refused(await invoke(f), kind === '500' ? 5 : 4, 'V7');
    expect(f.calls).toEqual(['GetInfo', 'ListPermissions', 'ListMacaroonIDs']);
    expect(f.prompt).not.toHaveBeenCalled();
  }));
it('CP-026/V7-present present ID proceeds to baseline and planning without a delete', async () => scratch(async f => {
  plan(await invoke(f, ['--dry-run']), f);
  expect(f.calls).toEqual(['GetInfo', 'ListPermissions', 'ListMacaroonIDs', 'CheckMacaroonPermissions']);
}));
it.each(['missing default', 'fingerprint mismatch', 'expired', 'not accepted', 'root missing',
  'empty permissions'])('CP-026/V8 %s selects by-id-only without mistaking the target for OWN',
  async kind => scratch(async f => {
    if (kind === 'missing default') f.target.outPath = join(directory('MACWARDEN_TEST_TMP'), 'cp026-no-such-target');
    if (kind === 'fingerprint mismatch') f.target.fingerprint = 'fp:0000000000000000';
    if (kind === 'expired') f.target = entry('time-before', maxId);
    if (kind === 'empty permissions') {
      f.target = { ...f.target, permissions: [], outPath: register(wireFixture('root-max', maxId, [])), grade: 'UNASSESSED' };
      // Matching file identity must not turn an empty permission check into a validity proof.
      const { createHash } = await import('node:crypto');
      f.target.fingerprint = 'fp:' + createHash('sha256').update(readFileSync(f.target.outPath)).digest('hex').slice(0, 16);
    }
    if (kind === 'not accepted' || kind === 'root missing') f.lnd.checkMacaroon.mockImplementationOnce(async () => {
      f.calls.push('CheckMacaroonPermissions'); return { valid: false as const,
        reason: kind === 'root missing' ? 'root-key-missing' : 'other', message: 'injected baseline refusal' };
    });
    save(f, [f.target]);
    plan(await invoke(f, ['--dry-run']), f, 'by-id-only');
    expect(f.lnd.checkMacaroon.mock.calls.length).toBe(kind === 'not accepted' || kind === 'root missing' ? 1 : 0);
  }));
it.each(['root-max', 'grade-uri-read-pair', 'preset-invoice-only', 'preset-pay-only']) (
  'CP-026/V8 usable %s uses its stored permissions and grade in accepted baseline and plan', async name => scratch(async f => {
    f.target = entry(name, maxId); save(f, [f.target]);
    plan(await invoke(f, ['--dry-run', '--target-file', f.target.outPath]), f);
    expect(f.lnd.checkMacaroon).toHaveBeenCalledTimes(1);
    expect(f.lnd.checkMacaroon.mock.calls[0][1]).toEqual(vector(name).printed.permissions);
  }));
it('CP-026/V8 explicit same-ID target remains usable when its fingerprint differs from the default entry', async () => scratch(async f => {
  const explicit = register(wireFixture('root-max', maxId));
  plan(await invoke(f, ['--dry-run', '--target-file', explicit]), f);
  expect(f.lnd.checkMacaroon).toHaveBeenCalledTimes(1);
}));
it('CP-026/V8 an unusable default never falls back to testing macwarden own credential', async () => scratch(async f => {
  f.target.outPath = null; save(f, [f.target]);
  plan(await invoke(f, ['--dry-run']), f, 'by-id-only');
  expect(f.lnd.checkMacaroon).not.toHaveBeenCalled();
}));
it.each(['--dry-run', '--dry-run --yes', '--dry-run --json']) (
  'CP-026/V9 %s produces a complete nonmutating plan and never prompts', async flags => scratch(async f => {
    const result = await invoke(f, flags.split(' ')); plan(result, f);
    expect(f.prompt).not.toHaveBeenCalled();
    const json = render(result, 'json');
    expect(JSON.parse(json)).toMatchObject({ schema: 1, command: 'revoke', ok: true,
      result: { dryRun: true, rootKeyId: maxId, label: 'Alice', grade: 'READ', proof: 'rejected' }, error: null });
    expect(json.trim().split('\n')).toHaveLength(1);
  }));
it.each(['wrong text', 'case differs', 'empty', 'EOF', 'non-TTY']) (
  'CP-026/V9 %s declines without a lock or mutation after an informed plan', async kind => scratch(async f => {
    const answer = kind === 'EOF' ? null : kind === 'empty' ? '' : kind === 'case differs' ? 'alice' : 'wrong';
    f.prompt.mockImplementation(async (question: string) => {
      expect(existsSync(`${f.registry}.lock`)).toBe(false);
      f.output.push(question); return answer;
    });
    if (kind === 'non-TTY') { f.stdin.isTTY = false; f.prompt.isTTY = false; }
    const result = await invoke(f); refused(result, 6, 'V9');
    if (kind === 'non-TTY') expect(f.prompt).not.toHaveBeenCalled();
    else {
      expect(f.prompt).toHaveBeenCalledTimes(1);
      const visible = f.output.join('') + render(result, 'text');
      for (const value of ['Alice', maxId, 'READ']) expect(visible).toContain(value);
      expect(visible).toMatch(/reject/i);
    }
  }));
it('CP-026/V9 unregistered confirmation asks for the exact ID and refuses the label', async () => scratch(async f => {
  save(f, []);
  f.prompt.mockImplementation(async (question: string) => {
    expect(existsSync(`${f.registry}.lock`)).toBe(false);
    f.output.push(question); return 'Alice';
  });
  refused(await invoke(f, ['--unregistered'], maxId), 6, 'V9');
  expect(f.prompt).toHaveBeenCalledTimes(1);
  expect(f.output.join('')).toContain(maxId);
}));
it.each(['exact label', 'exact unregistered ID', '--yes on non-TTY']) (
  'CP-026/V9 %s confirms deletion with independent proof and a revoked record', async kind => scratch(async f => {
    const flags: string[] = [];
    let target = 'Alice';
    if (kind === 'exact unregistered ID') {
      target = maxId; flags.push('--unregistered'); save(f, []);
      f.prompt.mockImplementation(async (question: string) => {
        expect(existsSync(`${f.registry}.lock`)).toBe(false);
        f.output.push(question); return maxId;
      });
    }
    if (kind === '--yes on non-TTY') {
      flags.push('--yes'); f.stdin.isTTY = false; f.prompt.isTTY = false;
    }
    const result = await invoke(f, flags, target, true);
    expect(result.error).toBeNull();
    if (kind === '--yes on non-TTY') expect(f.prompt).not.toHaveBeenCalled();
    else expect(f.prompt).toHaveBeenCalledTimes(1);
    expect(f.calls).toEqual(kind === 'exact unregistered ID'
      ? ['GetInfo', 'ListPermissions', 'ListMacaroonIDs', 'DeleteMacaroonID', 'ListMacaroonIDs']
      : ['GetInfo', 'ListPermissions', 'ListMacaroonIDs', 'CheckMacaroonPermissions',
        'DeleteMacaroonID', 'ListMacaroonIDs', 'CheckMacaroonPermissions']);
    expect(f.lnd.listMacaroonIds).toHaveBeenCalledTimes(2);
    expect(f.lnd.checkMacaroon).toHaveBeenCalledTimes(kind === 'exact unregistered ID' ? 0 : 2);
    expect(f.output.join('') + render(result, 'text')).toContain(maxId);
  }));
it('CP-026/V9 a preexisting lock remains untouched during dry-run and declined input', async () => scratch(async f => {
  writeFileSync(`${f.registry}.lock`, JSON.stringify({ pid: process.pid, hostname: 'other-host', startedAt: '2026-10-04T00:00:00Z' }));
  plan(await invoke(f, ['--dry-run', '--break-lock']), f);
  f.prompt.mockImplementation(async () => {
    expect(existsSync(`${f.registry}.lock`)).toBe(true); return 'wrong';
  });
  refused(await invoke(f, ['--break-lock']), 6, 'V9');
}));
