import { LndError } from '../src/errors.js';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { hostname } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';
import { Secret } from '../src/secret.js';
import { render } from './helpers/render-adversarial.js';
import { findLeaks } from "./helpers/leak-check.js";
import { directory, fixture, permissions, pubkey, responseBytes } from './helpers/cp025-bake-support.mjs';
import { contend } from './helpers/cp025-contention.js';
import { isolateLeakSuite } from './helpers/leak-suite.js';
import { expectSchemaValid } from './helpers/output-schema.js';

isolateLeakSuite('cp025');

const entropy = vi.hoisted(() => ({ draws: [4294967296n], at: 0 }));
vi.mock('node:crypto', async importOriginal => {
  const real = await importOriginal<typeof import('node:crypto')>();
  return { ...real, randomBytes: (size: number) => {
    if (size !== 8) return real.randomBytes(size);
    const bytes = Buffer.alloc(8);
    bytes.writeBigUInt64BE(entropy.draws[Math.min(entropy.at++, entropy.draws.length - 1)]);
    return bytes;
  } };
});
type Envelope = { schema: number; command: string; ok: boolean; warnings: Array<string | {code:string;message?:string}>;
  result: Record<string, unknown> | null; error: { code: number; step: string; message: string } | null };
type Fixture = ReturnType<typeof fixture>;
const repo = resolve();
async function scratch(work: (f: Fixture, dir: string) => Promise<void>) {
  const dir = mkdtempSync(join(directory('MACWARDEN_TEST_TMP'), 'cp025-unit-'));
  const f = fixture(dir, Secret);
  writeFileSync(f.registry, '{"schema":1,"entries":[]}', { mode: 0o600 });
  entropy.draws = [4294967296n]; entropy.at = 0;
  await work(f, dir);
}
async function invoke(f: Fixture, flags: string[] = []): Promise<Envelope> {

  const command = await import('../src/commands/bake/index.js') as {
    run: (args: string[], deps: unknown) => Promise<Envelope>;
  };
  const result = await command.run([...f.args, ...flags], f.deps);
  expect(result).toMatchObject({ schema: 1, command: 'bake' });
  expectSchemaValid(result);
  expect(findLeaks({ root: repo, sentinels: join(repo, 'test/sentinels.json'),
    sentinelDir: directory('MACWARDEN_SENTINEL_DIR'), testTmp: directory('MACWARDEN_TEST_TMP'),
    commandOutput: render(result, 'text') + render(result, 'json'), paths: [f.registry] })).toBeNull();
  return result;
}
function entries(f: Fixture): Array<Record<string, unknown>> {
  return JSON.parse(readFileSync(f.registry, 'utf8')).entries;
}
function deadPid(): number {
  const child = spawnSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))'],
    { encoding: 'utf8', timeout: 5000 });
  expect(child.status).toBe(0);
  const pid = Number(child.stdout);
  expect(pid).toBeGreaterThan(0);
  expect(() => process.kill(pid, 0)).toThrow();
  return pid;
}
const startedAt = '2026-10-04T00:00:00Z';
it('CP-025/B1 same-host dead lock is preserved with and without break-lock when namespace ownership is ambiguous',
  async () => scratch(async f => {
    const pid = deadPid(), lock = `${f.registry}.lock`;
    writeFileSync(lock, JSON.stringify({ pid, hostname: hostname(), startedAt }));
    const before = readFileSync(lock), registryBefore = readFileSync(f.registry);
    const refused = await invoke(f);
    expect(refused.error).toMatchObject({ code: 3, step: 'B6',
      message: `registry locked by pid ${pid} on ${hostname()} since ${startedAt}` });
    expect(f.state.calls).toEqual([]);
    expect(readFileSync(lock).equals(before)).toBe(true);
    expect(readFileSync(f.registry).equals(registryBefore)).toBe(true);
    expect(existsSync(f.out)).toBe(false);
    const result = await invoke(f, ['--break-lock']);
    expect(result.error).toMatchObject({code:3,step:'B6'});
    expect(result.error!.message).toBe(`registry locked by pid ${pid} on ${hostname()} since ${startedAt}; stale lock ownership cannot be proven safely; stop every registry writer, verify the recorded process is gone in its namespace, then remove this lock offline`);
    expect(f.state.calls).toEqual([]); expect(existsSync(f.out)).toBe(false);
    expect(readFileSync(lock).equals(before)).toBe(true);
    expect(readFileSync(f.registry).equals(registryBefore)).toBe(true);
  }));

it.each(['same-host live', 'other-host live', 'other-host dead'] as const)(
  'CP-025/B2 %s lock survives break-lock with no LND calls or credential output', async kind => scratch(async f => {
    const pid = kind === 'other-host dead' ? deadPid() : process.pid;
    const host = kind === 'same-host live' ? hostname() : `${hostname()}-other`;
    const lock = `${f.registry}.lock`;
    writeFileSync(lock, JSON.stringify({ pid, hostname: host, startedAt }));
    const before = readFileSync(lock), registryBefore = readFileSync(f.registry);
    const result = await invoke(f, ['--break-lock']);
    expect(result.error).toMatchObject({ code: 3, step: 'B6',
      message: expect.stringContaining('offline') });
    expect(f.state.calls).toEqual([]);
    expect(readFileSync(lock).equals(before)).toBe(true);
    expect(readFileSync(f.registry).equals(registryBefore)).toBe(true);
    expect(existsSync(f.out)).toBe(false);
  }));

const fault = (transport: boolean) => new LndError(transport ? 4 : 5, transport ? 'transport' : 'lnd', 'injected adapter failure');
const cases = [
  ['success', 0, null], ['label conflict', 2, 'B8'], ['reserve failure', 3, 'B7'],
  ['GetInfo transport', 4, 'B8'], ['GetInfo LND', 5, 'B8'],
  ['ListPermissions transport', 4, 'B8'], ['ListPermissions LND', 5, 'B8'],
  ['ListIDs transport', 4, 'B10'], ['ListIDs LND', 5, 'B10'], ['sixteen collisions', 5, 'B10'],
  ['Bake transport absent', 4, 'B11'], ['Bake LND absent', 5, 'B11'],
  ['Bake response lost present', 7, 'B11'], ['Bake state unknown', 7, 'B11'],
  ['wrong root ID', 7, 'B12'], ['wrong permissions', 7, 'B12'], ['undecodable response', 7, 'B12'],
  ['final rejected', 7, 'B14'], ['final error', 7, 'B14'], ['final timeout', 7, 'B14'],
  ['partial write', 7, 'B15'], ['flush failure', 7, 'B15'], ['close failure', 7, 'B15'],
  ['registry save failure', 7, 'B16'],
] as const;
function inject(f: Fixture, name: string) {
  if (name === 'label conflict') {
    const template = JSON.parse(readFileSync(resolve('test/registry-fixtures/registry.json'), 'utf8')).entries[0];
    writeFileSync(f.registry, JSON.stringify({ schema: 1, entries: [{ ...template, nodePubkey: pubkey, label: 'Alice' }] }));
  }
  for (const [prefix, method] of [['GetInfo', 'getInfo'], ['ListPermissions', 'listPermissions'],
    ['ListIDs', 'listMacaroonIds']] as const) {
    if (name.startsWith(prefix)) {
      const original = f.lnd[method];
      f.lnd[method] = async () => { await original(); throw fault(name.endsWith('transport')); };
    }
  }
  if (name === 'sixteen collisions') f.state.ids.push('4294967296');
  if (name.startsWith('Bake ')) f.lnd.bakeMacaroon = async (_requested, id) => {
    f.state.calls.push('BakeMacaroon');
    if (name.endsWith('present')) f.state.ids.push(String(id));
    if (name.endsWith('unknown')) f.lnd.listMacaroonIds = async () => {
      f.state.calls.push('ListMacaroonIDs'); throw fault(true);
    };
    throw fault(name.includes('transport'));
  };
  if (name.startsWith('wrong ') || name === 'undecodable response') {
    const original = f.lnd.bakeMacaroon;
    f.lnd.bakeMacaroon = async (requested, id) => {
      await original(requested, id);
      return new Secret(name === 'undecodable response' ?
        readFileSync(resolve('test/vectors/negative/truncated-protobuf.macaroon')) :
        responseBytes(name === 'wrong root ID' ? '4294967399' : id,
          name === 'wrong permissions' ? ['info:read'] : requested));
    };
  }
  if (name.startsWith('final ')) f.lnd.checkMacaroon = async () => {
    f.state.calls.push('CheckMacaroonPermissions');
    if (name === 'final rejected') return { valid: false as const, reason: 'other' as const, message: 'injected verification refusal' };
    throw new LndError(5, 'lnd', 'injected verification failure');
  };
  if (name === 'registry save failure') f.deps.fs.rename = async (...args: Parameters<typeof fs.rename>) => {
    if (args[1] === f.registry && f.state.checked) throw Object.assign(new Error('injected save failure'), { code: 'EACCES' });
    return fs.rename(...args);
  };
  const original = f.deps.fs.open;
  let closeFailed = false;
  f.deps.fs.open = async (...args) => {
    if (args[0] === f.out && name === 'reserve failure') {
      expect(existsSync(`${f.registry}.lock`)).toBe(true);
      throw Object.assign(new Error('injected reserve failure'), { code: 'EACCES' });
    }
    const handle = await original(...args);
    if (args[0] !== f.out) return handle;
    return new Proxy(handle, { get(target, key) {
      const value = Reflect.get(target, key, target);
      if (name === 'partial write' && ['write', 'writeFile', 'writev'].includes(String(key))) return async () => {
        await target.write(f.state.checked!.subarray(0, 8));
        throw Object.assign(new Error('injected partial write'), { code: 'EIO' });
      };
      if (name === 'flush failure' && ['sync', 'datasync'].includes(String(key))) return async () => {
        throw Object.assign(new Error('injected flush failure'), { code: 'EIO' });
      };
      if (name === 'close failure' && key === 'close') return async () => {
        await target.close();
        if (f.state.checked! && !closeFailed) {
          closeFailed = true;
          throw Object.assign(new Error('injected close failure'), { code: 'EIO' });
        }
      };
      return typeof value === 'function' ? value.bind(target) : value;
    } });
  };
}
it.each(cases)('CP-025/B3 %s exit %i releases its acquired lock and cleans or preserves out',
  async (name, code, step) => scratch(async f => {
    inject(f, name);
    const result = await invoke(f);
    expect(result.error?.code ?? 0).toBe(code);
    expect(result.error?.step ?? null).toBe(step);
    expect(existsSync(`${f.registry}.lock`)).toBe(false);
    if (name !== 'reserve failure') {
      expect(f.state.lockAtNetwork!).toMatchObject({ pid: process.pid, hostname: hostname() });
      expect(f.state.reservedAtNetwork).toBe(true);
      expect(f.state.handle!.fd).toBe(-1);
    }
    const keep = name === 'success' || name === 'registry save failure';
    expect(existsSync(f.out)).toBe(keep);
    if (keep) {
      expect(readFileSync(f.out).equals(f.state.checked!)).toBe(true);
      expect(f.state.checked!.length).toBeGreaterThan(0);
    }
    if (name === 'registry save failure') {
      expect(entries(f)).toEqual([expect.objectContaining({ rootKeyId: f.state.ids.at(-1),
        label: 'Alice', verified: false, fingerprint: null, outPath: null })]);
      expect(result.error?.message).toMatch(/file.*valid|valid.*file/i);
      expect(result.error?.message).toContain(f.state.ids.at(-1));
    }
    if (name === 'success') expect(entries(f)).toHaveLength(1);
    if (name === 'reserve failure') expect(f.state.calls).toEqual([]);
  }));

it('CP-025/B4 concurrent child bakes share the real registry lock; loser exits before any LND call',
  async () => scratch(async (f, dir) => {
    const rows = await contend(dir);
    expect(rows.map(row => row.code).sort()).toEqual([0, 3]);
    const winner = rows.findIndex(row => row.code === 0), loser = 1 - winner;
    expect(rows[loser].calls).toEqual([]);
    expect(rows[winner].calls.filter(call => call === 'bakeMacaroon')).toHaveLength(1);
    expect(rows.every(row => row.stderr === '')).toBe(true);
    expect(JSON.parse(rows[loser].stdout).error).toMatchObject({ code: 3, step: 'B6' });
    expect(existsSync(join(dir, `child-${loser}.macaroon`))).toBe(false);
    expect(existsSync(join(dir, `child-${winner}.macaroon`))).toBe(true);
    const recorded = entries(f);
    expect(recorded).toHaveLength(1);
    expect(recorded[0]).toMatchObject({ label: winner === 0 ? 'Alice' : 'Bob', status: 'active', verified: true });
    expect(existsSync(`${f.registry}.lock`)).toBe(false);
    expect(findLeaks({ root: repo, sentinels: join(repo, 'test/sentinels.json'),
      sentinelDir: directory('MACWARDEN_SENTINEL_DIR'), testTmp: directory('MACWARDEN_TEST_TMP'),
      commandOutput: rows.map(row => row.stdout + row.stderr).join(''), paths: [dir] })).toBeNull();
  }), 30_000);

it('CP-025/B5 consecutive injected bakes reject LND, revoked and other-node registry IDs before two fresh IDs',
  async () => scratch(async (f, dir) => {
    const template = JSON.parse(readFileSync(resolve('test/registry-fixtures/registry.json'), 'utf8')).entries[1];
    const prior = [{ ...template, rootKeyId: '4294967296' },
      { ...template, nodePubkey: '03' + 'cd'.repeat(32), rootKeyId: '4294967297' }];
    writeFileSync(f.registry, JSON.stringify({ schema: 1, entries: prior }));
    f.state.ids.push('4294967298');
    entropy.draws = [4294967296n, 4294967297n, 4294967298n, 4294967299n, 4294967299n, 4294967300n];
    const before = [...f.state.ids, ...prior.map(entry => entry.rootKeyId)];
    const first = await invoke(f);
    expect(first.error).toBeNull();
    const next = fixture(dir, Secret, 'Bob', 'second.macaroon');
    next.state.ids = f.state.ids;
    const second = await invoke(next);
    expect(second.error).toBeNull();
    const fresh = [first.result!.rootKeyId, second.result!.rootKeyId] as string[];
    expect(fresh).toEqual(['4294967299', '4294967300']);
    expect(new Set(fresh).size).toBe(2);
    for (const id of fresh) {
      expect(before).not.toContain(id);
      expect(BigInt(id) >= 4294967296n && BigInt(id) <= 9223372036854775807n).toBe(true);
    }
    expect(entropy.at).toBe(6);
    expect(entries(f)).toHaveLength(4);
    expect(entries(f).slice(0, 2)).toEqual(prior);
    expect(entries(f).slice(2).map(entry => entry.permissions)).toEqual([permissions, permissions]);
    expect(existsSync(`${f.registry}.lock`)).toBe(false);
  }));

it('CP-025/leak-check unit outputs and shared registry contain no registered credential representations', () => {
  expect(findLeaks({ root: repo, sentinels: join(repo, 'test/sentinels.json'),
    sentinelDir: directory('MACWARDEN_SENTINEL_DIR'), testTmp: directory('MACWARDEN_TEST_TMP'),
    paths: [directory('MACWARDEN_TEST_TMP')] })).toBeNull();
}, 60_000);
