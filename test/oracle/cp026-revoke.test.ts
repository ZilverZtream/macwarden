import { fixtureTopology } from '../fixture/topology.mjs';
import { childEnvironment } from '../helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { Readable } from 'node:stream';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { expect, it, vi } from 'vitest';
import { Secret } from '../../src/secret.js';
import { render } from '../helpers/render-adversarial.js';
import { findLeaks } from "../helpers/leak-check.js";
import { cp024Compose } from '../fixture/cp024-fixture.mjs';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { requirePinnedFixture } from '../helpers/lnd-facts.mjs';
import { declare, directory, otherPubkey, register, template, vector } from '../helpers/cp026-revoke-support.mjs';

// Authored here for the fixture owner. This isolated preparation never runs Docker.
const repo = resolve(), targetId = '4294967326', ownId = '4294967327';
const outerTmp = () => directory('MACWARDEN_TEST_TMP');
const tmp = () => {
  const path = join(outerTmp(), 'cp026-revoke');
  mkdirSync(path, { recursive: true, mode: 0o700 });
  return path;
};
const sentinels = () => directory('MACWARDEN_SENTINEL_DIR');
type Envelope = { schema: number; command: string; ok: boolean;
  result: Record<string, unknown> | null; error: { code: number; step: string; message: string } | null };
function docker(args: string[]) {
  return spawnSync('docker', [...cp024Compose, ...args], { cwd: repo, encoding: 'utf8',
    timeout: 20_000, maxBuffer: 2_000_000 });
}
function lncli(args: string[]): Record<string, unknown> {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (result.status !== 0) throw new FixtureInvalidError(`Fixture lncli ${args[0]} unavailable`);
  try { return JSON.parse(result.stdout); }
  catch { throw new FixtureInvalidError(`Fixture lncli ${args[0]} returned invalid JSON`); }
}
function ids(): string[] {
  const observed = lncli(['listmacaroonids']).root_key_ids;
  if (!Array.isArray(observed)) throw new FixtureInvalidError('Fixture IDs unavailable');
  return observed.map(String).sort();
}
function guard() {
  const info = lncli(['getinfo']), baseline = lncli(['listmacaroonids']);
  requirePinnedFixture(info, baseline);
  const cert = join(tmpdir(), 'macwarden-fixture/tls.cert'), admin = join(tmpdir(), 'macwarden-fixture/admin.macaroon');
  if (!existsSync(cert) || !existsSync(admin)) throw new FixtureInvalidError('Workspace fixture copies unavailable');
  declare(admin); register(readFileSync(admin));
  return { info, cert, admin, before: ids() };
}
function bake(id: string, permissions: string[]) {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
    'bakemacaroon', `--root_key_id=${id}`, ...permissions]);
  if (result.status !== 0) throw new FixtureInvalidError('Fixture bake unavailable');
  const credential = result.stdout.trim();
  if (!/^(?:[0-9a-f]{2})+$/i.test(credential))
    throw new FixtureInvalidError('Fixture bake response unavailable');
  return register(Buffer.from(credential, 'hex'));
}
let serial = 0;
async function scenario(work: (f: Context) => Promise<void>) {
  const guarded = guard(), dir = mkdtempSync(join(tmp(), 'cp026-live-'));
  const remote = `/tmp/macwarden-cp026-${process.pid}-${serial++}.macaroon`;
  const registry = join(dir, 'registry.json');
  const issued: string[] = [];
  try {
    // Guarded fresh IDs only; independent probes use this run's explicit target path.
    issued.push(targetId);
    const target = bake(targetId, vector('preset-invoice-only').printed.permissions);
    issued.push(ownId);
    const own = bake(ownId, vector('default-admin').printed.permissions);
    if (docker(['cp', target, `lnd:${remote}`]).status !== 0)
      throw new FixtureInvalidError('Fixture target copy unavailable');
    const printed = lncli(['printmacaroon', `--macaroon_file=${remote}`]);
    expect(printed.root_key_id).toBe(targetId);
    expect(printed.permissions).toEqual(vector('preset-invoice-only').printed.permissions);
    const row = { ...template, nodePubkey: guarded.info.identity_pubkey, rootKeyId: targetId,
      label: 'Alice', grade: vector('preset-invoice-only').expectedGrade,
      permissions: printed.permissions, caveats: [], outPath: target,
      fingerprint: 'fp:' + createHash('sha256').update(readFileSync(target)).digest('hex').slice(0, 16) };
    writeFileSync(registry, JSON.stringify({ schema: 1, entries: [row] }), { mode: 0o600 });
    const f = { ...guarded, dir, registry, remote, target, own, row,
      calls: [] as string[], outputs: [] as string[], issued };
    probe(f); await work(f);
  } finally {
    // Inspect the complete scenario scratch before cleanup removes its artifacts.
    try { safe('', [dir]); }
    finally { cleanup(guarded.before, issued, remote, dir); }
  }
}
function cleanup(before: string[], issued: string[], remote: string, dir: string) {
  // Never delete an ID that existed at the guarded baseline, nor any unrelated ID.
  for (const id of issued) if (ids().includes(id)) {
    if (before.includes(id) || id === '0') throw new FixtureInvalidError('Unsafe fixture cleanup');
    if (lncli(['deletemacaroonid', id]).deleted !== true) throw new FixtureInvalidError('Fixture cleanup failed');
  }
  if (docker(['exec', '-T', 'lnd', 'rm', '-f', remote]).status !== 0)
    throw new FixtureInvalidError('Fixture target cleanup failed');
  rmSync(dir, { recursive: true, force: true });
  requirePinnedFixture(lncli(['getinfo']), lncli(['listmacaroonids']));
}
type Context = ReturnType<typeof guard> & { dir: string; registry: string; remote: string;
  target: string; own: string; row: Record<string, unknown>; calls: string[]; outputs: string[]; issued: string[] };
function probe(f: Context) {
  const result = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest',
    `--macaroonpath=${f.remote}`, 'getinfo']);
  if (result.error) throw new FixtureInvalidError('Independent acceptance probe unavailable');
  expect(result.status, 'independent lncli still accepts the target').toBe(0);
  safe(result.stdout + result.stderr, [f.dir]);
}
function safe(output: string, paths: string[]) {
  expect(findLeaks({ root: repo, sentinels: join(repo, 'test/sentinels.json'),
    sentinelDir: sentinels(), testTmp: outerTmp(), commandOutput: output, paths })).toBeNull();
}
function save(f: Context, entries: Array<Record<string, unknown>>) {
  writeFileSync(f.registry, JSON.stringify({ schema: 1, entries }), { mode: 0o600 });
}
async function invoke(f: Context, options: { target?: string; flags?: string[]; own?: string; cert?: string;
  rest?: string; env?: Record<string, string>; answer?: string | null; tty?: boolean } = {}) {
  const commandPath = '../../src/commands/revoke.js', adapterPath = '../../src/lnd/index.js';
  const command = await import(/* @vite-ignore */ commandPath) as { run(args: string[], deps: unknown): Promise<Envelope> };
  const module = await import(/* @vite-ignore */ adapterPath);
  const adapter = module.createLndAdapter({ restUrl: `https://${options.rest ?? `localhost:${fixtureTopology().restPort}`}`,
    tlsCert: readFileSync(options.cert && existsSync(options.cert) ? options.cert : f.cert),
    macaroon: new Secret(readFileSync(f.own)) });
  const lnd = new Proxy(adapter, { get(target, key) {
    const value = Reflect.get(target, key, target);
    if (key === 'listMacaroonIds' && typeof value !== 'function') return async () => {
      f.calls.push(String(key)); return { root_key_ids: (await target.listMacaroonIds()).map(String) };
    };
    if (typeof value !== 'function') return value;
    return async (...args: unknown[]) => { f.calls.push(String(key)); return value.apply(target, args); };
  } });
  const before = ids(), bytes = readFileSync(f.registry), mtime = statSync(f.registry).mtimeMs;
  const targetBefore = readFileSync(f.target);
  const prompt = Object.assign(vi.fn(async (question: string) => {
    expect(existsSync(`${f.registry}.lock`)).toBe(false);
    f.outputs.push(question); return options.answer === undefined ? 'wrong' : options.answer;
  }), { isTTY: options.tty !== false });
  const stdin = Object.assign(Readable.from([`${options.answer ?? 'wrong'}\n`]), { isTTY: options.tty !== false });
  const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(((value: unknown) => {
    f.outputs.push(String(value)); return true;
  }) as typeof process.stdout.write);
  const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(((value: unknown) => {
    f.outputs.push(String(value)); return true;
  }) as typeof process.stderr.write);
  let result: Envelope;
  try {
    result = await command.run([options.target ?? 'Alice', '--registry', f.registry,
      '--lnd-rest', options.rest ?? `localhost:${fixtureTopology().restPort}`, '--tls-cert', options.cert ?? f.cert,
      '--macaroon', options.own ?? f.own, '--json', ...(options.flags ?? [])],
    { lnd, fs: { ...fs }, clock: () => new Date('2026-10-05T00:00:00Z'),
      env: options.env ?? {}, prompt, stdin,
      stdout: { write: (value: string) => { f.outputs.push(value); return true; } } });
  } finally { stdout.mockRestore(); stderr.mockRestore(); }
  expect(ids()).toEqual(before);
  expect(readFileSync(f.registry).equals(bytes)).toBe(true);
  expect(statSync(f.registry).mtimeMs).toBe(mtime);
  expect(readFileSync(f.target).equals(targetBefore)).toBe(true);
  expect(existsSync(`${f.registry}.lock`)).toBe(false);
  expect(f.calls.some(call => /delete|bake/i.test(call))).toBe(false);
  probe(f);
  safe(f.outputs.join('') + render(result, 'text') + render(result, 'json'), [f.dir]);
  return { result, prompt };
}
const refusals = [
  ['V1', 'zero', 2], ['V1', 'leading zero', 2], ['V1', 'negative', 2], ['V1', 'plus', 2],
  ['V1', 'hex', 2], ['V1', 'overflow', 2], ['V1', 'invalid label', 2],
  ['V2', 'NODE_DEBUG', 2], ['V2', 'NODE_OPTIONS', 2],
  ['V3', 'unreadable target', 3], ['V3', 'undecodable target', 3],
  ['V3', 'zero target', 2], ['V3', 'numeric target mismatch', 2],
  ['V4', 'unreadable cert', 4], ['V4', 'unreadable own', 4], ['V4', 'undecodable own', 4],
  ['V4', 'missing own permission', 4], ['V4', 'numeric own ID', 2],
  ['V5', 'unreachable', 4], ['V5', 'wrong TLS', 4],
  ['V6', 'invalid registry', 3], ['V6', 'absent label', 2], ['V6', 'revoked label', 2],
  ['V6', 'ambiguous label', 2], ['V6', 'other node', 2], ['V6', 'unregistered', 2],
  ['V6', 'label own ID', 2], ['V6', 'explicit mismatch', 2], ['V6', 'wrong default ID', 3],
] as const;
it.each(refusals)('CP-026/refusal-state-unchanged %s %s preserves independent live IDs, target acceptance and registry bytes',
  async (step, kind, code) => scenario(async f => {
    const options: Parameters<typeof invoke>[1] = { flags: [] };
    const badTargets: Record<string, string> = { zero: '0', 'leading zero': '007', negative: '-1',
      plus: '+5', hex: '0x10', overflow: '18446744073709551616', 'invalid label': 'bad label' };
    if (step === 'V1') options.target = badTargets[kind];
    if (kind === 'NODE_DEBUG') options.env = { NODE_DEBUG: 'https' };
    if (kind === 'NODE_OPTIONS') options.env = { NODE_OPTIONS: '--report-on-fatalerror' };
    if (kind === 'unreadable target') options.flags!.push('--target-file', join(f.dir, 'absent.macaroon'));
    if (kind === 'undecodable target') options.flags!.push('--target-file', resolve('test/vectors/negative/truncated-protobuf.macaroon'));
    if (kind === 'zero target') options.flags!.push('--target-file', f.admin);
    if (kind === 'numeric target mismatch') { options.target = targetId; options.flags!.push('--target-file', f.own); }
    if (kind === 'unreadable cert') options.cert = join(f.dir, 'absent.cert');
    if (kind === 'unreadable own') options.own = join(f.dir, 'absent.macaroon');
    if (kind === 'undecodable own') options.own = resolve('test/vectors/negative/truncated-protobuf.macaroon');
    if (kind === 'missing own permission') options.own = f.target;
    if (kind === 'numeric own ID') options.target = ownId;
    if (kind === 'unreachable') options.rest = '127.0.0.1:1';
    if (kind === 'wrong TLS') options.cert = resolve('test/fixture/cp016-wrong-ca.crt');
    if (kind === 'invalid registry') writeFileSync(f.registry, '{invalid');
    if (kind === 'absent label' || kind === 'unregistered') save(f, []);
    if (kind === 'revoked label') save(f, [{ ...f.row, status: 'revoked', revokedAt: '2026-10-04T00:00:00Z', revokeEvidence: 'by-id-only' }]);
    if (kind === 'ambiguous label') save(f, [f.row, { ...f.row, rootKeyId: ownId, outPath: null, replaces: f.row.rootKeyId }]);
    // SPEC 5 V6 changed in 1.1.1 (RL-04): with --unregistered this node's ID is revoked; without it the refusal stays.
    if (kind === 'other node') { save(f, [{ ...f.row, nodePubkey: otherPubkey }]); options.target = targetId; }
    if (kind === 'unregistered') options.target = targetId;
    if (kind === 'label own ID') save(f, [{ ...f.row, rootKeyId: ownId, outPath: f.own }]);
    if (kind === 'explicit mismatch') options.flags!.push('--target-file', f.own);
    // SPEC 5 V6 changed in 1.1.1 (RL-01): a default file on another root key ID is refused only when it
    // carries the entry's fingerprint (an edited entry); another credential at a reused path is proven by ID.
    if (kind === 'wrong default ID') save(f, [{ ...f.row, outPath: f.own,
      fingerprint: 'fp:' + createHash('sha256').update(readFileSync(f.own)).digest('hex').slice(0, 16) }]);
    const { result } = await invoke(f, options);
    expect(result.error).toMatchObject({ code, step });
    if (['V1', 'V2', 'V3', 'V4'].includes(step)) expect(f.calls).toEqual([]);
    if (step === 'V6') expect(f.calls).toEqual(['getInfo', 'listPermissions']);
  }), 60_000);
it.each(['registered dry-run', 'unregistered dry-run', 'missing file dry-run', 'fingerprint mismatch dry-run',
  'wrong text', 'EOF', 'non-TTY']) (
  'CP-026/refusal-state-unchanged %s preserves the live key and never locks before input', async kind => scenario(async f => {
    const options: Parameters<typeof invoke>[1] = {};
    if (kind.endsWith('dry-run')) options.flags = ['--dry-run'];
    if (kind === 'unregistered dry-run') { save(f, []); options.flags!.push('--unregistered'); options.target = targetId; }
    if (kind === 'missing file dry-run') save(f, [{ ...f.row, outPath: join(f.dir, 'missing.macaroon') }]);
    if (kind === 'fingerprint mismatch dry-run') save(f, [{ ...f.row, fingerprint: 'fp:0000000000000000' }]);
    if (kind === 'EOF') options.answer = null;
    if (kind === 'non-TTY') options.tty = false;
    const { result, prompt } = await invoke(f, options);
    if (kind.endsWith('dry-run')) {
      expect(result.error).toBeNull();
      expect(result.result).toMatchObject({ dryRun: true, rootKeyId: targetId,
        label: kind === 'unregistered dry-run' ? null : 'Alice',
        grade: kind === 'unregistered dry-run' ? null : 'RECEIVE',
        proof: kind === 'registered dry-run' ? 'rejected' : 'by-id-only' });
      expect(prompt).not.toHaveBeenCalled();
    } else {
      expect(result.error).toMatchObject({ code: 6, step: 'V9' });
      if (kind !== 'non-TTY') {
        expect(prompt).toHaveBeenCalledTimes(1);
        for (const value of ['Alice', targetId, 'RECEIVE']) expect(f.outputs.join('')).toContain(value);
      } else expect(prompt).not.toHaveBeenCalled();
    }
  }), 60_000);
it('CP-026/refusal-state-unchanged CLI non-TTY confirmation exits six with one safe JSON document',
  async () => scenario(async f => {
    const before = ids(), bytes = readFileSync(f.registry);
    const env = childEnvironment(); delete env.NODE_DEBUG; delete env.NODE_OPTIONS;
    const result = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'revoke', 'Alice',
      '--registry', f.registry, '--lnd-rest', `localhost:${fixtureTopology().restPort}`, '--tls-cert', f.cert,
      '--macaroon', f.own, '--json'], { cwd: repo, env, encoding: 'utf8', timeout: 20_000 });
    expect(result.error).toBeUndefined(); expect(result.status).toBe(6);
    expect(JSON.parse(result.stdout)).toMatchObject({ schema: 1, command: 'revoke', ok: false,
      error: { code: 6, step: 'V9' } });
    expect(result.stderr).toBe('');
    expect(ids()).toEqual(before); expect(readFileSync(f.registry).equals(bytes)).toBe(true);
    expect(existsSync(`${f.registry}.lock`)).toBe(false); probe(f);
    safe(result.stdout + result.stderr, [f.dir]);
  }), 60_000);
it('CP-026/leak-check standing sentinel scan covers revoke output artifacts and registry files', () => {
  safe('', [tmp()]);
}, 60_000);
