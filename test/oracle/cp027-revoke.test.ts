import { fixtureTopology } from '../fixture/topology.mjs';
import { childEnvironment } from '../helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { Readable } from 'node:stream';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';
import { Secret } from '../../src/secret.js';
import { render } from '../helpers/render-adversarial.js';
import { findLeaks } from "../helpers/leak-check.js";
import { cp024Compose } from '../fixture/cp024-fixture.mjs';
import { FixtureInvalidError } from '../helpers/fixture-invalid.mjs';
import { classifyAcceptance, requirePinnedFixture } from '../helpers/lnd-facts.mjs';
import { declare, directory, otherPubkey, register, template, vector } from '../helpers/cp026-revoke-support.mjs';
import { scope, type Envelope } from '../helpers/cp027-revoke-support.js';

// Runs against the shared regtest fixture (npm run fixture:up).
const repo = resolve(), targetId = '4294967336', otherId = '4294967337', ownId = '4294967338';
const outerTmp = () => directory('MACWARDEN_TEST_TMP');
const tmp = () => {
  const path = join(outerTmp(), 'cp027-revoke');
  mkdirSync(path, { recursive: true, mode: 0o700 });
  return path;
};
let serial = 0;
function docker(args: string[]) {
  return spawnSync('docker', [...cp024Compose, ...args], { cwd: repo, encoding: 'utf8', timeout: 20_000, maxBuffer: 2_000_000 });
}
function lncli(args: string[]): Record<string, unknown> {
  const observed = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', ...args]);
  if (observed.status !== 0) throw new FixtureInvalidError(`Fixture lncli ${args[0]} unavailable`);
  try { return JSON.parse(observed.stdout); } catch { throw new FixtureInvalidError('Fixture returned invalid JSON'); }
}
function ids() {
  const value = lncli(['listmacaroonids']).root_key_ids;
  if (!Array.isArray(value)) throw new FixtureInvalidError('Fixture ID state unavailable');
  return value.map(String).sort();
}
function bake(id: string, permissions: string[]) {
  const observed = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', 'bakemacaroon', `--root_key_id=${id}`, ...permissions]);
  if (observed.error || observed.signal || observed.status !== 0) throw new FixtureInvalidError('Fixture bake unavailable');
  const value = observed.stdout.trim();
  if (!/^(?:[0-9a-f]{2})+$/i.test(value)) throw new FixtureInvalidError('Fixture bake returned invalid credential text');
  return register(Buffer.from(value, 'hex'));
}
function copy(path: string, remote: string) {
  if (docker(['cp', path, `lnd:${remote}`]).status !== 0) throw new FixtureInvalidError('Fixture credential copy unavailable');
}
function probe(remote: string, expected: 'accepted' | 'rejected') {
  const observed = docker(['exec', '-T', 'lnd', 'lncli', '--network=regtest', `--macaroonpath=${remote}`, 'getinfo']);
  if (observed.error || observed.signal || observed.status === null) throw new FixtureInvalidError('Independent lncli probe unavailable');
  expect(classifyAcceptance(observed)).toBe(expected);
  if (expected === 'rejected') expect(observed.stderr).toContain(`root key with id ${targetId} doesn't exist`);
  safe(observed.stdout + observed.stderr, []);
}
function safe(output: string, paths: string[]) {
  expect(findLeaks({ root: repo, sentinels: join(repo, 'test/sentinels.json'), sentinelDir: directory('MACWARDEN_SENTINEL_DIR'),
    testTmp: outerTmp(), commandOutput: output, paths })).toBeNull();
}
function fingerprint(path: string) { return 'fp:' + createHash('sha256').update(readFileSync(path)).digest('hex').slice(0, 16); }
async function scenario(work: (f: Context) => Promise<void>) {
  const info = lncli(['getinfo']); requirePinnedFixture(info, lncli(['listmacaroonids']));
  const fixtureDir = join(tmpdir(), 'macwarden-fixture');
  const cert = join(fixtureDir, 'tls.cert'), admin = join(fixtureDir, 'admin.macaroon');
  if (!existsSync(cert) || !existsSync(admin)) throw new FixtureInvalidError('Harness fixture copies unavailable');
  declare(admin); register(readFileSync(admin));
  const before = ids(), dir = mkdtempSync(join(tmp(), 'cp027-live-')), issued: string[] = [], remotes: string[] = [];
  try {
    issued.push(targetId); const target = bake(targetId, vector('preset-invoice-only').printed.permissions);
    issued.push(otherId); const other = bake(otherId, vector('preset-invoice-only').printed.permissions);
    issued.push(ownId); const own = bake(ownId, vector('default-admin').printed.permissions);
    const remote = `/tmp/macwarden-cp027-${process.pid}-${serial++}.macaroon`;
    const otherRemote = `/tmp/macwarden-cp027-${process.pid}-${serial++}.macaroon`;
    remotes.push(remote, otherRemote); copy(target, remote); copy(other, otherRemote);
    const printed = lncli(['printmacaroon', `--macaroon_file=${remote}`]);
    expect(printed.root_key_id).toBe(targetId); expect(printed.permissions).toEqual(vector('preset-invoice-only').printed.permissions);
    const row = { ...template, nodePubkey: info.identity_pubkey, label: 'Alice', rootKeyId: targetId,
      grade: vector('preset-invoice-only').expectedGrade, permissions: printed.permissions,
      caveats: [], fingerprint: fingerprint(target), outPath: target };
    const otherRow = { ...row, label: 'Bob', rootKeyId: otherId, fingerprint: fingerprint(other), outPath: other };
    const registry = join(dir, 'registry.json');
    writeFileSync(registry, JSON.stringify({ schema: 1, entries: [row, otherRow] }), { mode: 0o600 });
    const f = { info, cert, own, target, other, remote, otherRemote, registry, dir, row, otherRow, calls: [] as string[], outputs: [] as string[] };
    probe(remote, 'accepted'); probe(otherRemote, 'accepted'); await work(f);
  } finally {
    // Inspect the complete scenario scratch before cleanup removes its artifacts.
    try { safe('', [dir]); }
    finally { cleanup(before, issued, remotes, dir); }
  }
}
function cleanup(before: string[], issued: string[], remotes: string[], dir: string) {
  for (const id of issued) if (ids().includes(id)) {
    if (id === '0' || before.includes(id)) throw new FixtureInvalidError('Unsafe fixture cleanup');
    if (lncli(['deletemacaroonid', id]).deleted !== true) throw new FixtureInvalidError('Fixture cleanup failed');
  }
  for (const remote of remotes) if (docker(['exec', '-T', 'lnd', 'rm', '-f', remote]).status !== 0)
    throw new FixtureInvalidError('Fixture remote cleanup failed');
  rmSync(dir, { recursive: true, force: true });
  requirePinnedFixture(lncli(['getinfo']), lncli(['listmacaroonids']));
}
type Context = { info: Record<string, unknown>; cert: string; own: string; target: string; other: string;
  remote: string; otherRemote: string; registry: string; dir: string; row: Record<string, unknown>;
  otherRow: Record<string, unknown>; calls: string[]; outputs: string[] };
async function invoke(f: Context, flags = ['--yes'], target = 'Alice', answer: string | null = 'Alice',
  afterDelete?: () => void) {
  const commandPath = '../../src/commands/revoke.js', adapterPath = '../../src/lnd/index.js';
  const command = await import(/* @vite-ignore */ commandPath) as { run(args: string[], deps: unknown): Promise<Envelope> };
  const module = await import(/* @vite-ignore */ adapterPath);
  const adapter = module.createLndAdapter({ restUrl: `https://localhost:${fixtureTopology().restPort}`, tlsCert: readFileSync(f.cert), macaroon: new Secret(readFileSync(f.own)) });
  const lnd = new Proxy(adapter, { get(target, key) {
    const value = Reflect.get(target, key, target);
    if (key === 'listMacaroonIds' && typeof value !== 'function') return async () => {
      f.calls.push('listMacaroonIds'); return { root_key_ids: (await target.listMacaroonIds()).map(String) };
    };
    if (typeof value !== 'function') return value;
    return async (...args: unknown[]) => {
      f.calls.push(String(key)); const observed = await value.apply(target, args);
      if (key === 'deleteMacaroonId') afterDelete?.(); return observed;
    };
  } });
  const prompt = Object.assign(vi.fn(async (question: string) => {
    expect(existsSync(`${f.registry}.lock`)).toBe(false); f.outputs.push(question); return answer;
  }), { isTTY: true });
  const stdin = Object.assign(Readable.from([`${answer ?? ''}\n`]), { isTTY: true });
  const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(((value: unknown) => {
    f.outputs.push(String(value)); return true;
  }) as typeof process.stdout.write);
  const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(((value: unknown) => {
    f.outputs.push(String(value)); return true;
  }) as typeof process.stderr.write);
  let result: Envelope;
  try { result = await command.run([target, '--registry', f.registry, '--lnd-rest', `localhost:${fixtureTopology().restPort}`, '--tls-cert', f.cert,
    '--macaroon', f.own, '--json', ...flags], { lnd, fs: { ...fs }, env: {}, clock: () => new Date('2026-10-05T00:00:00Z'),
    prompt, stdin, stdout: { write: (value: string) => { f.outputs.push(value); return true; } } }); }
  finally { stdout.mockRestore(); stderr.mockRestore(); }
  expect(existsSync(`${f.registry}.lock`)).toBe(false);
  safe(f.outputs.join('') + render(result, 'text') + render(result, 'json'), [f.dir]);
  return result;
}
function records(f: Context) { return JSON.parse(readFileSync(f.registry, 'utf8')).entries as Array<Record<string, unknown>>; }
function verify(f: Context, result: Envelope, evidence: string, repaired = false, label: string | null = 'Alice',
  processInterval?: { start: number; end: number }) {
  expect(result.error).toBeNull(); expect(result.result).toMatchObject({ rootKeyId: targetId, label, evidence, repaired });
  expect(ids()).not.toContain(targetId); expect(ids()).toContain(otherId);
  probe(f.remote, 'rejected'); probe(f.otherRemote, 'accepted');
  expect(records(f)).toContainEqual(result.result!.entry);
  expect(result.result!.entry).toMatchObject({ rootKeyId: targetId, nodePubkey: f.info.identity_pubkey,
    label, status: 'revoked', revokedAt: expect.any(String), revokeEvidence: evidence });
  const revokedAt = Date.parse(String((result.result!.entry as Record<string, unknown>).revokedAt));
  if (processInterval) {
    expect(revokedAt).toBeGreaterThanOrEqual(processInterval.start);
    expect(revokedAt).toBeLessThanOrEqual(processInterval.end);
  } else expect(revokedAt).toBe(Date.parse('2026-10-05T00:00:00Z'));
  expect(records(f)).toContainEqual(f.otherRow);
  expect(render(result, 'text').trimEnd().endsWith(scope)).toBe(true);
}
it('CP-027/revoke-live-state label deletion rejects its credential while another ID remains accepted', async () => scenario(async f => {
  verify(f, await invoke(f), 'rejected');
  expect(f.calls).toEqual(['getInfo', 'listPermissions', 'listMacaroonIds', 'checkMacaroon', 'deleteMacaroonId', 'listMacaroonIds', 'checkMacaroon']);
}), 120_000);
it.each(['missing file', 'fingerprint mismatch'])('CP-027/revoke-live-state %s proves absence by ID only with independent rejection',
  async kind => scenario(async f => {
    if (kind === 'missing file') f.row.outPath = join(f.dir, 'missing.macaroon');
    else f.row.fingerprint = 'fp:0000000000000000';
    writeFileSync(f.registry, JSON.stringify({ schema: 1, entries: [f.row, f.otherRow] }));
    const result = await invoke(f); verify(f, result, 'by-id-only');
    expect(render(result, 'text')).toContain('ID absent from LND (verified by ID only)');
    expect(f.calls.filter(call => call === 'checkMacaroon')).toEqual([]);
  }), 120_000);
it('CP-027/revoke-repair-live lncli deletion allows dry-run and decline before confirmed record-only repair', async () => scenario(async f => {
  expect(lncli(['deletemacaroonid', targetId]).deleted).toBe(true);
  expect(ids()).not.toContain(targetId); probe(f.remote, 'rejected'); probe(f.otherRemote, 'accepted');
  const before = ids(), bytes = readFileSync(f.registry);
  const dry = await invoke(f, ['--dry-run']);
  expect(dry.error).toBeNull(); expect(dry.result).toMatchObject({ dryRun: true, rootKeyId: targetId, proof: 'by-id-only' });
  expect(readFileSync(f.registry).equals(bytes)).toBe(true); expect(ids()).toEqual(before);
  expect(f.calls).toEqual(['getInfo', 'listPermissions', 'listMacaroonIds']); f.calls.length = 0;
  expect((await invoke(f, [], 'Alice', 'wrong')).error).toMatchObject({ code: 6, step: 'V9' });
  expect(readFileSync(f.registry).equals(bytes)).toBe(true); expect(ids()).toEqual(before);
  expect(f.calls).toEqual(['getInfo', 'listPermissions', 'listMacaroonIds']); f.calls.length = 0;
  const repaired = await invoke(f, []); verify(f, repaired, 'by-id-only', true);
  expect(render(repaired, 'text')).toMatch(/already absent/i);
  expect(f.calls).toEqual(['getInfo', 'listPermissions', 'listMacaroonIds']); expect(ids()).toEqual(before);
}), 120_000);
it('CP-027/revoke-live-state unregistered lncli-issued ID gains null-label record and preserves foreign-node entry', async () => scenario(async f => {
  const foreign = { ...f.otherRow, nodePubkey: otherPubkey, label: 'Foreign' };
  writeFileSync(f.registry, JSON.stringify({ schema: 1, entries: [f.otherRow, foreign] }));
  verify(f, await invoke(f, ['--unregistered', '--yes'], targetId), 'by-id-only', false, null);
  expect(records(f)).toContainEqual(foreign);
  expect(f.calls).toEqual(['getInfo', 'listPermissions', 'listMacaroonIds', 'deleteMacaroonId', 'listMacaroonIds']);
}), 120_000);
it('CP-027/revoke-live-state CLI renders one JSON document and exact text scope for independent live deletion', async () => scenario(async f => {
  const env = childEnvironment(); delete env.NODE_DEBUG; delete env.NODE_OPTIONS;
  const start = Date.now();
  const command = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'revoke', 'Alice', '--yes', '--json',
    '--registry', f.registry, '--lnd-rest', `localhost:${fixtureTopology().restPort}`, '--tls-cert', f.cert, '--macaroon', f.own],
  { cwd: repo, env, encoding: 'utf8', timeout: 20_000 });
  const end = Date.now();
  expect(command.error).toBeUndefined(); expect(command.status).toBe(0); expect(command.stderr).toBe('');
  safe(command.stdout + command.stderr, [f.dir]); verify(f, JSON.parse(command.stdout), 'rejected', false, 'Alice', { start, end });
}), 120_000);
it('CP-027/revoke-live-state real container pause after deletion makes proof uncertain and rerun repairs observed absence',
  async () => scenario(async f => {
    const before = readFileSync(f.registry);
    let paused = false, result: Envelope;
    try {
      result = await invoke(f, ['--yes'], 'Alice', 'Alice', () => {
        if (docker(['pause', 'lnd']).status !== 0) throw new FixtureInvalidError('Fixture pause unavailable');
        paused = true;
      });
    } finally { if (paused) unpause(); }
    expect(result!.error).toMatchObject({ code: 7, step: 'V12' });
    expect(result!.error!.message).toContain('LND state unknown'); expect(result!.error!.message).toContain('macwarden inventory');
    expect(readFileSync(f.registry).equals(before)).toBe(true);
    expect(f.calls).toEqual(['getInfo', 'listPermissions', 'listMacaroonIds', 'checkMacaroon', 'deleteMacaroonId', 'listMacaroonIds']);
    expect(ids()).not.toContain(targetId); probe(f.remote, 'rejected'); probe(f.otherRemote, 'accepted');
    f.calls.length = 0; verify(f, await invoke(f), 'by-id-only', true);
    expect(f.calls).toEqual(['getInfo', 'listPermissions', 'listMacaroonIds']);
  }), 120_000);
function unpause() {
  if (docker(['unpause', 'lnd']).status !== 0) throw new FixtureInvalidError('Fixture unpause failed');
}
it('CP-027/revoke-live-state adapter refuses root zero and preserves independently observed fixture state', async () => scenario(async f => {
  const adapterPath = '../../src/lnd/index.js', module = await import(/* @vite-ignore */ adapterPath);
  const adapter = module.createLndAdapter({ restUrl: `https://localhost:${fixtureTopology().restPort}`, tlsCert: readFileSync(f.cert), macaroon: new Secret(readFileSync(f.own)) });
  const before = ids(), registry = readFileSync(f.registry);
  await expect(adapter.deleteMacaroonId(0n)).rejects.toBeDefined();
  expect(ids()).toEqual(before); expect(readFileSync(f.registry).equals(registry)).toBe(true);
  probe(f.remote, 'accepted'); probe(f.otherRemote, 'accepted');
}), 120_000);
it('CP-027/leak-check standing sentinel scan covers all temporary outputs and registry artifacts', () => {
  safe('', [tmp()]);
}, 60_000);
