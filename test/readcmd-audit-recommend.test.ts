// Pre-1.4 audit (READCMD): recommend keeps the credential's restrictions, never narrows a
// canary, reports incomplete usage without records, prints a revoke that revoke accepts,
// and ignores methods that were only ever refused.
import * as fs from 'node:fs/promises';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { narrowLabel, remainingDuration, run as recommend } from '../src/commands/recommend.js';
import { macaroonId } from '../src/decode/index.js';
import { Secret } from '../src/secret.js';
import { shellQuote } from '../src/online.js';
import { expectSchemaValid } from './helpers/output-schema.js';

const repo = resolve();
const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
const PUBKEY = `02${'ab'.repeat(32)}`;
const snapshot = JSON.parse(readFileSync(join(repo, 'src/grade/lnd-permissions.json'), 'utf8')) as { methods: Record<string, string[]> };
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

const coverage = { nodePubkey: PUBKEY, firstStart: '2026-09-30T00:00:00.000Z', lastEnd: '2026-10-08T12:00:00.000Z',
  coveredSeconds: 8 * 86_400, sessions: 3 };
type Entry = Record<string, unknown>;
const entry = (label: string, rootKeyId: string, permissions: string[], changes: Entry = {}): Entry => ({ nodePubkey: PUBKEY, label,
  rootKeyId, permissions, caveats: [], grade: 'READ', fingerprint: 'fp:0123456789abcdef', outPath: null, createdAt: '2026-09-30T00:00:00Z',
  verified: true, status: 'active', revokedAt: null, revokeEvidence: null, replaces: null, replacedBy: null, ...changes });
const record = (rootKeyId: string, method: string, calls: number, changes: Entry = {}) => ({ nodePubkey: PUBKEY,
  credential: 'id:1111111111111111', rootKeyId, method, calls, errors: 0, firstSeen: '2026-10-08T09:00:00Z',
  lastSeen: '2026-10-08T10:00:00Z', ...changes });

function setup(entries: Entry[], records: Entry[], file: Entry = {}) {
  mkdirSync(tmpRoot, { recursive: true });
  const dir = mkdtempSync(join(tmpRoot, 'readcmd-recommend-'));
  dirs.push(dir);
  const registry = join(dir, 'registry.json');
  writeFileSync(registry, JSON.stringify({ schema: 1, entries }));
  writeFileSync(`${registry}.usage.json`, JSON.stringify({ schema: 1, dropped: 0, coverage: [coverage], entries: records, ...file }));
  writeFileSync(join(dir, 'tls.cert'), 'unused');
  writeFileSync(join(dir, 'own.macaroon'), readFileSync(join(repo, 'test/vectors/default-admin.macaroon')));
  const deps = { lnd: { getInfo: async () => ({ pubkey: PUBKEY, alias: 'a', network: 'regtest', version: 'v' }),
    listPermissions: async () => snapshot.methods } as never, fs, env: {}, clock: () => new Date(NOW) };
  const args = ['--lnd-rest', 'localhost:18080', '--tls-cert', join(dir, 'tls.cert'), '--macaroon', join(dir, 'own.macaroon'),
    '--registry', registry, '--json'];
  return async (...selector: string[]) => {
    const output = await recommend([...selector, ...args], deps);
    expectSchemaValid(output);
    expect(output.error).toBeNull();
    const result = output.result as { commands: string[]; observed: { method: string; lastUsed: string }[]; recommendedUris: string[] };
    return { result, codes: output.warnings.map(item => typeof item === 'string' ? item : item.code), warnings: output.warnings };
  };
}

const READ = ['info:read', 'offchain:read'];
/** The injected clock: the expiry checks measure the original's remaining lifetime from it. */
const NOW = '2026-10-08T12:00:00Z';
const getInfo = (rootKeyId = '4294967341') => record(rootKeyId, '/lnrpc.Lightning/GetInfo', 3);

it('READCMD-01 an expiry baked with a duration is carried into the narrowing command as --expires', async () => {
  const run = setup([entry('app', '4294967341', READ,
    { caveats: [{ type: 'time-before', value: '2027-06-01T00:00:00Z', requested: '90d' }] })], [getInfo()]);
  const { result, codes } = await run('app');
  expect(codes).not.toContain('recommendation-caveats');
  expect(result.commands[0]).toContain(` --uri ${shellQuote('/lnrpc.Lightning/GetInfo')} --expires 90d --out <file> `);
});

it('READCMD-01 an IP lock, an expiry without a recorded duration or a third-party caveat withholds the command', async () => {
  for (const caveats of [[{ type: 'ipaddr', value: '10.0.0.5' }], [{ type: 'time-before', value: '2026-12-29T00:00:00Z' }],
    [{ type: 'time-before', value: '2026-12-29T00:00:00Z', requested: '90d' }, { type: 'iprange', value: '10.0.0.0/8' }],
    [{ type: 'third-party', value: 'https://auth.example' }], [{ type: 'unknown', value: 'condition x' }]]) {
    const run = setup([entry('app', '4294967341', READ, { caveats })], [getInfo()]);
    const { result, codes, warnings } = await run('app');
    expect(result.commands).toEqual([]);
    expect(codes).toContain('recommendation-caveats');
    const message = (warnings.find(item => typeof item !== 'string' && item.code === 'recommendation-caveats') as { message: string }).message;
    for (const caveat of caveats) if (caveat.type !== 'time-before' || !('requested' in caveat)) expect(message).toContain(caveat.type);
  }
});

it('READCMD-03 usage-incomplete is raised even when no record remains for the credential', async () => {
  const run = setup([entry('app', '4294967341', READ)], [], { evictions: 1, lastEviction: '2026-10-08T09:30:00Z' });
  const { result, codes } = await run('app');
  expect(result.commands).toEqual([]);
  expect(codes).toContain('usage-incomplete');
  const dropped = setup([entry('app', '4294967341', READ)], [], { droppedAttributions: 2, lastAttributionDrop: '2026-10-08T09:30:00.000Z' });
  expect((await dropped('app')).codes).toContain('usage-incomplete');
});

it('READCMD-04 while a rotation is staged the revoke step names the root key ID, which revoke accepts', async () => {
  const run = setup([entry('app', '4294967341', READ), entry('app', '4294967342', READ, { replaces: '4294967341' })], [getInfo()]);
  const { result } = await run('4294967341');
  expect(result.commands[1]).toMatch(/^macwarden revoke 4294967341 --lnd-rest /);
  const single = setup([entry('app', '4294967341', READ)], [getInfo()]);
  expect((await single('app')).result.commands[1]).toMatch(/^macwarden revoke app --lnd-rest /);
});

it('READCMD-04 the suggested label never equals the original or another active label', async () => {
  const long = `${'a'.repeat(57)}-narrow`;
  expect(long).toHaveLength(64);
  expect(narrowLabel(long)).not.toBe(long);
  expect(narrowLabel(long)).toMatch(/^[A-Za-z][A-Za-z0-9._-]{0,63}$/);
  expect(narrowLabel('app', new Set(['app-narrow']))).toBe('app-narrow2');
  const run = setup([entry('app', '4294967341', READ), entry('app-narrow', '4294967342', READ)], [getInfo()]);
  expect((await run('app')).result.commands[0]).toMatch(/^macwarden bake --label app-narrow2 /);
});

it('READCMD-05 a canary is never narrowed: a custom caveat or recorded denied uses withhold the command', async () => {
  const custom = setup([entry('bait', '4294967341', READ, { caveats: [{ type: 'lnd-custom', value: 'macwarden-canary 1' }] })], [getInfo()]);
  const first = await custom('bait');
  expect(first.result.commands).toEqual([]);
  expect(first.codes).toContain('canary-not-narrowed');
  const used = setup([entry('bait', '4294967341', READ)], [getInfo()], { canaryUses: [{ nodePubkey: PUBKEY, rootKeyId: '4294967341',
    uses: 2, firstUse: '2026-10-08T09:00:00Z', lastUse: '2026-10-08T10:00:00Z' }] });
  const second = await used('bait');
  expect(second.result.commands).toEqual([]);
  expect(second.codes).toContain('canary-not-narrowed');
});

it('READCMD-10 a method only ever refused is left out instead of blocking the recommendation as broader', async () => {
  const run = setup([entry('app', '4294967341', READ)], [getInfo(),
    record('4294967341', '/routerrpc.Router/SendPaymentV2', 0, { errors: 2 })]);
  const { result, codes } = await run('app');
  expect(codes).not.toContain('recommendation-broader');
  expect(codes).toContain('recommendation-denied');
  expect(result.recommendedUris).toEqual(['uri:/lnrpc.Lightning/GetInfo']);
  expect(result.commands[0]).toContain(`--uri ${shellQuote('/lnrpc.Lightning/GetInfo')} --out`);
});

it('READCMD-13 the last use is the later instant, not the later string', async () => {
  const run = setup([entry('app', '4294967341', READ)], [
    record('4294967341', '/lnrpc.Lightning/GetInfo', 1, { credential: 'id:1111111111111111', lastSeen: '2026-10-08T10:00:00.900Z' }),
    record('4294967341', '/lnrpc.Lightning/GetInfo', 1, { credential: 'id:2222222222222222', lastSeen: '2026-10-08T10:00:00Z' })]);
  expect((await run('app')).result.observed[0].lastUsed).toBe('2026-10-08T10:00:00.900Z');
});

const expiring = (value: string) => setup([entry('app', '4294967341', READ,
  { caveats: [{ type: 'time-before', value, requested: '90d' }] })], [getInfo()]);

it('READCMD-01 an original whose expiry has passed gets no narrowing command, only rotate or revoke advice', async () => {
  for (const value of ['2026-10-01T00:00:00Z', '2026-10-08T12:00:30Z']) {
    const { result, codes, warnings } = await (await expiring(value))('app');
    expect(result.commands).toEqual([]);
    expect(codes).toContain('recommendation-expired');
    const message = (warnings.find(item => typeof item !== 'string' && item.code === 'recommendation-expired') as { message: string }).message;
    expect(message).toContain('macwarden rotate');
    expect(message).toContain('macwarden revoke');
  }
});

it('READCMD-01 the narrowed credential never outlives the original: --expires is capped by the remaining lifetime', async () => {
  // 1 day 6.5 hours left: whole days, rounded down.
  expect((await (await expiring('2026-10-09T18:30:00Z'))('app')).result.commands[0]).toContain(' --expires 1d --out <file> ');
  // 3.5 hours left: whole hours.
  expect((await (await expiring('2026-10-08T15:30:00Z'))('app')).result.commands[0]).toContain(' --expires 3h --out <file> ');
  // 20.5 minutes left: whole minutes.
  expect((await (await expiring('2026-10-08T12:20:30+00:00'))('app')).result.commands[0]).toContain(' --expires 20m --out <file> ');
  // More left than recorded: the recorded duration.
  expect((await (await expiring('2027-06-01T00:00:00Z'))('app')).result.commands[0]).toContain(' --expires 90d --out <file> ');
  expect(remainingDuration(59_999_999_999n)).toBeNull();
  expect(remainingDuration(-1n)).toBeNull();
  expect(remainingDuration(60_000_000_000n)).toBe('1m');
  expect(remainingDuration(10n ** 30n)).toBe('99999d');
});

it('READCMD-01 an expired --target-file credential gets no narrowing command', async () => {
  // The vector's caveat is time-before 2026-10-02T17:38:38.792272998Z, before NOW.
  const file = join(repo, 'test/vectors/time-before.macaroon');
  const id = macaroonId(new Secret(readFileSync(file)));
  const run = setup([], [record(id.rootKeyId.toString(), '/lnrpc.Lightning/GetInfo', 3, { credential: id.id })]);
  const { result, codes } = await run('--target-file', file);
  expect(result.commands).toEqual([]);
  expect(codes).toContain('recommendation-expired');
});
