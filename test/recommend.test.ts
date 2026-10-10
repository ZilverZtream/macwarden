import { createHash } from 'node:crypto';
import * as fs from 'node:fs/promises';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { narrowLabel, run as recommend } from '../src/commands/recommend.js';
import { LndError } from '../src/errors.js';
import { shellQuote } from '../src/online.js';
import { expectSchemaValid } from './helpers/output-schema.js';
import { render } from '../src/output/index.js';
import { SPAN_LIMIT, UsageStore, writeUsage } from '../src/watch/usage.js';

const repo = resolve();
/** Every recommend run in this file, success or refusal, is checked against the shipped schema. */
async function run(...args: Parameters<typeof recommend>): ReturnType<typeof recommend> {
  const result = await recommend(...args);
  expectSchemaValid(result);
  return result;
}
const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
const PUBKEY = `02${'ab'.repeat(32)}`;
const snapshot = JSON.parse(readFileSync(join(repo, 'src/grade/lnd-permissions.json'), 'utf8')) as { methods: Record<string, string[]> };
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

function identityOf(bytes: Buffer): string {
  const varint = (at: number): [number, number] => { let value = 0, shift = 0; for (;;) { const b = bytes[at++]; value += (b & 0x7f) * 2 ** shift; if (!(b & 0x80)) return [value, at]; shift += 7; } };
  let at = 1;
  for (;;) {
    const [type, afterType] = varint(at);
    const [length, start] = varint(afterType);
    if (type === 2) return `id:${createHash('sha256').update(bytes.subarray(start, start + length)).digest('hex').slice(0, 16)}`;
    at = start + length;
  }
}

function setup(entries: object[], usage: object[] | string) {
  mkdirSync(tmpRoot, { recursive: true });
  const dir = mkdtempSync(join(tmpRoot, 'recommend-'));
  dirs.push(dir);
  const registry = join(dir, 'registry.json');
  writeFileSync(registry, JSON.stringify({ schema: 1, entries }));
  // Eight days of watch coverage, so the observation window is long enough to narrow.
  writeFileSync(`${registry}.usage.json`, typeof usage === 'string' ? usage : JSON.stringify({ schema: 1, dropped: 0, coverage: [week(8)], entries: usage }));
  writeFileSync(join(dir, 'tls.cert'), 'unused');
  writeFileSync(join(dir, 'own.macaroon'), readFileSync(join(repo, 'test/vectors/default-admin.macaroon')));
  const deps = { lnd: { getInfo: async () => ({ pubkey: PUBKEY, alias: 'a', network: 'regtest', version: 'v' }),
    listPermissions: async () => snapshot.methods } as never, fs, env: {} };
  return { dir, registry, deps, args: ['--lnd-rest', 'localhost:18080', '--tls-cert', join(dir, 'tls.cert'),
    '--macaroon', join(dir, 'own.macaroon'), '--registry', registry, '--json'] };
}

/** A coverage record: watch registered for this many days, ending 2026-10-08T12:00:00Z. */
const week = (days: number, firstStart = '2026-09-30T00:00:00.000Z') => ({ nodePubkey: PUBKEY, firstStart,
  lastEnd: '2026-10-08T12:00:00.000Z', coveredSeconds: Math.round(days * 86_400), sessions: 3 });
const entry = (label: string, rootKeyId: string, permissions: string[]) => ({ nodePubkey: PUBKEY, label, rootKeyId, permissions,
  caveats: [], grade: 'READ', fingerprint: 'fp:0123456789abcdef', outPath: null, createdAt: '2026-10-01T00:00:00Z', verified: true,
  status: 'active', revokedAt: null, revokeEvidence: null, replaces: null, replacedBy: null });
const record = (credential: string, rootKeyId: string, method: string, calls: number, lastSeen = '2026-10-08T10:00:00Z') =>
  ({ nodePubkey: PUBKEY, credential, rootKeyId, method, calls, errors: 0, firstSeen: '2026-10-08T09:00:00Z', lastSeen });

it('RECOMMEND/label observed methods map to the exact permissions LND requires and the narrowing commands', async () => {
  const s = setup([entry('app1', '4294967341', ['info:read', 'invoices:read', 'invoices:write', 'offchain:read', 'onchain:read'])], [
    record('id:1111111111111111', '4294967341', '/lnrpc.Lightning/GetInfo', 3),
    record('id:2222222222222222', '4294967341', '/lnrpc.Lightning/AddInvoice', 2, '2026-10-08T11:00:00Z'),
    record('id:3333333333333333', '999', '/lnrpc.Lightning/SendCoins', 9),
  ]);
  const result = await run(['app1', ...s.args], s.deps);
  expect(result.ok).toBe(true);
  const expected = [...new Set([...snapshot.methods['/lnrpc.Lightning/GetInfo'], ...snapshot.methods['/lnrpc.Lightning/AddInvoice']])].sort();
  expect(expected).toEqual(['info:read', 'invoices:write']);
  expect(result.result).toMatchObject({ label: 'app1', rootKeyId: '4294967341', recommended: expected,
    recommendedUris: ['uri:/lnrpc.Lightning/AddInvoice', 'uri:/lnrpc.Lightning/GetInfo'],
    unneeded: ['invoices:read', 'offchain:read', 'onchain:read'], unmapped: [],
    credentials: ['id:1111111111111111', 'id:2222222222222222'] });
  expect((result.result as { observed: unknown[] }).observed).toEqual([
    { method: '/lnrpc.Lightning/AddInvoice', calls: 2, lastUsed: '2026-10-08T11:00:00Z', permissions: ['invoices:write'] },
    { method: '/lnrpc.Lightning/GetInfo', calls: 3, lastUsed: '2026-10-08T10:00:00Z', permissions: ['info:read'] }]);
  const commands = (result.result as { commands: string[] }).commands;
  // The --uri list is quoted like the paths (1.2.1): unquoted, PowerShell (a function or npm's .ps1
  // shim) turns a,b into an array and passes "a b". <file> is a placeholder the operator replaces.
  expect(commands[0].startsWith(`macwarden bake --label app1-narrow --uri ${shellQuote('/lnrpc.Lightning/AddInvoice,/lnrpc.Lightning/GetInfo')} --out <file> --lnd-rest localhost:18080 `)).toBe(true);
  if (process.platform === 'win32') expect(commands[0]).toContain(" --uri '/lnrpc.Lightning/AddInvoice,/lnrpc.Lightning/GetInfo' --out <file> ");
  // A runnable command: the note is a trailing comment, valid in POSIX sh and PowerShell (1.2.1).
  expect(commands[1]).toMatch(/^macwarden revoke app1 --lnd-rest localhost:18080 .*[^ ] {2}# after switching the app to the new file$/);
  expect(render(result, 'text')).toMatch(/^next {9}macwarden revoke app1 .* {2}# after switching the app to the new file$/m);
  // Recommendation only: registry and usage are untouched.
  expect(JSON.parse(readFileSync(s.registry, 'utf8')).entries).toHaveLength(1);
});

it('RECOMMEND/target-file a default macaroon is selected by its identifier, never by shared root key 0', async () => {
  const admin = readFileSync(join(repo, 'test/vectors/default-admin.macaroon'));
  const s = setup([], [record(identityOf(admin), '0', '/lnrpc.Lightning/ListChannels', 4)]);
  writeFileSync(join(s.dir, 'app.macaroon'), admin);
  const byFile = await run(['--target-file', join(s.dir, 'app.macaroon'), ...s.args], s.deps);
  expect(byFile.result).toMatchObject({ selector: identityOf(admin), recommended: ['offchain:read'], label: null });
  const byId = await run([identityOf(admin), ...s.args], s.deps);
  expect(byId.result).toMatchObject({ recommended: ['offchain:read'] });
  expect(await run(['0', ...s.args], s.deps)).toMatchObject({ ok: false, error: { code: 2, step: 'R6' } });
});

it('RECOMMEND/limits unmapped methods block the narrowing command; no observations say how to collect them', async () => {
  const s = setup([entry('app1', '4294967341', ['info:read'])], [record('id:1111111111111111', '4294967341', '/custom.Svc/Do', 1)]);
  const unmapped = await run(['app1', ...s.args], s.deps);
  expect(unmapped.result).toMatchObject({ unmapped: ['/custom.Svc/Do'], commands: [] });
  const empty = setup([entry('app2', '4294967342', ['info:read'])], []);
  const none = await run(['app2', ...empty.args.filter(arg => arg !== '--json')], empty.deps);
  expect(none.result).toMatchObject({ observed: [], commands: [] });
  const bad = setup([], '{"schema":1,"dropped":0,"entries":[{"oops":1}]}');
  expect(await run(['app1', ...bad.args], bad.deps)).toMatchObject({ ok: false, error: { code: 3, step: 'R4' } });
});

it('RECOMMEND/broader usage that the credential never held cannot produce a narrowing command', async () => {
  // Poisoned or mismatched usage: an invoice-only credential "observed" sending payments.
  const s = setup([entry('shop', '4294967341', ['info:read', 'invoices:read', 'invoices:write'])], [
    record('id:1111111111111111', '4294967341', '/lnrpc.Lightning/GetInfo', 3),
    record('id:1111111111111111', '4294967341', '/routerrpc.Router/SendPaymentV2', 1),
  ]);
  const result = await run(['shop', ...s.args], s.deps);
  expect(result.ok).toBe(true);
  expect(result.result).toMatchObject({ commands: [] });
  const codes = result.warnings.map(item => typeof item === 'string' ? item : item.code);
  expect(codes).toContain('recommendation-broader');
  expect(JSON.stringify(result.warnings)).toContain('/routerrpc.Router/SendPaymentV2');
});

it('RECOMMEND/incomplete any eviction blocks the narrowing command, even one before the remaining records were first seen', async () => {
  const records = [record('id:1111111111111111', '4294967341', '/lnrpc.Lightning/GetInfo', 3)];
  const entries = [entry('app1', '4294967341', ['info:read'])];
  // Eviction after first sighting (09:00): some of its methods may be gone.
  const evicted = setup(entries, JSON.stringify({ schema: 1, dropped: 0, evictions: 4, lastEviction: '2026-10-08T09:30:00Z', entries: records }));
  const after = await run(['app1', ...evicted.args], evicted.deps);
  expect(after.result).toMatchObject({ commands: [] });
  expect(after.warnings.map(item => typeof item === 'string' ? item : item.code)).toContain('usage-incomplete');
  // An eviction before the remaining records were first seen can still have removed this
  // credential's record of another method (called at 07:00, evicted at 08:00, GetInfo
  // first seen at 09:00), so it blocks too.
  const before = setup(entries, JSON.stringify({ schema: 1, dropped: 0, evictions: 4, lastEviction: '2026-10-08T08:00:00Z', entries: records }));
  const blocked = await run(['app1', ...before.args], before.deps);
  expect(blocked.result).toMatchObject({ commands: [] });
  expect(blocked.warnings.map(item => typeof item === 'string' ? item : item.code)).toContain('usage-incomplete');
  // With nothing evicted or dropped, the narrowing command is printed.
  const none = setup(entries, JSON.stringify({ schema: 1, dropped: 0, evictions: 0, lastEviction: null, coverage: [week(8)], entries: records }));
  const clean = await run(['app1', ...none.args], none.deps);
  expect((clean.result as { commands: string[] }).commands.length).toBeGreaterThan(0);
  expect(clean.warnings.map(item => typeof item === 'string' ? item : item.code)).not.toContain('usage-incomplete');
});

it('RECOMMEND/unattributed calls an overloaded watch that dropped attributions blocks the narrowing command', async () => {
  // The dropped call may have been this credential's only AddInvoice: narrowing to what was
  // recorded (GetInfo) would break the app, so no command is printed.
  const records = [record('id:1111111111111111', '4294967341', '/lnrpc.Lightning/GetInfo', 3)];
  const entries = [entry('app1', '4294967341', ['info:read', 'invoices:write'])];
  const dropped = setup(entries, JSON.stringify({ schema: 1, dropped: 0, evictions: 0, lastEviction: null,
    droppedAttributions: 1, lastAttributionDrop: '2026-10-08T08:00:00.000Z', entries: records }));
  const out = await run(['app1', ...dropped.args], dropped.deps);
  expect(out.result).toMatchObject({ commands: [] });
  expect(out.warnings.map(item => typeof item === 'string' ? item : item.code)).toContain('usage-incomplete');
});

it('WATCH/usage-store counts, bounds, validates and writes owner-only atomically', async () => {
  const store = new UsageStore(2);
  const at = new Date('2026-10-08T12:00:00Z');
  store.record(PUBKEY, 'id:1111111111111111', '5', '/lnrpc.Lightning/GetInfo', at);
  store.record(PUBKEY, 'id:1111111111111111', '5', '/lnrpc.Lightning/GetInfo', at, true);
  store.record(PUBKEY, 'id:1111111111111111', '5', 'not a method', at);
  // At capacity the least recently seen record (5, GetInfo) is evicted: new calls are never refused.
  store.record(PUBKEY, 'id:2222222222222222', '6', '/lnrpc.Lightning/GetInfo', at);
  expect(store.entries().map(item => [item.rootKeyId, item.method, item.calls, item.errors])).toEqual([
    ['5', '/unknown/Unknown', 1, 0], ['6', '/lnrpc.Lightning/GetInfo', 1, 0]]);
  expect([store.dropped, store.evictions, store.lastEviction]).toEqual([0, 1, at.toISOString()]);
  const s = setup([], []);
  const path = `${s.registry}.usage.json`;
  await writeUsage(path, store, fs);
  expect(readdirSync(s.dir).filter(name => name.endsWith('.tmp'))).toEqual([]);
  if (process.platform !== 'win32') expect(statSync(path).mode & 0o777).toBe(0o600);
  const reread = UsageStore.parse(readFileSync(path, 'utf8'), 2);
  expect(reread.entries()).toEqual(store.entries());
  expect([reread.dropped, reread.evictions, reread.lastEviction]).toEqual([0, 1, at.toISOString()]);
  // A file from before eviction tracking still parses.
  expect(UsageStore.parse(JSON.stringify({ schema: 1, dropped: 0, entries: [] })).evictions).toBe(0);
  // Format version 1 only ever gains fields: an unknown field is ignored, so a newer file
  // stays readable; a change older readers must understand to stay safe needs schema 2.
  expect(UsageStore.parse('{"schema":1,"dropped":0,"entries":[],"extra":1}').entries()).toEqual([]);
  const attributed = UsageStore.parse(JSON.stringify({ schema: 1, dropped: 0, droppedAttributions: 3,
    lastAttributionDrop: '2026-10-08T12:00:00.000Z', entries: [] }));
  expect([attributed.droppedAttributions, attributed.lastAttributionDrop]).toEqual([3, '2026-10-08T12:00:00.000Z']);
  for (const broken of ['{"schema":2,"dropped":0,"entries":[]}', '{"schema":1,"entries":[]}',
    '{"schema":1,"dropped":0,"entries":[],"droppedAttributions":-1}', '{"schema":1,"dropped":0,"entries":[],"droppedAttributions":"3"}',
    '{"schema":1,"dropped":0,"entries":[],"lastAttributionDrop":"yesterday"}', '{"schema":1,"dropped":0,"entries":[],"evictions":1.5}',
    JSON.stringify({ schema: 1, dropped: 0, entries: [store.entries()[0], store.entries()[0]] }),
    JSON.stringify({ schema: 1, dropped: 0, entries: [{ ...store.entries()[0], credential: 'fp:0123456789abcdef' }] })])
    expect(() => UsageStore.parse(broken)).toThrow('invalid usage file');
  expect(existsSync(path)).toBe(true);
});

it('RECOMMEND/narrow-label the suggested label always satisfies bake\'s label rule, even for a 64-character original', () => {
  // bake's label rule (SPEC, bake B1): a letter, then up to 63 of letters, digits, dot, underscore, dash.
  const bakeLabel = /^[A-Za-z][A-Za-z0-9._-]{0,63}$/;
  for (const original of ['app', 'a'.repeat(57), 'a'.repeat(58), `x${'y'.repeat(63)}`]) {
    const label = narrowLabel(original);
    expect(label).toMatch(bakeLabel);
    expect(label.endsWith('-narrow')).toBe(true);
    expect(label.length).toBeLessThanOrEqual(64);
  }
  expect(narrowLabel('app')).toBe('app-narrow');
  expect(narrowLabel('a'.repeat(64))).toBe(`${'a'.repeat(57)}-narrow`);
});

// Found in the live field check: after a one-minute watch, recommend printed a bake command
// that would have removed a payment credential's payment methods.
// Created when the fixture's coverage began (week()'s default firstStart): all of it counts.
const watched = (permissions: string[]) => ({ ...entry('pay', '4294967341', permissions), createdAt: '2026-09-30T00:00:00Z' });
const shortUsage = (coverage: object[]) => JSON.stringify({ schema: 1, dropped: 0, coverage,
  entries: [record('id:1111111111111111', '4294967341', '/lnrpc.Lightning/GetInfo', 3)] });

it('RECOMMEND/short-observation under 7 days of watch coverage warns and withholds the narrowing command', async () => {
  const s = setup([watched(['info:read', 'offchain:read', 'offchain:write'])], shortUsage([week(1 / 24)]));
  const result = await run(['pay', ...s.args], s.deps);
  expect(result.ok).toBe(true);
  expect(result.result).toMatchObject({ commands: [],
    observation: { seconds: 3_600, since: '2026-09-30T00:00:00.000Z', until: '2026-10-08T12:00:00.000Z', sessions: 3, short: true, accepted: false } });
  const warning = result.warnings.find(item => typeof item !== 'string' && item.code === 'short-observation') as { message: string };
  expect(warning.message).toMatch(/observed for 1h 0m, less than 7d 0h; methods the app calls rarely \(such as payments\) may be missing/);
  const text = render(result, 'text');
  expect(text).toContain('window       observed for 1h 0m (3 watch sessions since 2026-09-30T00:00:00.000Z); SHORT OBSERVATION');
  expect(text).not.toContain('macwarden bake');
});

it('RECOMMEND/short-observation --accept-short-observation prints the command and keeps the warning', async () => {
  const s = setup([watched(['info:read', 'offchain:read', 'offchain:write'])], shortUsage([week(1 / 24)]));
  const result = await run(['pay', '--accept-short-observation', ...s.args], s.deps);
  expect(result.result).toMatchObject({ observation: { short: true, accepted: true } });
  expect((result.result as { commands: string[] }).commands[0]).toMatch(/^macwarden bake --label pay-narrow --uri \/lnrpc\.Lightning\/GetInfo /);
  expect(result.warnings.some(item => typeof item !== 'string' && item.code === 'short-observation')).toBe(true);
  expect(await run(['pay', '--accept-short-observation', '--accept-short-observation', ...s.args], s.deps))
    .toMatchObject({ ok: false, error: { code: 2, step: 'R1' } });
});

it('RECOMMEND/short-observation coverage before the credential existed does not count, and no coverage record is unknown', async () => {
  // Watch has covered 30 days, but the credential was created a day before the last coverage.
  const late = { ...entry('pay', '4294967341', ['info:read']), createdAt: '2026-10-07T12:00:00Z' };
  // Without recorded spans (a 1.0.1 file) the covered day cannot be placed after creation:
  // 30 days covered in a 37.5-day window may all lie before it, so the provable time is 0.
  const s = setup([late], shortUsage([week(30, '2026-09-01T00:00:00.000Z')]));
  const result = await run(['pay', ...s.args], s.deps);
  expect(result.result).toMatchObject({ commands: [], observation: { seconds: 0, short: true } });
  // With spans, the day after creation is counted and nothing before it.
  const spans = JSON.parse(shortUsage([week(30, '2026-09-01T00:00:00.000Z')])) as Record<string, unknown>;
  spans.coverageSpans = [{ nodePubkey: PUBKEY, spans: [['2026-09-01T00:00:00.000Z', '2026-09-30T12:00:00.000Z'], ['2026-10-07T12:00:00.000Z', '2026-10-08T12:00:00.000Z']] }];
  const placed = setup([late], JSON.stringify(spans));
  expect((await run(['pay', ...placed.args], placed.deps)).result).toMatchObject({ commands: [], observation: { seconds: 86_400, short: true } });
  // A usage file written before 1.0.1 has no coverage: the window is unknown, so short.
  const old = setup([entry('pay', '4294967341', ['info:read'])], JSON.stringify({ schema: 1, dropped: 0,
    entries: [record('id:1111111111111111', '4294967341', '/lnrpc.Lightning/GetInfo', 3)] }));
  const unknown = await run(['pay', ...old.args], old.deps);
  expect(unknown.result).toMatchObject({ commands: [], observation: { seconds: null, short: true, sessions: 0 } });
  expect(render(unknown, 'text')).toContain('observed for an unknown time');
});

it('RECOMMEND/short-observation 7 days or more of coverage is long enough', async () => {
  const s = setup([watched(['info:read'])], shortUsage([week(7)]));
  const result = await run(['pay', ...s.args], s.deps);
  expect(result.result).toMatchObject({ observation: { seconds: 604_800, short: false, accepted: false } });
  expect((result.result as { commands: string[] }).commands).toHaveLength(2);
  expect(render(result, 'text')).toContain('window       observed for 7d 0h (3 watch sessions since 2026-09-30T00:00:00.000Z)\n');
});

it('WATCH/usage-store canary uses and coverage are bounded, round-trip, and files without them still read', () => {
  const store = new UsageStore();
  store.recordCanary(PUBKEY, '42', 2, new Date('2026-10-08T10:00:00Z'));
  store.recordCanary(PUBKEY, '42', 1, new Date('2026-10-08T11:00:00Z'));
  store.recordCanary(PUBKEY, 'not-an-id', 1, new Date('2026-10-08T11:00:00Z'));
  store.beginCoverage(PUBKEY, new Date('2026-10-08T10:00:00Z'));
  store.extendCoverage(PUBKEY, new Date('2026-10-08T10:00:01.500Z'));
  store.endCoverage(PUBKEY, new Date('2026-10-08T10:01:00Z'));
  store.extendCoverage(PUBKEY, new Date('2026-10-08T11:00:00Z')); // not registered: not counted
  store.beginCoverage(PUBKEY, new Date('2026-10-08T12:00:00Z'));
  store.endCoverage(PUBKEY, new Date('2026-10-08T12:00:30Z'));
  const copy = UsageStore.parse(store.toText());
  expect(copy.canaryUsesFor(PUBKEY, '42')).toEqual({ nodePubkey: PUBKEY, rootKeyId: '42', uses: 3,
    firstUse: '2026-10-08T10:00:00.000Z', lastUse: '2026-10-08T11:00:00.000Z' });
  expect(copy.coverageFor(PUBKEY)).toEqual({ nodePubkey: PUBKEY, firstStart: '2026-10-08T10:00:00.000Z',
    lastEnd: '2026-10-08T12:00:30.000Z', coveredSeconds: 90, sessions: 2 });
  for (let i = 0; i < 1_100; i++) store.recordCanary(PUBKEY, String(1_000 + i), 1, new Date(Date.UTC(2026, 9, 9, 0, 0, i)));
  expect((JSON.parse(store.toText()) as { canaryUses: unknown[] }).canaryUses).toHaveLength(1_000);
  for (let i = 0; i < 70; i++) store.beginCoverage(`03${i.toString(16).padStart(64, '0')}`, new Date(Date.UTC(2026, 9, 9, 0, 0, i)));
  expect((JSON.parse(store.toText()) as { coverage: unknown[] }).coverage).toHaveLength(64);
  expect(UsageStore.parse(JSON.stringify({ schema: 1, dropped: 0, entries: [] })).coverageFor(PUBKEY)).toBeNull();
  expect(() => UsageStore.parse(JSON.stringify({ schema: 1, dropped: 0, entries: [], coverage: [{ nodePubkey: PUBKEY }] }))).toThrow('invalid usage file');
  expect(() => UsageStore.parse(JSON.stringify({ schema: 1, dropped: 0, entries: [], canaryUses: 'x' }))).toThrow('invalid usage file');
});

// MW102-03: the widening guard must not depend on how the credential was selected. One
// registered credential holds info:read and invoices:write; its (inconsistent) usage claims
// SendPaymentV2, which needs offchain:write. Every selector must refuse to narrow.
it('RECOMMEND/selectors label, root key ID, credential ID and target file all apply the widening guard to identical evidence', async () => {
  const file = readFileSync(join(repo, 'test/vectors/root-max.macaroon'));
  const credential = identityOf(file);
  const root = '18446744073709551615';
  const s = setup([entry('shop', root, ['info:read', 'invoices:write'])], [
    record(credential, root, '/lnrpc.Lightning/GetInfo', 3),
    record(credential, root, '/routerrpc.Router/SendPaymentV2', 1),
  ]);
  writeFileSync(join(s.dir, 'app.macaroon'), file);
  for (const selector of [['shop'], [root], [credential], ['--target-file', join(s.dir, 'app.macaroon')]]) {
    const result = await run([...selector, ...s.args], s.deps);
    expect(result.ok, selector.join(' ')).toBe(true);
    expect(result.result, selector.join(' ')).toMatchObject({ commands: [], current: ['info:read', 'invoices:write'], label: 'shop', rootKeyId: root });
    const broader = result.warnings.find(item => typeof item !== 'string' && item.code === 'recommendation-broader') as { message: string } | undefined;
    expect(broader?.message, selector.join(' ')).toContain('/routerrpc.Router/SendPaymentV2');
    // --accept-short-observation only bypasses the time guard; it never authorizes widening.
    const accepted = await run([...selector, '--accept-short-observation', ...s.args], s.deps);
    expect(accepted.result, selector.join(' ')).toMatchObject({ commands: [] });
  }
});

it('RECOMMEND/selectors a credential ID narrows when consistent, but never suggests revoking a root key it did not fully observe', async () => {
  const file = readFileSync(join(repo, 'test/vectors/root-max.macaroon'));
  const credential = identityOf(file);
  const root = '18446744073709551615';
  const s = setup([entry('shop', root, ['info:read', 'invoices:write'])], [record(credential, root, '/lnrpc.Lightning/GetInfo', 3)]);
  writeFileSync(join(s.dir, 'app.macaroon'), file);
  for (const selector of [[credential], ['--target-file', join(s.dir, 'app.macaroon')]]) {
    const result = await run([...selector, ...s.args], s.deps);
    expect(result.result, selector.join(' ')).toMatchObject({ current: ['info:read', 'invoices:write'], label: 'shop', unneeded: ['invoices:write'] });
    const commands = (result.result as { commands: string[] }).commands;
    expect(commands).toHaveLength(1);
    expect(commands[0]).toMatch(/^macwarden bake --label shop-narrow --uri \/lnrpc\.Lightning\/GetInfo /);
  }
  const byLabel = await run(['shop', ...s.args], s.deps);
  expect((byLabel.result as { commands: string[] }).commands[1]).toMatch(/^macwarden revoke shop --lnd-rest \S+ .*[^ ] {2}# after switching the app to the new file$/);
});

it('RECOMMEND/selectors no narrowing command when the usage identity cannot be resolved to one set of permissions', async () => {
  const unverified = (result: Awaited<ReturnType<typeof run>>) => result.warnings.some(item => typeof item !== 'string' && item.code === 'recommendation-unverified');
  // Unregistered non-zero root key: the credential's permissions are unknown.
  const s = setup([], [record('id:1111111111111111', '4294967341', '/routerrpc.Router/SendPaymentV2', 1)]);
  for (const selector of ['id:1111111111111111', '4294967341']) {
    const result = await run([selector, ...s.args], s.deps);
    expect(result.result, selector).toMatchObject({ current: null, commands: [] });
    expect(unverified(result), selector).toBe(true);
  }
  // One credential ID recorded under two root key IDs is inconsistent evidence.
  const twice = setup([entry('shop', '4294967341', ['info:read', 'offchain:write'])], [
    record('id:1111111111111111', '4294967341', '/lnrpc.Lightning/GetInfo', 1),
    record('id:1111111111111111', '4294967342', '/routerrpc.Router/SendPaymentV2', 1)]);
  const ambiguous = await run(['id:1111111111111111', ...twice.args], twice.deps);
  expect(ambiguous.result).toMatchObject({ current: null, commands: [] });
  expect(unverified(ambiguous)).toBe(true);
  // A default macaroon (root key 0) by credential ID: nothing records its permissions.
  const admin = readFileSync(join(repo, 'test/vectors/default-admin.macaroon'));
  const zero = setup([], [record(identityOf(admin), '0', '/lnrpc.Lightning/ListChannels', 4)]);
  const byId = await run([identityOf(admin), ...zero.args], zero.deps);
  expect(byId.result).toMatchObject({ current: null, commands: [] });
  expect(unverified(byId)).toBe(true);
});

it('RECOMMEND/selectors a target file without a registry entry is checked against the file\'s own permissions', async () => {
  const readOnly = readFileSync(join(repo, 'test/vectors/default-readonly.macaroon'));
  // First seen when last seen: a usage record whose first sighting is after its last is invalid evidence (MW110-05).
  const s = setup([], [{ ...record(identityOf(readOnly), '0', '/routerrpc.Router/SendPaymentV2', 1, '2026-09-30T00:00:00Z'),
    firstSeen: '2026-09-30T00:00:00Z' }]);
  writeFileSync(join(s.dir, 'app.macaroon'), readOnly);
  const result = await run(['--target-file', join(s.dir, 'app.macaroon'), '--accept-short-observation', ...s.args], s.deps);
  expect(result.result).toMatchObject({ commands: [], label: null });
  expect(result.warnings.some(item => typeof item !== 'string' && item.code === 'recommendation-broader')).toBe(true);
});

// MW102-04: only coverage after the credential was created counts.
function observed(spans: [string, string][]): UsageStore {
  const store = new UsageStore();
  for (const [from, to] of spans) { store.beginCoverage(PUBKEY, new Date(from)); store.endCoverage(PUBKEY, new Date(to)); }
  return store;
}

it('RECOMMEND/post-creation coverage long coverage before creation, a gap, then one second after stays short', async () => {
  // Eight days September 1-9, the credential created October 1, one second on October 8.
  const store = observed([['2026-09-01T00:00:00Z', '2026-09-09T00:00:00Z'], ['2026-10-08T00:00:00Z', '2026-10-08T00:00:01Z']]);
  store.record(PUBKEY, 'id:1111111111111111', '4294967341', '/lnrpc.Lightning/GetInfo', new Date('2026-10-08T00:00:00Z'));
  const s = setup([entry('pay', '4294967341', ['info:read', 'offchain:write'])], store.toText());
  const result = await run(['pay', ...s.args], s.deps);
  expect(result.result).toMatchObject({ commands: [], observation: { seconds: 1, short: true, sessions: 2 } });
  expect(result.warnings.some(item => typeof item !== 'string' && item.code === 'short-observation')).toBe(true);
  // The same file read back without the interval list (as a 1.0.1 writer would leave it) is still short.
  const legacy = JSON.parse(store.toText()) as Record<string, unknown>;
  delete legacy.coverageSpans;
  const old = setup([entry('pay', '4294967341', ['info:read', 'offchain:write'])], JSON.stringify(legacy));
  expect((await run(['pay', ...old.args], old.deps)).result).toMatchObject({ commands: [], observation: { short: true } });
});

it('RECOMMEND/post-creation coverage recorded spans prove coverage after creation even with earlier coverage and a gap', async () => {
  const store = observed([['2026-09-01T00:00:00Z', '2026-09-09T00:00:00Z'], ['2026-10-01T00:00:00Z', '2026-10-09T00:00:00Z']]);
  store.record(PUBKEY, 'id:1111111111111111', '4294967341', '/lnrpc.Lightning/GetInfo', new Date('2026-10-08T00:00:00Z'));
  const s = setup([entry('pay', '4294967341', ['info:read', 'offchain:write'])], store.toText());
  const result = await run(['pay', ...s.args], s.deps);
  expect(result.result).toMatchObject({ observation: { seconds: 8 * 86_400, short: false } });
  expect((result.result as { commands: string[] }).commands).toHaveLength(2);
  // A span straddling the creation counts only its part after it.
  const straddle = observed([['2026-09-28T00:00:00Z', '2026-10-05T00:00:00Z']]);
  straddle.record(PUBKEY, 'id:1111111111111111', '4294967341', '/lnrpc.Lightning/GetInfo', new Date('2026-10-04T00:00:00Z'));
  const t = setup([entry('pay', '4294967341', ['info:read'])], straddle.toText());
  expect((await run(['pay', ...t.args], t.deps)).result).toMatchObject({ commands: [], observation: { seconds: 4 * 86_400, short: true } });
});

it('RECOMMEND/post-creation coverage without a registry entry counts only from the credential\'s first recorded use', async () => {
  // A default macaroon has no recorded creation time; it existed no later than its first use.
  const admin = readFileSync(join(repo, 'test/vectors/default-admin.macaroon'));
  const store = observed([['2026-09-01T00:00:00Z', '2026-09-20T00:00:00Z'], ['2026-10-08T00:00:00Z', '2026-10-08T01:00:00Z']]);
  store.record(PUBKEY, identityOf(admin), '0', '/lnrpc.Lightning/ListChannels', new Date('2026-10-08T00:00:00Z'));
  const s = setup([], store.toText());
  writeFileSync(join(s.dir, 'app.macaroon'), admin);
  const result = await run(['--target-file', join(s.dir, 'app.macaroon'), ...s.args], s.deps);
  expect(result.result).toMatchObject({ commands: [], observation: { seconds: 3_600, short: true } });
});

it('WATCH/usage-store coverage spans are bounded, merged, round-trip, and keep the coverage record readable by 1.0.1', () => {
  const store = new UsageStore();
  const start = Date.parse('2026-10-01T00:00:00Z');
  for (let i = 0; i < SPAN_LIMIT + 10; i++) {
    store.beginCoverage(PUBKEY, new Date(start + i * 120_000));
    store.endCoverage(PUBKEY, new Date(start + i * 120_000 + 60_000));
  }
  const text = JSON.parse(store.toText()) as { coverage: Record<string, unknown>[]; coverageSpans: { nodePubkey: string; spans: string[][] }[] };
  // The coverage record keeps exactly its 1.0.1 keys; spans are a separate top-level field older readers ignore.
  expect(Object.keys(text.coverage[0]).sort()).toEqual(['coveredSeconds', 'firstStart', 'lastEnd', 'nodePubkey', 'sessions']);
  expect(text.coverageSpans).toHaveLength(1);
  expect(text.coverageSpans[0].spans).toHaveLength(SPAN_LIMIT);
  // The oldest spans were dropped: the newest is kept.
  expect(text.coverageSpans[0].spans.at(-1)).toEqual([new Date(start + (SPAN_LIMIT + 9) * 120_000).toISOString(), new Date(start + (SPAN_LIMIT + 9) * 120_000 + 60_000).toISOString()]);
  const copy = UsageStore.parse(store.toText());
  expect(copy.coveredSince(PUBKEY, start + (SPAN_LIMIT + 9) * 120_000)).toBe(60);
  expect(copy.coveredSince(PUBKEY, 0)).toBe(SPAN_LIMIT * 60);
  // Overlapping or unordered spans in a file are merged, never counted twice.
  const merged = UsageStore.parse(JSON.stringify({ schema: 1, dropped: 0, entries: [], coverage: [week(1)],
    coverageSpans: [{ nodePubkey: PUBKEY, spans: [['2026-10-02T00:00:00.000Z', '2026-10-03T00:00:00.000Z'], ['2026-10-01T00:00:00.000Z', '2026-10-02T12:00:00.000Z']] }] }));
  expect(merged.coveredSince(PUBKEY, 0)).toBe(2 * 86_400);
  // A file without spans (1.0.1) has no span evidence; spans for a node without coverage are ignored.
  expect(UsageStore.parse(JSON.stringify({ schema: 1, dropped: 0, entries: [], coverage: [week(1)] })).coveredSince(PUBKEY, 0)).toBeNull();
  expect(UsageStore.parse(JSON.stringify({ schema: 1, dropped: 0, entries: [],
    coverageSpans: [{ nodePubkey: PUBKEY, spans: [['2026-10-01T00:00:00.000Z', '2026-10-02T00:00:00.000Z']] }] })).coveredSince(PUBKEY, 0)).toBeNull();
  for (const bad of [{ nodePubkey: PUBKEY }, { nodePubkey: PUBKEY, spans: [['2026-10-02T00:00:00.000Z', '2026-10-01T00:00:00.000Z']] },
    { nodePubkey: PUBKEY, spans: Array.from({ length: SPAN_LIMIT + 1 }, () => ['2026-10-01T00:00:00.000Z', '2026-10-01T00:00:00.000Z']) }])
    expect(() => UsageStore.parse(JSON.stringify({ schema: 1, dropped: 0, entries: [], coverage: [week(1)], coverageSpans: [bad] }))).toThrow('invalid usage file');
  // A clock that steps backwards never makes spans overlap.
  const skew = new UsageStore();
  skew.beginCoverage(PUBKEY, new Date('2026-10-01T10:00:00Z'));
  skew.endCoverage(PUBKEY, new Date('2026-10-01T11:00:00Z'));
  skew.beginCoverage(PUBKEY, new Date('2026-10-01T10:30:00Z'));
  skew.endCoverage(PUBKEY, new Date('2026-10-01T11:30:00Z'));
  expect(skew.coveredSince(PUBKEY, 0)).toBe(5_400);
});

it('RECOMMEND/schema refusals at every step and a recommendation validate against the shipped schema', async () => {
  const s = setup([entry('app1', '4294967341', ['info:read'])], [record('id:1111111111111111', '4294967341', '/lnrpc.Lightning/GetInfo', 3)]);
  const ok = await run(['app1', ...s.args], s.deps);
  expect(ok).toMatchObject({ ok: true, result: { commands: [expect.stringMatching(/^macwarden bake /), expect.any(String)] } });
  const refusals = [
    await run([...s.args], s.deps),
    await run(['app1', ...s.args.filter(arg => arg !== '--lnd-rest' && arg !== 'localhost:18080')], { ...s.deps, env: {} }),
    await run(['app1', ...s.args.map(arg => arg.endsWith('tls.cert') ? join(s.dir, 'missing.cert') : arg)], s.deps),
    await run(['app1', ...s.args], { ...s.deps, lnd: { getInfo: async () => { throw new LndError(4, 'transport', 'connect ECONNREFUSED'); } } as never }),
    await run(['nobody', ...s.args], s.deps),
  ];
  expect(refusals.map(result => result.error?.step)).toEqual(['R1', 'R1', 'R3', 'R5', 'R6']);
});
