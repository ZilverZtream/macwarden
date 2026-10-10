// MW110-05: usage evidence must hold real instants in a consistent order, and recommend must
// never print a narrowing command from an observation window it cannot compute.
import * as fs from 'node:fs/promises';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { run as recommend } from '../src/commands/recommend.js';
import { run as inventory } from '../src/commands/inventory.js';
import { render } from '../src/output/index.js';
import { UsageStore, usagePath } from '../src/watch/usage.js';
import { fixture } from './helpers/cp038-online.js';
import { expectSchemaValid } from './helpers/output-schema.js';

const repo = resolve();
const tmpRoot = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
const PUBKEY = `02${'ab'.repeat(32)}`;
const snapshot = JSON.parse(readFileSync(join(repo, 'src/grade/lnd-permissions.json'), 'utf8')) as { methods: Record<string, string[]> };
const dirs: string[] = [];
afterEach(() => { vi.restoreAllMocks(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

const entry = { nodePubkey: PUBKEY, label: 'app', rootKeyId: '18', permissions: ['info:read', 'offchain:read'], caveats: [],
  grade: 'READ', fingerprint: 'fp:0123456789abcdef', outPath: null, createdAt: '2026-09-30T00:00:00Z', verified: true,
  status: 'active', revokedAt: null, revokeEvidence: null, replaces: null, replacedBy: null };
const record = { nodePubkey: PUBKEY, credential: 'id:1111111111111111', rootKeyId: '18', method: '/lnrpc.Lightning/GetInfo',
  calls: 1, errors: 0, firstSeen: '2026-10-08T09:00:00Z', lastSeen: '2026-10-08T10:00:00Z' };
// Eight days of coverage: long enough to narrow when the evidence is valid.
const coverage = { nodePubkey: PUBKEY, firstStart: '2026-09-30T00:00:00Z', lastEnd: '2026-10-08T12:00:00Z', coveredSeconds: 8 * 86_400, sessions: 1 };
const canary = { nodePubkey: PUBKEY, rootKeyId: '77', uses: 1, firstUse: '2026-10-08T09:00:00Z', lastUse: '2026-10-08T10:00:00Z' };
const spans = { nodePubkey: PUBKEY, spans: [['2026-09-30T00:00:00Z', '2026-10-08T12:00:00Z']] };
const base = () => ({ schema: 1, dropped: 0, evictions: 0, lastEviction: null, droppedAttributions: 0, lastAttributionDrop: null,
  canaryUses: [{ ...canary }], coverage: [{ ...coverage }], coverageSpans: [structuredClone(spans)], entries: [{ ...record }] });
type File = ReturnType<typeof base>;

// Shaped like an instant, but not one: each calendar or clock field out of range.
const impossible = ['2026-99-09T12:00:00Z', '2026-00-09T12:00:00Z', '2026-13-01T00:00:00Z', '2026-02-29T00:00:00Z',
  '2026-02-30T00:00:00Z', '2026-04-31T00:00:00Z', '2026-10-00T00:00:00Z', '2026-10-32T00:00:00Z', '2026-10-08T24:00:00Z',
  '2026-10-08T23:60:00Z', '2026-10-08T23:59:60Z', '2026-10-08T99:00:00.000Z'];
// Every timestamp the usage file holds, with a setter that puts a value in that one place.
const places: [string, (file: File, value: string) => void][] = [
  ['entries.firstSeen', (file, value) => { file.entries[0].firstSeen = value; }],
  ['entries.lastSeen', (file, value) => { file.entries[0].lastSeen = value; }],
  ['canaryUses.firstUse', (file, value) => { file.canaryUses[0].firstUse = value; }],
  ['canaryUses.lastUse', (file, value) => { file.canaryUses[0].lastUse = value; }],
  ['coverage.firstStart', (file, value) => { file.coverage[0].firstStart = value; }],
  ['coverage.lastEnd', (file, value) => { file.coverage[0].lastEnd = value; }],
  ['coverageSpans.start', (file, value) => { file.coverageSpans[0].spans[0][0] = value; }],
  ['coverageSpans.end', (file, value) => { file.coverageSpans[0].spans[0][1] = value; }],
  ['lastEviction', (file, value) => { (file as Record<string, unknown>).lastEviction = value; }],
  ['lastAttributionDrop', (file, value) => { (file as Record<string, unknown>).lastAttributionDrop = value; }],
];
const variant = (place: (file: File, value: string) => void, value: string) => { const file = base(); place(file, value); return JSON.stringify(file); };

function setup(usage: string) {
  mkdirSync(tmpRoot, { recursive: true });
  const dir = mkdtempSync(join(tmpRoot, 'usage-evidence-'));
  dirs.push(dir);
  const registry = join(dir, 'registry.json');
  writeFileSync(registry, JSON.stringify({ schema: 1, entries: [entry] }));
  writeFileSync(usagePath(registry), usage);
  writeFileSync(join(dir, 'tls.cert'), 'unused');
  writeFileSync(join(dir, 'own.macaroon'), readFileSync(join(repo, 'test/vectors/default-admin.macaroon')));
  const deps = { lnd: { getInfo: async () => ({ pubkey: PUBKEY, alias: 'a', network: 'regtest', version: 'v' }),
    listPermissions: async () => snapshot.methods } as never, fs, env: {} };
  return { registry, deps, args: ['--lnd-rest', 'localhost:18080', '--tls-cert', join(dir, 'tls.cert'),
    '--macaroon', join(dir, 'own.macaroon'), '--registry', registry, '--json'] };
}

async function advise(usage: string, ...extra: string[]) {
  const s = setup(usage);
  const result = await recommend(['app', ...extra, ...s.args], s.deps);
  expectSchemaValid(result);
  return result;
}
const commandsOf = (result: Awaited<ReturnType<typeof advise>>) => (result.result as { commands: string[] } | null)?.commands ?? [];

it('USAGE/instants the baseline file is valid evidence: eight days observed, narrowing commands printed', async () => {
  const result = await advise(JSON.stringify(base()));
  expect(result.ok).toBe(true);
  expect(result.result).toMatchObject({ observation: { seconds: 8.5 * 86_400, short: false, accepted: false } });
  expect(commandsOf(result)).toHaveLength(2);
});

it('USAGE/instants an impossible date in any usage timestamp makes the file invalid', () => {
  for (const [name, place] of places) for (const value of impossible)
    expect(() => UsageStore.parse(variant(place, value)), `${name} = ${value}`).toThrow('invalid usage file');
});

it('USAGE/instants real edge instants and every legacy shape still parse', () => {
  // Leap day, end of month, end of day, fractions of any length, no fraction.
  for (const value of ['2028-02-29T00:00:00Z', '2000-02-29T12:00:00Z', '2026-04-30T23:59:59Z', '2026-12-31T23:59:59.999Z',
    '2026-10-08T12:00:00.123456789Z', '2026-10-08T12:00:00Z']) {
    const file = base();
    file.entries[0].firstSeen = file.entries[0].lastSeen = value;
    file.canaryUses[0].firstUse = file.canaryUses[0].lastUse = value;
    expect(() => UsageStore.parse(JSON.stringify(file)), value).not.toThrow();
  }
  // A 1.0.0 file (no counters, lists or coverage) and a 1.0.1 file (no spans) still read.
  expect(UsageStore.parse(JSON.stringify({ schema: 1, dropped: 0, entries: [record] })).size).toBe(1);
  const v101: Partial<File> = base();
  delete v101.coverageSpans;
  expect(UsageStore.parse(JSON.stringify(v101)).coverageFor(PUBKEY)).toMatchObject({ coveredSeconds: 8 * 86_400 });
});

it('USAGE/order a later-before-earlier pair makes the file invalid; equal instants are fine', () => {
  const reversed: [string, (file: File) => void][] = [
    ['firstSeen after lastSeen', file => { file.entries[0].firstSeen = '2026-10-08T11:00:00Z'; }],
    ['firstUse after lastUse', file => { file.canaryUses[0].firstUse = '2026-10-08T11:00:00Z'; }],
    ['firstStart after lastEnd', file => { file.coverage[0].firstStart = '2026-10-09T00:00:00Z'; }],
    ['span start after end', file => { file.coverageSpans[0].spans[0] = ['2026-10-08T12:00:00Z', '2026-09-30T00:00:00Z']; }],
    // Compared as instants, not text: 12:00:00.5Z is after 12:00:00Z although it sorts before it.
    ['fraction after whole second', file => { file.entries[0].firstSeen = '2026-10-08T10:00:00.5Z'; }],
  ];
  for (const [name, change] of reversed) {
    const file = base();
    change(file);
    expect(() => UsageStore.parse(JSON.stringify(file)), name).toThrow('invalid usage file');
  }
  const equal = base();
  equal.entries[0].firstSeen = equal.entries[0].lastSeen;
  equal.canaryUses[0].firstUse = equal.canaryUses[0].lastUse;
  expect(() => UsageStore.parse(JSON.stringify(equal))).not.toThrow();
});

it('RECOMMEND/invalid-evidence malformed usage dates or order withhold advice, even with --accept-short-observation', async () => {
  const cases: [string, string][] = [];
  for (const [name, place] of places) for (const value of ['2026-99-09T12:00:00Z', '2026-02-30T12:00:00Z', '2026-10-08T24:00:00Z'])
    cases.push([`${name} = ${value}`, variant(place, value)]);
  const reversed = base();
  reversed.coverage[0] = { ...coverage, firstStart: '2026-10-08T12:00:00Z', lastEnd: '2026-09-30T00:00:00Z' };
  cases.push(['coverage reversed', JSON.stringify(reversed)]);
  for (const [name, usage] of cases) for (const extra of [[], ['--accept-short-observation']]) {
    const result = await advise(usage, ...extra);
    expect(result, name).toMatchObject({ ok: false, error: { code: 3, step: 'R4', message: 'unreadable or invalid usage file' } });
    expect(commandsOf(result), name).toEqual([]);
  }
});

it('RECOMMEND/invalid-evidence an observation window that cannot be computed is never accepted as short', async () => {
  // Defence in depth, behind the parser: evidence that reaches the calculation and makes it
  // non-finite withholds the narrowing command; --accept-short-observation cannot accept it.
  const bad: [string, () => void][] = [
    ['lastEnd', () => vi.spyOn(UsageStore.prototype, 'coverageFor').mockReturnValue({ ...coverage, lastEnd: '2026-99-08T12:00:00Z' })],
    ['firstStart', () => vi.spyOn(UsageStore.prototype, 'coverageFor').mockReturnValue({ ...coverage, firstStart: 'not a time' })],
    ['coveredSeconds', () => vi.spyOn(UsageStore.prototype, 'coverageFor').mockReturnValue({ ...coverage, coveredSeconds: Number.NaN })],
    ['spans', () => vi.spyOn(UsageStore.prototype, 'coveredSince').mockReturnValue(Number.NaN)],
    ['firstSeen', () => vi.spyOn(UsageStore.prototype, 'forCredential').mockReturnValue([{ ...record, firstSeen: '2026-02-30T09:00:00Z!' }])],
  ];
  for (const [name, inject] of bad) for (const extra of [[], ['--accept-short-observation']]) {
    inject();
    const s = setup(JSON.stringify(base()));
    // Without an entry, creation is the first recorded use, so a bad firstSeen reaches the window.
    if (name === 'firstSeen') writeFileSync(s.registry, JSON.stringify({ schema: 1, entries: [] }));
    const result = await recommend([name === 'firstSeen' ? 'id:1111111111111111' : 'app', ...extra, ...s.args], s.deps);
    vi.restoreAllMocks();
    expectSchemaValid(result);
    expect(result.ok, name).toBe(true);
    expect(result.result, name).toMatchObject({ commands: [], observation: { seconds: null, short: true, accepted: false } });
    const codes = result.warnings.map(item => typeof item === 'string' ? item : item.code);
    expect(codes, name).toContain('observation-invalid');
    const text = render(result, 'text');
    expect(text, name).not.toContain('macwarden bake');
    expect(text, name).not.toContain('--accept-short-observation prints it');
  }
});

it('RECOMMEND/invalid-evidence a registry createdAt that is not a real instant makes the registry invalid', async () => {
  for (const createdAt of ['2026-02-30T00:00:00Z', '2026-10-08T24:00:00Z']) {
    const s = setup(JSON.stringify(base()));
    writeFileSync(s.registry, JSON.stringify({ schema: 1, entries: [{ ...entry, createdAt }] }));
    const result = await recommend(['app', ...s.args], s.deps);
    expect(result, createdAt).toMatchObject({ ok: false, error: { code: 3, step: 'R4', message: 'unreadable or invalid registry' } });
  }
});

it('INVENTORY/invalid-evidence the same malformed usage files are reported unreadable and add no usage', async () => {
  const forFixture = (usage: string, f: ReturnType<typeof fixture>) => usage.replaceAll(PUBKEY, f.old.nodePubkey)
    .replaceAll('"rootKeyId":"18"', `"rootKeyId":"${f.old.rootKeyId}"`).replaceAll('"rootKeyId":"77"', `"rootKeyId":"${f.old.rootKeyId}"`);
  const rowsOf = (output: Awaited<ReturnType<typeof inventory>>) =>
    (output.result as { rootKeys: { rootKeyId: string; usage?: unknown; canary?: unknown }[] }).rootKeys;
  // Control: the valid file adds usage and the canary record to the credential's row.
  const control = fixture();
  writeFileSync(usagePath(control.registry), forFixture(JSON.stringify(base()), control));
  const valid = await inventory(['--json', ...control.flags], control.deps);
  expect(valid.warnings.map(item => typeof item === 'string' ? item : item.code)).not.toContain('usage-unreadable');
  expect(rowsOf(valid).find(row => row.rootKeyId === control.old.rootKeyId)).toMatchObject({ usage: { calls: 1 }, canary: { uses: 1 } });
  for (const usage of [variant(places[1][1], '2026-99-09T12:00:00Z'), variant(places[5][1], '2026-02-30T00:00:00Z'),
    (() => { const file = base(); file.entries[0].firstSeen = '2026-10-08T11:00:00Z'; return JSON.stringify(file); })()]) {
    const f = fixture();
    writeFileSync(usagePath(f.registry), forFixture(usage, f));
    const output = await inventory(['--json', ...f.flags], f.deps);
    expectSchemaValid(output);
    expect(output.ok).toBe(true);
    expect(output.warnings.map(item => typeof item === 'string' ? item : item.code)).toContain('usage-unreadable');
    expect(rowsOf(output).every(row => row.usage === undefined && row.canary === undefined)).toBe(true);
  }
});

it('WATCH/usage-store a clock that steps back never writes a file the reader refuses', () => {
  const store = new UsageStore();
  const node = PUBKEY;
  store.record(node, 'id:1111111111111111', '18', '/lnrpc.Lightning/GetInfo', new Date('2026-10-08T12:00:00Z'));
  store.record(node, 'id:1111111111111111', '18', '/lnrpc.Lightning/GetInfo', new Date('2026-10-08T11:00:00Z'));
  store.recordCanary(node, '77', 1, new Date('2026-10-08T12:00:00Z'));
  store.recordCanary(node, '77', 1, new Date('2026-10-08T11:00:00Z'));
  store.beginCoverage(node, new Date('2026-10-08T12:00:00Z'));
  store.endCoverage(node, new Date('2026-10-08T12:30:00Z'));
  store.beginCoverage(node, new Date('2026-10-08T10:00:00Z'));
  store.extendCoverage(node, new Date('2026-10-08T09:00:00Z'));
  const copy = UsageStore.parse(store.toText());
  const [only] = copy.entries();
  expect(Date.parse(only.firstSeen)).toBeLessThanOrEqual(Date.parse(only.lastSeen));
  expect(only.calls).toBe(2);
  const used = copy.canaryUsesFor(node, '77')!;
  expect(Date.parse(used.firstUse)).toBeLessThanOrEqual(Date.parse(used.lastUse));
  const covered = copy.coverageFor(node)!;
  expect(Date.parse(covered.firstStart)).toBeLessThanOrEqual(Date.parse(covered.lastEnd));
});

// 1.2.1 (owner finding): the covered-seconds counter starts where the span starts, so a clock that
// stepped back between sessions cannot count time the spans already hold.
it('USAGE/coverage-rollback a registration that begins before the last span ended counts no covered second twice', () => {
  const store = new UsageStore();
  const t = (seconds: number) => new Date(Date.parse('2026-10-01T00:00:00Z') + seconds * 1_000);
  store.beginCoverage(PUBKEY, t(0));
  store.extendCoverage(PUBKEY, t(600));
  store.endCoverage(PUBKEY, t(600));
  // The clock steps back 300 s, watch reconnects, then the clock is corrected.
  store.beginCoverage(PUBKEY, t(300));
  store.extendCoverage(PUBKEY, t(900));
  store.endCoverage(PUBKEY, t(900));
  const record = store.coverageFor(PUBKEY)!;
  const spans = store.toText().includes('coverageSpans') ? (JSON.parse(store.toText()) as { coverageSpans: { spans: [string, string][] }[] }).coverageSpans[0].spans : [];
  const spanSeconds = spans.reduce((total, [from, to]) => total + (Date.parse(to) - Date.parse(from)) / 1_000, 0);
  expect(spanSeconds).toBe(900);
  expect(record.coveredSeconds).toBe(900);
  expect(record.sessions).toBe(2);
});
