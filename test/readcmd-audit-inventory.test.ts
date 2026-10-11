// Pre-1.4 audit (READCMD): inventory and its access review report incomplete or unreadable
// usage, render large tables in linear time, never show hidden characters on stdout, keep
// `expires` within RFC 3339.
import { writeFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { run as inventory } from '../src/commands/inventory.js';
import { inventoryResult, render, type InventoryResult } from '../src/output/index.js';
import { buildAccessReview, formatAccessReview, REPORT_FORMATS } from '../src/report/access-review.js';
import { usagePath } from '../src/watch/usage.js';
import { entry, fixture, oldId, ownId } from './helpers/cp038-online.js';
import { expectSchemaValid } from './helpers/output-schema.js';

const bobId = 4294967401n;
type Row = InventoryResult['rootKeys'][number];
const rowsOf = (output: Awaited<ReturnType<typeof inventory>>) => (output.result as InventoryResult).rootKeys;
const codes = (output: Awaited<ReturnType<typeof inventory>>) => output.warnings.map(item => typeof item === 'string' ? item : item.code);

function setup(usage?: object | string) {
  const f = fixture();
  f.save([f.old, entry(bobId, 'Bob')]);
  f.lnd.ids = [0n, ownId, oldId, bobId];
  if (usage !== undefined) writeFileSync(usagePath(f.registry), typeof usage === 'string' ? usage : JSON.stringify(usage));
  return f;
}
const aliceRecord = (changes: object = {}) => ({ nodePubkey: entry(oldId).nodePubkey, credential: 'id:aaaaaaaaaaaaaaaa',
  rootKeyId: String(oldId), method: '/lnrpc.Lightning/GetInfo', calls: 1, errors: 0, firstSeen: '2026-10-03T08:00:00Z',
  lastSeen: '2026-10-03T08:00:00Z', ...changes });

it('READCMD-02 the text table stays linear: 40,000 expired and pending-replacement rows render quickly', () => {
  const base = { grade: 'READ', permissions: [], caveats: [], createdAt: '2026-09-01T00:00:00Z', fingerprint: null, outPath: null,
    replacedBy: null };
  const rows: Row[] = [];
  for (let i = 0; i < 20_000; i++) {
    const id = String(4294967296 + 2 * i);
    rows.push({ rootKeyId: id, inLnd: true, flags: ['expired', 'pending-replacement'], verify: 'not-checked', expires: '2026-09-02T00:00:00Z',
      entry: { ...base, label: `app${i}`, status: 'active', replaces: null } } as Row);
    rows.push({ rootKeyId: String(4294967297 + 2 * i), inLnd: true, flags: ['replacement'], verify: 'not-checked', expires: null,
      entry: { ...base, label: `app${i}`, status: 'active', replaces: id } } as Row);
  }
  const started = performance.now();
  const text = render(inventoryResult({ node: { pubkey: `02${'ab'.repeat(32)}`, alias: 'n', network: 'regtest', version: 'v' }, rootKeys: rows },
    [], new Date('2026-10-08T00:00:00Z')), 'text');
  const elapsed = performance.now() - started;
  // Quadratic, this took about 16 s on the audit machine (over 100 s under load); linear, a few seconds at most.
  expect(elapsed).toBeLessThan(10_000);
  // The label names two active entries (original and replacement), so revoke takes the ID.
  expect(text).toContain('expired; revoke with: macwarden revoke 4294967296; rotation staged -> 4294967297');
}, 180_000);

it('READCMD-03 inventory warns usage-incomplete and the access review marks usage incomplete', async () => {
  const f = setup({ schema: 1, dropped: 0, evictions: 5, lastEviction: '2026-10-04T00:00:00Z', entries: [aliceRecord()] });
  const output = await inventory(['--report', 'json', ...f.flags], f.deps);
  expectSchemaValid(output);
  expect(codes(output)).toContain('usage-incomplete');
  const review = (output.result as InventoryResult).report!.review;
  const control = review.controls.find(item => item.control === 'Usage evidence');
  expect(control?.observation).toContain('5 records evicted');
  expect(control?.rootKeyIds).toContain(String(bobId));
  const markdown = render(await inventory(['--report', 'markdown', ...f.flags], f.deps), 'text');
  expect(markdown.split('\n').find(line => line.startsWith(`| ${bobId} |`))).toContain('| not observed \\(usage incomplete\\) |');
  const csv = render(await inventory(['--report', 'csv', ...f.flags], f.deps), 'text');
  expect(csv.split('\r\n').find(line => line.startsWith(`${bobId},`))).toContain('Usage evidence');
  // Complete usage adds neither the warning nor the control.
  const complete = setup({ schema: 1, dropped: 0, entries: [aliceRecord()] });
  const clean = await inventory(['--report', 'json', ...complete.flags], complete.deps);
  expect(codes(clean)).not.toContain('usage-incomplete');
  expect((clean.result as InventoryResult).report!.review.controls.map(item => item.control)).not.toContain('Usage evidence');
});

it('READCMD-03 an unreadable usage file makes the access review say usage is unavailable, not "not observed"', async () => {
  const f = setup('{"schema":1,"dropped":0,"entries":[{"oops":1}]}');
  const output = await inventory(['--report', 'markdown', ...f.flags], f.deps);
  expect(codes(output)).toContain('usage-unreadable');
  const markdown = render(output, 'text');
  expect(markdown.split('\n').find(line => line.startsWith(`| ${bobId} |`))).toContain('| usage unreadable |');
  expect(markdown).toContain('### Usage evidence');
});

const HIDDEN = /[\u202a-\u202e\u2066-\u2069\u200b\u2028]/u;

it('READCMD-07 / CLI-04 the access review escapes bidirectional and invisible characters and ##[ in every format', async () => {
  const f = fixture();
  f.save([{ ...f.old, caveats: [{ type: 'unknown', value: 'pay\u202etxt.exe \u2066x\u2069 zero\u200bwidth line\u2028sep ##[error]x' }] }]);
  f.lnd.ids = [0n, ownId, oldId];
  f.lnd.info = { ...f.lnd.info, alias: 'node\u202eevil' };
  for (const format of REPORT_FORMATS) {
    const output = await inventory(['--report', format, ...f.flags], f.deps);
    expect(output.error).toBeNull();
    const text = render(output, 'text');
    expect(text).not.toMatch(HIDDEN);
    expect(text).not.toContain('##[');
    expect(text).toContain('202e');
    if (format === 'json') expect(JSON.parse(text).kind).toBe('macwarden-access-review');
    if (format === 'csv') expect(text.endsWith('\r\n')).toBe(true);
    // The file written with --out holds the same escaped text.
    const review = buildAccessReview({ node: f.lnd.info, ids: [String(oldId)], entries: [{ ...f.old,
      caveats: [{ type: 'unknown', value: 'a\u202eb ##[x' }] }], ownRootKeyId: String(ownId), now: new Date(), version: '0' });
    expect(formatAccessReview(review, format)).not.toMatch(HIDDEN);
    expect(formatAccessReview(review, format)).not.toContain('##[');
  }
});

it('READCMD-08 an expiry past year 9999 is unparseable: expires is null or RFC 3339 and the envelope validates', async () => {
  const f = fixture();
  f.save([{ ...f.old, caveats: [{ type: 'time-before', value: '9999-12-31T23:59:59-24:00' }] }]);
  f.lnd.ids = [0n, ownId, oldId];
  const output = await inventory(f.flags, f.deps);
  expectSchemaValid(output);
  const expires = rowsOf(output).find(row => row.rootKeyId === String(oldId))!.expires;
  expect(expires === null || /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(expires!)).toBe(true);
});

it('READCMD-11 the access review writes the expiry as a UTC instant, whatever the caveat\'s offset', async () => {
  const f = fixture();
  f.save([{ ...f.old, caveats: [{ type: 'time-before', value: '2027-01-01T01:00:00,5+01:00' }] }]);
  f.lnd.ids = [0n, ownId, oldId];
  const output = await inventory(['--report', 'json', ...f.flags], f.deps);
  const review = (output.result as InventoryResult).report!.review;
  expect(review.credentials.find(item => item.rootKeyId === String(oldId))!.expiresAt).toBe('2027-01-01T00:00:00Z');
});

it('READCMD-12 --json result.report.review is the escaped review the report holds', async () => {
  const f = fixture();
  f.save([{ ...f.old, caveats: [{ type: 'unknown', value: 'a\u202eb' }] }]);
  f.lnd.ids = [0n, ownId, oldId];
  const output = await inventory(['--report', 'json', ...f.flags], f.deps);
  const review = (output.result as InventoryResult).report!.review;
  expect(review.credentials.find(item => item.rootKeyId === String(oldId))!.caveats).toEqual(['unknown a\\u202eb']);
  expect(JSON.parse(render(output, 'text'))).toEqual(JSON.parse(JSON.stringify(review)));
});

it('READCMD-13 inventory takes the later instant as last use, not the later string', async () => {
  const f = setup({ schema: 1, dropped: 0, entries: [aliceRecord({ lastSeen: '2026-10-03T08:00:00.900Z' }),
    aliceRecord({ credential: 'id:bbbbbbbbbbbbbbbb', lastSeen: '2026-10-03T08:00:00Z' })] });
  const output = await inventory(f.flags, f.deps);
  expect(rowsOf(output).find(row => row.rootKeyId === String(oldId))!.usage?.lastUsed).toBe('2026-10-03T08:00:00.900Z');
  const review = (await inventory(['--report', 'json', ...f.flags], f.deps)).result as InventoryResult;
  expect(review.report!.review.credentials.find(item => item.rootKeyId === String(oldId))!.lastUsed).toBe('2026-10-03T08:00:00.900Z');
});
