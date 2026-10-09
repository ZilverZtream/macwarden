// Parser review 2026-10-08, MEDIUM-2: identifier shapes LND authorizes (an extra op with an
// empty entity or no actions, unknown protobuf groups, non-minimal tags, long entities, many
// ops or actions, many caveats) must never be refused and ignored. Within the decoder's
// memory bounds they decode exactly as LND expands them; past a bound the result fails closed
// (warning identifier-exceeds-bounds, grade UNASSESSED unless the kept permissions give ADMIN).
// Verdicts come from the LND v0.21.4 oracle recorded in test/vectors/lnd-oracle/m2.json.
import { createHash } from 'node:crypto';
import * as fs from 'node:fs/promises';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterAll, expect, it } from 'vitest';
import { run as inspect } from '../src/commands/inspect.js';
import { run as scan } from '../src/commands/scan.js';
import { DecodeError, decodeMacaroon, macaroonId } from '../src/decode/index.js';
import { grade, gradeFacts } from '../src/grade/index.js';
import type { ScanResult } from '../src/scan/index.js';
import { Secret } from '../src/secret.js';
import { LINEAR_4X, compare } from './helpers/growth.js';
import { m2 } from './vectors/lnd-oracle/cases.mjs';

type Run<T> = [T, number][];
type OracleCase = { name: string; sha256: string; length: number; lnd: {
  parse: boolean; verify: boolean; error: string | null; identifierSha256: string | null; storageId: string | null;
  ops: Run<string> | null; caveats: Run<{ location: string; id: string; vidLength: number }> | null;
  allow: Record<string, boolean> | null } };

const repo = resolve();
const fixture = JSON.parse(readFileSync(join(repo, 'test/vectors/lnd-oracle/m2.json'), 'utf8')) as { cases: OracleCase[] };
const built = m2() as Record<string, Buffer>;
const sha256 = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
const digest = (text: string) => text.length > 128 ? `sha256:${sha256(Buffer.from(text, 'utf8'))}:${text.length}` : text;
const expand = <T>(runs: Run<T>): T[] => runs.flatMap(([value, count]) => Array<T>(count).fill(value));
const bytesOf = (item: OracleCase): Buffer => {
  const bytes = built[item.name];
  expect(bytes && sha256(bytes), `${item.name} rebuilds the bytes the oracle judged`).toBe(item.sha256);
  return bytes;
};
const honoured = fixture.cases.filter(item => item.lnd.verify);
const refused = fixture.cases.filter(item => !item.lnd.verify);
const LADDER = ['READ', 'RECEIVE', 'OPERATE', 'SPEND', 'ADMIN'];
const scratch = mkdtempSync(join(resolve(process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp')), 'parsers-m2-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

it('PARSERS-M2/fixture covers every shape, and LND grants SPEND or ADMIN for each honoured one', () => {
  expect(Object.keys(built).sort()).toEqual(fixture.cases.map(item => item.name).sort());
  expect(honoured.length).toBeGreaterThanOrEqual(18);
  expect(refused.length).toBeGreaterThanOrEqual(8);
  for (const item of honoured) expect(item.lnd.allow?.['macaroon:generate'] || item.lnd.allow?.['offchain:write'], item.name).toBe(true);
});

it.each(honoured)('PARSERS-M2/$name is decoded, never refused, and graded no lower than LND authorizes', item => {
  const facts = decodeMacaroon(new Secret(bytesOf(item)));
  expect(facts.rootKeyId).toBe(BigInt(item.lnd.storageId!));
  expect(macaroonId(new Secret(bytesOf(item))).id).toBe(`id:${item.lnd.identifierSha256!.slice(0, 16)}`);
  expect(facts.caveats.map(caveat => digest(caveat.type === 'unknown' ? caveat.value : `${caveat.type} ${caveat.value}`)))
    .toEqual(expand(item.lnd.caveats!).slice(0, 4096).map(caveat => caveat.id));
  const lndPermissions = expand(item.lnd.ops!);
  const assessed = gradeFacts(facts);
  if (facts.warnings.includes('identifier-exceeds-bounds')) {
    // Fail closed: what was kept is exactly what LND expands first, and the grade never drops
    // below what LND authorizes (UNASSESSED fails every --fail-on threshold).
    expect(lndPermissions.slice(0, facts.permissions.length)).toEqual(facts.permissions.map(digest));
    expect(facts.permissions.length).toBeLessThan(lndPermissions.length);
    expect(['ADMIN', 'UNASSESSED']).toContain(assessed.grade);
    expect(assessed.warnings).toContain('identifier-exceeds-bounds');
  } else {
    expect(facts.permissions.map(digest)).toEqual(lndPermissions);
  }
  const lndGrade = grade(lndPermissions).grade;
  if (assessed.grade !== 'UNASSESSED' && lndGrade !== 'UNASSESSED')
    expect(LADDER.indexOf(assessed.grade)).toBeGreaterThanOrEqual(LADDER.indexOf(lndGrade));
  if (lndGrade === 'ADMIN') expect(['ADMIN', 'UNASSESSED']).toContain(assessed.grade);
});

it.each(refused)('PARSERS-M2/$name is refused as LND refuses it', item => {
  let thrown: unknown;
  try { decodeMacaroon(new Secret(bytesOf(item))); } catch (error) { thrown = error; }
  expect(thrown).toBeInstanceOf(DecodeError);
  expect((thrown as DecodeError).stage).toBe('identifier-proto');
});

it('PARSERS-M2/the fail-closed cases are the ones past a bound, with the kept facts intact', () => {
  const warned = (name: string) => decodeMacaroon(new Secret(built[name])).warnings;
  for (const name of ['2000 ops (exceeds 1,024 permissions)', 'admin after 1,024 permissions',
    'admin after 64 KiB of permission text', 'extra op with 17-byte entity', 'extra op with 300-byte action'])
    expect(warned(name), name).toContain('identifier-exceeds-bounds');
  for (const name of ['257 ops', '600 actions in one op', 'extra op with empty entity', 'groups nested 10001 deep'])
    expect(warned(name), name).not.toContain('identifier-exceeds-bounds');
  expect(warned('4097 caveats')).toEqual(['caveats-exceed-bounds']);
  // Bounds hold: never more than 1,024 permissions or 64 KiB of permission text.
  for (const bytes of Object.values(built)) {
    let facts;
    try { facts = decodeMacaroon(new Secret(bytes)); } catch { continue; }
    expect(facts.permissions.length).toBeLessThanOrEqual(1024);
    expect(facts.permissions.reduce((total, value) => total + Buffer.byteLength(value), 0)).toBeLessThanOrEqual(65_536);
    expect(facts.caveats.length).toBeLessThanOrEqual(4096);
  }
  // A truncated list whose kept part is below ADMIN still fails closed; one with ADMIN stays ADMIN.
  expect(gradeFacts({ permissions: ['info:read'], warnings: ['identifier-exceeds-bounds'] }).grade).toBe('UNASSESSED');
  expect(gradeFacts({ permissions: ['macaroon:generate'], warnings: ['identifier-exceeds-bounds'] }).grade).toBe('ADMIN');
  expect(gradeFacts({ permissions: [], warnings: ['identifier-exceeds-bounds'] }).warnings).toEqual(['identifier-exceeds-bounds']);
});

it('PARSERS-M2/inspect and scan report an over-bound credential instead of an undecodable one', async () => {
  const dir = mkdtempSync(join(scratch, 'scan-'));
  const bytes = built['admin after 1,024 permissions'];
  writeFileSync(join(dir, 'backdoor.macaroon'), bytes);
  writeFileSync(join(dir, 'over.env'), `MAC=${built['2000 ops (exceeds 1,024 permissions)'].toString('hex')}\n`);
  const result = (await scan([dir, '--json', '--fail-on', 'ADMIN'], { fs }));
  const findings = (result.result as ScanResult).findings;
  expect(result.exitCode).toBe(1);
  expect(findings.map(finding => [finding.kind, finding.grade, finding.warnings.includes('identifier-exceeds-bounds')]).sort())
    .toEqual([['macaroon-file', 'UNASSESSED', true], ['macaroon-hex', 'ADMIN', true]]);
  const output = await inspect([join(dir, 'backdoor.macaroon'), '--json'], { fs, clock: () => new Date('2026-10-08T12:00:00Z') } as never);
  expect(output).toMatchObject({ ok: true, result: { grade: 'UNASSESSED', rootKeyId: '0' } });
  expect((output.result as { warnings: string[] }).warnings).toContain('identifier-exceeds-bounds');
});

it('PARSERS-M2/decode stays small at the input limit and its cost grows linearly to it', async () => {
  // A 1 MiB identifier of nested groups, and a 1 MiB identifier of one-byte actions: both are
  // walked once; the permission text kept stays within 64 KiB. Cost is measured as growth from a
  // quarter of the limit, not against a fixed limit: walking groups or actions more than once
  // would cost sixteen times as much for four times the input.
  const tag = (field: number, wire: number) => Buffer.from([(field << 3) | wire]);
  const field = (number: number, value: Buffer) => {
    const length: number[] = []; let n = value.length;
    do { let d = n % 128; n = Math.floor(n / 128); if (n) d |= 0x80; length.push(d); } while (n);
    return Buffer.concat([Buffer.from([number << 3 | 2]), Buffer.from(length), value]);
  };
  const lengthOf = (n: number) => { const out: number[] = []; do { let d = n % 128; n = Math.floor(n / 128); if (n) d |= 0x80; out.push(d); } while (n); return Buffer.from(out); };
  // scale 4 is the limit: 10,001 nested groups and 300,000 actions.
  const build = (scale: number) => {
    const groupCount = Math.round(10_001 * scale / 4);
    const groups = Buffer.concat([...Array(groupCount).fill(tag(10, 3)), ...Array(groupCount).fill(tag(10, 4))]);
    const actions = Buffer.concat(Array.from({ length: 75_000 * scale }, () => Buffer.from([0x12, 1, 0x72])));
    const identifier = Buffer.concat([Buffer.from([3]), field(2, Buffer.from('0')),
      field(3, Buffer.concat([field(1, Buffer.from('e'.repeat(16))), actions])), groups]);
    return Buffer.concat([Buffer.from([2, 2]), lengthOf(identifier.length), identifier, Buffer.from([0, 0, 6, 32]), Buffer.alloc(32, 1)]);
  };
  const mac = build(4);
  expect(mac.length).toBeLessThanOrEqual(1_048_576);
  const before = process.memoryUsage().heapUsed;
  const facts = decodeMacaroon(new Secret(mac));
  expect(facts.permissions.length).toBe(1024);
  expect(facts.warnings).toContain('identifier-exceeds-bounds');
  expect(process.memoryUsage().heapUsed - before).toBeLessThan(64 * 1024 * 1024);
  const quarter = build(1);
  const timing = await compare(() => decodeMacaroon(new Secret(quarter)), () => decodeMacaroon(new Secret(mac)), 5);
  console.log(`PARSERS-M2 decode at a quarter of the limit and at the limit: ${timing.summary}`);
  expect(timing.ratio, timing.summary).toBeLessThan(LINEAR_4X);
}, 60_000);
