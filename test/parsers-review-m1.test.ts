// Parser review 2026-10-08, MEDIUM-1: LND (go-macaroon v2.0.0) reads packet kinds,
// lengths and end-of-section markers with binary.Uvarint, so anyone holding a macaroon
// can re-frame it (non-minimal varints, 0x80 0x00 as end-of-section) without the root
// key and LND still honours it. Verdicts come from the LND v0.21.4 oracle recorded in
// test/vectors/lnd-oracle/m1.json; the synthetic bytes are rebuilt from cases.mjs.
import { createHash } from 'node:crypto';
import * as fs from 'node:fs/promises';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { join, resolve } from 'node:path';
import { afterAll, expect, it } from 'vitest';
import { withCancellation } from '../src/cancellation.js';
import { run as scan } from '../src/commands/scan.js';
import { run as watch, type Register } from '../src/commands/watch.js';
import { redactEncodedCredentials } from '../src/credential-recognition.js';
import { DecodeError, decodeMacaroon, macaroonId } from '../src/decode/index.js';
import type { MiddlewareCall } from '../src/lnd/index.js';
import type { ScanResult } from '../src/scan/index.js';
import { Secret } from '../src/secret.js';
import { m1 } from './vectors/lnd-oracle/cases.mjs';

type Run<T> = [T, number][];
type OracleCase = { name: string; sha256: string; length: number; lnd: {
  parse: boolean; verify: boolean; error: string | null; location: string | null; identifierSha256: string | null;
  canonicalSha256: string | null; storageId: string | null; ops: Run<string> | null;
  caveats: Run<{ location: string; id: string; vidLength: number }> | null } };

const repo = resolve();
const fixture = JSON.parse(readFileSync(join(repo, 'test/vectors/lnd-oracle/m1.json'), 'utf8')) as { cases: OracleCase[] };
const built = m1() as Record<string, Buffer>;
const sha256 = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
const expand = <T>(runs: Run<T>): T[] => runs.flatMap(([value, count]) => Array<T>(count).fill(value));
const bytesOf = (item: OracleCase): Buffer => {
  const bytes = built[item.name];
  expect(bytes && sha256(bytes), `${item.name} rebuilds the bytes the oracle judged`).toBe(item.sha256);
  return bytes;
};
const accepted = fixture.cases.filter(item => item.lnd.parse);
const rejected = fixture.cases.filter(item => !item.lnd.parse);
const scratch = mkdtempSync(join(resolve(process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp')), 'parsers-m1-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

it('PARSERS-M1/fixture covers every re-framing and the oracle accepts them with full authority', () => {
  expect(Object.keys(built).sort()).toEqual(fixture.cases.map(item => item.name).sort());
  expect(accepted.length).toBeGreaterThanOrEqual(13);
  expect(rejected.length).toBeGreaterThanOrEqual(5);
  for (const item of accepted.filter(value => !value.name.startsWith('third-party')))
    expect(item.lnd.verify, `${item.name}: LND honours it`).toBe(true);
});

it.each(accepted)('PARSERS-M1/$name decodes to the facts LND parses and enforces', item => {
  const facts = decodeMacaroon(new Secret(bytesOf(item)));
  expect(facts.rootKeyId).toBe(BigInt(item.lnd.storageId!));
  if (item.lnd.ops) expect(facts.permissions).toEqual(expand(item.lnd.ops));
  else expect(facts.permissions).toEqual(['onchain:read', 'onchain:write', 'offchain:read', 'offchain:write', 'macaroon:generate']);
  expect(facts.location ?? '').toBe(item.lnd.location);
  const caveats = expand(item.lnd.caveats!);
  expect(facts.caveats.map(caveat => caveat.type === 'third-party' ? `third-party@${caveat.value}`
    : caveat.type === 'unknown' ? caveat.value : `${caveat.type} ${caveat.value}`))
    .toEqual(caveats.map(caveat => caveat.vidLength > 0 ? `third-party@${caveat.location}` : caveat.id));
  // One credential, one fingerprint: the canonical form (go-macaroon's MarshalBinary).
  expect(facts.fingerprint).toBe(`fp:${item.lnd.canonicalSha256!.slice(0, 16)}`);
  expect(macaroonId(new Secret(bytesOf(item))).id).toBe(`id:${item.lnd.identifierSha256!.slice(0, 16)}`);
});

it.each(rejected)('PARSERS-M1/$name is refused as LND refuses it', item => {
  let thrown: unknown;
  try { decodeMacaroon(new Secret(bytesOf(item))); } catch (error) { thrown = error; }
  expect(thrown).toBeInstanceOf(DecodeError);
  expect((thrown as DecodeError).stage).toBe('packet');
  expect(() => macaroonId(new Secret(bytesOf(item)))).toThrow(DecodeError);
});

it('PARSERS-M1/re-framed copies share the canonical copy\'s fingerprint and credential ID; canonical bytes hash unchanged', () => {
  const canonical = built.canonical;
  const canonicalFacts = decodeMacaroon(new Secret(canonical));
  expect(canonicalFacts.fingerprint).toBe(`fp:${sha256(canonical).slice(0, 16)}`);
  expect(new Secret(canonical).fingerprint).toBe(canonicalFacts.fingerprint);
  const reframed = accepted.filter(item => !item.name.startsWith('third-party') && item.name !== 'canonical'
    && !item.name.startsWith('empty location') && !item.name.includes('no location'));
  expect(reframed.length).toBeGreaterThanOrEqual(8);
  for (const item of reframed) {
    const secret = new Secret(bytesOf(item));
    expect(secret.fingerprint, item.name).toBe(canonicalFacts.fingerprint);
    expect(macaroonId(secret), item.name).toEqual(macaroonId(new Secret(canonical)));
  }
});

it('PARSERS-M1/scan grades re-framed .macaroon files and output redaction recognises re-framed hex', async () => {
  const dir = mkdtempSync(join(scratch, 'scan-'));
  const names = ['canonical', 'all kinds non-minimal', 'all lengths padded to 10 bytes', 'end-of-section as 0x80 0x00',
    'every varint non-minimal'];
  names.forEach((name, index) => writeFileSync(join(dir, `copy-${index}.macaroon`), built[name]));
  const output = await scan([dir, '--json'], { fs });
  expect(output.ok).toBe(true);
  const findings = (output.result as ScanResult).findings;
  expect(findings).toHaveLength(names.length);
  const expected = decodeMacaroon(new Secret(built.canonical)).fingerprint;
  for (const finding of findings) expect(finding).toMatchObject({ kind: 'macaroon-file', grade: 'ADMIN', fingerprint: expected, rootKeyId: '1234' });
  for (const name of names) {
    const hex = built[name].toString('hex');
    const redacted = redactEncodedCredentials(`left ${hex} right`);
    expect(redacted, name).toBe('left [redacted] right');
  }
});

it('PARSERS-M1/watch attributes re-framed copies to the same credential and labelled root key', async () => {
  mkdirSync(join(repo, 'test/.tmp'), { recursive: true });
  const dir = mkdtempSync(join(scratch, 'watch-'));
  const pubkey = `02${'ab'.repeat(32)}`;
  const registry = join(dir, 'registry.json');
  writeFileSync(registry, JSON.stringify({ schema: 1, entries: [{ nodePubkey: pubkey, label: 'app1', rootKeyId: '1234',
    permissions: ['info:read'], caveats: [], grade: 'READ', fingerprint: 'fp:0123456789abcdef', outPath: null,
    createdAt: '2026-10-01T00:00:00Z', verified: true, status: 'active', revokedAt: null, revokeEvidence: null,
    replaces: null, replacedBy: null }] }));
  writeFileSync(join(dir, 'tls.cert'), 'not used by the fake middleware');
  writeFileSync(join(dir, 'own.macaroon'), readFileSync(join(repo, 'test/vectors/default-admin.macaroon')));
  let decide!: (call: MiddlewareCall) => string;
  let ready!: () => void;
  const registered = new Promise<void>(done => { ready = done; });
  const register = ((_target, _registration, decider, onRegistered) => {
    decide = decider;
    let end!: (value: never) => void;
    const ended = new Promise(done => { end = done as never; });
    queueMicrotask(() => { onRegistered(); ready(); });
    return { ended, close: () => end({ registered: true, code: 4, stage: 'middleware-stream', message: 'closed', disabled: false } as never) };
  }) as Register;
  const lines: string[] = [];
  const controller = new AbortController();
  const names = ['canonical', 'all kinds non-minimal', 'end-of-section padded to 10 bytes', 'every varint non-minimal'];
  const result = withCancellation(controller.signal, () => watch(['--lnd-rest', 'localhost:18080', '--tls-cert', join(dir, 'tls.cert'),
    '--macaroon', join(dir, 'own.macaroon'), '--registry', registry, '--json'], {
    lnd: { getInfo: async () => ({ pubkey, alias: 'fixture', network: 'regtest', version: '0.21.4-beta' }) } as never,
    register, fs, env: {}, clock: () => new Date('2026-10-08T12:00:00Z'), emit: line => { lines.push(line); },
    alert: async () => {}, sleep: async () => {}, hostname: () => hostname(), pid: process.pid,
  }));
  await registered;
  names.forEach((name, index) => decide({ kind: 'request', requestId: BigInt(index + 1), method: '/lnrpc.Lightning/GetInfo',
    isError: false, customCaveatCondition: '', macaroon: new Secret(built[name]) }));
  await new Promise(done => setTimeout(done, 50));
  controller.abort();
  expect(await result).toMatchObject({ ok: true, result: { calls: names.length, credentials: 1 } });
  const calls = lines.map(line => JSON.parse(line) as { event: string; credential?: string; rootKeyId?: string; label?: string | null })
    .filter(event => event.event === 'call');
  const expected = macaroonId(new Secret(built.canonical)).id;
  expect(calls.map(event => [event.credential, event.rootKeyId, event.label]))
    .toEqual(names.map(() => [expected, '1234', 'app1']));
});
