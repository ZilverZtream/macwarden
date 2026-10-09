import { createHash, createHmac } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect, it } from 'vitest';
import { findLeaks } from "./helpers/leak-check.js";
import { captureMain } from './support/capture.js';

const repo = resolve();
const tempRoot = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = tempRoot;
const validateScan = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(JSON.parse(
  readFileSync(join(repo, 'schemas/output/scan.schema.json'), 'utf8')));
const validateInspect = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(JSON.parse(
  readFileSync(join(repo, 'schemas/output/inspect.schema.json'), 'utf8')));
const readonly = () => readFileSync(join(repo, 'test/vectors/default-readonly.macaroon'));

async function temp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(tempRoot, { recursive: true });
  const dir = mkdtempSync(join(tempRoot, 'cp011-review-'));
  try { return await work(dir); }
  finally { rmSync(dir, { recursive: true, force: true }); }
}

function packet(kind: number, data: Buffer): Buffer {
  const length: number[] = [];
  let n = data.length;
  do { length.push((n & 127) | (n >= 128 ? 128 : 0)); n = Math.floor(n / 128); } while (n);
  return Buffer.concat([Buffer.from([kind, ...length]), data]);
}

function caveated(base: Buffer, condition: string): Buffer {
  let at = 1;
  for (const expected of [1, 2]) {
    const kind = base[at++];
    let length = 0, scale = 1, byte: number;
    do { byte = base[at++]; length += (byte & 127) * scale; scale *= 128; } while (byte & 128);
    if (kind !== expected) throw new Error('unexpected reference packet');
    at += length;
  }
  if (base[at] !== 0 || base[at + 1] !== 0 || base[at + 2] !== 6 ||
      base[at + 3] !== 32 || at + 36 !== base.length)
    throw new Error('unexpected reference signature');
  const caveat = Buffer.from(condition, 'utf8');
  const signature = createHmac('sha256', base.subarray(at + 4)).update(caveat).digest();
  return Buffer.concat([base.subarray(0, at + 1), packet(2, caveat), Buffer.from([0, 0]),
    packet(6, signature)]);
}

async function cli(args: string[]) {
  const { main } = await import('../src/cli.js');
  return captureMain(main, args);
}

function json(run: Awaited<ReturnType<typeof cli>>) {
  let value: unknown;
  try { value = JSON.parse(run.stdout); } catch { throw new Error('stdout is not one JSON document'); }
  expect(run.stderr).toBe('');
  return value as { ok: boolean; result: { caveats: { value: string }[];
    findings: { path: string; kind: string; caveats: { value: string }[] | null }[];
    skipped: { path: string; reason: string }[] } };
}

function assertNoSecret(value: unknown, secret: Buffer, sentinelDir: string) {
  const rendered = typeof value === 'string' ? value : JSON.stringify(value);
  for (const encoding of ['hex', 'base64', 'base64url'] as const) {
    expect(rendered.includes(secret.toString(encoding)), 'confirmed secret encoding exposed').toBe(false);
  }
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
    commandOutput: rendered, testTmp: tempRoot, root: repo }), 'registered credential exposed').toBeNull();
}

function nwc(secret: Buffer) {
  return `nostr+walletconnect://${'22'.repeat(32)}?secret=${secret.toString('hex')}`;
}

it('CP-011/B14 inspect redacts a separate low-entropy encoding of a confirmed NWC secret', async () => temp(async dir => {
  const secret = Buffer.alloc(32, 0x11);
  const sentinelDir = join(dir, 'sentinels'); mkdirSync(sentinelDir);
  writeFileSync(join(sentinelDir, 'nwc.bin'), secret);
  const outer = caveated(readonly(), `lnd-custom safe-left ${nwc(secret)} safe-middle ${secret.toString('base64url')} safe-right`);
  writeFileSync(join(sentinelDir, 'outer.macaroon'), outer);
  const path = join(dir, 'outer.macaroon'); writeFileSync(path, outer);
  const run = await cli(['inspect', path, '--json']);
  expect(run.code).toBe(0);
  const document = json(run);
  expect(document.result.caveats[0].value.includes('safe-left [redacted] safe-middle [redacted] safe-right'),
    'inspect caveat redaction').toBe(true);
  assertNoSecret(document, secret, sentinelDir);
  assertNoSecret(run.stdout + run.stderr, secret, sentinelDir);
}));

it('CP-011/B16 scan redacts low-entropy NWC encodings in decoded facts and JSON output', async () => temp(async dir => {
  const secret = Buffer.alloc(32, 0x11);
  const sentinelDir = join(dir, 'sentinels'); mkdirSync(sentinelDir);
  writeFileSync(join(sentinelDir, 'nwc.bin'), secret);
  const outer = caveated(readonly(), `lnd-custom safe-left ${nwc(secret)} safe-middle ${secret.toString('base64')} safe-right`);
  writeFileSync(join(sentinelDir, 'outer.macaroon'), outer);
  const tree = join(dir, 'tree'); mkdirSync(tree);
  writeFileSync(join(tree, 'outer.macaroon'), outer);
  writeFileSync(join(tree, 'wallet.env'), nwc(secret));
  const run = await cli(['scan', tree, '--json']);
  expect(run.code).toBe(0);
  const document = json(run);
  expect(validateScan(document)).toBe(true);
  expect(document.result.findings.some(finding => finding.kind === 'nwc')).toBe(true);
  expect(document.result.findings.find(finding => finding.kind === 'macaroon-file')?.caveats?.[0].value
    .includes('safe-left [redacted] safe-middle [redacted] safe-right'),
  'scan caveat redaction').toBe(true);
  assertNoSecret(document.result.findings, secret, sentinelDir);
  assertNoSecret(run.stdout + run.stderr, secret, sentinelDir);
}));

it('CP-011/B14 scan preserves an unrelated high-entropy caveat exactly', async () => temp(async dir => {
  const ordinary = createHash('sha512').update('ordinary-cp011-review-value').digest('base64url').slice(0, 64);
  const condition = `lnd-custom ordinary ${ordinary}`;
  const path = join(dir, 'ordinary.macaroon');
  writeFileSync(path, caveated(readonly(), condition));
  const run = await cli(['scan', path, '--json']);
  expect(run.code).toBe(0);
  const document = json(run);
  expect(validateScan(document)).toBe(true);
  expect(document.result.findings).toHaveLength(1);
  expect(document.result.findings[0].caveats?.[0].value === `ordinary ${ordinary}`,
    'ordinary decoded caveat retained').toBe(true);
}));

function ordinaryBytes(): Buffer {
  for (let index = 0; index < 1000; index++) {
    const bytes = createHash('sha256').update(`ordinary-cp011-b14-${index}`).digest();
    const standard = bytes.toString('base64');
    if (standard.includes('+') && standard.includes('/')) return bytes;
  }
  throw new Error('ordinary-value generation failed');
}

const ordinary = ordinaryBytes();
const standard = ordinary.toString('base64');
const url = ordinary.toString('base64url');
const ordinaryForms = [
  { name: '43-character standard base64', value: standard.replace(/=+$/, ''), length: 43 },
  { name: '44-character standard base64', value: standard, length: 44 },
  { name: '43-character base64url', value: url, length: 43 },
  { name: '44-character base64url', value: `${url}=`, length: 44 },
  { name: '64-character lower hex', value: ordinary.toString('hex'), length: 64 },
  { name: '64-character upper hex', value: ordinary.toString('hex').toUpperCase(), length: 64 },
];

for (const form of ordinaryForms) for (const command of ['inspect', 'scan'] as const) {
  it(`CP-011/B14 ${command} preserves unconfirmed ${form.name} caveat values`, async () => temp(async dir => {
    expect(form.value.length).toBe(form.length);
    const value = `ordinary ${form.value}`;
    const path = join(dir, 'ordinary.macaroon');
    writeFileSync(path, caveated(readonly(), `lnd-custom ${value}`));

    const result = await cli([command, path, '--json']);
    expect(result.code).toBe(0);
    const document = json(result);
    expect(command === 'scan' ? validateScan(document) : validateInspect(document)).toBe(true);
    const caveat = command === 'scan' ? document.result.findings[0]?.caveats?.[0]
      : document.result.caveats[0];
    const rendered = await cli([command, path]);
    expect(rendered.code).toBe(0);
    expect(rendered.stderr).toBe('');
    expect.soft(caveat?.value === value, `${command} JSON caveat must be verbatim`).toBe(true);
    if (command === 'inspect')
      expect.soft(rendered.stdout.includes(value), 'inspect text caveat must be verbatim').toBe(true);
  }));
}

it('CP-011/B16 scan redacts a confirmed NWC secret from finding paths in text and JSON', async () => temp(async dir => {
  const secret = Buffer.alloc(32, 0x11);
  const sentinelDir = join(dir, 'sentinels'); mkdirSync(sentinelDir);
  writeFileSync(join(sentinelDir, 'nwc.bin'), secret);
  const tree = join(dir, 'tree'); mkdirSync(tree);
  const named = join(tree, `${secret.toString('hex')}.env`);
  writeFileSync(named, nwc(secret));
  const normal = await cli(['scan', tree, '--json']);
  expect(normal.code).toBe(0);
  const document = json(normal);
  expect(validateScan(document)).toBe(true);
  expect(document.result.findings.some(finding => finding.kind === 'nwc')).toBe(true);
  assertNoSecret(document.result.findings, secret, sentinelDir);
  assertNoSecret(normal.stdout + normal.stderr, secret, sentinelDir);
  const text = await cli(['scan', tree]);
  expect(text.code).toBe(0);
  assertNoSecret(text.stdout + text.stderr, secret, sentinelDir);
}));

it('CP-011/B16 scan redacts a confirmed NWC secret from skipped paths', async () => temp(async dir => {
  const secret = Buffer.alloc(32, 0x11);
  const sentinelDir = join(dir, 'sentinels'); mkdirSync(sentinelDir);
  writeFileSync(join(sentinelDir, 'nwc.bin'), secret);
  const tree = join(dir, 'tree'); mkdirSync(tree);
  const blocked = join(tree, `${secret.toString('base64url')}.txt`);
  writeFileSync(blocked, 'ordinary text');
  writeFileSync(join(tree, 'wallet.env'), nwc(secret));
  const injected = { ...fs, open: (async (...args: Parameters<typeof fs.open>) => {
    if (String(args[0]) === blocked) throw Object.assign(new Error('access refused'), { code: 'EACCES' });
    return fs.open(...args);
  }) as typeof fs.open };
  const command = await import('../src/commands/scan.js');
  const result = await command.run([tree, '--json'], { fs: injected });
  expect(result.ok).toBe(true);
  expect(((result.result && 'skipped' in result.result ? result.result.skipped : undefined) as { reason: string }[] | undefined)?.some(item => item.reason === 'unreadable')).toBe(true);
  assertNoSecret(result.result && 'skipped' in result.result ? result.result.skipped : undefined, secret, sentinelDir);
  const { render } = await import('./helpers/render-adversarial.js');
  assertNoSecret(render(result, 'json'), secret, sentinelDir);
}));

it('CP-011/B15 stdin consumes at most the first excess byte from one oversized chunk', async () => {
  const { readCredential } = await import('../src/input/index.js');
  const stdin = Readable.from([Buffer.alloc(2_097_152, 0x78)]);
  let consumed = 0;
  const originalRead = stdin.read.bind(stdin);
  stdin.read = ((size?: number) => {
    const chunk = originalRead(size);
    if (chunk) consumed += Buffer.byteLength(chunk);
    return chunk;
  }) as typeof stdin.read;
  let failure: { stage?: string } | undefined;
  try { await readCredential('-', { stdin, fs }, { unsafeArg: false }); }
  catch (error) { failure = error as { stage?: string }; }
  expect(failure?.stage).toBe('input-read');
  expect(consumed, 'raw stdin bytes consumed').toBeLessThanOrEqual(1_048_577);
});

it('CP-011/B4 scan text qualifies UNASSESSED as SPEND or worse', async () => temp(async dir => {
  const path = join(dir, 'unknown.macaroon');
  writeFileSync(path, readFileSync(join(repo, 'test/vectors/grade-unknown-entity.macaroon')));
  const run = await cli(['scan', path]);
  expect(run.code).toBe(0);
  expect(run.stdout.includes('UNASSESSED (treat as SPEND or worse)'),
    'UNASSESSED text qualifier').toBe(true);
}));
