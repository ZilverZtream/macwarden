import { createHash, createHmac } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect, it } from 'vitest';
import { captureMain } from './support/capture.js';
import { findLeaks } from "./helpers/leak-check.js";

const repo = resolve();
const vectors = join(repo, 'test/vectors');
const tempRoot = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = tempRoot;
const schema = JSON.parse(readFileSync(join(repo, 'schemas/output/scan.schema.json'), 'utf8'));
const validate = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(schema);
const references = JSON.parse(readFileSync(join(vectors, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string; expectedGrade: string }[] };
const reference = (name: string) => references.vectors.find(item => item.name === name)!;
const vector = (name: string) => readFileSync(join(vectors, `${name}.macaroon`));
const fp = (bytes: Buffer) => `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;
function temp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(tempRoot, { recursive: true });
  const dir = mkdtempSync(join(tempRoot, 'cp011-audit-'));
  return work(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}
async function cli(command: string, args: string[]) {
  const { main } = await import('../src/cli.js');
  return captureMain(main, [command, ...args]);
}
type AuditResult = { fingerprint?: string; caveats: { value: string }[];
  findings: { kind: string; fingerprint: string; grade: string | null;
    rootKeyId: string | null; permissions: string[] | null; caveats: { value: string }[] | null }[];
  summary: { dropped: number; byGrade: Record<string, number> };
  failOn: { threshold: string; count: number } | null };
function json(run: Awaited<ReturnType<typeof cli>>) {
  let value: unknown;
  try { value = JSON.parse(run.stdout); } catch { throw new Error('stdout is not one JSON document'); }
  expect(run.stderr).toBe('');
  return value as { ok: boolean; result: AuditResult; error: { code: number; step: string | null } | null };
}
function scanJson(run: Awaited<ReturnType<typeof cli>>) {
  const value = json(run);
  expect(validate(value)).toBe(true);
  return value;
}
function noLeaks(text: string, sentinelDir: string) {
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
    commandOutput: text, testTmp: tempRoot, root: repo }), 'credential leaked').toBeNull();
}

it('CP-011/B12 NWC fingerprints the later exact 32-byte secret and never an earlier overlong value', async () => temp(async dir => {
  const first = Buffer.alloc(33, 0x33);
  const later = Buffer.alloc(32, 0x44);
  const sentinelDir = join(dir, 'sentinels'); mkdirSync(sentinelDir);
  writeFileSync(join(sentinelDir, 'early.bin'), first);
  writeFileSync(join(sentinelDir, 'later.bin'), later);
  const path = join(dir, 'nwc.env');
  writeFileSync(path, `nostr+walletconnect://${'22'.repeat(32)}?secret=${first.toString('hex')}&secret=${later.toString('hex')}`);
  const expected = fp(later);
  expect(expected).not.toBe(fp(first.subarray(0, 32)));
  const run = await cli('scan', [path, '--json', '--fail-on', 'SPEND']);
  expect(run.code).toBe(1);
  const value = scanJson(run);
  expect(value.result.findings).toHaveLength(1);
  const finding = value.result.findings[0];
  expect([finding.kind, finding.fingerprint, finding.grade, finding.rootKeyId,
    finding.permissions, finding.caveats]).toEqual(['nwc', expected, null, null, null, null]);
  expect(value.result.summary.byGrade.NWC).toBe(1);
  expect(value.result.failOn).toEqual({ threshold: 'SPEND', count: 1 });
  noLeaks(JSON.stringify(value) + run.stdout + run.stderr, sentinelDir);
  const text = await cli('scan', [path, '--fail-on', 'SPEND']);
  expect(text.code).toBe(1);
  expect(text.stdout).toContain(expected);
  expect(text.stdout).toContain('(counted as SPEND)');
  noLeaks(text.stdout + text.stderr, sentinelDir);
}));

it('CP-011/B13 inspect and scan share strict one-pass canonical base64url URI parsing', async () => temp(async dir => {
  const bytes = vector('default-readonly');
  const url = bytes.toString('base64url');
  const padding = '='.repeat((4 - url.length % 4) % 4);
  const encoded = `%${url.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')}${url.slice(1).replace(/-/g, '%2D').replace(/_/g, '%5F')}`;
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const last = alphabet.indexOf(url.at(-1)!);
  const alteredLast = alphabet[(last & ~15) | ((last + 1) & 15)];
  const valid = [url, url + padding, encoded, encoded + padding];
  for (const form of valid) {
    const uri = `lndconnect://h:10009?macaroon=${form}`;
    const inspect = await cli('inspect', [uri, '--unsafe-arg', '--json']);
    expect(inspect.code, String(json(inspect).error?.step)).toBe(0);
    expect(json(inspect).result?.fingerprint).toBe(reference('default-readonly').fingerprint);
    const path = join(dir, 'uri.env'); writeFileSync(path, uri);
    const scan = await cli('scan', [path, '--json']);
    expect(scan.code).toBe(0);
    const result = scanJson(scan).result;
    expect(result.findings).toHaveLength(1);
    expect([result.findings[0].kind, result.findings[0].fingerprint])
      .toEqual(['lndconnect', reference('default-readonly').fingerprint]);
    expect(result.summary.dropped).toBe(0);
  }
  const invalid = [url + '===', `${url.slice(0, 10)}=${url.slice(10)}`,
    url.slice(0, -1) + alteredLast + padding, `${url}&macaroon=${url}`,
    url.replace(/-/g, '+').replace(/_/g, '/').replace(/A/, '+'),
    url.replace(/-/g, '%2B').replace(/_/g, '%2F').replace(/A/, '%2B'),
    `${url.slice(0, 2)}/${url.slice(3)}`, `${url.slice(0, 2)}%2F${url.slice(3)}`,
    `${url.slice(0, 20)} ${url.slice(20)}`, `${url}%20`, `${url}%0A`, `${url}%`,
    `%25${url}`, `${url}%253D`];
  for (const form of invalid) {
    const uri = `lndconnect://h:10009?macaroon=${form}`;
    const inspect = await cli('inspect', [uri, '--unsafe-arg', '--json']);
    expect(inspect.code).toBe(3);
    expect(json(inspect).error?.step).toBe('input-form');
    expect(inspect.stdout.includes(uri) || inspect.stderr.includes(uri)).toBe(false);
    const path = join(dir, 'uri.env'); writeFileSync(path, uri);
    const scan = await cli('scan', [path, '--json']);
    expect(scan.code).toBe(0);
    const result = scanJson(scan).result;
    // The URI is not accepted as lndconnect, as inspect refuses it. Since RR-01 a credential
    // inside a URI that does not parse is still reported on its own, decoded or as a candidate.
    expect(result.findings.filter(finding => finding.kind === 'lndconnect')).toEqual([]);
    for (const finding of result.findings)
      expect([finding.kind, finding.kind === 'undecodable-candidate' || finding.fingerprint === reference('default-readonly').fingerprint])
        .toEqual([expect.stringMatching(/^(macaroon-base64|undecodable-candidate)$/), true]);
    expect(result.summary.dropped).toBe(1);
  }
  const standard = await cli('inspect', [bytes.toString('base64'), '--unsafe-arg', '--json']);
  expect(standard.code).toBe(0);
  expect(json(standard).result?.fingerprint).toBe(reference('default-readonly').fingerprint);
}));

// This helper attenuates the stored vector using the documented v2 signature chain.
function packet(kind: number, data: Buffer) {
  const length: number[] = [];
  let n = data.length;
  do { length.push((n & 127) | (n >= 128 ? 128 : 0)); n = Math.floor(n / 128); } while (n);
  return Buffer.concat([Buffer.from([kind, ...length]), data]);
}
function caveated(base: Buffer, condition: string) {
  let at = 1;
  for (let i = 0; i < 2; i++) {
    const kind = base[at++];
    let length = 0, scale = 1, byte: number;
    do { byte = base[at++]; length += (byte & 127) * scale; scale *= 128; } while (byte & 128);
    if (kind !== i + 1) throw new Error('unexpected reference vector packet');
    at += length;
  }
  if (base[at] !== 0 || base[at + 1] !== 0 || base[at + 2] !== 6 || base[at + 3] !== 32)
    throw new Error('unexpected reference vector signature');
  const caveat = Buffer.from(condition, 'utf8');
  const signature = createHmac('sha256', base.subarray(at + 4)).update(caveat).digest();
  return Buffer.concat([base.subarray(0, at + 1), packet(2, caveat), Buffer.from([0, 0]), packet(6, signature)]);
}

it('CP-011/B14 preserves ordinary decoded caveats while redacting confirmed nested credentials', async () => temp(async dir => {
  const ordinary = 'QWxwaGFCZXRh'.repeat(10);
  const inner = vector('default-invoice');
  const outer = caveated(vector('default-readonly'), `lnd-custom ${ordinary} left${inner.toString('hex')}right`);
  const path = join(dir, 'outer.macaroon'); writeFileSync(path, outer);
  const sentinelDir = join(dir, 'sentinels'); mkdirSync(sentinelDir);
  writeFileSync(join(sentinelDir, 'inner.macaroon'), inner);
  writeFileSync(join(sentinelDir, 'outer.macaroon'), outer);
  const inspect = await cli('inspect', [path, '--json']);
  expect(inspect.code).toBe(0);
  const inspected = json(inspect);
  expect(inspected.result.caveats[0].value === `${ordinary} left[redacted]right`,
    'ordinary caveat preserved and nested credential redacted').toBe(true);
  noLeaks(inspect.stdout + inspect.stderr, sentinelDir);
  const scan = await cli('scan', [path, '--json']);
  expect(scan.code).toBe(0);
  const scanned = scanJson(scan);
  expect(scanned.result.findings[0].caveats![0].value === `${ordinary} left[redacted]right`,
    'scan caveat preserved and nested credential redacted').toBe(true);
  noLeaks(JSON.stringify(scanned) + scan.stdout + scan.stderr, sentinelDir);
  const text = await cli('scan', [path]);
  expect(text.code).toBe(0);
  noLeaks(text.stdout + text.stderr, sentinelDir);
}));

it('CP-011/B15 bounds file and non-TTY stdin raw input at the first excess byte', async () => temp(async dir => {
  const { readCredential } = await import('../src/input/index.js');
  const binary = Buffer.concat([vector('default-readonly'),
    Buffer.alloc(65_536 - vector('default-readonly').length)]);
  const hex = binary.toString('hex');
  const base64 = binary.toString('base64');
  const forms = [binary, Buffer.from(hex), Buffer.from(base64),
    Buffer.from(`\ufeff${hex}`, 'utf16le'),
    Buffer.from(base64.match(/.{1,76}/g)!.join('\n'))];
  for (const [index, content] of forms.entries()) {
    const path = join(dir, `accepted-${index}.dat`); writeFileSync(path, content);
    const fileRun = await cli('inspect', [path, '--json']);
    expect(fileRun.code).toBe(0);
    expect(json(fileRun).result?.fingerprint).toBe(reference('default-readonly').fingerprint);
    const input = await readCredential('-', { stdin: Readable.from([content]), fs }, { unsafeArg: false });
    expect(input.secret).toBeDefined();
  }
  const within = Buffer.alloc(1_048_576, 0x78);
  const beyond = Buffer.alloc(1_048_577, 0x78);
  const io = (data: Buffer) => ({ stdin: Readable.from([data]), fs });
  const insideFile = join(dir, 'inside.bin'), outsideFile = join(dir, 'outside.bin');
  writeFileSync(insideFile, within); writeFileSync(outsideFile, beyond);
  async function stage(work: () => Promise<unknown>) {
    try { await work(); return 'accepted'; } catch (error) {
      return (error as { stage?: string }).stage || 'unknown';
    }
  }
  expect(await stage(() => readCredential(insideFile, io(Buffer.alloc(0)), { unsafeArg: false }))).not.toBe('input-read');
  expect(await stage(() => readCredential('-', io(within), { unsafeArg: false }))).not.toBe('input-read');
  expect(await stage(() => readCredential(outsideFile, io(Buffer.alloc(0)), { unsafeArg: false }))).toBe('input-read');
  expect(await stage(() => readCredential('-', io(beyond), { unsafeArg: false }))).toBe('input-read');
  const measured = { bytes: 0 };
  const tracked = { ...fs,
    readFile: (async (path: string) => {
      const bytes = await fs.readFile(path);
      measured.bytes += bytes.length;
      return bytes;
    }) as typeof fs.readFile,
    open: async (...args: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...args);
    return new Proxy(handle, { get(target, key) {
      if (key === 'read') return async (...params: Parameters<typeof handle.read>) => {
        const result = await handle.read(...params); measured.bytes += result.bytesRead; return result;
      };
      if (key === 'readFile') return async () => {
        const bytes = await handle.readFile(); measured.bytes += bytes.length; return bytes;
      };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
  } };
  expect(await stage(() => readCredential(outsideFile, { stdin: Readable.from([]), fs: tracked as typeof fs },
    { unsafeArg: false }))).toBe('input-read');
  expect(measured.bytes).toBeLessThanOrEqual(1_048_577);
  let yielded = 0;
  const growing = Readable.from((async function* () {
    for (const chunk of [within, Buffer.from([0x78]), beyond]) {
      if (chunk === beyond) await new Promise(resolve => setTimeout(resolve, 20));
      yielded += chunk.length;
      yield chunk;
    }
  })());
  expect(await stage(() => readCredential('-', { stdin: growing, fs }, { unsafeArg: false }))).toBe('input-read');
  expect(yielded).toBeLessThanOrEqual(1_048_577);
  const cliOverflow = await cli('inspect', [outsideFile, '--json']);
  expect(cliOverflow.code).toBe(3);
  expect(json(cliOverflow).error?.step).toBe('input-read');
  expect(cliOverflow.stdout.length).toBeLessThan(4096);
}));

it('CP-011/B16 keeps supported NWC encodings absent while retaining unrelated text', async () => temp(async dir => {
  const secret = createHash('sha256').update('cp011-nwc-audit').digest();
  const sentinelDir = join(dir, 'sentinels'); mkdirSync(sentinelDir);
  writeFileSync(join(sentinelDir, 'nwc.bin'), secret);
  const harmless = 'ordinary-reading-note-' + 'QWxwaGFCZXRh'.repeat(8);
  const uri = `nostr+walletconnect://${'22'.repeat(32)}?secret=${secret.toString('hex')}`;
  const outer = caveated(vector('default-readonly'), `lnd-custom ${harmless} ${uri} ${secret.toString('base64url')}`);
  writeFileSync(join(sentinelDir, 'outer.macaroon'), outer);
  const path = join(dir, 'nwc-note.macaroon'); writeFileSync(path, outer);
  const scan = await cli('scan', [path, '--json']);
  expect(scan.code).toBe(0);
  const value = scanJson(scan);
  expect(value.result.findings[0].caveats![0].value.includes(harmless)).toBe(true);
  noLeaks(JSON.stringify(value) + scan.stdout + scan.stderr, sentinelDir);
  const text = await cli('scan', [path]);
  expect(text.code).toBe(0);
  noLeaks(text.stdout + text.stderr, sentinelDir);
}));
