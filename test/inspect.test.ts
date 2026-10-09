import { childEnvironment } from './helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import * as fs from 'node:fs/promises';
import { Readable } from 'node:stream';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect, it, vi } from 'vitest';
import { captureMain } from './support/capture.js';
import { findLeaks } from "./helpers/leak-check.js";
import { Secret } from '../src/secret.js';
import { decodeMacaroon } from '../src/decode/index.js';
import { grade, describe } from '../src/grade/index.js';

const networkCalls = vi.hoisted(() => [] as string[]);
vi.mock('node:https', async importOriginal => {
  const original = await importOriginal<typeof import('node:https') & { default: typeof import('node:https') }>();
  const blocked = () => { networkCalls.push('https'); throw new Error('network called'); };
  return { ...original, request: blocked, get: blocked,
    default: { ...original.default, request: blocked, get: blocked } };
});
vi.mock('node:http', async importOriginal => {
  const original = await importOriginal<typeof import('node:http') & { default: typeof import('node:http') }>();
  const blocked = () => { networkCalls.push('http'); throw new Error('network called'); };
  return { ...original, request: blocked, get: blocked,
    default: { ...original.default, request: blocked, get: blocked } };
});
vi.mock('node:net', async importOriginal => {
  const original = await importOriginal<typeof import('node:net') & { default: typeof import('node:net') }>();
  const blocked = () => { networkCalls.push('net'); throw new Error('network called'); };
  return { ...original, connect: blocked, createConnection: blocked,
    default: { ...original.default, connect: blocked, createConnection: blocked } };
});

type Envelope = { schema: number; command: string | null; ok: boolean; warnings: string[];
  result: Result | null; error: { code: number; step: string | null; message: string } | null };
type Result = { fingerprint: string; location: string | null; rootKeyId: string; permissions: string[];
  caveats: { type: string; value: string; expired?: boolean }[]; grade: string; reasons: string[];
  warnings: string[]; unassessed: string[]; snapshot: string };
type Invocation = { code: number | null; stdout: string; stderr: string };
const repo = resolve();
const vectors = join(repo, 'test/vectors');
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const manifest = JSON.parse(readFileSync(join(vectors, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; file: string; purpose: string; fingerprint: string; expectedGrade: string }[] };
const negatives = JSON.parse(readFileSync(join(vectors, 'negative/manifest.json'), 'utf8')) as {
  vectors: { name: string; file: string; stage: string }[] };
const schema = JSON.parse(readFileSync(join(repo, 'schemas/output/inspect.schema.json'), 'utf8'));
const validate = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(schema);
const vector = (name: string) => readFileSync(join(vectors, `${name}.macaroon`));
const stored = (name: string) => JSON.parse(readFileSync(join(vectors, `${name}.printmacaroon.json`), 'utf8')) as {
  root_key_id: string; permissions: string[]; caveats: string[] | null; location: string };
const refusal = 'pass a file path or - (stdin); literal credentials end up in shell history and process listings';
function withTemp<T>(work: (dir: string) => T): T {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp008-'));
  try { return work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}
async function withTempAsync<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp008-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}
async function loadCommand(): Promise<{ run: (args: string[], deps: { stdin: Readable; fs: typeof fs; clock: () => Date }) => Promise<Envelope> }> {

  return import('../src/commands/inspect.js') as unknown as Awaited<ReturnType<typeof loadCommand>>;
}
async function command(args: string[], stdin = Readable.from([]), clock = () => new Date()): Promise<Envelope> {
  const implementation = await loadCommand();
  return implementation.run(args, { stdin, fs, clock });
}
async function cli(args: string[]): Promise<Invocation> {
  const { main } = await import('../src/cli.js');
  return captureMain(main, ['inspect', ...args]);
}
function processCli(args: string[], input?: Buffer, cwd = repo, env?: NodeJS.ProcessEnv): Invocation {
  const run = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'inspect', ...args],
    { cwd, input, encoding: 'utf8', timeout: 10_000, env: childEnvironment({ ...env  }), maxBuffer: 1_000_000 });
  return { code: run.status, stdout: run.stdout || '', stderr: run.stderr || '' };
}
function document(run: Invocation): Envelope {
  let parsed: unknown;
  try { parsed = JSON.parse(run.stdout); }
  catch { throw new Error('inspect stdout is not one JSON document'); }
  expect(validate(parsed), 'inspect schema validation').toBe(true);
  expect(run.stderr, 'JSON mode stderr').toBe('');
  return parsed as Envelope;
}
function result(run: Invocation): Result {
  expect(run.code, 'inspect exit code').toBe(0);
  const value = document(run);
  expect(value.ok).toBe(true);
  expect(value.error).toBeNull();
  expect(value.result).not.toBeNull();
  return value.result!;
}
function noLeak(output: string, sentinel: Buffer): void {
  withTemp(dir => {
    const sentinelDir = join(dir, 'sentinels');
    mkdirSync(sentinelDir);
    writeFileSync(join(sentinelDir, 'input.macaroon'), sentinel);
    expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
      commandOutput: output, testTmp, root: repo }), 'credential leaked').toBeNull();
  });
}
function caveatMatches(actual: Result['caveats'], expected: string[] | null): boolean {
  return actual.length === (expected?.length || 0) && actual.every((caveat, index) =>
    (caveat.type === 'unknown' ? caveat.value : `${caveat.type} ${caveat.value}`) === expected?.[index]);
}
const byteSort = (values: string[]) => [...new Set(values)].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));

// Assemble controlled first-party caveats from the reference v2 packet layout. The
// source vector has no caveats, so its final signature can attenuate each condition.
function packet(kind: number, data: Buffer): Buffer {
  const varint = (value: number): Buffer => {
    const digits: number[] = [];
    do { digits.push((value & 127) | (value >= 128 ? 128 : 0)); value = Math.floor(value / 128); } while (value);
    return Buffer.from(digits);
  };
  return Buffer.concat([varint(kind), varint(data.length), data]);
}
function firstPacket(bytes: Buffer, offset: number): { kind: number; end: number; value: Buffer } {
  const readVarint = (start: number): { value: number; end: number } => {
    let value = 0, scale = 1, cursor = start;
    for (let count = 0; count < 10 && cursor < bytes.length; count++) {
      const digit = bytes[cursor++];
      value += (digit & 127) * scale;
      if (!(digit & 128)) return { value, end: cursor };
      scale *= 128;
    }
    throw new Error('controlled vector packet varint is unsuitable');
  };
  const kind = readVarint(offset);
  const length = readVarint(kind.end);
  if (length.end + length.value > bytes.length) throw new Error('controlled vector packet length is unsuitable');
  return { kind: kind.value, end: length.end + length.value,
    value: bytes.subarray(length.end, length.end + length.value) };
}
function bareVectorLayout(bytes: Buffer): { headerEnd: number; signature: Buffer } {
  if (bytes[0] !== 2) throw new Error('controlled vector header is unsuitable');
  let offset = 1;
  if (bytes[offset] === 1) offset = firstPacket(bytes, offset).end;
  const identifier = firstPacket(bytes, offset);
  if (identifier.kind !== 2) throw new Error('controlled vector identifier is missing');
  offset = identifier.end;
  if (bytes[offset++] !== 0 || bytes[offset] !== 0) throw new Error('controlled vector has caveats');
  const signature = firstPacket(bytes, offset + 1);
  if (signature.kind !== 6 || signature.value.length !== 32 || signature.end !== bytes.length)
    throw new Error('controlled vector signature is unsuitable');
  return { headerEnd: offset, signature: signature.value };
}
function addFirstParty(base: Buffer, condition: string): Buffer {
  const { headerEnd, signature } = bareVectorLayout(base);
  const identifier = Buffer.from(condition, 'utf8');
  const attenuated = createHmac('sha256', signature).update(identifier).digest();
  return Buffer.concat([base.subarray(0, headerEnd), packet(2, identifier), Buffer.from([0, 0]),
    packet(6, attenuated)]);
}
function withHeaderLocation(base: Buffer, location: string | null): Buffer {
  if (base[0] !== 2) throw new Error('controlled inner vector header is unsuitable');
  const first = firstPacket(base, 1);
  const afterLocation = first.kind === 1 ? first.end : 1;
  if (firstPacket(base, afterLocation).kind !== 2) throw new Error('controlled inner identifier is missing');
  return Buffer.concat([Buffer.from([2]), ...(location === null ? [] : [packet(1, Buffer.from(location))]),
    base.subarray(afterLocation)]);
}
function fingerprint(bytes: Buffer): string {
  return `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;
}

it('CP-008/B1 invalid argument counts and unknown long or short flags give schema-valid usage errors', async () => {
  for (const args of [[], ['one', 'two'], ['one', '--frob'], ['-x'], ['one', '-x']]) {
    const run = await cli([...args, '--json']);
    expect(run.code).toBe(2);
    expect(document(run)).toMatchObject({ command: 'inspect', ok: false, result: null,
      error: { code: 2, step: null } });
  }
});

it('CP-008/B2 end of flags permits a leading-dash file name', () => {
  withTemp(dir => {
    copyFileSync(join(vectors, 'default-readonly.macaroon'), join(dir, '--odd.macaroon'));
    copyFileSync(join(vectors, 'default-readonly.macaroon'), join(dir, 'plain.macaroon'));
    const odd = processCli(['--json', '--', '--odd.macaroon'], undefined, dir);
    const plain = processCli(['plain.macaroon', '--json'], undefined, dir);
    expect(odd.code).toBe(0);
    expect(result(odd)).toEqual(result(plain));
  });
});

it('CP-008/B3 binary, text encodings, and stdin give identical invoice results', () => {
  withTemp(dir => {
    const bytes = vector('default-invoice');
    const hex = bytes.toString('hex');
    const b64 = bytes.toString('base64');
    const forms: Array<[string, Buffer]> = [
      ['binary', bytes], ['hex', Buffer.from(hex)],
      ['hex-bom-crlf', Buffer.from(`\ufeff${hex.match(/.{1,76}/g)?.join('\r\n')}`)],
      ['base64', Buffer.from(b64)], ['utf16le-base64', Buffer.from(`\ufeff${b64}`, 'utf16le')],
    ];
    const values = forms.map(([name, data]) => {
      const path = join(dir, name); writeFileSync(path, data);
      const run = processCli([path, '--json']);
      expect(document(run).warnings).toEqual([]);
      return result(run);
    });
    const stdin = processCli(['-', '--json'], bytes);
    expect(document(stdin).warnings).toEqual([]);
    values.push(result(stdin));
    for (const value of values.slice(1)) expect(value).toEqual(values[0]);
  });
});

it('CP-008/B4 unsafe literal forms give one JSON document and invocation warnings', () => {
  const bytes = vector('default-invoice');
  const forms = [bytes.toString('hex'), bytes.toString('base64'),
    `lndconnect://h:10009?macaroon=${bytes.toString('base64url')}`];
  const baseline = result(processCli([join(vectors, 'default-invoice.macaroon'), '--json']));
  for (const literal of forms) {
    const run = processCli([literal, '--unsafe-arg', '--json']);
    expect(run.code).toBe(0);
    expect(document(run).warnings).toEqual(['unsafe-arg']);
    expect(result(run)).toEqual(baseline);
  }
});

it('CP-008/B5 literal refusal is exact and never leaks credential fragments', () => {
  const bytes = vector('default-invoice');
  const forms = [bytes.toString('hex'), bytes.toString('base64'),
    `lndconnect://h:10009?macaroon=${bytes.toString('base64url')}`];
  for (const literal of forms) for (const json of [false, true]) {
    const run = processCli([literal, ...(json ? ['--json'] : [])]);
    expect(run.code).toBe(2);
    const message = json ? document(run).error?.message : run.stderr;
    expect(message?.includes(refusal)).toBe(true);
    if (json) expect(document(run).error?.step).toBeNull();
    const output = run.stdout + run.stderr;
    noLeak(output, bytes);
    for (let at = 0; at <= literal.length - 16; at++)
      expect(output.includes(literal.slice(at, at + 16)), 'literal fragment leaked').toBe(false);
  }
});

it('CP-008/B6 text mode prints unsafe-arg warning and fingerprint', () => {
  const run = processCli([vector('default-invoice').toString('hex'), '--unsafe-arg']);
  expect(run.code).toBe(0);
  expect(run.stderr.split(/\r?\n/).some(line => line.startsWith('warning: unsafe-arg: '))).toBe(true);
  expect(run.stdout).toContain(manifest.vectors.find(item => item.name === 'default-invoice')!.fingerprint);
});

it('CP-008/B7 missing paths and unsafe malformed literals reach the stated stages', async () => {
  for (const [argument, safeStep, unsafeStep] of [
    ['%%not a macaroon%%', 'input-read', 'input-form'],
    ['./missing.macaroon', 'input-read', 'input-form'],
    ['dGVzdA', 'input-read', 'v2-header'],
  ]) for (const unsafe of [false, true]) {
    const run = await cli([argument, ...(unsafe ? ['--unsafe-arg'] : []), '--json']);
    expect(run.code).toBe(3);
    const error = document(run).error;
    expect(error?.step).toBe(unsafe ? unsafeStep : safeStep);
    if (!unsafe) expect(error?.message).toBe('no such file');
  }
});

it('CP-008/B8 TTY stdin is refused promptly without reading', async () => {
  const stdin = Readable.from([]) as Readable & { isTTY?: boolean };
  stdin.isTTY = true;
  const read = vi.spyOn(stdin, 'read');
  const implementation = await loadCommand();
  const started = performance.now();
  const result = await implementation.run(['-', '--json'], { stdin, fs, clock: () => new Date() });
  expect(performance.now() - started).toBeLessThan(1000);
  expect(result.error).toMatchObject({ code: 2, step: null });
  expect(read).not.toHaveBeenCalled();
});

it('CP-008/B9 raw negative inputs respect input parsing and text forms reach decoder stages', () => {
  for (const entry of negatives.vectors) {
    const input = join(vectors, 'negative', entry.file);
    const bytes = readFileSync(input);
    const run = processCli([input, '--json']);
    expect(run.code, entry.name).toBe(3);
    const error = document(run).error;
    // These raw v1 files also parse as hex text under the input rules.
    const rawStage = bytes[0] === 0x02 || entry.name === 'v1-binary' ||
      entry.name === 'v1-base64-decoded' ? entry.stage : 'input-form';
    expect(error?.step, entry.name).toBe(rawStage);
    noLeak(run.stdout + run.stderr, bytes);

    if (bytes.length > 0 && bytes[0] !== 0x02) withTemp(dir => {
      const textFile = join(dir, `${entry.name}.base64.txt`);
      const encoded = bytes.toString('base64');
      if (entry.name === 'v1-binary') expect(encoded.startsWith('MDAx')).toBe(true);
      writeFileSync(textFile, encoded);
      const textRun = processCli([textFile, '--json']);
      expect(textRun.code, entry.name).toBe(3);
      const textError = document(textRun).error;
      expect(textError?.step, entry.name).toBe(entry.stage);
      if (entry.name.startsWith('v1-'))
        expect(textError?.message).toBe('macaroon v1 format is not supported');
      noLeak(textRun.stdout + textRun.stderr, bytes);
    });
  }
}, 20_000);

it('CP-008/B10 every positive vector has the exact result shape and independent fields', () => {
  const keys = ['fingerprint', 'location', 'rootKeyId', 'permissions', 'caveats', 'grade', 'reasons',
    'warnings', 'unassessed', 'snapshot'].sort();
  for (const entry of manifest.vectors) {
    const run = processCli([join(vectors, entry.file), '--json']);
    const value = result(run);
    const oracle = stored(entry.name);
    expect(Object.keys(value).sort(), entry.name).toEqual(keys);
    expect(value.rootKeyId, entry.name).toBe(oracle.root_key_id);
    expect(value.permissions, entry.name).toEqual(oracle.permissions);
    expect(value.location, entry.name).toBe(oracle.location || null);
    if (entry.name === 'third-party') {
      expect(entry.purpose.startsWith('third-party caveat at ')).toBe(true);
      const location = entry.purpose.slice('third-party caveat at '.length);
      expect(location.length).toBeGreaterThan(0);
      expect(value.caveats, entry.name).toEqual([{ type: 'third-party', value: location }]);
    } else {
      expect(caveatMatches(value.caveats, oracle.caveats), entry.name).toBe(true);
    }
    expect(value.snapshot, entry.name).toBe('0.21.4-beta');
    const facts = decodeMacaroon(new Secret(vector(entry.name)));
    expect(value.warnings, entry.name).toEqual(byteSort([
      ...grade(oracle.permissions).warnings, ...describe(facts),
    ]));
  }
}, 30_000);

it('CP-008/B11 signed Z and numeric-offset time-before boundaries agree in every timezone', async () => {
  await withTempAsync(async dir => {
    const originalFile = join(vectors, 'time-before.macaroon');
    const originalBytes = vector('time-before');
    const originalCondition = stored('time-before').caveats![0].slice('time-before '.length);
    const fraction = /\.(\d{3})(\d{6})Z$/.exec(originalCondition);
    expect(fraction).not.toBeNull();
    expect(fraction![2]).not.toBe('000000');
    expect(fingerprint(originalBytes)).toBe(manifest.vectors.find(item => item.name === 'time-before')!.fingerprint);

    const base = vector('default-readonly');
    const controlled = [
      { label: 'Z exact', condition: 'time-before 2030-01-01T00:00:00.000000000Z', offsets: [[-1, false], [0, true], [1, true]] },
      { label: 'plus zero fractional', condition: 'time-before 2030-01-01T00:00:00.000000001+00:00', offsets: [[0, false], [1, true]] },
      { label: 'plus one exact', condition: 'time-before 2030-01-01T01:00:00.000000000+01:00', offsets: [[-1, false], [0, true], [1, true]] },
      { label: 'minus one fractional', condition: 'time-before 2029-12-31T23:00:00.000000001-01:00', offsets: [[0, false], [1, true]] },
    ] as const;
    const fixtures = controlled.map((entry, index) => {
      const path = join(dir, `signed-${index}.macaroon`);
      writeFileSync(path, addFirstParty(base, entry.condition));
      return { ...entry, path, instant: Date.parse(entry.condition.slice('time-before '.length)) };
    });
    const originalInstant = Date.parse(originalCondition);
    const all = [{ label: 'original Z fractional', condition: `time-before ${originalCondition}`,
      offsets: [[0, false], [1, true]] as const, path: originalFile, instant: originalInstant }, ...fixtures];

    const originalTz = process.env.TZ;
    try {
      for (const timezone of ['UTC', 'America/Los_Angeles', 'Asia/Kolkata']) {
        process.env.TZ = timezone;
        for (const entry of all) for (const [offset, expected] of entry.offsets) {
          const at = new Date(entry.instant + offset);
          const output = await command([entry.path, '--json'], Readable.from([]), () => at);
          expect(output.ok, entry.label).toBe(true);
          expect(output.warnings, entry.label).toEqual([]);
          const value = output.result!;
          const caveat = value.caveats.find(item => item.type === 'time-before');
          expect(caveat?.value === entry.condition.slice('time-before '.length), entry.label).toBe(true);
          expect(caveat?.expired, entry.label).toBe(expected);
          expect(value.warnings.includes('bad-time-before'), entry.label).toBe(false);
          expect(value.grade, entry.label).toBe('READ');
          vi.useFakeTimers();
          try {
            vi.setSystemTime(at);
            const text = await cli([entry.path]);
            expect(text.code, entry.label).toBe(0);
            expect(text.stdout.includes(expected ? '(expired)' : '(valid)'), entry.label).toBe(true);
          } finally { vi.useRealTimers(); }
        }
      }
    } finally {
      if (originalTz === undefined) delete process.env.TZ;
      else process.env.TZ = originalTz;
    }
    expect(readFileSync(originalFile).equals(originalBytes)).toBe(true);
  });
});

it('CP-008/B12 malformed time-before carries warning and no expired property', () => {
  const value = result(processCli([join(vectors, 'time-unparseable.macaroon'), '--json']));
  expect(value.warnings).toContain('bad-time-before');
  const caveat = value.caveats.find(item => item.type === 'time-before');
  expect(caveat).toBeDefined();
  expect(Object.hasOwn(caveat!, 'expired')).toBe(false);
});

it('CP-008/B13 admin, address caveat and trailing bytes render the required warnings', () => {
  for (const name of ['default-admin', 'ipaddr', 'trailing-bytes']) {
    const file = join(vectors, `${name}.macaroon`);
    const value = result(processCli([file, '--json']));
    const text = processCli([file]);
    expect(text.code).toBe(0);
    expect(text.stdout.split(/\r?\n/).some(line => line.startsWith('snapshot') && line.includes('LND 0.21.4-beta'))).toBe(true);
    if (name === 'default-admin') {
      expect(value.grade).toBe('ADMIN');
      expect(value.warnings).toContain('root-key-0');
      expect(text.stdout).toContain('root-key-0');
      expect(text.stdout).toContain('cannot be individually revoked');
    }
    if (name === 'ipaddr') expect(text.stdout).toContain('enforced against the address LND sees; REST clients appear as the REST proxy');
    if (name === 'trailing-bytes') expect(value.warnings).toContain('trailing-bytes');
  }
});

it('CP-008/B14 macaroon generation permission is graded ADMIN', () => {
  expect(result(processCli([join(vectors, 'grade-admin-set.macaroon'), '--json'])).grade).toBe('ADMIN');
});

it('CP-008/B15 inspect is offline, read-only and creates no files', async () => {
  await withTempAsync(async dir => {
    const copied = ['default-invoice', ...manifest.vectors.map(entry => entry.name)];
    for (const name of new Set(copied)) copyFileSync(join(vectors, `${name}.macaroon`), join(dir, `${name}.macaroon`));
    const invoice = vector('default-invoice');
    writeFileSync(join(dir, 'invoice.hex'), invoice.toString('hex'));
    writeFileSync(join(dir, 'invoice.b64'), invoice.toString('base64'));
    writeFileSync(join(dir, 'invoice.utf16'), `\ufeff${invoice.toString('base64')}`, 'utf16le');
    const before = new Map(readdirSync(dir).map(name => [name,
      { bytes: readFileSync(join(dir, name)), mtime: statSync(join(dir, name)).mtimeMs }]));
    networkCalls.length = 0;
    const previousCwd = process.cwd();
    try {
      process.chdir(dir);
      for (const name of [...new Set(copied)].map(name => `${name}.macaroon`).concat(['invoice.hex', 'invoice.b64', 'invoice.utf16'])) {
        const run = await cli([join(dir, name), '--json']);
        expect(run.code, name).toBe(0);
      }
    } finally {
      process.chdir(previousCwd);
    }
    expect(readdirSync(dir)).toEqual([...before.keys()]);
    for (const [name, old] of before) {
      expect(readFileSync(join(dir, name)).equals(old.bytes), name).toBe(true);
      expect(statSync(join(dir, name)).mtimeMs, name).toBe(old.mtime);
    }
    expect(networkCalls).toHaveLength(0);
  });
});

it('CP-008/B16 embedded credential encodings with optional header locations are redacted', () => {
  const base = vector('default-readonly');
  const contexts = [
    { name: 'separated', prefix: 'note-start:', suffix: ':note-end' },
    { name: 'adjacent', prefix: 'safeA', suffix: 'Bsafe' },
  ];
  for (const location of [null, 'lnd', 'other']) {
    const inner = withHeaderLocation(base, location);
    const carriers = [
      { name: 'hex', encoded: inner.toString('hex') },
      { name: 'base64', encoded: inner.toString('base64') },
      { name: 'base64url', encoded: inner.toString('base64url') },
    ];
    for (const carrier of carriers) {
      for (const context of contexts) {
        const label = `${location ?? 'omitted'} ${carrier.name} ${context.name}`;
        const expected = `${context.prefix}[redacted]${context.suffix}`;
        const outputs = withTemp(dir => {
          const outer = addFirstParty(base, `opaque ${context.prefix}${carrier.encoded}${context.suffix}`);
          const path = join(dir, 'outer.macaroon');
          writeFileSync(path, outer);
          const json = processCli([path, '--json']);
          const text = processCli([path]);
          expect(json.code, `${label} JSON exit`).toBe(0);
          expect(text.code, `${label} text exit`).toBe(0);
          const envelope = document(json);
          expect(envelope.warnings, `${label} invocation warnings`).toEqual([]);
          expect(envelope.result?.caveats.some(caveat => caveat.value.includes(expected)),
            `${label} exact safe JSON context`).toBe(true);
          expect(text.stdout.includes(expected), `${label} exact safe text context`).toBe(true);
          return [json.stdout + json.stderr, text.stdout + text.stderr];
        });
        for (const output of outputs) {
          expect(output.includes(carrier.encoded), `${label} encoding leaked`).toBe(false);
          noLeak(output, inner);
        }
      }
    }
  }
}, 30_000);
