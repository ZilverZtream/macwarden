import { revealSecret } from './helpers/secret-bytes.js';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, resolve, sep } from 'node:path';
import { inspect } from 'node:util';
import { expect, it } from 'vitest';
import { Secret } from '../src/secret.js';
import { findLeaks } from "./helpers/leak-check.js";

type Caveat = { type: string; value: string; expired?: boolean };
type Facts = { location: string | null; rootKeyId: bigint; permissions: string[]; caveats: Caveat[]; fingerprint: string; warnings: string[] };
type Decoder = { decodeMacaroon: (mac: Secret) => Facts; encodeMacaroon: (facts: Facts) => Secret; parseTimeBefore: (value: string) => bigint | undefined; DecodeError: new (...args: never[]) => Error };
type Vector = { name: string; file: string; purpose: string; fingerprint: string; canonicalLength: number };
type Negative = { name: string; file: string; stage: string };
const repo = resolve();
const vectorsDir = join(repo, 'test/vectors');
const manifest = JSON.parse(readFileSync(join(vectorsDir, 'manifest.json'), 'utf8')) as { vectors: Vector[] };
const negatives = JSON.parse(readFileSync(join(vectorsDir, 'negative/manifest.json'), 'utf8')) as { vectors: Negative[] };

const decoder = (): Promise<Decoder> => import('../src/decode/index.js') as Promise<Decoder>;
const vector = (name: string) => {
  const entry = manifest.vectors.find(value => value.name === name);
  if (!entry) throw new Error(`Missing vector ${name}`);
  return entry;
};
const bytes = (entry: Vector) => readFileSync(join(vectorsDir, entry.file));
const printed = (entry: Vector) => JSON.parse(readFileSync(join(vectorsDir, `${entry.name}.printmacaroon.json`), 'utf8')) as {
  root_key_id: string; location: string | null; permissions: string[]; caveats: string[] | null;
};
const decode = (implementation: Decoder, entry: Vector) => implementation.decodeMacaroon(new Secret(bytes(entry)));
const sameCaveats = (facts: Facts, strings: string[] | null) => facts.caveats.length === (strings?.length || 0)
  && facts.caveats.every((caveat, index) =>
    (caveat.type === 'unknown' ? caveat.value : `${caveat.type} ${caveat.value}`) === strings?.[index]);

function readVarint(input: Buffer, start: number): [number, number] {
  let value = 0, scale = 1, pos = start;
  for (let i = 0; i < 10 && pos < input.length; i++) {
    const digit = input[pos++]; value += (digit & 127) * scale;
    if (!(digit & 128)) return [value, pos];
    scale *= 128;
  }
  throw new Error('Positive vector packet is malformed');
}
const vint = (value: number): Buffer => value < 128 ? Buffer.from([value]) : Buffer.from([(value & 127) | 128, value >> 7]);
function withSkippedProtoFields(source: Buffer): Buffer {
  let pos = 1;
  while (pos < source.length) {
    const start = pos;
    const [type, afterType] = readVarint(source, pos);
    const [length, data] = readVarint(source, afterType);
    pos = data + length;
    if (type !== 2) continue;
    const id = source.subarray(data, pos);
    const augmented = Buffer.concat([id, Buffer.from([0x09]), Buffer.alloc(8, 0), Buffer.from([0x15]), Buffer.alloc(4, 0)]);
    return Buffer.concat([source.subarray(0, start), vint(2), vint(augmented.length), augmented, source.subarray(pos)]);
  }
  throw new Error('Positive vector identifier is missing');
}

function withFirstCaveat(source: Buffer, condition: string): Buffer {
  let pos = 1;
  while (pos < source.length && source[pos] !== 0) {
    const [, afterType] = readVarint(source, pos);
    const [length, data] = readVarint(source, afterType);
    pos = data + length;
  }
  if (source[pos] !== 0) throw new Error('Positive vector header is malformed');
  pos++;
  while (pos < source.length) {
    const start = pos;
    const [type, afterType] = readVarint(source, pos);
    const [length, data] = readVarint(source, afterType);
    pos = data + length;
    if (type === 1) continue;
    if (type !== 2) break;
    const replacement = Buffer.from(condition, 'utf8');
    return Buffer.concat([source.subarray(0, start), vint(2), vint(replacement.length), replacement, source.subarray(pos)]);
  }
  throw new Error('Positive vector caveat identifier is missing');
}

function withNonminimalFirstPacket(source: Buffer, field: 'kind' | 'length'): Buffer {
  const [kind, afterKind] = readVarint(source, 1);
  const [length, data] = readVarint(source, afterKind);
  if (kind !== 1 || length >= 128) throw new Error('Positive vector location packet is unsuitable');
  return Buffer.concat([
    source.subarray(0, 1),
    field === 'kind' ? Buffer.from([kind | 0x80, 0]) : vint(kind),
    field === 'length' ? Buffer.from([length | 0x80, 0]) : vint(length),
    source.subarray(data),
  ]);
}

it('CP-005/B1 stored LND facts match every comparable vector', async () => {
  const implementation = await decoder();
  for (const entry of manifest.vectors.filter(value => value.name !== 'third-party')) {
    const facts = decode(implementation, entry), oracle = printed(entry);
    expect(facts.rootKeyId.toString() === oracle.root_key_id, entry.name).toBe(true);
    expect(JSON.stringify(facts.permissions) === JSON.stringify(oracle.permissions), entry.name).toBe(true);
    const expectedLocation = entry.name === 'no-location' ? null : oracle.location;
    expect(facts.location === expectedLocation, entry.name).toBe(true);
    expect(sameCaveats(facts, oracle.caveats), entry.name).toBe(true);
  }
  expect(decode(implementation, vector('no-location')).location).toBeNull();
});

it('CP-005/B2 third-party caveat reports its location without an expired field', async () => {
  const entry = vector('third-party');
  const location = entry.purpose.match(/ at ([^ ]+)$/)?.[1];
  expect(typeof location === 'string').toBe(true);
  const facts = decode(await decoder(), entry);
  expect(facts.caveats.some(value => value.type === 'third-party' && value.value === location
    && !Object.hasOwn(value, 'expired'))).toBe(true);
});

it('CP-005/B3 uint64 maximum and default root key IDs remain bigint', async () => {
  const implementation = await decoder();
  expect(decode(implementation, vector('root-max')).rootKeyId).toBe(18446744073709551615n);
  expect(decode(implementation, vector('default-admin')).rootKeyId).toBe(0n);
});

it('CP-005/B4 every decoded vector re-encodes to its canonical bytes', async () => {
  const implementation = await decoder();
  for (const entry of manifest.vectors) {
    const encoded = implementation.encodeMacaroon(decode(implementation, entry));
    expect(encoded instanceof Secret, entry.name).toBe(true);
    expect(Buffer.from(revealSecret(encoded)).equals(bytes(entry).subarray(0, entry.canonicalLength)), entry.name).toBe(true);
  }
});

it('CP-005/B4 nonminimal packet varints reject or agree with re-encoded fingerprint bytes', async () => {
  const implementation = await decoder();
  const source = bytes(vector('grade-signer-read'));
  for (const field of ['kind', 'length'] as const) {
    const input = withNonminimalFirstPacket(source, field);
    let facts: Facts;
    try { facts = implementation.decodeMacaroon(new Secret(input)); }
    catch (error) {
      expect(error instanceof implementation.DecodeError, field).toBe(true);
      expect((error as { stage?: string }).stage === 'packet', field).toBe(true);
      continue;
    }
    const encoded = implementation.encodeMacaroon(facts);
    expect(encoded instanceof Secret, field).toBe(true);
    const canonical = Buffer.from(revealSecret(encoded));
    const expectedFingerprint = `fp:${createHash('sha256').update(canonical).digest('hex').slice(0, 16)}`;
    expect(facts.fingerprint === expectedFingerprint, field).toBe(true);
  }
});

it('CP-005/B5 trailing bytes preserve canonical facts and add one warning', async () => {
  const implementation = await decoder();
  const facts = decode(implementation, vector('trailing-bytes'));
  const oracle = printed(vector('trailing-bytes'));
  expect(facts.warnings).toEqual(['trailing-bytes']);
  expect(facts.rootKeyId.toString() === oracle.root_key_id).toBe(true);
  expect(JSON.stringify(facts.permissions) === JSON.stringify(oracle.permissions)).toBe(true);
  expect(sameCaveats(facts, oracle.caveats)).toBe(true);
});

it('CP-005/B6 caveat types and verbatim values match the stored conditions', async () => {
  const implementation = await decoder();
  for (const [name, type] of [
    ['time-before', 'time-before'], ['time-nanosecond', 'time-before'], ['ipaddr', 'ipaddr'],
    ['iprange', 'iprange'], ['lnd-custom', 'lnd-custom'], ['unknown-condition', 'unknown'],
    ['time-unparseable', 'time-before'],
  ]) {
    const entry = vector(name), facts = decode(implementation, entry);
    expect(facts.caveats[0]?.type === type, name).toBe(true);
    expect(sameCaveats(facts, printed(entry).caveats), name).toBe(true);
    expect(facts.caveats.every(caveat => !Object.hasOwn(caveat, 'expired')), name).toBe(true);
  }
  expect(decode(implementation, vector('time-unparseable')).warnings.includes('bad-time-before')).toBe(true);
});

it('CP-005/B6 impossible calendar date warns while leap-day nanoseconds remain valid', async () => {
  const implementation = await decoder();
  const source = bytes(vector('time-before'));
  for (const [condition, invalid] of [
    ['time-before 2025-02-30T12:34:56Z', true],
    ['time-before 2024-02-29T23:59:59.123456789Z', false],
  ] as const) {
    const facts = implementation.decodeMacaroon(new Secret(withFirstCaveat(source, condition)));
    expect(facts.caveats[0]?.type).toBe('time-before');
    expect(`time-before ${facts.caveats[0]?.value}` === condition).toBe(true);
    expect(facts.warnings.includes('bad-time-before'), condition).toBe(invalid);
    expect(Object.hasOwn(facts.caveats[0], 'expired')).toBe(false);
  }
});

// Go's time.Parse(time.RFC3339Nano, ...) accepts a comma or a period before the fraction
// (Go 1.17+), and LND parses time-before caveats that way, so both must yield the same instant.
it('TIME-BEFORE/comma-fraction a comma before the fraction parses like Go and raises no warning', async () => {
  const implementation = await decoder();
  const expected = BigInt(Date.UTC(2026, 0, 2, 3, 4, 5)) * 1_000_000n + 500_000_000n;
  expect(implementation.parseTimeBefore('2026-01-02T03:04:05,5Z')).toBe(expected);
  expect(implementation.parseTimeBefore('2026-01-02T03:04:05.5Z')).toBe(expected);
  expect(implementation.parseTimeBefore('2026-01-02T05:04:05,5+02:00')).toBe(expected);
  for (const invalid of ['2026-01-02T03:04:05,Z', '2026-01-02T03:04:05;5Z'])
    expect(implementation.parseTimeBefore(invalid), invalid).toBeUndefined();
  const source = bytes(vector('time-before'));
  const facts = implementation.decodeMacaroon(new Secret(withFirstCaveat(source, 'time-before 2026-01-02T03:04:05,5Z')));
  expect(facts.warnings.includes('bad-time-before')).toBe(false);
});

it('CP-005/B7 every malformed vector fails at its named decode stage', async () => {
  const implementation = await decoder();
  expect(negatives.vectors).toHaveLength(26);
  for (const entry of negatives.vectors) {
    let error: unknown;
    try { implementation.decodeMacaroon(new Secret(readFileSync(join(vectorsDir, 'negative', entry.file)))); }
    catch (caught) { error = caught; }
    expect(error instanceof implementation.DecodeError, entry.name).toBe(true);
    expect((error as { stage?: string }).stage === entry.stage, entry.name).toBe(true);
    if (entry.name.startsWith('v1-')) expect((error as Error).message === 'macaroon v1 format is not supported', entry.name).toBe(true);
  }
});

it('CP-005/B8 protobuf fixed-width fields are skipped', async () => {
  const implementation = await decoder();
  const source = vector('grade-signer-read');
  const expected = decode(implementation, source);
  const actual = implementation.decodeMacaroon(new Secret(withSkippedProtoFields(bytes(source))));
  expect(actual.rootKeyId === expected.rootKeyId).toBe(true);
  expect(JSON.stringify(actual.permissions) === JSON.stringify(expected.permissions)).toBe(true);
});

it('CP-005/B9 decode errors never reveal malformed input in any representation', async () => {
  const implementation = await decoder();
  const base = resolve(process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp'));
  mkdirSync(base, { recursive: true });
  const root = mkdtempSync(join(base, 'cp005-errors-'));
  let verifiedDisclosure = false;
  try {
    for (const entry of negatives.vectors) {
      const input = readFileSync(join(vectorsDir, 'negative', entry.file));
      let error: unknown;
      try { implementation.decodeMacaroon(new Secret(input)); } catch (caught) { error = caught; }
      expect(error instanceof implementation.DecodeError, entry.name).toBe(true);
      // Stack frames contain checkout paths, which can incidentally match short malformed inputs.
      // Preserve the error header and inspected properties, where input disclosure is meaningful.
      const inspected = inspect(error).split('\n').filter(line => !/^\s+at\s/.test(line)).join('\n');
      const output = [String(error), (error as Error).message, inspected, JSON.stringify(error)].join('\n');
      const sentinel = join(root, entry.name);
      mkdirSync(sentinel);
      writeFileSync(join(sentinel, 'input.macaroon'), input);
      const options = { sentinels: join(repo, 'test/sentinels.json'), sentinelDir: sentinel, root: repo };
      const leak = findLeaks({ ...options, commandOutput: output });
      expect(leak === null, entry.name).toBe(true);
      if (!verifiedDisclosure && input.length > 16) {
        const encoded = input.toString('hex');
        const representations = [
          String(new Error(encoded)),
          new Error(encoded).message,
          inspect(Object.assign(new Error('safe'), { disclosure: encoded })),
          JSON.stringify({ disclosure: encoded }),
        ];
        for (const representation of representations) {
          expect(findLeaks({ ...options, commandOutput: representation }) !== null, entry.name).toBe(true);
        }
        const base64 = input.toString('base64');
        for (const disclosure of [input.toString('utf8'), input.toString('latin1'), encoded, encoded.toUpperCase(),
          base64, base64.replace(/=+$/, ''), base64.replace(/\+/g, '-').replace(/\//g, '_'), input.toString('base64url')]) {
          expect(findLeaks({ ...options, commandOutput: disclosure }) !== null, entry.name).toBe(true);
        }
        verifiedDisclosure = true;
      }
    }
    expect(verifiedDisclosure).toBe(true);
  } finally {
    if (root !== base && root.startsWith(base + sep)) rmSync(root, { recursive: true, force: true });
  }
});

it('CP-005/B10 decode sources have no LND or network imports', () => {
  const dir = join(repo, 'src/decode');
  const files = (function list(path: string): string[] {
    try { return readdirSync(path, { withFileTypes: true }).flatMap(entry =>
      entry.isDirectory() ? list(join(path, entry.name)) : entry.isFile() ? [join(path, entry.name)] : []); }
    catch { return []; }
  })(dir).filter(path => /\.[cm]?[jt]s$/.test(path));
  expect(files.length).toBeGreaterThan(0);
  for (const file of files) {
    const source = readFileSync(file, 'utf8');
    const imports = [...source.matchAll(/\b(?:import|export)\s+(?:[^;]*?\s+from\s+)?['"]([^'"]+)['"]|\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g)]
      .map(match => match[1] || match[2]);
    for (const target of imports) {
      const resolved = target.startsWith('.') ? resolve(join(file, '..'), target) : target;
      expect(!resolved.includes(`${sep}src${sep}lnd${sep}`) && !['node:http', 'node:https', 'node:net', 'node:tls'].includes(target), relative(repo, file)).toBe(true);
    }
  }
});
