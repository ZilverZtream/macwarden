import { createHash, createHmac } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import * as fs from 'node:fs/promises';
import { expect, it } from 'vitest';
import { Secret } from '../src/secret.js';
import { auditVectors } from './helpers/cp015-audit-vectors.mjs';

const root = process.cwd();
const vectors = join(root, 'test/vectors');
const testTmp = process.env.MACWARDEN_TEST_TMP || join(root, 'test/.tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const observations = JSON.parse(readFileSync(join(root, 'test/oracle/facts/observations.json'), 'utf8')) as {
  handMadeAuditReferences: { name: string; printAccepted: boolean; fingerprint: string;
    location: string | null; permissions: string[] | null; caveats: string[] | null }[];
  permissionOrder: { printed: string[] };
};
type DecodeFacts = { location: string | null; permissions: string[]; fingerprint: string;
  caveats: { type: string; value: string }[] };
async function decoder() {

  return await import('../src/decode/index.js') as {
    decodeMacaroon: (secret: Secret) => DecodeFacts;
    DecodeError: new (...args: never[]) => Error;
  };
}
const fp = (bytes: Buffer) => `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;
const varint = (n: number): Buffer => {
  const bytes: number[] = [];
  do { bytes.push((n & 127) | (n >= 128 ? 128 : 0)); n = Math.floor(n / 128); } while (n);
  return Buffer.from(bytes);
};
const packet = (kind: number, value: Buffer) => Buffer.concat([varint(kind), varint(value.length), value]);
function readPacket(bytes: Buffer, start: number) {
  const number = (pos: number) => {
    let value = 0, scale = 1;
    for (let i = 0; i < 10 && pos < bytes.length; i++) {
      const digit = bytes[pos++]; value += (digit & 127) * scale;
      if (!(digit & 128)) return { value, pos };
      scale *= 128;
    }
    throw new Error('Audit base vector packet is malformed');
  };
  const kind = number(start), length = number(kind.pos);
  return { kind: kind.value, value: bytes.subarray(length.pos, length.pos + length.value),
    end: length.pos + length.value };
}
function attenuate(base: Buffer, condition: string) {
  let cursor = 1;
  while (base[cursor] !== 0) cursor = readPacket(base, cursor).end;
  const headerEnd = ++cursor;
  if (base[cursor++] !== 0) throw new Error('Audit base vector has caveats');
  const signature = readPacket(base, cursor);
  if (signature.kind !== 6 || signature.value.length !== 32) throw new Error('Audit base vector has no signature');
  const text = Buffer.from(condition, 'utf8');
  const next = createHmac('sha256', signature.value).update(text).digest();
  return Buffer.concat([base.subarray(0, headerEnd), packet(2, text), Buffer.from([0, 0]), packet(6, next)]);
}
async function inspect(path: string, now: Date) {

  const { run } = await import('../src/commands/inspect.js') as {
    run: (args: string[], deps: { stdin: Readable; fs: typeof fs; clock: () => Date }) => Promise<{
      ok: boolean; result: { fingerprint: string; permissions: string[]; caveats: { type: string; value: string; expired?: boolean }[];
        warnings: string[] } | null; warnings: string[] }>;
  };
  return run([path, '--json'], { stdin: Readable.from([]), fs, clock: () => now });
}

it('CP-015/B7 over-nine-digit Go time-before values stay parseable, verbatim and truncate to nanoseconds', async () => {
  const base = readFileSync(join(vectors, 'default-readonly.macaroon'));
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp015-time-'));
  try {
    const cases = [
      { value: '2030-01-01T00:00:00.0000000009Z', at: '2030-01-01T00:00:00.000Z', expired: true },
      { value: '2030-01-01T00:00:00.0000000019Z', at: '2030-01-01T00:00:00.000Z', expired: false },
      { value: '2030-01-01T00:00:00.0000000019Z', at: '2030-01-01T00:00:00.001Z', expired: true },
    ];
    for (const [index, item] of cases.entries()) {
      const path = join(dir, `fraction-${index}.macaroon`);
      writeFileSync(path, attenuate(base, `time-before ${item.value}`));
      const output = await inspect(path, new Date(item.at));
      expect(output.ok).toBe(true);
      expect(output.warnings).not.toContain('bad-time-before');
      const caveat = output.result?.caveats.find(value => value.type === 'time-before');
      expect(caveat?.value, `case ${index} verbatim value`).toBe(item.value);
      expect(caveat?.expired, `case ${index} truncated Go instant`).toBe(item.expired);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

it('CP-015/B9 trailing data preserves the independent canonical fingerprint', async () => {
  const manifest = JSON.parse(readFileSync(join(vectors, 'manifest.json'), 'utf8')) as {
    vectors: { name: string; canonicalLength: number; fingerprint: string }[];
  };
  const entry = manifest.vectors.find(item => item.name === 'trailing-bytes');
  expect(entry).toBeDefined();
  const bytes = readFileSync(join(vectors, 'trailing-bytes.macaroon'));
  const canonical = bytes.subarray(0, entry!.canonicalLength);
  expect(fp(bytes)).not.toBe(fp(canonical));
  expect(fp(canonical)).toBe(entry!.fingerprint);
  const output = await inspect(join(vectors, 'trailing-bytes.macaroon'), new Date('2030-01-01T00:00:00Z'));
  expect(output.result?.fingerprint).toBe(fp(canonical));
  expect(output.result?.warnings).toContain('trailing-bytes');
});

it('CP-015/B5 first-party location follows pinned go-macaroon rejection', async () => {
  const item = auditVectors(root).find(value => value.name === 'first-party-location')!;
  const reference = observations.handMadeAuditReferences.find(value => value.name === item.name)!;
  expect(reference.printAccepted).toBe(false);
  const implementation = await decoder();
  expect(() => implementation.decodeMacaroon(new Secret(item.bytes))).toThrow(implementation.DecodeError);
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp015-location-'));
  try {
    const path = join(dir, 'location.macaroon');
    writeFileSync(path, item.bytes);
    const output = await inspect(path, new Date('2030-01-01T00:00:00Z'));
    expect(output.ok).toBe(false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

it('CP-015/B6 empty verification ID is a first-party caveat under pinned verification rules', async () => {
  const item = auditVectors(root).find(value => value.name === 'empty-verification-id')!;
  const reference = observations.handMadeAuditReferences.find(value => value.name === item.name)!;
  expect(reference.printAccepted).toBe(true);
  const facts = (await decoder()).decodeMacaroon(new Secret(item.bytes));
  expect(facts.permissions).toEqual(reference.permissions);
  expect(facts.caveats).toContainEqual({ type: 'unknown', value: 'fixture-third-party' });
});

it.each(auditVectors(root).filter(value => value.audit === 'B4'))(
  'CP-015/B8 $name follows pinned UTF-8 and protobuf parse outcome', async item => {
  const implementation = await decoder();
  const reference = observations.handMadeAuditReferences.find(value => value.name === item.name)!;
  expect(reference.fingerprint, item.name).toBe(fp(item.bytes));
  if (!reference.printAccepted) {
    let thrown: unknown;
    try { implementation.decodeMacaroon(new Secret(item.bytes)); }
    catch (error) { thrown = error; }
    expect(thrown, `${item.name} accepted despite pinned parser rejection`).toBeInstanceOf(implementation.DecodeError);
    expect((thrown as { stage?: string }).stage, item.name).toBe('identifier-proto');
  } else {
    const facts = implementation.decodeMacaroon(new Secret(item.bytes));
    expect(facts.permissions, item.name).toEqual(reference.permissions);
    expect(facts.location, item.name).toBe(reference.location);
  }
});

it('CP-015/B10 decoded permissions preserve pinned LND order and multiplicity', async () => {
  expect(observations.permissionOrder.printed).toEqual(['info:read', 'invoices:read', 'invoices:write']);
  const bytes = readFileSync(join(vectors, 'cp015-permission-order.macaroon'));
  const implementation = await decoder();
  const facts = implementation.decodeMacaroon(new Secret(bytes));
  expect(facts.permissions).toEqual(observations.permissionOrder.printed);
  const reversed = auditVectors(root).find(item => item.name === 'permission-order-reversed')!;
  const reference = observations.handMadeAuditReferences.find(item => item.name === reversed.name)!;
  expect(reference.printAccepted).toBe(true);
  expect(reference.permissions).not.toEqual(observations.permissionOrder.printed);
  expect(implementation.decodeMacaroon(new Secret(reversed.bytes)).permissions).toEqual(reference.permissions);
});
