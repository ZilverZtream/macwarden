import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';

const repo = resolve();

it('CP-036/sentinel-independent-structure independent byte layout and decode agree on global sentinel', async () => {
  const directory = join(repo, 'test', 'sentinels');
  const bytes = readFileSync(join(directory, 'sentinel.macaroon'));
  const manifest = JSON.parse(readFileSync(join(directory, 'manifest.json'), 'utf8')) as {
    file: string; length: number; fingerprint: string; storageId: string };
  expect(manifest.file).toBe('sentinel.macaroon');
  expect(bytes.length).toBe(manifest.length);
  expect(bytes[0]).toBe(2);
  let at = 1;
  function packet() {
    const kind = bytes[at++];
    const length = bytes[at++];
    const value = bytes.subarray(at, at + length);
    at += length;
    return { kind, value };
  }
  expect(packet().kind).toBe(1);
  const id = packet();
  expect(id.kind).toBe(2);
  expect(id.value[0]).toBe(3);
  expect(id.value[1]).toBe(0x12);
  expect(id.value[2]).toBe(id.value.length - 3);
  expect(id.value.subarray(3).toString('ascii')).toBe(manifest.storageId);
  expect(bytes[at++]).toBe(0);
  expect(bytes[at++]).toBe(0);
  const signature = packet();
  expect(signature.kind).toBe(6);
  expect(signature.value.length).toBe(32);
  expect(at).toBe(bytes.length);
  const fingerprint = `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;
  expect(fingerprint).toBe(manifest.fingerprint);
  const { Secret } = await import('../../src/secret.js');
  const { decodeMacaroon } = await import('../../src/decode/index.js');
  const facts = decodeMacaroon(new Secret(bytes));
  expect(facts.rootKeyId).toBe(424242n);
  expect(facts.fingerprint).toBe(manifest.fingerprint);
});
