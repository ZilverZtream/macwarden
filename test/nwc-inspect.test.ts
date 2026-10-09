import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect, it, vi } from 'vitest';
import { run as inspect } from '../src/commands/inspect.js';
import { readCredential } from '../src/input/index.js';
import { render } from '../src/output/index.js';
import { scan } from '../src/scan/index.js';
import { findLeaks } from '../scripts/leak-check.mjs';
import { scratchDirectory } from './support/cp039-scratch.js';

// Synthetic NIP-47 connections: random keys generated per run, never real.
const networkCalls = vi.hoisted(() => [] as string[]);
vi.mock('node:https', async importOriginal => {
  const original = await importOriginal<typeof import('node:https') & { default: typeof import('node:https') }>();
  const blocked = () => { networkCalls.push('https'); throw new Error('network called'); };
  return { ...original, request: blocked, get: blocked, default: { ...original.default, request: blocked, get: blocked } };
});

const repo = resolve();
const schema = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(
  JSON.parse(readFileSync(join(repo, 'schemas/output/inspect.schema.json'), 'utf8')));
const fingerprintOf = (hex: string) => 'fp:' + createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex').slice(0, 16);
const clock = () => new Date('2026-10-07T09:00:00Z');
const wallet32 = 'ab'.repeat(32);

function connection(query?: (secret: string) => string) {
  const secret = randomBytes(32).toString('hex'), wallet = randomBytes(32).toString('hex');
  const params = query ? query(secret) : `relay=wss%3A%2F%2Frelay.example.com&secret=${secret}&lud16=alice%40example.com`;
  return { secret, wallet, uri: `nostr+walletconnect://${wallet}?${params}` };
}

async function withFile<T>(text: string, work: (path: string, dir: string) => Promise<T>): Promise<T> {
  const { dir, cleanup } = scratchDirectory('nwc-');
  try {
    const path = join(dir, 'connection.txt');
    writeFileSync(path, text);
    return await work(path, dir);
  } finally { cleanup(); }
}

const deps = () => ({ stdin: Readable.from([]) as Readable & { isTTY?: boolean }, fs, clock });

function secretForms(secret: string): string[] {
  const bytes = Buffer.from(secret, 'hex');
  return [secret, secret.toUpperCase(), bytes.toString('base64'), bytes.toString('base64').replace(/=+$/, ''),
    bytes.toString('base64url')];
}

function noSecret(text: string, secret: string): void {
  for (const form of secretForms(secret)) expect(text.includes(form), 'connection secret exposed').toBe(false);
}

it('NWC-inspect/decode reports wallet, client, relays, lud16, fingerprint and SPEND without the secret', async () => {
  const { secret, wallet, uri } = connection();
  await withFile(`${uri}\n`, async path => {
    const result = await inspect([path], deps());
    expect(result.error).toBeNull();
    expect(result.result).toEqual({ kind: 'nwc', fingerprint: fingerprintOf(secret), walletPubkey: wallet,
      clientPubkey: expect.stringMatching(/^[0-9a-f]{64}$/), relays: ['wss://relay.example.com'], lud16: 'alice@example.com',
      grade: 'SPEND', reasons: ['nwc-wallet-side-limits'], warnings: [] });
    for (const mode of ['text', 'json'] as const) {
      const out = render(result, mode);
      noSecret(out, secret);
      if (mode === 'json') expect(schema(JSON.parse(out)), JSON.stringify(schema.errors)).toBe(true);
      else expect(out).toMatch(/grade\s+SPEND/);
    }
    expect(networkCalls).toEqual([]);
  });
});

it('NWC-inspect/client-key derives the x-only secp256k1 public key of the secret', async () => {
  const one = '0'.repeat(63) + '1';
  await withFile(`nostr+walletconnect://${wallet32}?relay=wss://r.example&secret=${one}`, async path => {
    const result = await inspect([path], deps());
    // The generator point G: the public key of private key 1.
    expect((result.result as { clientPubkey: string }).clientPubkey)
      .toBe('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  });
});

it('NWC-inspect/fingerprint equals the scan fingerprint for the same connection', async () => {
  const { secret, uri } = connection();
  await withFile(`NWC_URL=${uri}\n`, async (path, dir) => {
    const scanned = await scan([dir]);
    const nwc = scanned.findings.filter(finding => finding.kind === 'nwc');
    expect(nwc).toHaveLength(1);
    writeFileSync(path, uri);
    const result = await inspect([path], deps());
    expect((result.result as { fingerprint: string }).fingerprint).toBe(nwc[0].fingerprint);
    expect(nwc[0].fingerprint).toBe(fingerprintOf(secret));
  });
});

it.each([
  ['relay userinfo', (s: string) => `relay=wss%3A%2F%2Fuser%3Apass%40relay.example.com&secret=${s}`],
  ['relay query', (s: string) => `relay=wss%3A%2F%2Frelay.example.com%2F%3Ftoken%3Dabc&secret=${s}`],
])('NWC-inspect/relay-redaction %s never reaches output', async (_name, query) => {
  const { secret, uri } = connection(query);
  await withFile(uri, async path => {
    const result = await inspect([path], deps());
    expect(result.ok).toBe(true);
    const text = render(result, 'text'), json = render(result, 'json');
    noSecret(text + json, secret);
    for (const hidden of ['user', 'pass', 'token']) expect(json.includes(hidden)).toBe(false);
    expect(schema(JSON.parse(json)), JSON.stringify(schema.errors)).toBe(true);
  });
});

it('NWC-inspect/relay-redaction reports removed relay details as a warning', async () => {
  const { uri } = connection(s => `relay=wss%3A%2F%2Fu%3Ap%40relay.example.com&secret=${s}`);
  await withFile(uri, async path => {
    const result = await inspect([path], deps());
    expect((result.result as { warnings: string[] }).warnings).toEqual(['relay-details-removed']);
    expect(render(result, 'text')).toMatch(/relay-details-removed/);
  });
});

const malformed: [string, (secret: string) => string, string][] = [
  ['no query', () => `nostr+walletconnect://${wallet32}`, 'nwc-uri'],
  ['short wallet key', s => `nostr+walletconnect://abcd?relay=wss://r.example&secret=${s}`, 'nwc-wallet-pubkey'],
  ['missing secret', () => `nostr+walletconnect://${wallet32}?relay=wss://r.example`, 'nwc-secret'],
  ['two secrets', s => `nostr+walletconnect://${wallet32}?relay=wss://r.example&secret=${s}&secret=${s}`, 'nwc-secret'],
  ['zero secret', () => `nostr+walletconnect://${wallet32}?relay=wss://r.example&secret=${'0'.repeat(64)}`, 'nwc-secret'],
  ['secret above curve order', () => `nostr+walletconnect://${wallet32}?relay=wss://r.example&secret=${'f'.repeat(64)}`, 'nwc-secret'],
  ['no relay', s => `nostr+walletconnect://${wallet32}?secret=${s}`, 'nwc-relay'],
  ['https relay', s => `nostr+walletconnect://${wallet32}?relay=https://r.example&secret=${s}`, 'nwc-relay'],
  ['two lud16', s => `nostr+walletconnect://${wallet32}?relay=wss://r.example&secret=${s}&lud16=a%40b.c&lud16=d%40e.f`, 'nwc-lud16'],
  ['fragment', s => `nostr+walletconnect://${wallet32}?relay=wss://r.example&secret=${s}#x`, 'nwc-uri'],
];
it.each(malformed)('NWC-inspect/malformed %s fails at its stage without echoing input', async (_name, build, stage) => {
  const secret = randomBytes(32).toString('hex');
  await withFile(build(secret), async path => {
    const result = await inspect([path], deps());
    expect(result.error).toEqual({ code: 3, step: stage, message: `invalid NWC URI ${stage}` });
    const out = render(result, 'text') + render(result, 'json');
    noSecret(out, secret);
    expect(out.includes('walletconnect')).toBe(false);
    expect(schema(JSON.parse(render(result, 'json'))), JSON.stringify(schema.errors)).toBe(true);
  });
});

it('NWC-inspect/literal refuses an NWC URI argument unless --unsafe-arg', async () => {
  const { secret, uri } = connection();
  const refused = await inspect([uri], deps());
  expect(refused.error).toMatchObject({ code: 2, step: null });
  expect(refused.error!.message).toMatch(/pass a file path or - \(stdin\)/);
  noSecret(render(refused, 'text'), secret);
  const accepted = await inspect([uri, '--unsafe-arg'], deps());
  expect(accepted.warnings).toEqual(['unsafe-arg']);
  expect((accepted.result as { fingerprint: string }).fingerprint).toBe(fingerprintOf(secret));
});

it('NWC-inspect/stdin decodes an NWC URI from standard input', async () => {
  const { secret, uri } = connection();
  const result = await inspect(['-'], { ...deps(), stdin: Readable.from([Buffer.from(uri + '\n')]) });
  expect((result.result as { fingerprint: string }).fingerprint).toBe(fingerprintOf(secret));
});

it('NWC-inspect/scope other commands keep refusing NWC input at input-form', async () => {
  const { uri } = connection();
  await withFile(uri, async path => {
    await expect(readCredential(path, deps(), { unsafeArg: false })).rejects.toMatchObject({ stage: 'input-form' });
  });
});

it('NWC-inspect/leak-check finds a bare NWC secret leaked without its URI in every encoding', async () => {
  const { secret, uri } = connection();
  const { dir, cleanup } = scratchDirectory('nwc-');
  try {
    const sentinels = join(dir, 'sentinels');
    await fs.mkdir(sentinels);
    writeFileSync(join(sentinels, 'connection.txt'), uri);
    const list = join(dir, 'list.json');
    writeFileSync(list, '[]');
    for (const form of secretForms(secret)) {
      expect(findLeaks({ sentinels: list, sentinelDir: sentinels, root: dir, commandOutput: `value ${form} end` }),
        `bare secret form of length ${form.length}`).not.toBeNull();
    }
    expect(findLeaks({ sentinels: list, sentinelDir: sentinels, root: dir, commandOutput: 'ordinary safe output' })).toBeNull();
  } finally { cleanup(); }
});
