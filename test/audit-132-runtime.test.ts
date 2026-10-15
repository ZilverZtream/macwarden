import { getEventListeners } from 'node:events';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it, vi } from 'vitest';

// Audit 1.3.2: runtime findings outside the command modules. Synthetic vectors only.
const canonical = vi.hoisted(() => ({ calls: 0 }));
vi.mock('../src/decode/index.js', async original => {
  const actual = await original<typeof import('../src/decode/index.js')>();
  return { ...actual, canonicalMacaroonForm: (...args: Parameters<typeof actual.canonicalMacaroonForm>) => {
    canonical.calls++;
    return actual.canonicalMacaroonForm(...args);
  } };
});

const { Secret } = await import('../src/secret.js');
const { cancellable, withCancellation } = await import('../src/cancellation.js');
const { normalizedArgv } = await import('../src/cli.js');
const { redactCredentialText } = await import('../src/output/index.js');

const manifest = JSON.parse(readFileSync(resolve('test/vectors/manifest.json'), 'utf8')) as { vectors: { name: string; fingerprint: string }[] };
const admin = readFileSync(resolve('test/vectors/default-admin.macaroon'));

// watch wraps every intercepted macaroon in a Secret while it answers LND and needs only the
// identifier; the canonical parse and hash behind the fingerprint ran in the constructor.
it('AUDIT-132/secret the fingerprint is computed on first read only, with the same value', () => {
  canonical.calls = 0;
  const secret = new Secret(admin);
  expect(canonical.calls).toBe(0);
  expect(secret.fingerprint).toBe(manifest.vectors.find(item => item.name === 'default-admin')!.fingerprint);
  expect(secret.fingerprint).toBe(secret.fingerprint);
  expect(canonical.calls).toBe(1);
  expect(String(secret)).toBe(`[redacted ${secret.fingerprint}]`);
});

it('AUDIT-132/cancellable an operation that throws before returning a promise leaves no abort listener', async () => {
  const controller = new AbortController();
  await withCancellation(controller.signal, async () => {
    for (let i = 0; i < 3; i++)
      await expect(cancellable((): Promise<void> => { throw new Error('thrown at once'); })).rejects.toThrow('thrown at once');
  });
  expect(getEventListeners(controller.signal, 'abort')).toHaveLength(0);
});

it('AUDIT-132/cli a leading --json names the command main runs, as bin.ts reads it', () => {
  expect(normalizedArgv(['--json', 'watch', '--lnd-rest', 'x'])).toEqual(['watch', '--json', '--lnd-rest', 'x']);
  expect(normalizedArgv(['watch', '--json'])[0]).toBe('watch');
  expect(normalizedArgv(['--json'])).toEqual(['--json']);
});

// The output read an lndconnect URI only in base64url and only without the punctuation that
// follows it in prose or YAML; the URI was then kept with just its macaroon redacted.
it('AUDIT-132/lndconnect a URI followed by punctuation or in standard base64 is redacted whole', () => {
  const url = admin.toString('base64url');
  const standard = admin.toString('base64');
  const uri = (macaroon: string) => `lndconnect://node.example:10009?cert=MIICabc&macaroon=${encodeURIComponent(macaroon)}`;
  expect(redactCredentialText(`(${uri(url)})`)).toBe('([redacted])');
  expect(redactCredentialText(`see ${uri(url)}, then`)).toBe('see [redacted], then');
  expect(redactCredentialText(`${uri(url)}.`)).toBe('[redacted].');
  expect(redactCredentialText(`key: ${uri(standard)}`)).toBe('key: [redacted]');
});
