import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect, it } from 'vitest';
import { run as inspect } from '../src/commands/inspect.js';
import { render } from '../src/output/index.js';
import { scan } from '../src/scan/index.js';
import { nwc as nwcPattern } from '../src/scan/patterns.js';
import { findLeaks } from '../scripts/leak-check.mjs';
import { jsRegex, rules } from './gitleaks/rules-support.js';
import { scratchDirectory } from './support/cp039-scratch.js';

// Specified behaviour: a reported NWC field that carries the connection
// secret in any recognisable encoding is refused (exit 3), never partially
// redacted. Synthetic keys only.
const repo = resolve();
const schema = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(
  JSON.parse(readFileSync(join(repo, 'schemas/output/inspect.schema.json'), 'utf8')));
const fingerprintOf = (hex: string) => 'fp:' + createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex').slice(0, 16);
const deps = () => ({ stdin: Readable.from([]) as Readable & { isTTY?: boolean }, fs, clock: () => new Date('2026-10-07T09:00:00Z') });

// A secret whose base64url form is purely alphanumeric, so it is a valid DNS label.
function alphanumericSecret(): Buffer {
  for (;;) {
    const bytes = randomBytes(32);
    if (/^[A-Za-z0-9]+$/.test(bytes.toString('base64url'))) return bytes;
  }
}

async function inspectText(text: string) {
  const { dir, cleanup } = scratchDirectory('nwc-closed-');
  try {
    const path = join(dir, 'connection.txt');
    writeFileSync(path, text);
    return await inspect([path], deps());
  } finally { cleanup(); }
}

function exposed(text: string, secret: Buffer): string[] {
  const hex = secret.toString('hex'), lower = text.toLowerCase();
  const forms = [hex, secret.toString('base64').replace(/=+$/, '').toLowerCase(), secret.toString('base64url').toLowerCase()];
  return forms.filter(form => lower.includes(form));
}

const percentEach = (text: string) => [...text].map(char => `%${char.charCodeAt(0).toString(16)}`).join('');
const relay = (url: string) => `relay=${encodeURIComponent(url)}`;
const wallet = 'ab'.repeat(32);

const refused: [string, (secret: Buffer) => string, string][] = [
  ['hex in relay path', s => `${relay(`wss://relay.example.com/${s.toString('hex')}`)}`, 'nwc-relay'],
  ['base64 in relay path', s => `${relay(`wss://relay.example.com/${s.toString('base64')}`)}`, 'nwc-relay'],
  ['base64url in relay path', s => `${relay(`wss://relay.example.com/${s.toString('base64url')}`)}`, 'nwc-relay'],
  ['percent-encoded hex in relay path', s => `${relay(`wss://relay.example.com/${percentEach(s.toString('hex'))}`)}`, 'nwc-relay'],
  ['hex split across host labels', s => `${relay(`wss://${s.toString('hex').slice(0, 32)}.${s.toString('hex').slice(32)}.example`)}`, 'nwc-relay'],
  ['case-folded base64url host', s => `${relay(`wss://${s.toString('base64url')}.example`)}`, 'nwc-relay'],
  ['hex split across path segments of the second relay', s => `${relay('wss://a.example')}&${relay(`wss://b.example/${s.toString('hex').slice(0, 20)}/${s.toString('hex').slice(20)}`)}`, 'nwc-relay'],
  ['hex split across lud16', s => `${relay('wss://relay.example.com')}&lud16=${s.toString('hex').slice(0, 32)}-x%40${s.toString('hex').slice(32)}.y`, 'nwc-lud16'],
  ['base64 as lud16 user', s => `${relay('wss://relay.example.com')}&lud16=${encodeURIComponent(s.toString('base64url'))}%40example.com`, 'nwc-lud16'],
  // Bytes in front of the secret shift its base64 alignment, so its characters differ from the
  // aligned encoding; SPEC requires every byte alignment to be recognised.
  ['base64 shifted by one leading byte in relay path', s => `${relay(`wss://relay.example.com/${Buffer.concat([Buffer.from([0x7f]), s]).toString('base64url')}`)}`, 'nwc-relay'],
  ['base64 shifted by two leading bytes in relay path', s => `${relay(`wss://relay.example.com/${Buffer.concat([Buffer.from([0x7f, 0x01]), s]).toString('base64url')}`)}`, 'nwc-relay'],
];

it.each(refused)('NWC-inspect/fail-closed %s is refused with exit 3 and no secret in output', async (_name, query, stage) => {
  const secret = alphanumericSecret();
  const result = await inspectText(`nostr+walletconnect://${wallet}?${query(secret)}&secret=${secret.toString('hex')}`);
  expect(result.error).toEqual({ code: 3, step: stage, message: `invalid NWC URI ${stage}` });
  const out = render(result, 'text') + render(result, 'json');
  expect(exposed(out, secret)).toEqual([]);
  expect(schema(JSON.parse(render(result, 'json'))), JSON.stringify(schema.errors)).toBe(true);
});

it('NWC-inspect/fail-closed wallet pubkey equal to the secret is refused', async () => {
  const secret = alphanumericSecret(), hex = secret.toString('hex');
  const result = await inspectText(`nostr+walletconnect://${hex}?${relay('wss://relay.example.com')}&secret=${hex}`);
  expect(result.error).toEqual({ code: 3, step: 'nwc-wallet-pubkey', message: 'invalid NWC URI nwc-wallet-pubkey' });
  expect(exposed(render(result, 'text') + render(result, 'json'), secret)).toEqual([]);
});

it('NWC-inspect/fail-closed unrelated hex and base64 in relays and lud16 are still reported', async () => {
  const secret = alphanumericSecret(), other = randomBytes(32);
  const query = `${relay(`wss://relay.example.com/${other.toString('hex')}`)}&${relay(`wss://${other.toString('base64url').replace(/[-_]/g, 'x')}.example`)}` +
    `&lud16=${other.toString('hex').slice(0, 40)}%40example.com`;
  const result = await inspectText(`nostr+walletconnect://${wallet}?${query}&secret=${secret.toString('hex')}`);
  expect(result.error).toBeNull();
  expect((result.result as { relays: string[] }).relays).toHaveLength(2);
  expect((result.result as { lud16: string }).lud16).toBe(`${other.toString('hex').slice(0, 40)}@example.com`);
});

const schemes = ['nostr+walletconnect://', 'nostr+walletconnect:', 'nostrwalletconnect://', 'nostrwalletconnect:',
  'NOSTR+WALLETCONNECT://'];

it.each(schemes.flatMap(scheme => [[scheme, ''], [scheme, '/']]))(
  'NWC-inspect/legacy-forms %s with suffix "%s" decodes exactly like the canonical form', async (scheme, slash) => {
    const secret = randomBytes(32).toString('hex'), key = randomBytes(32).toString('hex');
    const query = `${relay('wss://relay.example.com')}&secret=${secret}&lud16=alice%40example.com`;
    const canonical = await inspectText(`nostr+walletconnect://${key}?${query}`);
    const variant = await inspectText(`${scheme}${key}${slash}?${query}`);
    expect(canonical.error).toBeNull();
    expect(variant.error).toBeNull();
    expect(variant.result).toEqual(canonical.result);
    expect((variant.result as { fingerprint: string }).fingerprint).toBe(fingerprintOf(secret));
  });

it('NWC-inspect/legacy-forms scan finds legacy-scheme connections with the secret fingerprint', async () => {
  const secrets = schemes.slice(1, 4).map(() => randomBytes(32).toString('hex'));
  const lines = schemes.slice(1, 4).map((scheme, at) =>
    `NWC_${at}=${scheme}${'22'.repeat(32)}${at === 0 ? '/' : ''}?relay=wss%3A%2F%2Fr&secret=${secrets[at]}`);
  const { dir, cleanup } = scratchDirectory('nwc-legacy-scan-');
  try {
    writeFileSync(join(dir, 'app.env'), lines.join('\n') + '\n');
    const result = await scan([dir]);
    expect(result.findings.filter(finding => finding.kind === 'nwc').map(finding => finding.fingerprint))
      .toEqual(secrets.map(fingerprintOf));
    const json = JSON.stringify(result);
    for (const secret of secrets) expect(json.includes(secret)).toBe(false);
  } finally { cleanup(); }
});

it('NWC-inspect/legacy-forms gitleaks rule and scan regex give identical spans on legacy lines', () => {
  const rule = rules().find(item => item.id === 'macwarden-nwc');
  expect(rule).toBeDefined();
  const secret = '3'.repeat(64);
  const lines = [...schemes, 'nostr+walletconnect//', 'nostr-walletconnect://'].flatMap(scheme => [
    `x=${scheme}${'22'.repeat(32)}?relay=wss%3A%2F%2Fr&secret=${secret} y`,
    `x=${scheme}${'22'.repeat(32)}/?secret=${secret}`,
  ]);
  const spans = (regex: RegExp, line: string) => [...line.matchAll(new RegExp(regex.source,
    regex.flags.includes('g') ? regex.flags : `${regex.flags}g`))].map(match => [match.index, match.index + match[0].length]);
  let matched = 0;
  for (const line of lines) {
    const scanSpans = spans(nwcPattern, line);
    expect(spans(jsRegex(rule!.regex), line), line).toEqual(scanSpans);
    matched += scanSpans.length;
  }
  // Ten legacy and canonical lines match; the two malformed schemes do not.
  expect(matched).toBe(10);
});

it('NWC-inspect/leak-check catches percent-encoded, case-folded and separator-split forms of the secret', async () => {
  const secret = alphanumericSecret(), hex = secret.toString('hex');
  // A legacy-scheme sentinel must still register its secret.
  const uri = `nostrwalletconnect:${wallet}?relay=wss%3A%2F%2Fr&secret=${hex}`;
  const { dir, cleanup } = scratchDirectory('nwc-leak-');
  try {
    const sentinels = join(dir, 'sentinels');
    await fs.mkdir(sentinels);
    writeFileSync(join(sentinels, 'connection.txt'), uri);
    const list = join(dir, 'list.json');
    writeFileSync(list, '[]');
    const forms = [
      percentEach(hex),
      `wss://${secret.toString('base64url').toLowerCase()}.example`,
      `${secret.toString('base64').replace(/=+$/, '').toLowerCase()}`,
      hex.match(/../g)!.join(':'),
      `wss://${hex.slice(0, 32)}.${hex.slice(32)}.example`,
    ];
    for (const form of forms) {
      expect(findLeaks({ sentinels: list, sentinelDir: sentinels, root: dir, commandOutput: `value ${form} end` }), form.slice(0, 12))
        .not.toBeNull();
    }
    expect(findLeaks({ sentinels: list, sentinelDir: sentinels, root: dir, commandOutput: 'ordinary safe output' })).toBeNull();
  } finally { cleanup(); }
});
