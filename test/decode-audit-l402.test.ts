import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { afterAll, describe, expect, it } from 'vitest';
import { run as inspect } from '../src/commands/inspect.js';
import { run as scanCommand } from '../src/commands/scan.js';
import { DecodeError, decodeL402, macaroonId } from '../src/decode/index.js';
import { parseValidUntil } from '../src/l402.js';
import type { OutputResult } from '../src/output/index.js';
import { Secret } from '../src/secret.js';
import { toV1, v2Macaroon } from './helpers/decode-audit-vectors.js';
import { identifier, sha256, token } from './helpers/l402-vectors.js';
import { rune } from './support/runes.js';

// 1.4.0 decode audit. Synthetic L402 tokens, runes and NWC URIs; LND vectors read by path.
const repo = resolve();
const scratch = mkdtempSync(join(resolve(process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp')), 'decode-audit-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));
const clock = () => new Date('2026-10-09T12:00:00Z');
const admin = readFileSync(join(repo, 'test/vectors/default-admin.macaroon'));
const readonly = readFileSync(join(repo, 'test/vectors/default-readonly.macaroon'));
const env = {};

async function inspectText(text: string | Buffer): Promise<OutputResult> {
  const stdin = Object.assign(Readable.from([Buffer.isBuffer(text) ? text : Buffer.from(text, 'utf8')]), { isTTY: false });
  return inspect(['-', '--json'], { stdin, fs, clock, env });
}
const kind = (result: OutputResult) => (result.result as { kind?: string } | null)?.kind;

describe('DECODE-AUDIT/an LND macaroon inside a multi-macaroon L402 value', () => {
  const t = token(401);
  const preimage = t.preimage.toString('hex');
  const cases: [string, Buffer[], string][] = [
    ['admin then readonly', [admin, readonly], 'ADMIN'],
    ['readonly then admin', [readonly, admin], 'ADMIN'],
    ['Aperture macaroon then admin', [t.macaroon, admin], 'ADMIN'],
    ['admin then Aperture macaroon', [admin, t.macaroon], 'ADMIN'],
    ['Aperture macaroon then readonly', [t.macaroon, readonly], 'READ'],
  ];

  it.each(cases)('DECODE-AUDIT/inspect %s is graded as the LND macaroon', async (_name, macaroons, grade) => {
    const result = await inspectText(`L402 ${macaroons.map(mac => mac.toString('base64')).join(',')}:${preimage}`);
    expect(result.error).toBeNull();
    expect(kind(result)).toBeUndefined();
    expect(result.result).toMatchObject({ grade, location: 'lnd' });
    const decoded = decodeL402(new Secret(Buffer.from(`L402 ${macaroons.map(mac => mac.toString('base64')).join(',')}:${preimage}`)));
    expect('lnd' in decoded && decoded.index).toBe(macaroons.indexOf(grade === 'ADMIN' ? admin : readonly));
  });

  it('DECODE-AUDIT/scan counts the value under its LND grade and --fail-on ADMIN fails', async () => {
    const dir = mkdtempSync(join(scratch, 'scan-'));
    writeFileSync(join(dir, 'app.env'), `AUTH_HEADER="L402 ${t.base64},${admin.toString('base64')}:${preimage}"\n`);
    const failed = await scanCommand([dir, '--fail-on', 'ADMIN'], { fs, env }) as OutputResult & { exitCode?: number;
      result: { summary: { byGrade: Record<string, number> } } };
    // In `L402 <aperture>,<admin>:<pre>` the Aperture macaroon is itself an L402 credential: the scan
    // reports the inner matches the L402 decode did not account for, so L402 counts 1 beside ADMIN 1.
    expect(failed.result.summary.byGrade).toMatchObject({ ADMIN: 1, L402: 1 });
    expect(failed.exitCode).toBe(1);
  });
});

describe('DECODE-AUDIT/L402 text is ASCII', () => {
  const t = token(402);
  const preimage = t.preimage.toString('hex');
  it.each([
    ['Authorization value', `L402 ${t.base64}ĺ${preimage}`],
    ['header line', `Authorization: L402 ${t.base64}ĺ${preimage}`],
    ['pair', `${t.base64}ĺ${preimage}`],
    ['pair with a Latin-1 character', `${t.base64}:${preimage}é`],
  ])('DECODE-AUDIT/an %s with a character above 0x7f exits 3', async (_name, text) => {
    const result = await inspectText(text);
    expect(result.error).toMatchObject({ code: 3 });
    expect(kind(result)).toBeUndefined();
  });

  it('DECODE-AUDIT/the decoder refuses L402 text holding a byte above 0x7f', () => {
    let thrown: unknown;
    try { decodeL402(new Secret(Buffer.from(`L402 ${t.base64}:${preimage}é`, 'latin1'))); } catch (error) { thrown = error; }
    expect(thrown).toBeInstanceOf(DecodeError);
    expect((thrown as DecodeError).stage).toBe('l402-form');
  });
});

describe('DECODE-AUDIT/decoded hex or base64 is read as a macaroon only', () => {
  const t = token(403);
  const nwc = `nostr+walletconnect://${'b'.repeat(64)}?relay=wss://relay.example&secret=${'1'.repeat(64)}`;
  const forms: [string, string][] = [['rune', rune('=1&method=getinfo')], ['NWC URI', nwc], ['L402 pair', t.pair], ['L402 header', t.header]];
  for (const [name, text] of forms) {
    it(`DECODE-AUDIT/hex and base64 of a ${name} exit 3`, async () => {
      // The form itself is still recognised.
      expect((await inspectText(text)).error).toBeNull();
      const bytes = Buffer.from(text, 'utf8');
      for (const encoded of [bytes.toString('hex'), bytes.toString('base64')]) {
        const result = await inspectText(encoded);
        expect(result.error, encoded.slice(0, 16)).toMatchObject({ code: 3 });
        expect(kind(result)).toBeUndefined();
      }
    });
  }

  it('DECODE-AUDIT/hex and base64 of an L402 macaroon are still an L402 token', async () => {
    for (const encoded of [t.macaroon.toString('hex'), t.base64]) {
      expect(await inspectText(encoded)).toMatchObject({ ok: true, result: { kind: 'l402', form: 'macaroon' } });
    }
  });
});

describe('DECODE-AUDIT/Aperture caveat details', () => {
  it('DECODE-AUDIT/a preimage in a third-party caveat ID is read as Aperture reads it, and that caveat is withheld', async () => {
    const preimage = sha256(Buffer.from('synthetic third-party preimage'));
    const id = identifier(sha256(preimage), sha256(Buffer.from('synthetic token')));
    const mac = v2Macaroon('lsat', id, [{ id: 'services=weather:0' },
      { id: `preimage=${preimage.toString('hex')}`, vid: Buffer.alloc(48, 9), location: 'auth.example' }]);
    const result = await inspectText(mac.toString('base64'));
    expect(result.result).toMatchObject({ kind: 'l402', preimage: 'matches', preimageSource: 'caveat', status: 'live',
      caveats: [{ type: 'services' }, { type: 'withheld', condition: null, value: null }] });
    expect((result.result as { warnings: string[] }).warnings).toContain('l402-caveat-withheld');
    expect(JSON.stringify(result)).not.toContain(preimage.toString('hex'));
  });

  it('DECODE-AUDIT/_valid_until with leading zeros is read as Go\'s ParseInt reads it', async () => {
    expect(parseValidUntil(`${'0'.repeat(60)}1893456000`)).toBe(1893456000n);
    expect(parseValidUntil(`-${'0'.repeat(60)}1`)).toBe(-1n);
    expect(parseValidUntil(`+${'0'.repeat(30)}`)).toBe(0n);
    expect(parseValidUntil('9223372036854775807')).toBe(9223372036854775807n);
    expect(parseValidUntil('9223372036854775808')).toBeUndefined();
    expect(parseValidUntil(`${'0'.repeat(10)}12345678901234567890`)).toBeUndefined();
    const t = token(404, ['services=weather:0', `weather_valid_until=${'0'.repeat(50)}1893456000`]);
    const result = await inspectText(t.header);
    expect(result.result).toMatchObject({ kind: 'l402', status: 'live', expired: false });
    expect((result.result as { warnings: string[] }).warnings).not.toContain('l402-bad-valid-until');
    expect((result.result as { caveats: { until?: string }[] }).caveats[1].until).toBe('2030-01-01T00:00:00Z');
  });
});

describe('DECODE-AUDIT/credential identity of a v1 re-encoding', () => {
  it('DECODE-AUDIT/a v1 binary macaroon has the identity of its v2 form', () => {
    for (const v2 of [admin, readonly]) {
      const v1 = toV1(v2);
      expect(v1[0]).toBe(0x30);
      expect(macaroonId(new Secret(v1))).toEqual(macaroonId(new Secret(v2)));
    }
  });

  it('DECODE-AUDIT/a malformed v1 macaroon is refused', () => {
    const v1 = toV1(admin);
    const broken = [v1.subarray(0, 5), Buffer.concat([Buffer.from('0004'), v1]), Buffer.from(v1.toString('latin1').replace('location', 'locatioN'), 'latin1'),
      Buffer.from(v1.toString('latin1').replace(/^[0-9a-f]{4}/, match => match.toUpperCase().replace(/[0-9]/g, 'A')), 'latin1')];
    for (const bytes of broken) expect(() => macaroonId(new Secret(bytes))).toThrow(DecodeError);
  });
});
