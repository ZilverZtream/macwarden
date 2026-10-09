import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import * as fs from 'node:fs/promises';
import Ajv2020 from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';
import { main } from '../src/cli.js';
import { run } from '../src/commands/inspect.js';
import { captureMain } from './support/capture.js';
import { repo, scratch } from './support/cp039-audit.js';
import { rune, runeFingerprint } from './support/runes.js';

// docs/spec.md, Commands > 1. inspect > Core Lightning runes.

const validateInspect = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(
  JSON.parse(readFileSync(join(repo, 'schemas/output/inspect.schema.json'), 'utf8')));
const TEXT = '=12&method=pay|method=keysend&time<1700000000';
const RUNE = rune(TEXT);

describe('RUNE/inspect', () => {
  it('RUNE/inspect a rune file gives the rune result, schema-valid, with recognition, assessment and verification apart', async () => scratch(async dir => {
    const file = join(dir, 'app.rune');
    writeFileSync(file, `${RUNE}\n`);
    const result = await captureMain(main, ['inspect', file, '--json']);
    expect(result.code).toBe(0);
    const parsed = JSON.parse(result.stdout);
    expect(validateInspect(parsed), JSON.stringify(validateInspect.errors)).toBe(true);
    expect(parsed.result).toEqual({
      kind: 'rune', fingerprint: runeFingerprint(TEXT), grade: 'SPEND', reasons: ['keysend', 'pay'], unassessed: [],
      rune: {
        recognition: 'rune-syntax', methodTable: 'cln-v26.06.8', uniqueId: '12', version: null,
        restrictions: [[{ field: 'method', condition: '=', value: 'pay' }, { field: 'method', condition: '=', value: 'keysend' }],
          [{ field: 'time', condition: '<', value: '1700000000' }]],
        omittedAlternatives: 0, methods: 'listed', allowedMethods: ['keysend', 'pay'], capabilities: ['SPEND'],
        sensitiveMethods: [], conditions: ['time'], expiry: { status: 'deadline-passed', deadline: '1700000000' },
        verification: 'unchecked', warnings: [],
      },
    });
    expect(result.stdout.includes(RUNE.slice(0, 43))).toBe(false);
  }));

  it('RUNE/inspect text output names what is and is not checked', async () => scratch(async dir => {
    const file = join(dir, 'app.rune');
    writeFileSync(file, RUNE);
    const result = await captureMain(main, ['inspect', file]);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('kind         rune (Core Lightning)');
    expect(result.stdout).toContain('unique ID    12');
    expect(result.stdout).toContain('grade        SPEND   (keysend, pay)');
    expect(result.stdout).toContain('restriction  method=pay OR method=keysend');
    expect(result.stdout).toContain('and          time<1700000000');
    expect(result.stdout).toContain('deadline passed according to local clock');
    expect(result.stdout).toContain('verified     no: authenticity, issuing node, blacklist and rate-limit state are not checked offline');
    expect(result.stdout.includes(RUNE.slice(0, 43))).toBe(false);
  }));

  it('RUNE/inspect stdin, an unpadded copy and a literal with --unsafe-arg give the same result', async () => {
    const deps = (input: string) => ({ stdin: Object.assign(Readable.from([Buffer.from(input)]), { isTTY: false }), fs,
      clock: () => new Date('2026-10-09T00:00:00Z') });
    const stdin = await run(['-'], deps(RUNE));
    const unpadded = await run(['-'], deps(RUNE.replace(/=+$/, '')));
    const literal = await run([RUNE, '--unsafe-arg'], deps(''));
    expect(stdin.ok).toBe(true);
    expect(unpadded.result).toMatchObject({ fingerprint: runeFingerprint(TEXT), grade: 'SPEND' });
    expect(literal.result).toEqual(stdin.result);
    expect(literal.warnings).toEqual(['unsafe-arg']);
  });

  it('RUNE/inspect a literal rune without --unsafe-arg is refused as a literal credential and not echoed', async () => {
    const result = await captureMain(main, ['inspect', RUNE, '--json']);
    expect(result.code).toBe(2);
    expect(JSON.parse(result.stdout).error.message).toBe('pass a file path or - (stdin); literal credentials end up in shell history and process listings');
    expect((result.stdout + result.stderr).includes(RUNE.slice(0, 20))).toBe(false);
  });

  it('RUNE/inspect a macaroon is still a macaroon', async () => {
    const macaroon = readFileSync(join(repo, 'test/vectors/default-readonly.macaroon'));
    const deps = { stdin: Object.assign(Readable.from([Buffer.from(macaroon.toString('base64url'))]), { isTTY: false }), fs, clock: () => new Date() };
    const result = await run(['-'], deps);
    expect(result.ok).toBe(true);
    expect(result.result).toMatchObject({ grade: 'READ', snapshot: '0.21.4-beta' });
  });

  it('RUNE/inspect text that is neither keeps the macaroon decoding error', async () => {
    const deps = { stdin: Object.assign(Readable.from([Buffer.from(rune('=1&method').replace(/=+$/, ''))]), { isTTY: false }), fs, clock: () => new Date() };
    const result = await run(['-'], deps);
    expect(result.ok).toBe(false);
    expect(result.error?.code).toBe(3);
  });

  it('RUNE/inspect restriction values that hold secrets are redacted and bounded', async () => {
    const preimage = 'ab'.repeat(32);
    const deps = { stdin: Object.assign(Readable.from([Buffer.from(rune(`=1&method=pay&pnamepreimage=${preimage}`))]), { isTTY: false }),
      fs, clock: () => new Date() };
    const result = await run(['-'], deps);
    const text = JSON.stringify(result);
    expect(text.includes(preimage)).toBe(false);
    expect(text).toContain('[redacted]');
  });

  it('RUNE/inspect the deadline uses the injected clock', async () => {
    const at = (iso: string) => run(['-'], { stdin: Object.assign(Readable.from([Buffer.from(rune('=1&time<1800000000'))]), { isTTY: false }),
      fs, clock: () => new Date(iso) });
    expect(((await at('2027-01-15T07:59:59Z')).result as { rune: { expiry: unknown } }).rune.expiry).toEqual({ status: 'deadline-ahead', deadline: '1800000000' });
    expect(((await at('2027-01-15T08:00:00Z')).result as { rune: { expiry: unknown } }).rune.expiry).toEqual({ status: 'deadline-passed', deadline: '1800000000' });
  });
});
