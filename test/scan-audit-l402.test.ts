import { writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { run } from '../src/commands/scan.js';
import { scan } from '../src/scan/index.js';
import { token } from './helpers/l402-vectors.js';
import { scratch, vector } from './support/cp039-audit.js';

// An L402 Authorization value carrying LND macaroons: every LND macaroon in it is reported at its
// own column with its own grade; only the one the L402 decode reports stands for the credential.
const PREIMAGE = 'ab'.repeat(32);
const clock = () => new Date('2026-10-09T12:00:00Z');

async function scanValue(dir: string, value: string) {
  const path = join(dir, 'app.env');
  writeFileSync(path, `AUTH=${value}\n`);
  const result = await scan([path], { clock });
  const gate = await run([path, '--fail-on', 'ADMIN'], { fs });
  return { result, gate, findings: result.findings.map(f => [f.column, f.kind, f.fingerprint, f.grade]) };
}

it('L402 <admin>,<readonly>:<preimage> reports the admin macaroon as ADMIN and the readonly one as READ', async () => scratch(async dir => {
  const admin = vector('default-admin'), readonly = vector('default-readonly');
  const a = admin.bytes.toString('base64'), r = readonly.bytes.toString('base64');
  const { result, gate, findings } = await scanValue(dir, `L402 ${a},${r}:${PREIMAGE}`);
  const first = 'AUTH=L402 '.length + 1;
  expect(findings).toEqual([
    [first, 'macaroon-base64', admin.fingerprint, 'ADMIN'],
    [first + a.length + 1, 'macaroon-base64', readonly.fingerprint, 'READ'],
  ]);
  expect(result.summary.byGrade).toMatchObject({ ADMIN: 1, READ: 1, L402: 0 });
  expect(gate.exitCode).toBe(1);
}));

it('L402 <readonly>,<admin>:<preimage> reports the admin macaroon at its own column', async () => scratch(async dir => {
  const admin = vector('default-admin'), readonly = vector('default-readonly');
  const a = admin.bytes.toString('base64'), r = readonly.bytes.toString('base64');
  const { result, gate, findings } = await scanValue(dir, `L402 ${r},${a}:${PREIMAGE}`);
  const first = 'AUTH=L402 '.length + 1;
  expect(findings).toEqual([
    [first, 'macaroon-base64', readonly.fingerprint, 'READ'],
    [first + r.length + 1, 'macaroon-base64', admin.fingerprint, 'ADMIN'],
  ]);
  expect(result.summary.byGrade).toMatchObject({ ADMIN: 1, READ: 1 });
  expect(gate.exitCode).toBe(1);
}));

it('L402 <aperture>,<admin>:<preimage> reports the LND admin macaroon, not an L402 token counted as READ', async () => scratch(async dir => {
  const admin = vector('default-admin');
  const aperture = token(301).base64;
  const a = admin.bytes.toString('base64');
  const { result, gate, findings } = await scanValue(dir, `L402 ${aperture},${a}:${PREIMAGE}`);
  // The Aperture macaroon is not what the finding stands for: it is reported as a bare L402 macaroon.
  expect(findings).toEqual([
    ['AUTH=L402 '.length + 1, 'l402', expect.stringMatching(/^fp:[0-9a-f]{16}$/), null],
    ['AUTH=L402 '.length + 1 + aperture.length + 1, 'macaroon-base64', admin.fingerprint, 'ADMIN'],
  ]);
  expect(result.summary.byGrade).toMatchObject({ ADMIN: 1, L402: 1 });
  expect(gate.exitCode).toBe(1);
}));

it('an L402 value that does not decode hides none of the macaroons inside it', async () => scratch(async dir => {
  const admin = vector('default-admin');
  const a = admin.bytes.toString('base64');
  // The second macaroon is not a macaroon, so the value does not decode as an L402 credential.
  const { findings } = await scanValue(dir, `L402 ${a},${'A'.repeat(60)}:${PREIMAGE}`);
  // The value fails closed as an undecodable candidate, and the admin macaroon inside it is reported.
  expect(findings).toEqual([
    ['AUTH='.length + 1, 'undecodable-candidate', expect.stringMatching(/^fp:[0-9a-f]{16}$/), null],
    ['AUTH=L402 '.length + 1, 'macaroon-base64', admin.fingerprint, 'ADMIN'],
  ]);
}));

it('an L402 token of Aperture macaroons alone is one l402 finding', async () => scratch(async dir => {
  const one = token(302), two = token(303);
  const { findings } = await scanValue(dir, `L402 ${one.base64},${two.base64}:${one.preimage.toString('hex')}`);
  expect(findings.map(f => [f.at(0), f.at(1)])).toEqual([['AUTH='.length + 1, 'l402']]);
}));

it('a single LND macaroon in an L402 value is still reported once', async () => scratch(async dir => {
  const admin = vector('default-admin');
  const { findings } = await scanValue(dir, `L402 ${admin.bytes.toString('base64')}:${PREIMAGE}`);
  expect(findings).toEqual([['AUTH=L402 '.length + 1, 'macaroon-base64', admin.fingerprint, 'ADMIN']]);
}));
