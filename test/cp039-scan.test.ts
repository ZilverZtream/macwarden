import { linkSync, readFileSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { expect, it, vi } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';
import { main } from '../src/cli.js';
import { readCredential } from '../src/input/index.js';
import { scan } from '../src/scan/index.js';
import { captureMain } from './support/capture.js';
import { repo, scratch, vector } from './support/cp039-audit.js';

const validateScan = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(
  JSON.parse(readFileSync(join(repo, 'schemas/output/scan.schema.json'), 'utf8')));

for (const [name, glob] of [['long glob', 'a'.repeat(65_536)], ['token-heavy glob', '?*'.repeat(32_768)]] as const) {
  it(`CP-039/B8-ignore-bounds refuses ${name} as an invalid ignore file`, async () => scratch(async dir => {
    const v = vector('default-readonly'), file = join(dir, 'fixture.macaroon'); writeFileSync(file, v.bytes);
    writeFileSync(join(dir, '.macwardenignore'), `${v.fingerprint} ${glob}\n`);
    const result = await captureMain(main, ['scan', dir, '--json']);
    expect(result.code).toBe(3);
    expect(JSON.parse(result.stdout)).toMatchObject({ ok: false, result: null, error: { code: 3, step: 'ignore-file' } });
  }));
}
it('CP-039/B8-ignore-bounds discloses suppressed fingerprints in text and JSON without counting fail-on', async () => scratch(async dir => {
  const v = vector('default-readonly'), other = vector('preset-invoice-only');
  writeFileSync(join(dir, 'first.macaroon'), v.bytes);
  writeFileSync(join(dir, 'repeated.macaroon'), v.bytes);
  writeFileSync(join(dir, 'distinct.macaroon'), other.bytes);
  const fingerprints = [v.fingerprint, other.fingerprint].sort();
  writeFileSync(join(dir, '.macwardenignore'), `${other.fingerprint}\n${v.fingerprint}\n`);
  for (const mode of ['text', 'json']) {
    const result = await captureMain(main, ['scan', dir, '--fail-on', 'READ', ...(mode === 'json' ? ['--json'] : [])]);
    expect(result.code).toBe(0);
    for (const fingerprint of fingerprints)
      expect.soft((result.stdout + result.stderr).includes(fingerprint), `${mode} discloses the suppressed fingerprint`).toBe(true);
    if (mode === 'text') {
      const line = result.stdout.split('\n').find(value => value.startsWith('ignored-fingerprints'));
      expect.soft(line).toBeDefined();
      expect.soft(line?.match(/fp:[0-9a-f]{16}/g)).toEqual(fingerprints);
    } else {
      const parsed = JSON.parse(result.stdout);
      expect.soft(validateScan(parsed), 'public scan schema validation').toBe(true);
      expect.soft(parsed.result.ignoredFingerprints).toEqual(fingerprints);
      expect.soft(parsed).toMatchObject({ ok: true, error: null,
        result: { findings: [], summary: { ignored: 3, findings: 0, distinct: 0,
          byGrade: { ADMIN: 0, SPEND: 0, OPERATE: 0, RECEIVE: 0, READ: 0, UNASSESSED: 0, NWC: 0, UNDECODABLE: 0, L402: 0 } },
        failOn: { threshold: 'READ', count: 0 } } });
      expect.soft(parsed.result.summary.filesSkipped).toBe(parsed.result.skipped.length);
    }
  }
}));
it('CP-039/B8-ignore-bounds explicit trusted ignore file controls suppression despite local attacker entries', async () => scratch(async dir => {
  const v = vector('default-readonly'), file = join(dir, 'fixture.macaroon'); writeFileSync(file, v.bytes);
  writeFileSync(join(dir, '.macwardenignore'), `${v.fingerprint}\n`);
  const trusted = join(dir, 'trusted.txt'); writeFileSync(trusted, '# operator-owned policy\n');
  const result = await captureMain(main, ['scan', dir, '--ignore-file', trusted, '--fail-on', 'READ', '--json']);
  expect(result.code).toBe(1);
  const parsed = JSON.parse(result.stdout);
  expect(validateScan(parsed), 'public scan schema validation').toBe(true);
  expect(parsed.result).not.toHaveProperty('ignoredFingerprints');
  expect(parsed.result.summary.filesSkipped).toBe(parsed.result.skipped.length);
  expect(parsed).toMatchObject({ ok: true, error: null,
    result: { findings: [{ fingerprint: v.fingerprint, grade: v.expectedGrade }], summary: { ignored: 0, findings: 1 },
      failOn: { threshold: 'READ', count: 1 } } });
}));
it('CP-039/B9-protected-limits protected names are refused before open and a safe hardlink has the documented name limitation', async () => scratch(async dir => {
  const v = vector('default-readonly'), protectedPath = join(dir, 'macaroons.db'), alias = join(dir, 'hard.macaroon');
  // A synthetic vector fixture, never an LND database. Never read the protected name.
  writeFileSync(protectedPath, v.bytes); linkSync(protectedPath, alias);
  const opened: string[] = [];
  const guarded = { ...fs, open: vi.fn(async (...args: Parameters<typeof fs.open>) => {
    opened.push(String(args[0]));
    if (String(args[0]) === protectedPath) throw new Error('Protected fixture must never be opened');
    return fs.open(...args);
  }) };
  await expect(readCredential(protectedPath, { fs: guarded, stdin: Readable.from([]) }, { unsafeArg: false }))
    .rejects.toMatchObject({ stage: 'input-read' });
  expect(opened).toEqual([]);
  const refused = await scan([protectedPath], { includeDirs: false, fs: guarded });
  expect(refused.findings).toEqual([]); expect(refused.skipped).toMatchObject([{ reason: 'never-open' }]);
  expect(opened).toEqual([]);
  const inspected = await captureMain(main, ['inspect', alias, '--json']);
  expect(inspected.code).toBe(0); expect(JSON.parse(inspected.stdout).result.fingerprint).toBe(v.fingerprint);
  const accepted = await scan([alias], { includeDirs: false, fs: guarded });
  expect(accepted.findings).toMatchObject([{ fingerprint: v.fingerprint, grade: v.expectedGrade }]);
  expect(opened).toEqual([alias]);
  expect(readFileSync(alias).equals(v.bytes)).toBe(true);
}));
