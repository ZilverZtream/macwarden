import { writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { run } from '../src/commands/scan.js';
import { scan } from '../src/scan/index.js';
import { scratch, vector } from './support/cp039-audit.js';

const kinds = (result: Awaited<ReturnType<typeof scan>>) =>
  result.findings.map(finding => [finding.column, finding.kind, finding.fingerprint, finding.grade]);

it('a confirmed lndconnect URI hides only its own macaroon, not another credential in a further query parameter', async () => scratch(async dir => {
  const invoice = vector('default-invoice'), admin = vector('default-admin');
  const uri = `lndconnect://h:10009?macaroon=${invoice.bytes.toString('base64url')}`;
  const path = join(dir, 'two-in-uri.env');
  writeFileSync(path, `A=${uri}&note=${admin.bytes.toString('hex')}\n`);
  const result = await scan([path]);
  const note = 3 + uri.length + '&note='.length;
  expect(kinds(result)).toEqual([
    [3, 'lndconnect', invoice.fingerprint, invoice.expectedGrade],
    [note, 'macaroon-hex', admin.fingerprint, 'ADMIN'],
  ]);
  const gate = await run([path, '--fail-on', 'ADMIN'], { fs });
  expect(gate.exitCode).toBe(1);
  expect(gate.result).toMatchObject({ failOn: { threshold: 'ADMIN', count: 1 } });
}));

it('the same macaroon repeated in another parameter of its lndconnect URI is reported once', async () => scratch(async dir => {
  const invoice = vector('default-invoice');
  const path = join(dir, 'same.env');
  writeFileSync(path, `A=lndconnect://h:10009?macaroon=${invoice.bytes.toString('base64url')}&copy=${invoice.bytes.toString('hex')}\n`);
  expect(kinds(await scan([path]))).toEqual([[3, 'lndconnect', invoice.fingerprint, invoice.expectedGrade]]);
}));

it('a percent-encoded standard base64 macaroon parameter is still hidden by its confirmed URI', async () => scratch(async dir => {
  const invoice = vector('default-invoice');
  const encoded = encodeURIComponent(invoice.bytes.toString('base64'));
  const path = join(dir, 'encoded.env');
  writeFileSync(path, `A=lndconnect://h:10009?cert=abc&macaroon=${encoded}\n`);
  expect(kinds(await scan([path]))).toEqual([[3, 'lndconnect', invoice.fingerprint, invoice.expectedGrade]]);
}));

it('a JSON-escaped lndconnect URI hides only its macaroon parameter', async () => scratch(async dir => {
  const invoice = vector('default-invoice'), admin = vector('default-admin');
  const uri = `lndconnect:\\/\\/h:10009?macaroon=${invoice.bytes.toString('base64url')}`;
  const path = join(dir, 'escaped.json');
  writeFileSync(path, `{"u":"${uri}&n=${admin.bytes.toString('base64')}"}\n`);
  const result = await scan([path]);
  expect(kinds(result)).toEqual([
    [7, 'lndconnect', invoice.fingerprint, invoice.expectedGrade],
    [7 + uri.length + '&n='.length, 'macaroon-base64', admin.fingerprint, 'ADMIN'],
  ]);
}));
