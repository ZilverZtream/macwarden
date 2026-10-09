import { createHmac, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect, it } from 'vitest';
import { findLeaks } from "./helpers/leak-check.js";
import { captureMain } from './support/capture.js';

const repo = resolve();
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const validateScan = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(JSON.parse(
  readFileSync(join(repo, 'schemas/output/scan.schema.json'), 'utf8')));
const readonly = () => readFileSync(join(repo, 'test/vectors/default-readonly.macaroon'));

async function temp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp011-uri-location-'));
  try { return await work(dir); }
  finally { rmSync(dir, { recursive: true, force: true }); }
}

async function cli(args: string[]) {
  const { main } = await import('../src/cli.js');
  return captureMain(main, args);
}

function document(run: Awaited<ReturnType<typeof cli>>) {
  let parsed: unknown;
  try { parsed = JSON.parse(run.stdout); }
  catch { throw new Error('command did not return one JSON document'); }
  expect(run.stderr).toBe('');
  return parsed as { ok: boolean; error: { step: string } | null; result: {
    findings: { kind: string; caveats: { value: string }[] | null }[];
    summary: { dropped: number };
  } };
}

for (const whitespace of [
  { name: 'tab', value: '\t' },
  { name: 'LF', value: '\n' },
  { name: 'CR', value: '\r' },
]) {
  it(`CP-011/B13 inspect rejects literal ${whitespace.name} inside a lndconnect macaroon value`,
    async () => temp(async () => {
      const encoded = readonly().toString('base64url');
      const uri = `lndconnect://h:10009?macaroon=${encoded.slice(0, 10)}${whitespace.value}${encoded.slice(10)}`;
      const inspected = await cli(['inspect', uri, '--unsafe-arg', '--json']);
      expect(inspected.code).toBe(3);
      const inspectDocument = document(inspected);
      expect(inspectDocument.ok).toBe(false);
      expect(inspectDocument.error?.step).toBe('input-form');
      expect(inspected.stdout.includes(uri) || inspected.stderr.includes(uri)).toBe(false);
    }));

  it(`CP-011/B13 scan drops literal ${whitespace.name} inside a lndconnect macaroon value`,
    async () => temp(async dir => {
      const encoded = readonly().toString('base64url');
      const uri = `lndconnect://h:10009?macaroon=${encoded.slice(0, 10)}${whitespace.value}${encoded.slice(10)}`;
      const path = join(dir, 'uri.env');
      writeFileSync(path, uri);
      const scanned = await cli(['scan', path, '--json']);
      expect(scanned.code).toBe(0);
      const scanDocument = document(scanned);
      expect(validateScan(scanDocument)).toBe(true);
      // The URI is still not accepted as lndconnect. Since RR-01 and RR-10, a line break inside
      // it leaves a credential wrapped across two lines, which is joined and reported on its own.
      expect(scanDocument.result.findings.filter(finding => finding.kind === 'lndconnect')).toEqual([]);
      expect(scanDocument.result.findings.map(finding => finding.kind))
        .toEqual(whitespace.value === '\t' ? [] : ['macaroon-base64']);
      expect(scanDocument.result.summary.dropped).toBe(1);
    }));
}

it('CP-011/B13 inspect and scan accept a canonical lndconnect control', async () => temp(async dir => {
  const uri = `lndconnect://h:10009?macaroon=${readonly().toString('base64url')}`;
  const inspected = await cli(['inspect', uri, '--unsafe-arg', '--json']);
  expect(inspected.code).toBe(0);
  expect(document(inspected).ok).toBe(true);

  const path = join(dir, 'uri.env');
  writeFileSync(path, uri);
  const scanned = await cli(['scan', path, '--json']);
  expect(scanned.code).toBe(0);
  const scanDocument = document(scanned);
  expect(validateScan(scanDocument)).toBe(true);
  expect(scanDocument.result.findings).toHaveLength(1);
  expect(scanDocument.result.findings[0].kind).toBe('lndconnect');
  expect(scanDocument.result.summary.dropped).toBe(0);
}));

function packet(kind: number, data: Buffer): Buffer {
  const length: number[] = [];
  let n = data.length;
  do { length.push((n & 127) | (n >= 128 ? 128 : 0)); n = Math.floor(n / 128); } while (n);
  return Buffer.concat([Buffer.from([kind, ...length]), data]);
}

function withLocationAndCaveat(base: Buffer, location: string, condition: string): Buffer {
  let at = 1;
  if (base[at++] !== 1) throw new Error('unexpected reference location packet');
  let length = 0, scale = 1, byte: number;
  do { byte = base[at++]; length += (byte & 127) * scale; scale *= 128; } while (byte & 128);
  at += length;
  const relocated = Buffer.concat([base.subarray(0, 1), packet(1, Buffer.from(location)), base.subarray(at)]);

  at = 1;
  for (const expected of [1, 2]) {
    const kind = relocated[at++];
    length = 0; scale = 1;
    do { byte = relocated[at++]; length += (byte & 127) * scale; scale *= 128; } while (byte & 128);
    if (kind !== expected) throw new Error('unexpected reference packet');
    at += length;
  }
  if (relocated[at] !== 0 || relocated[at + 1] !== 0 || relocated[at + 2] !== 6 ||
      relocated[at + 3] !== 32 || at + 36 !== relocated.length)
    throw new Error('unexpected reference signature');
  const caveat = Buffer.from(condition);
  const signature = createHmac('sha256', relocated.subarray(at + 4)).update(caveat).digest();
  return Buffer.concat([relocated.subarray(0, at + 1), packet(2, caveat), Buffer.from([0, 0]),
    packet(6, signature)]);
}

it('CP-011/B16 scan redacts a secret in a caveat confirmed by an NWC URI in the macaroon location',
  async () => temp(async dir => {
    const secret = randomBytes(32);
    const sentinelDir = join(dir, 'sentinels');
    mkdirSync(sentinelDir);
    writeFileSync(join(sentinelDir, 'nwc.bin'), secret);
    const uri = `nostr+walletconnect://${'22'.repeat(32)}?secret=${secret.toString('hex')}`;
    const macaroon = withLocationAndCaveat(readonly(), `safe-location ${uri} safe-end`,
      `lnd-custom safe-before ${secret.toString('hex')} safe-after`);
    const path = join(dir, 'outer.macaroon');
    writeFileSync(path, macaroon);

    const { scan } = await import('../src/scan/index.js');
    const returned = await scan([path], {});
    expect(returned.findings).toHaveLength(1);
    const finding = returned.findings[0];
    expect(finding.kind).toBe('macaroon-file');
    expect(finding.caveats?.[0].value === 'safe-before [redacted] safe-after',
      'returned caveat must retain safe context and redact the confirmed secret').toBe(true);
    expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
      commandOutput: JSON.stringify(returned.findings), testTmp, root: repo }),
    'returned scan facts expose a confirmed secret').toBeNull();

    const run = await cli(['scan', path, '--json']);
    expect(run.code).toBe(0);
    const scanned = document(run);
    expect(validateScan(scanned)).toBe(true);
    expect(scanned.result.findings).toHaveLength(1);
    expect(scanned.result.findings[0].caveats?.[0].value === 'safe-before [redacted] safe-after',
      'rendered caveat must retain safe context and redact the confirmed secret').toBe(true);
    expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
      commandOutput: run.stdout + run.stderr, testTmp, root: repo }),
    'rendered scan JSON exposes a confirmed secret').toBeNull();
  }));
