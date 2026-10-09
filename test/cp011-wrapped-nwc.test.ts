import { createHmac, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { expect, it } from 'vitest';
import { findLeaks } from "./helpers/leak-check.js";
import { captureMain } from './support/capture.js';

const repo = resolve();
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const validateScan = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(JSON.parse(
  readFileSync(join(repo, 'schemas/output/scan.schema.json'), 'utf8')));
const validateInspect = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(JSON.parse(
  readFileSync(join(repo, 'schemas/output/inspect.schema.json'), 'utf8')));

function packet(kind: number, data: Buffer): Buffer {
  const length: number[] = [];
  let n = data.length;
  do { length.push((n & 127) | (n >= 128 ? 128 : 0)); n = Math.floor(n / 128); } while (n);
  return Buffer.concat([Buffer.from([kind, ...length]), data]);
}

// Attenuate a committed, caveat-free regtest vector using the v2 signature chain.
function caveated(base: Buffer, condition: string): Buffer {
  let at = 1;
  for (const expected of [1, 2]) {
    const kind = base[at++];
    let length = 0, scale = 1, byte: number;
    do { byte = base[at++]; length += (byte & 127) * scale; scale *= 128; } while (byte & 128);
    if (kind !== expected) throw new Error('unexpected reference packet');
    at += length;
  }
  if (base[at] !== 0 || base[at + 1] !== 0 || base[at + 2] !== 6 ||
      base[at + 3] !== 32 || at + 36 !== base.length)
    throw new Error('unexpected reference signature');
  const caveat = Buffer.from(condition, 'utf8');
  const signature = createHmac('sha256', base.subarray(at + 4)).update(caveat).digest();
  return Buffer.concat([base.subarray(0, at + 1), packet(2, caveat), Buffer.from([0, 0]),
    packet(6, signature)]);
}

async function inTemp<T>(work: (dir: string, sentinelDir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp011-wrapped-nwc-'));
  const previousSentinelDir = process.env.MACWARDEN_SENTINEL_DIR;
  if (!previousSentinelDir) throw new Error('Global sentinel root is required');
  const sentinelDir = join(previousSentinelDir, basename(dir));
  mkdirSync(sentinelDir, { recursive: true });
  process.env.MACWARDEN_SENTINEL_DIR = sentinelDir;
  try { return await work(dir, sentinelDir); }
  finally {
    if (previousSentinelDir === undefined) delete process.env.MACWARDEN_SENTINEL_DIR;
    else process.env.MACWARDEN_SENTINEL_DIR = previousSentinelDir;
    // Keep registered sources until the whole-run leak scan and global teardown.
    rmSync(dir, { recursive: true, force: true });
  }
}

async function cli(args: string[]) {
  const { main } = await import('../src/cli.js');
  return captureMain(main, args);
}

function document(run: Awaited<ReturnType<typeof cli>>) {
  let parsed: unknown;
  try { parsed = JSON.parse(run.stdout); }
  catch { throw new Error('command did not return one JSON document'); }
  expect(run.stderr === '', 'unexpected stderr').toBe(true);
  return parsed as { ok: boolean; result: {
    caveats: { value: string }[];
    findings: { kind: string; caveats: { value: string }[] | null }[];
    summary: { byGrade: Record<string, number> };
  } };
}

function assertNoConfirmedSecret(value: unknown, secret: Buffer, sentinelDir: string, surface: string) {
  const rendered = typeof value === 'string' ? value : JSON.stringify(value);
  const hex = secret.toString('hex');
  const compact = rendered.replace(/(?:\\[rnt]|\s)+/g, '').toLowerCase();
  expect.soft(compact.includes(hex), `${surface}: confirmed wrapped hex exposed`).toBe(false);
  for (const encoding of ['base64', 'base64url'] as const) {
    expect.soft(rendered.includes(secret.toString(encoding)),
      `${surface}: confirmed secret encoding exposed`).toBe(false);
  }
  expect.soft(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
    commandOutput: rendered, testTmp, root: repo }) === null,
  `${surface}: registered credential exposed`).toBe(true);
}

const separators = [
  { name: 'LF', value: '\n' },
  { name: 'CRLF', value: '\r\n' },
  { name: 'spaces', value: '  ' },
  { name: 'tabs', value: '\t' },
];

for (const separator of separators) {
  it(`CP-011/B16 redacts confirmed NWC hex wrapped with ${separator.name} in scan facts and rendered scan and inspect output`,
    async () => inTemp(async (dir, sentinelDir) => {
      const secret = randomBytes(32);
      const hex = secret.toString('hex');
      const wrapped = `${hex.slice(0, 32)}${separator.value}${hex.slice(32)}`;
      const uri = `nostr+walletconnect://${'22'.repeat(32)}?secret=${hex}`;
      writeFileSync(join(sentinelDir, 'nwc.bin'), secret);
      const outer = caveated(readFileSync(join(repo, 'test/vectors/default-readonly.macaroon')),
        `lnd-custom safe-before ${wrapped} safe-middle ${uri} safe-after`);
      writeFileSync(join(sentinelDir, 'outer.macaroon'), outer);
      const tree = join(dir, 'tree'); mkdirSync(tree);
      const credential = join(tree, 'outer.macaroon');
      writeFileSync(credential, outer);
      writeFileSync(join(tree, 'wallet.env'), uri);

      const { scan } = await import('../src/scan/index.js');
      const returned = await scan([tree], {});
      const caveat = returned.findings.find(finding => finding.kind === 'macaroon-file')?.caveats?.[0].value;
      expect(returned.findings.some(finding => finding.kind === 'nwc'), 'recognized NWC context').toBe(true);
      expect(returned.summary.byGrade.NWC === 1, 'NWC grade preserved').toBe(true);
      expect(typeof caveat === 'string' && caveat.includes('safe-before') &&
        caveat.includes('safe-middle') && caveat.includes('safe-after') &&
        caveat.includes('[redacted]'), 'safe caveat context and redaction retained').toBe(true);
      expect.soft(typeof caveat === 'string' && !caveat.includes(wrapped),
        'confirmed wrapped caveat hex exposed').toBe(true);
      assertNoConfirmedSecret(returned.findings, secret, sentinelDir, 'returned scan facts');

      for (const format of [[], ['--json']]) {
        const scanRun = await cli(['scan', tree, ...format]);
        expect(scanRun.code === 0, 'scan exit').toBe(true);
        if (format.length) {
          const parsed = document(scanRun);
          expect(validateScan(parsed), 'scan schema').toBe(true);
          expect(parsed.ok === true, 'scan result').toBe(true);
          assertNoConfirmedSecret(parsed.result.findings, secret, sentinelDir, 'scan JSON findings');
        }
        expect(scanRun.stdout.includes('macaroon-file') && scanRun.stdout.includes('nwc'),
          'scan findings retained').toBe(true);
        assertNoConfirmedSecret(scanRun.stdout + scanRun.stderr, secret, sentinelDir,
          format.length ? 'scan JSON output' : 'scan text output');

        const inspectRun = await cli(['inspect', credential, ...format]);
        expect(inspectRun.code === 0, 'inspect exit').toBe(true);
        if (format.length) {
          const inspected = document(inspectRun);
          expect(validateInspect(inspected), 'inspect schema').toBe(true);
          expect(inspected.ok === true, 'inspect result').toBe(true);
          const value = inspected.result.caveats[0].value;
          expect(value.includes('safe-before') && value.includes('safe-after') &&
            value.includes('[redacted]'), 'safe inspect caveat retained').toBe(true);
          assertNoConfirmedSecret(inspected.result.caveats, secret, sentinelDir, 'inspect JSON facts');
        }
        expect(inspectRun.stdout.includes('safe-before') && inspectRun.stdout.includes('safe-after'),
          'safe inspect text retained').toBe(true);
        assertNoConfirmedSecret(inspectRun.stdout + inspectRun.stderr, secret, sentinelDir,
          format.length ? 'inspect JSON output' : 'inspect text output');
      }
    }));
}
