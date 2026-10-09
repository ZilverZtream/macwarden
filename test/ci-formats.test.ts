import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import Ajv from 'ajv';
import { afterAll, expect, it } from 'vitest';
import { renderChunks, type OutputResult } from '../src/output/index.js';
import { escapeData, escapeProperty, fileUri, SARIF_MAX_RESULTS } from '../src/output/scan-formats.js';
import { scan } from '../src/scan/index.js';
import { childEnvironment } from './helpers/environment.js';

const repo = resolve();
const scratch = mkdtempSync(join(resolve(process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp')), 'ci-formats-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

// Expected values come from the committed vector manifest and independent hashing,
// never from the scanner under test.
const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as
  { vectors: { name: string; file: string; fingerprint: string; expectedGrade: string }[] };
const admin = manifest.vectors.find(vector => vector.name === 'default-admin')!;
const readonly = manifest.vectors.find(vector => vector.name === 'default-readonly')!;
const adminBytes = readFileSync(join(repo, 'test/vectors', admin.file));
const readonlyBytes = readFileSync(join(repo, 'test/vectors', readonly.file));
const nwcSecret = randomBytes(32).toString('hex');
const nwcWallet = randomBytes(32).toString('hex');
const nwcUri = `nostr+walletconnect://${nwcWallet}?relay=wss%3A%2F%2Frelay.example.com&secret=${nwcSecret}`;
const nwcFingerprint = `fp:${createHash('sha256').update(Buffer.from(nwcSecret, 'hex')).digest('hex').slice(0, 16)}`;

function tree(): string {
  const dir = mkdtempSync(join(scratch, 'tree-'));
  mkdirSync(join(dir, 'app'));
  writeFileSync(join(dir, 'app', 'settings.env'), `# comment\nLND_MACAROON=${adminBytes.toString('hex')}\n`);
  writeFileSync(join(dir, 'odd,na%me.env'), `X=1\nY=  ${readonlyBytes.toString('hex')}\n`);
  writeFileSync(join(dir, 'wallet.txt'), `${nwcUri}\n`);
  return dir;
}

const sentinels = () => [adminBytes.toString('hex'), adminBytes.toString('base64'), readonlyBytes.toString('hex'), nwcSecret];

async function result(dir: string, format: 'sarif' | 'github'): Promise<OutputResult> {
  const scanned = await scan([dir]);
  return { command: 'scan', ok: true, warnings: [], error: null, result: scanned,
    display: { format, scanRoot: dir, toolVersion: '9.8.7' } } as OutputResult;
}

function sarifValidator() {
  // The official OASIS schema is draft-04; Ajv 8 reads it once `id` is `$id`.
  const schema = JSON.parse(readFileSync(join(repo, 'test/vendor/sarif-schema-2.1.0.json'), 'utf8')) as Record<string, unknown>;
  const { id, $schema: _ignored, ...rest } = schema;
  void _ignored;
  return new (Ajv as unknown as typeof import('ajv').default)({ strict: false, validateFormats: false, allErrors: true }).compile({ $id: id as string, ...rest });
}

it('CI-FORMATS/sarif output is a valid SARIF 2.1.0 log with independent locations, fingerprints and severities', async () => {
  const dir = tree();
  const text = [...renderChunks(await result(dir, 'sarif'), 'text')].join('');
  const log = JSON.parse(text) as { version: string; runs: { tool: { driver: { name: string; version: string; rules: { id: string;
    properties: Record<string, string> }[] } }; results: { ruleId: string; level: string; message: { text: string };
      partialFingerprints: Record<string, string>; locations: { physicalLocation: { artifactLocation: { uri: string; uriBaseId?: string };
        region?: { startLine: number; startColumn?: number; snippet?: unknown } } }[] }[] }[] };
  const validate = sarifValidator();
  expect(validate(log), JSON.stringify(validate.errors?.slice(0, 3))).toBe(true);
  expect(log.version).toBe('2.1.0');
  const run = log.runs[0];
  expect(run.tool.driver).toMatchObject({ name: 'macwarden', version: '9.8.7' });
  for (const rule of run.tool.driver.rules) expect(Number(rule.properties['security-severity'])).toBeGreaterThan(0);
  const byUri = Object.fromEntries(run.results.map(item => [item.locations[0].physicalLocation.artifactLocation.uri, item]));
  expect(Object.keys(byUri).sort()).toEqual(['app/settings.env', 'odd%2Cna%25me.env', 'wallet.txt']);
  expect(byUri['app/settings.env']).toMatchObject({ ruleId: 'macwarden/macaroon-hex/admin', level: 'error',
    partialFingerprints: { 'macwardenFingerprint/v1': admin.fingerprint },
    locations: [{ physicalLocation: { artifactLocation: { uriBaseId: '%SRCROOT%' }, region: { startLine: 2, startColumn: 14 } } }] });
  expect(byUri['odd%2Cna%25me.env']).toMatchObject({ ruleId: 'macwarden/macaroon-hex/read', level: 'note', partialFingerprints: { 'macwardenFingerprint/v1': readonly.fingerprint },
    locations: [{ physicalLocation: { region: { startLine: 2, startColumn: 5 } } }] });
  expect(byUri['wallet.txt']).toMatchObject({ ruleId: 'macwarden/nwc', level: 'error',
    partialFingerprints: { 'macwardenFingerprint/v1': nwcFingerprint } });
  // GitHub takes security-severity from the rule only: each finding's rule carries its grade's score.
  const ruleSeverity = (id: string) => Number(run.tool.driver.rules.find(rule => rule.id === id)!.properties['security-severity']);
  expect(ruleSeverity('macwarden/macaroon-hex/admin')).toBe(9.5);
  expect(ruleSeverity('macwarden/macaroon-hex/read')).toBe(3);
  expect(ruleSeverity('macwarden/nwc')).toBe(9);
  for (const item of run.results as unknown as { ruleId: string; ruleIndex: number }[])
    expect((run.tool.driver.rules as { id: string }[])[item.ruleIndex].id).toBe(item.ruleId);
  // Columns are code points (SARIF defaults to UTF-16 code units).
  expect((run as unknown as { columnKind: string }).columnKind).toBe('unicodeCodePoints');
  expect(text).not.toContain('"snippet"');
  for (const secret of sentinels()) expect(text.toLowerCase()).not.toContain(secret.toLowerCase());
});

it('CI-FORMATS/github annotations escape workflow-command properties and data and end with the summary', async () => {
  expect(escapeData('50% done\r\nnext')).toBe('50%25 done%0D%0Anext');
  expect(escapeProperty('a:b,c%d\ne')).toBe('a%3Ab%2Cc%25d%0Ae');
  const dir = tree();
  const lines = [...renderChunks(await result(dir, 'github'), 'text')].join('').split('\n');
  expect(lines).toContain(`::error file=app/settings.env,line=2,col=14,title=macwarden macaroon-hex::ADMIN ${admin.fingerprint} root key 0`);
  expect(lines).toContain(`::notice file=odd%2Cna%25me.env,line=2,col=5,title=macwarden macaroon-hex::READ ${readonly.fingerprint} root key 0`);
  expect(lines).toContain(`::error file=wallet.txt,line=1,col=1,title=macwarden nwc::SPEND (NWC) ${nwcFingerprint}`);
  expect(lines.at(-2)).toMatch(/^3 findings \(3 distinct\) in 3 files; 0 skipped; 0 ignored$/);
  for (const secret of sentinels()) expect(lines.join('\n').toLowerCase()).not.toContain(secret.toLowerCase());
});

it('CI-FORMATS/file URIs for paths outside the scan root are absolute and percent-encoded', () => {
  expect(fileUri('C:\\Users\\a b\\x,y.env')).toBe('file:///C:/Users/a%20b/x%2Cy.env');
  expect(fileUri('/home/a b/x.env')).toBe('file:///home/a%20b/x.env');
});

it('CI-FORMATS/cli --format selects the rendering, --format json equals --json, and conflicts are usage errors', () => {
  const dir = tree();
  const cli = (...args: string[]) => spawnSync(process.execPath, [resolve('dist/bin.js'), 'scan', ...args],
    { cwd: dir, env: childEnvironment(), encoding: 'utf8', timeout: 30_000, windowsHide: true });
  const sarif = cli('.', '--format', 'sarif', '--fail-on', 'ADMIN');
  expect(sarif.status).toBe(1);
  expect(JSON.parse(sarif.stdout).runs[0].results).toHaveLength(3);
  expect(JSON.parse(sarif.stdout).runs[0].tool.driver.version).toBe(JSON.parse(readFileSync(join(repo, 'package.json'), 'utf8')).version);
  expect(cli('.', '--format', 'json').stdout).toBe(cli('.', '--json').stdout);
  const github = cli('.', '--format', 'github');
  expect(github.status).toBe(0);
  expect(github.stdout).toMatch(/^::error file=app\/settings\.env,line=2,col=14,/m);
  for (const [args, message] of [[['--format', 'github', '--json'], /--json cannot be combined with --format github/],
    [['--format', 'xml'], /--format takes one of text, json, sarif, github/], [['--format'], /--format takes one of/],
    [['--format', 'sarif', '--format', 'sarif'], /--format takes one of/]] as const) {
    const refused = cli('.', ...args);
    expect(refused.status).toBe(2);
    expect(refused.stderr).toMatch(message);
  }
});

it('CI-FORMATS/sarif caps results at GitHub\'s 25,000 per run and reports the omitted count', () => {
  const finding = (index: number) => ({ path: join('/r', `f${index}.env`), line: 1, column: 1, kind: 'macaroon-hex', fingerprint: `fp:${index.toString(16).padStart(16, '0')}`,
    grade: 'READ', rootKeyId: '0', location: 'lnd', permissions: [], caveats: [], warnings: [] });
  const findings = Array.from({ length: SARIF_MAX_RESULTS + 3 }, (_, index) => finding(index));
  const output = { command: 'scan', ok: true, warnings: [], error: null, result: { findings, skipped: [],
    summary: { findings: findings.length, distinct: findings.length, filesScanned: findings.length, filesSkipped: 0, ignored: 0 }, failOn: null },
    display: { format: 'sarif', scanRoot: '/r', toolVersion: '1.0.0' } } as unknown as OutputResult;
  const log = JSON.parse([...renderChunks(output, 'text')].join('')) as { runs: { results: unknown[];
    invocations: { toolExecutionNotifications?: { level: string; message: { text: string } }[]; properties: { omittedResults?: number } }[] }[] };
  expect(log.runs[0].results).toHaveLength(SARIF_MAX_RESULTS);
  expect(log.runs[0].invocations[0].properties.omittedResults).toBe(3);
  expect(log.runs[0].invocations[0].toolExecutionNotifications![0]).toMatchObject({ level: 'warning',
    message: { text: expect.stringContaining('3 further findings') } });
}, 60_000);
