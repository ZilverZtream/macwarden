import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import Ajv from 'ajv';
import { afterAll, expect, it } from 'vitest';
import { run } from '../src/commands/scan.js';
import { renderChunks, type OutputResult } from '../src/output/index.js';
import { scan, type ScanFinding } from '../src/scan/index.js';
import { findLeaks } from './helpers/leak-check.js';
import { expectDocumentValid } from './helpers/output-schema.js';
import { encodings, fp, identifier, macaroon, sha256, token, tokenFile, type Token } from './helpers/l402-vectors.js';

// L402 detection in scan (docs/spec.md, Commands > 2. scan, L402 credentials). Expected
// fingerprints come from the independent helper, never from the scanner. Synthetic tokens only.
const repo = resolve();
const scratch = mkdtempSync(join(resolve(process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp')), 'l402-scan-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));
const clock = () => new Date('2026-10-09T12:00:00Z');
const lndReadonly = readFileSync(join(repo, 'test/vectors/default-readonly.macaroon'));
const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as
  { vectors: { name: string; fingerprint: string }[] };
const readonlyFingerprint = manifest.vectors.find(vector => vector.name === 'default-readonly')!.fingerprint;

const live = token(101);
const legacy = token(102);
const paired = token(103, ['services=data:0'], 'aperture.example');
const challenge = token(104);
const grpc = token(105);
const stored = token(106);
const pending = token(107);
const expired = token(108, ['services=old:0', 'old_valid_until=1700000000']);
const grpcPaid = macaroon(identifier(grpc.paymentHash, grpc.tokenId), ['services=lnd:0', `preimage=${grpc.preimage.toString('hex')}`]);
const all: Token[] = [live, legacy, paired, challenge, grpc, stored, pending, expired];
const secretBytes = (): Buffer[] => [...all.flatMap(t => [t.preimage, t.macaroon]), grpcPaid];

function tree(): string {
  const dir = mkdtempSync(join(scratch, 'tree-'));
  mkdirSync(join(dir, 'lnget', 'tokens', 'api.example.com'), { recursive: true });
  mkdirSync(join(dir, 'loop'), { recursive: true });
  writeFileSync(join(dir, 'app.env'), `# synthetic\nL402_TOKEN=${live.header}\n`);
  writeFileSync(join(dir, 'access.log'), `GET /v1/x HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: LSAT ${legacy.pair}\r\n`);
  writeFileSync(join(dir, 'client.ts'), `const credential = "${paired.pair}";\n`);
  writeFileSync(join(dir, 'session.har'), JSON.stringify({ log: { entries: [{ response: { status: 402, headers: [
    { name: 'WWW-Authenticate', value: `L402 macaroon="${challenge.base64}", invoice="lnbcrt1synthetic"` }] } },
  { request: { headers: [{ name: 'Authorization', value: expired.header }] } }] } }, null, 1));
  writeFileSync(join(dir, 'grpc.txt'), `macaroon: ${grpcPaid.toString('hex')}\n`);
  writeFileSync(join(dir, 'lnget', 'tokens', 'api.example.com', 'l402.token'), tokenFile(stored));
  writeFileSync(join(dir, 'lnget', 'tokens', 'api.example.com', 'l402.token.pending'), tokenFile(pending, true));
  writeFileSync(join(dir, 'loop', 'LSAT.TOKEN'), Buffer.from('not a token store file at all'));
  return dir;
}

type L402Fields = NonNullable<ScanFinding['l402']>;
/** 1-based line and code point column of the first occurrence of `needle`, computed from the file itself. */
function where(path: string, needle: string): { line: number; column: number } {
  const lines = readFileSync(path, 'utf8').split(/\r\n|\n|\r/);
  const line = lines.findIndex(text => text.includes(needle));
  return { line: line + 1, column: Array.from(lines[line].slice(0, lines[line].indexOf(needle))).length + 1 };
}

const brief = (finding: ScanFinding) => ({ path: finding.path.replace(/^.*?tree-[^/]+\//, ''), line: finding.line,
  column: finding.column, kind: finding.kind, fingerprint: finding.fingerprint,
  status: finding.l402?.status ?? null, form: finding.l402?.form ?? null, countedAs: finding.l402?.countedAs ?? null });

it('L402-scan/finds headers, pairs, challenges, paid macaroons and token store files with independent fingerprints', async () => {
  const dir = tree();
  const result = await scan([dir], { clock });
  const har = join(dir, 'session.har');
  expect(result.findings.map(brief)).toEqual([
    { path: 'access.log', line: 3, column: 16, kind: 'l402', fingerprint: legacy.fingerprint, status: 'live', form: 'authorization', countedAs: 'READ' },
    { path: 'app.env', line: 2, column: 12, kind: 'l402', fingerprint: live.fingerprint, status: 'live', form: 'authorization', countedAs: 'READ' },
    { path: 'client.ts', line: 1, column: 21, kind: 'l402', fingerprint: paired.fingerprint, status: 'live', form: 'pair', countedAs: 'READ' },
    { path: 'grpc.txt', line: 1, column: 11, kind: 'l402', fingerprint: fp(grpcPaid), status: 'live', form: 'macaroon', countedAs: 'READ' },
    { path: 'lnget/tokens/api.example.com/l402.token', line: null, column: null, kind: 'l402-file', fingerprint: stored.fingerprint,
      status: 'live', form: 'token-file', countedAs: 'READ' },
    { path: 'lnget/tokens/api.example.com/l402.token.pending', line: null, column: null, kind: 'l402-file',
      fingerprint: pending.macaroonFingerprint, status: 'unpaid', form: 'token-file', countedAs: null },
    { path: 'loop/LSAT.TOKEN', line: null, column: null, kind: 'undecodable', fingerprint: fp(Buffer.from('not a token store file at all')),
      status: null, form: null, countedAs: null },
    { path: 'session.har', ...where(har, 'L402 macaroon='), kind: 'l402', fingerprint: challenge.macaroonFingerprint, status: 'unpaid',
      form: 'challenge', countedAs: null },
    { path: 'session.har', ...where(har, expired.header), kind: 'l402', fingerprint: expired.fingerprint, status: 'expired',
      form: 'authorization', countedAs: 'READ' },
  ]);
  const first = result.findings.find(finding => finding.fingerprint === live.fingerprint)!;
  expect(first).toMatchObject({ grade: null, rootKeyId: null, permissions: null, caveats: null, warnings: [], unassessed: [] });
  expect(first.l402).toMatchObject({ scheme: 'L402', location: 'lsat', macaroonFingerprint: live.macaroonFingerprint,
    identifier: { version: 0, paymentHash: live.paymentHash.toString('hex'), tokenId: live.tokenId.toString('hex') },
    services: [{ name: 'weather', tier: '0' }], preimage: 'matches', access: 'service-access' } satisfies Partial<L402Fields>);
  expect(result.findings.find(finding => finding.fingerprint === fp(grpcPaid))!.l402!.caveats[1])
    .toEqual({ type: 'preimage', condition: 'preimage', value: null });
  expect(result.summary.byGrade).toMatchObject({ L402: 8, UNDECODABLE: 1, ADMIN: 0, READ: 0 });
});

it('L402-scan/--fail-on counts a token with a usable preimage as READ, never an unpaid or mismatched one', async () => {
  const dir = mkdtempSync(join(scratch, 'failon-'));
  writeFileSync(join(dir, 'live.env'), `X=${live.header}\n`);
  const counted = async (args: string[]) => {
    const out = await run([dir, ...args], { fs });
    expectDocumentValid(JSON.parse([...renderChunks(out, 'json')].join('')) as { command: string });
    return out as OutputResult & { exitCode?: number; result: { failOn: { count: number } | null } };
  };
  expect((await counted(['--fail-on', 'READ'])).exitCode).toBe(1);
  expect((await counted(['--fail-on', 'READ'])).result.failOn).toEqual({ threshold: 'READ', count: 1 });
  for (const grade of ['RECEIVE', 'OPERATE', 'SPEND', 'ADMIN']) expect((await counted(['--fail-on', grade])).exitCode, grade).toBe(0);
  rmSync(join(dir, 'live.env'));
  const wrong = sha256(Buffer.from('not the preimage')).toString('hex');
  writeFileSync(join(dir, 'unpaid.json'), JSON.stringify({ challenge: `L402 macaroon="${challenge.base64}"`,
    wrong: `L402 ${live.base64}:${wrong}` }));
  const quiet = await counted(['--fail-on', 'READ']);
  expect(quiet.exitCode).toBe(0);
  expect(quiet.result.failOn).toEqual({ threshold: 'READ', count: 0 });
});

it('L402-scan/precedence: one finding per credential; an L402 header carrying an LND macaroon is that macaroon', async () => {
  const dir = mkdtempSync(join(scratch, 'precedence-'));
  const preimage = sha256(Buffer.from('p')).toString('hex');
  writeFileSync(join(dir, 'a.txt'), [
    `Authorization: L402 ${live.pair}`,
    live.pair,
    `L402 ${lndReadonly.toString('base64')}:${preimage}`,
    `l402 ${Buffer.from('x'.repeat(60)).toString('base64')}:${preimage}`,
  ].join('\n'));
  const result = await scan([dir], { clock });
  expect(result.findings.map(finding => [finding.line, finding.column, finding.kind, finding.fingerprint])).toEqual([
    [1, 16, 'l402', live.fingerprint],
    [2, 1, 'l402', live.fingerprint],
    [3, 6, 'macaroon-base64', readonlyFingerprint],
    [4, 1, 'undecodable-candidate', fp(Buffer.from(`l402 ${Buffer.from('x'.repeat(60)).toString('base64')}:${preimage}`))],
  ]);
  expect(result.findings[2].grade).toBe('READ');
});

it('L402-scan/escaped and encoded forms: JSON-escaped slashes and base64 of a header (Kubernetes Secret data)', async () => {
  const slashy = token(120, ['services=a:0', 'x=' + '?'.repeat(40)]);
  expect(slashy.base64).toContain('/');
  const dir = mkdtempSync(join(scratch, 'escaped-'));
  writeFileSync(join(dir, 'php.json'), `{"auth":"${slashy.header.replace(/\//g, '\\/')}"}\n`);
  writeFileSync(join(dir, 'secret.yaml'), `data:\n  L402_TOKEN: ${Buffer.from(live.header).toString('base64')}\n`);
  const result = await scan([dir], { clock });
  expect(result.findings.map(brief).map(({ path, line, column, fingerprint }) => ({ path, line, column, fingerprint }))).toEqual([
    { path: `${dir.replace(/\\/g, '/')}/php.json`, line: 1, column: 10, fingerprint: slashy.fingerprint },
    { path: `${dir.replace(/\\/g, '/')}/secret.yaml`, line: 2, column: 15, fingerprint: live.fingerprint },
  ]);
});

it('L402-scan/token store files: oversized and malformed files fail closed as undecodable; text detectors do not run on them', async () => {
  const dir = mkdtempSync(join(scratch, 'store-'));
  const big = tokenFile(token(130, ['x=' + 'y'.repeat(70_000)]));
  writeFileSync(join(dir, 'l402.token'), big);
  writeFileSync(join(dir, 'lsat.token.pending'), Buffer.from(live.header));
  const result = await scan([dir], { clock });
  expect(result.findings.map(finding => [finding.path.split('/').at(-1), finding.kind])).toEqual([
    ['l402.token', 'undecodable'], ['lsat.token.pending', 'undecodable']]);
});

it('L402-scan/an ignore entry suppresses an L402 finding by its fingerprint', async () => {
  const dir = mkdtempSync(join(scratch, 'ignore-'));
  writeFileSync(join(dir, 'a.env'), `T=${live.header}\nU=${legacy.header}\n`);
  writeFileSync(join(dir, '.macwardenignore'), `${live.fingerprint} a.env\n`);
  const result = await scan([dir], { clock });
  expect(result.findings.map(finding => finding.fingerprint)).toEqual([legacy.fingerprint]);
  expect(result.ignoredFingerprints).toEqual([live.fingerprint]);
});

function sarifValidator() {
  const schema = JSON.parse(readFileSync(join(repo, 'test/vendor/sarif-schema-2.1.0.json'), 'utf8')) as Record<string, unknown>;
  const { id, $schema: _ignored, ...rest } = schema;
  void _ignored;
  return new (Ajv as unknown as typeof import('ajv').default)({ strict: false, validateFormats: false, allErrors: true })
    .compile({ $id: id as string, ...rest });
}

it('L402-scan/redaction: text, JSON, SARIF and github output carry no preimage or macaroon, and pass the leak check', async () => {
  const dir = tree();
  const scanned = await scan([dir], { clock });
  const outputs: Record<string, string> = {};
  for (const format of ['text', 'json', 'sarif', 'github'] as const) {
    const result = { command: 'scan', ok: true, warnings: [], error: null, result: scanned,
      ...(format === 'sarif' || format === 'github' ? { display: { format, scanRoot: dir, toolVersion: '9.8.7' } } : {}) } as OutputResult;
    outputs[format] = [...renderChunks(result, format === 'json' ? 'json' : 'text')].join('');
  }
  expectDocumentValid(JSON.parse(outputs.json) as { command: string });
  const sarif = JSON.parse(outputs.sarif) as { runs: { tool: { driver: { rules: { id: string; defaultConfiguration: { level: string };
    properties: Record<string, string> }[] } }; results: { ruleId: string; level: string; message: { text: string } }[] }[] };
  const validate = sarifValidator();
  expect(validate(sarif), JSON.stringify(validate.errors)).toBe(true);
  const rules = new Map(sarif.runs[0].tool.driver.rules.map(rule => [rule.id, rule]));
  expect(rules.get('macwarden/l402/paid')).toMatchObject({ defaultConfiguration: { level: 'note' }, properties: { 'security-severity': '3.0' } });
  expect(rules.get('macwarden/l402/unpaid')).toMatchObject({ defaultConfiguration: { level: 'note' }, properties: { 'security-severity': '1.0' } });
  expect(rules.get('macwarden/l402-file/paid')).toBeDefined();
  expect(sarif.runs[0].results.filter(item => item.ruleId.startsWith('macwarden/l402')).map(item => item.ruleId).sort()).toEqual([
    'macwarden/l402-file/paid', 'macwarden/l402-file/unpaid', 'macwarden/l402/paid', 'macwarden/l402/paid',
    'macwarden/l402/paid', 'macwarden/l402/paid', 'macwarden/l402/paid', 'macwarden/l402/unpaid']);
  expect(outputs.github).toMatch(/^::notice file=[^\n]*app\.env,line=2,col=12,title=macwarden l402::READ \(L402 live\) fp:/m);
  expect(outputs.text).toMatch(/app\.env:2:12 {2}l402 {2}fp:[0-9a-f]{16} live \(counted as READ\)/);
  expect(outputs.text).toMatch(/session\.har:\d+:\d+ {2}l402 {2}fp:[0-9a-f]{16} unpaid \(not counted\)/);
  const sentinelDir = mkdtempSync(join(scratch, 'sentinels-'));
  secretBytes().forEach((bytes, index) => writeFileSync(join(sentinelDir, `s${index}.bin`), bytes));
  for (const [format, text] of Object.entries(outputs)) {
    for (const bytes of secretBytes()) for (const form of encodings(bytes))
      expect(text.includes(form), `${format} holds a credential encoding`).toBe(false);
    expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir, commandOutput: text }), format).toBeNull();
  }
  // Positive control: the leak check does see a planted preimage.
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir, commandOutput: `x ${live.preimage.toString('base64')}` }))
    .not.toBeNull();
});

it('L402-scan/an error and an unreadable argument echo no credential', async () => {
  const missing = await run([join(scratch, live.header.replace(/[/:]/g, '_'))], { fs });
  const text = [...renderChunks(missing, 'text')].join('') + [...renderChunks(missing, 'json')].join('');
  expect(missing.error).toMatchObject({ code: 3 });
  for (const form of encodings(live.preimage)) expect(text.includes(form)).toBe(false);
});

it('L402-scan/linear time: hostile lines of open L402 prefixes and colon-hex runs scale linearly', async () => {
  const hex = 'a'.repeat(64);
  const shapes: Record<string, (n: number) => string> = {
    scheme: n => 'L402 '.repeat(Math.ceil(n / 5)).slice(0, n),
    run: n => `L402 ${'A'.repeat(n)}`,
    commas: n => `L402 ${`${'A'.repeat(40)},`.repeat(Math.ceil(n / 41))}`.slice(0, n),
    pairs: n => `${'A'.repeat(40)}:${hex}`.repeat(Math.ceil(n / 105)).slice(0, n),
    colons: n => `:${hex}`.repeat(Math.ceil(n / 65)).slice(0, n),
    longPair: n => `${'B'.repeat(n)}:${hex}`,
    prefix: n => ('AgEEbHNhdAJCAA' + 'A'.repeat(4_082)).repeat(Math.ceil(n / 4_096)).slice(0, n),
    challenge: n => 'L402 macaroon="'.repeat(Math.ceil(n / 15)).slice(0, n),
    challengeRun: n => `L402 invoice="${'a'.repeat(n / 2)}", macaroon="${'A'.repeat(n / 2)}`,
    invoices: n => 'L402 invoice=x, '.repeat(Math.ceil(n / 16)).slice(0, n),
  };
  const timings: Record<string, number[]> = {};
  for (const [name, shape] of Object.entries(shapes)) {
    timings[name] = [];
    for (const size of [1_000_000, 4_000_000]) {
      const path = join(scratch, `${name}-${size}.txt`);
      writeFileSync(path, shape(size));
      const started = performance.now();
      await scan([path], { clock });
      timings[name].push(performance.now() - started);
    }
  }
  console.log(`L402-scan linear timings ms [1 MB, 4 MB]: ${JSON.stringify(timings, (_, v: unknown) => typeof v === 'number' ? Math.round(v) : v)}`);
  // Four times the input takes at most about four times as long (with headroom for noise).
  for (const [name, [small, large]] of Object.entries(timings)) expect(large, name).toBeLessThan(8 * Math.max(small, 25));
}, 180_000);

it('L402-scan/real-world forms: several macaroons, challenge variants, curl, YAML, .env pairs and MCP agent configs', async () => {
  const dir = mkdtempSync(join(scratch, 'forms-'));
  const discharge = macaroon(Buffer.from('discharge'), ['x=1'], 'auth.example');
  const several = `L402 ${discharge.toString('base64')},${live.base64}:${live.preimage.toString('hex')}`;
  writeFileSync(join(dir, 'several.log'), `Authorization: ${several}\n`);
  writeFileSync(join(dir, 'challenges.txt'), [
    `WWW-Authenticate: LSAT macaroon="${challenge.base64}", invoice="lnbcrt1a", L402 macaroon="${challenge.base64}", invoice="lnbcrt1a"`,
    `www-authenticate: L402 invoice="lnbcrt1b", token="${legacy.base64}"`,
    `L402 macaroon=${pending.base64}, invoice=lnbcrt1c`,
  ].join('\n'));
  writeFileSync(join(dir, 'fetch.sh'), `curl -H 'Authorization: L402 ${paired.pair}' https://api.example.com/v1/data\n`);
  writeFileSync(join(dir, 'client.yaml'), `service:\n  auth: "LSAT ${stored.pair}"\n`);
  writeFileSync(join(dir, '.env'), `API_TOKEN=${grpc.pair}\n`);
  writeFileSync(join(dir, 'mcp.json'), JSON.stringify({ mcpServers: { paid: { command: 'x', env: { L402: expired.header } } } }, null, 2));
  const result = await scan([dir], { clock });
  const rows = result.findings.map(finding => ({ file: finding.path.split('/').at(-1), line: finding.line, kind: finding.kind,
    fingerprint: finding.fingerprint, form: finding.l402?.form, scheme: finding.l402?.scheme, context: finding.context }));
  expect(rows).toEqual([
    { file: '.env', line: 1, kind: 'l402', fingerprint: grpc.fingerprint, form: 'pair', scheme: null, context: undefined },
    { file: 'challenges.txt', line: 1, kind: 'l402', fingerprint: challenge.macaroonFingerprint, form: 'challenge', scheme: 'LSAT', context: undefined },
    { file: 'challenges.txt', line: 1, kind: 'l402', fingerprint: challenge.macaroonFingerprint, form: 'challenge', scheme: 'L402', context: undefined },
    { file: 'challenges.txt', line: 2, kind: 'l402', fingerprint: legacy.macaroonFingerprint, form: 'challenge', scheme: 'L402', context: undefined },
    { file: 'challenges.txt', line: 3, kind: 'l402', fingerprint: pending.macaroonFingerprint, form: 'challenge', scheme: 'L402', context: undefined },
    { file: 'client.yaml', line: 2, kind: 'l402', fingerprint: stored.fingerprint, form: 'authorization', scheme: 'LSAT', context: undefined },
    { file: 'fetch.sh', line: 1, kind: 'l402', fingerprint: paired.fingerprint, form: 'authorization', scheme: 'L402', context: undefined },
    { file: 'mcp.json', line: 6, kind: 'l402', fingerprint: expired.fingerprint, form: 'authorization', scheme: 'L402', context: 'mcp-config' },
    { file: 'several.log', line: 1, kind: 'l402', fingerprint: fp(discharge, live.macaroon, live.preimage), form: 'authorization',
      scheme: 'L402', context: undefined },
  ]);
  const severalFinding = result.findings.find(finding => finding.path.endsWith('several.log'))!;
  expect(severalFinding.l402).toMatchObject({ macaroons: 2, macaroonFingerprint: live.macaroonFingerprint, preimage: 'matches',
    countedAs: 'READ', warnings: ['l402-several-macaroons'] });
  expect(result.findings.filter(finding => finding.l402?.countedAs === 'READ')).toHaveLength(5);
});

it('L402-scan/negative shapes: look-alikes, short preimages, digests and undecodable pairs report only real macaroons', async () => {
  const dir = mkdtempSync(join(scratch, 'negative-'));
  const hex = 'ab'.repeat(32);
  writeFileSync(join(dir, 'lookalike.txt'), [
    'Authorization: L402 <macaroon>:<preimage>',
    `Authorization: L402 ${'A'.repeat(39)}:${hex}`,
    `Authorization: L402 ${live.base64}:${hex.slice(2)}`,
    `Authorization: L402 ${live.base64}:${hex}0`,
    `image: example/app@sha256:${hex}`,
    `${Buffer.from('a plain base64 text that is not a macaroon at all').toString('base64')}:${hex}`,
    `XL402 ${live.pair}`,
    'WWW-Authenticate: L402 macaroon="short", invoice="lnbc1"',
    'docs: L402 macaroon="<base64>", invoice="<bolt11>"',
  ].join('\n'));
  const result = await scan([dir], { clock });
  // A header whose preimage is too short or too long is no Authorization credential, but its
  // macaroon is still an (unpaid) L402 macaroon; "XL402 <pair>" is a pair.
  expect(result.findings.map(finding => [finding.line, finding.kind, finding.l402?.form, finding.l402?.status])).toEqual([
    [3, 'l402', 'macaroon', 'unpaid'], [4, 'l402', 'macaroon', 'unpaid'], [7, 'l402', 'pair', 'live']]);
});

it('L402-scan/git history: a token later replaced in the work tree is still found in history', async () => {
  const { spawnSync } = await import('node:child_process');
  const dir = mkdtempSync(join(scratch, 'history-'));
  const git = (...args: string[]) => spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false',
    ...args], { cwd: dir, encoding: 'utf8' });
  expect(git('init', '-q').status).toBe(0);
  writeFileSync(join(dir, 'config.env'), `TOKEN=${live.header}\n`);
  writeFileSync(join(dir, 'l402.token'), tokenFile(stored));
  expect(git('add', '.').status).toBe(0);
  expect(git('commit', '-q', '-m', 'add').status).toBe(0);
  writeFileSync(join(dir, 'config.env'), 'TOKEN=\n');
  writeFileSync(join(dir, 'l402.token'), tokenFile(pending, true));
  expect(git('commit', '-q', '-am', 'replace').status).toBe(0);
  const result = await scan([dir], { clock, gitHistory: true });
  expect(result.findings.map(finding => [finding.path.split('/').at(-1), finding.kind, finding.fingerprint, finding.commit !== undefined]))
    .toEqual([
      ['config.env', 'l402', live.fingerprint, true],
      ['l402.token', 'l402-file', pending.macaroonFingerprint, false],
      ['l402.token', 'l402-file', stored.fingerprint, true],
    ]);
});

it('L402-scan/the committed fixture tree matches its independently generated manifest', async () => {
  const root = join(repo, 'test/scan-fixtures/l402');
  const expected = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8')) as {
    files: { path: string; findings: { line: number | null; column: number | null; kind: string; form: string; status: string; fingerprint: string }[] }[];
    summary: { findings: number; distinct: number; countedAtRead: number; byGrade: { L402: number } } };
  const result = await scan([root], { clock });
  const prefix = `${root.replace(/\\/g, '/')}/`;
  expect(result.findings.map(finding => ({ path: finding.path.slice(prefix.length), line: finding.line, column: finding.column,
    kind: finding.kind, form: finding.l402?.form, status: finding.l402?.status, fingerprint: finding.fingerprint })))
    .toEqual(expected.files.flatMap(file => file.findings.map(item => ({ path: file.path, line: item.line, column: item.column,
      kind: item.kind, form: item.form, status: item.status, fingerprint: item.fingerprint }))));
  expect(result.summary).toMatchObject({ findings: expected.summary.findings, distinct: expected.summary.distinct,
    byGrade: { L402: expected.summary.byGrade.L402 } });
  const counted = await run([root, '--fail-on', 'READ'], { fs });
  expect((counted.result as { failOn: { count: number } }).failOn.count).toBe(expected.summary.countedAtRead);
});
