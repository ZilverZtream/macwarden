import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { expect } from 'vitest';
import { childEnvironment } from '../helpers/environment.js';
import { findLeaks } from '../helpers/leak-check.js';

type FullEvidence = {
  level: string; platform: string; candidate: string; status: string;
  toolchain: { node: string; npm: string | null; lockfileSha256: string | null };
  inputs: Array<{ file: string; sha256: string }>;
  reports: Array<{ label: string; originalPath: string; originalSha256: string; retainedSha256: string }>;
  commands: unknown[]; checks: Array<{ name: string; status: string }>; inventories: unknown; startedAt: string;
};
const digest = (path: string) => createHash('sha256').update(readFileSync(path)).digest('hex');
function files(root: string): string[] {
  return readdirSync(root, { withFileTypes: true }).flatMap(entry =>
    entry.isDirectory() ? files(join(root, entry.name)) : [join(root, entry.name)]);
}

// Bounds one synthetic full validation (about a dozen npm and Vitest processes): 5 to 30 s
// depending on the machine. The limit only stops a hung run; every check failure ends the run
// with exit 1 long before it, and a timeout is reported as such.
export const FULL_CONTROL_TIMEOUT_MS = 150_000;

export function fullControl(variant: 'complete' | 'changed-candidate' | 'selective-as-full' | 'metadata-leak' | 'oracle-config-exclusion', producerRoot = resolve()) {
  prepareFullControl(variant, producerRoot)();
}

export function prepareFullControl(variant: 'complete' | 'changed-candidate' | 'selective-as-full' | 'metadata-leak' | 'oracle-config-exclusion', producerRoot = resolve()): () => void {
  if (!process.env.MACWARDEN_TEST_TMP) throw new Error('Private test scratch is required');
  const scratch = mkdtempSync(join(process.env.MACWARDEN_TEST_TMP, 'cp050-full-'));
  const root = join(scratch, 'project'), evidence = join(scratch, 'evidence');
  const put = (name: string, value: string) => {
    const path = join(root, name); mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, value);
  };
  const git = (...args: string[]) => {
    const result = spawnSync('git', args, { cwd: root, encoding: 'utf8', timeout: 15_000, env: childEnvironment() });
    expect(result.status, `private fixture git ${args[0]}`).toBe(0); return result.stdout.trim();
  };
  const vitest = resolve('node_modules/vitest/vitest.mjs').replaceAll('\\', '/');
  const api = resolve('node_modules/vitest/dist/index.js').replaceAll('\\', '/');
  const run = (config: string) => `node "${vitest}" run --config ${config}`;
  put('package.json', JSON.stringify({ name: 'cp050-full-fixture', version: '1.0.0', type: 'module', scripts: {
    test: run('vitest.config.ts'), 'test:oracle': `${run('vitest.oracle.config.ts')}${variant === 'selective-as-full' ? ' --exclude test/oracle/b.test.ts' : ''}`,
    'test:harness': run('vitest.harness.config.ts'), 'test:gitleaks': run('vitest.harness.config.ts'),
    lint: 'node scripts/phase.mjs lint', build: 'node scripts/phase.mjs build',
    'fixture:up': 'node scripts/phase.mjs fixture-up', 'fixture:down': 'node scripts/phase.mjs fixture-down',
    'test:cln-oracle': run('vitest.cln.config.ts'),
    'fixture:cln:up': 'node scripts/phase.mjs fixture-cln-up', 'fixture:cln:down': 'node scripts/phase.mjs fixture-cln-down',
  } }));
  put('package-lock.json', JSON.stringify({ name: 'cp050-full-fixture', version: '1.0.0', lockfileVersion: 3,
    packages: { '': { name: 'cp050-full-fixture', version: '1.0.0' } } }));
  for (const [config, include] of [['vitest.config.ts', 'test/unit/**/*.test.ts'],
    ['vitest.oracle.config.ts', 'test/oracle/**/*.test.ts'], ['vitest.harness.config.ts', 'test/harness/**/*.test.ts'],
    ['vitest.cln.config.ts', 'test/cln-oracle/**/*.test.ts']])
    put(config!, `export default {test:{include:[${JSON.stringify(include)}],${variant === 'oracle-config-exclusion' && config === 'vitest.oracle.config.ts' ? "exclude:['test/oracle/c.test.ts']," : ''}fileParallelism:false,maxWorkers:1}};\n`);
  const test = (title: string) => `import {it,expect} from ${JSON.stringify(api)};\nit(${JSON.stringify(title)},()=>expect(1).toBe(1));\n`;
  let firstProductTitle = 'CP-950/B1 first independent product case';
  if (variant === 'metadata-leak') {
    if (!process.env.MACWARDEN_SENTINEL_DIR) throw new Error('Independent registered sentinel root is required');
    const registered = join(process.env.MACWARDEN_SENTINEL_DIR, 'cp050-existing-metadata-sentinel.macaroon');
    copyFileSync(resolve('test/sentinels/sentinel.macaroon'), registered);
    const separated = readFileSync(registered).toString('hex').match(/../g)!.join(':');
    // Only the protected private project receives this deliberately unsafe
    // metadata. Actual Vitest collection and execution carry it into reports.
    firstProductTitle += ` ${separated}`;
  }
  put('test/unit/a.test.ts', test(firstProductTitle));
  put('test/unit/b.test.ts', test('CP-951/B1 second independent product case'));
  put('test/oracle/a.test.ts', test('CP-950/probe first independent reference'));
  put('test/oracle/b.test.ts', test('CP-951/probe second independent reference'));
  if (variant === 'oracle-config-exclusion') put('test/oracle/c.test.ts', test('CP-950/probe third original reference'));
  put('test/harness/a.test.ts', test('CP-950/B1 independent harness case'));
  put('test/cln-oracle/a.test.ts', test('CP-952/cln-probe independent Core Lightning reference'));
  put('src/input.ts', 'export const input = 1;\n');
  put('scripts/phase.mjs', `import {writeFileSync} from 'node:fs';import {spawnSync} from 'node:child_process';
if(process.argv[2]==='build'&&${JSON.stringify(variant)}==='changed-candidate'){
writeFileSync('src/input.ts','export const input = 2;\\n');
for(const args of [['add','src/input.ts'],['commit','-m','Private input mutation']]){if(spawnSync('git',args,{stdio:'pipe'}).status!==0)process.exit(1);}}
`);
  put('test/sentinels.json', JSON.stringify(['test/sentinels/sentinel.macaroon']));
  mkdirSync(join(root, 'test/sentinels'), { recursive: true });
  copyFileSync(resolve('test/sentinels/sentinel.macaroon'), join(root, 'test/sentinels/sentinel.macaroon'));
  // Public fixture topology is test-owned. These copies provide the fixed API
  // without exposing any producer implementation or invoking a real node.
  for (const path of ['test/fixture/topology.mjs', 'test/helpers/fixture-invalid.mjs',
    'test/fixture/docker-compose.yml', 'test/fixture/cp024-compose.yml', 'test/fixture/shard-1.yml', 'test/fixture/shard-2.yml']) {
    mkdirSync(dirname(join(root, path)), { recursive: true }); copyFileSync(resolve(path), join(root, path));
  }
  git('init', '-b', 'main'); git('config', 'user.name', 'Private Fixture'); git('config', 'user.email', 'fixture@example.invalid');
  git('add', '.'); git('commit', '-m', 'Independent full validation input');
  const candidate = git('rev-parse', 'HEAD');
  const inputs = new Map(git('ls-files').split(/\r?\n/).map(file => [file, digest(join(root, file))]));
  expect(git('status', '--porcelain'), 'Private inputs including selected metadata must be committed before validation').toBe('');
  const result = spawnSync(process.execPath, [resolve(producerRoot, 'scripts/full-validation.mjs'), '--root', root, '--evidence-dir', evidence],
    { cwd: resolve(), env: childEnvironment(), encoding: 'utf8', timeout: FULL_CONTROL_TIMEOUT_MS, maxBuffer: 2_000_000 });
  writeFileSync(join(scratch, 'captured-output.txt'), result.stdout + result.stderr);
  // The selected-case metadata is a private input. Remove the planted source
  // after execution so the caller's standing scan examines retained output.
  if (variant === 'metadata-leak') rmSync(join(root, 'test/unit/a.test.ts'));
  // The nested fixture sentinel is an input. Remove its private copy before the
  // caller scans retained reports and the original captured command output.
  rmSync(join(root, 'test/sentinels/sentinel.macaroon'));
  return () => {
  expect(findLeaks({ root: process.cwd(), sentinels: 'test/sentinels.json', sentinelDir: process.env.MACWARDEN_SENTINEL_DIR,
    paths: variant === 'metadata-leak' ? [join(scratch, 'captured-output.txt'), ...(existsSync(evidence) ? [evidence] : [])] : [scratch],
    testTmp: variant === 'metadata-leak' ? undefined : scratch, commandOutput: result.stdout + result.stderr })).toBeNull();
  expect(result.error, `${variant} public full validation did not finish (${result.error?.message}); output tail:
${(result.stdout + result.stderr).slice(-1500)}`).toBeUndefined();
  if (variant !== 'oracle-config-exclusion') expect(result.status, `${variant} public full validation exit; output tail:
${(result.stdout + result.stderr).slice(-4000)}`).toBe(variant === 'complete' ? 0 : 1);
  expect(existsSync(evidence), 'Public CLI must retain its original attempt evidence').toBe(true);
  const artifacts = files(evidence).filter(path => path.endsWith('full-validation.json'));
  expect(artifacts).toHaveLength(1);
  expect(artifacts[0]).toMatch(/[\\/]attempt-[^\\/]+[\\/]full-validation\.json$/);
  const record = JSON.parse(readFileSync(artifacts[0]!, 'utf8')) as FullEvidence;
  expect(record.level).toBe('full'); expect(record.platform).toBe(process.platform); expect(record.candidate).toBe(candidate);
  // Audit TOOLING-10: the evidence names the toolchain that produced it, and is written whole.
  expect(record.toolchain.node).toBe(process.version);
  expect(record.toolchain.npm).toMatch(/^\d+\.\d+\.\d+/);
  expect(files(evidence).some(path => path.endsWith('.partial')), 'no partial evidence file is left').toBe(false);
  expect(record.startedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  if (variant !== 'metadata-leak') expect(record.commands.length).toBeGreaterThan(0);
  expect(record.checks.length).toBeGreaterThan(0);
  if (variant === 'oracle-config-exclusion') {
    const originals = record.reports.map(report => {
      expect(report.originalSha256).toBe(digest(report.originalPath));
      const bytes = readFileSync(report.originalPath, 'utf8').trim();
      const original = (bytes.startsWith('{') ? JSON.parse(bytes) : {}) as {
        testResults?: Array<{assertionResults:Array<{fullName:string}>}>;
      };
      return { ...report, titles: original.testResults?.flatMap(file => file.assertionResults.map(assertion => assertion.fullName)) ?? [] };
    });
    const shards = originals.filter(report => report.titles.some(title => /^CP-95[01]\/probe /.test(title)));
    // A correct runner may reject the omission before executing either shard.
    // Any false PASS must prove that both actual shards ran the reduced cases.
    if (result.status === 0) {
      expect(shards, 'Both actual oracle shards must remain nonempty').toHaveLength(2);
      for (const shard of shards) expect(shard.titles.length).toBeGreaterThan(0);
      const titles = shards.flatMap(shard => shard.titles);
      expect(titles).toContain('CP-950/probe first independent reference');
      expect(titles).toContain('CP-951/probe second independent reference');
      expect(titles).not.toContain('CP-950/probe third original reference');
    }
    const omitted = 'test/oracle/c.test.ts';
    expect(digest(join(root, omitted))).toBe(inputs.get(omitted));
    writeFileSync(join(scratch, 'oracle-config-control-proof.json'), JSON.stringify({
      candidate, exitCode: result.status, status: record.status,
      originalOracleInputs: ['test/oracle/a.test.ts', 'test/oracle/b.test.ts', omitted].map(file => ({file,sha256:inputs.get(file)})),
      originalReports: originals, safeArtifact: artifacts[0], safeArtifactSha256: digest(artifacts[0]!),
    }));
    expect(result.status, 'A frozen config excluding an existing original oracle must fail full validation').toBe(1);
  }
  if (variant === 'complete') {
    expect(result.status).toBe(0); expect(record.status).toBe('PASS');
    expect(record.inputs.length).toBeGreaterThan(0);
    const recordedFiles = record.inputs.map(input => (isAbsolute(input.file) ? relative(root, input.file) : input.file).replaceAll('\\', '/'));
    for (const required of ['package.json', 'src/input.ts', 'scripts/phase.mjs', 'vitest.config.ts', 'vitest.oracle.config.ts',
      'vitest.cln.config.ts', 'test/unit/a.test.ts', 'test/unit/b.test.ts', 'test/oracle/a.test.ts', 'test/oracle/b.test.ts',
      'test/cln-oracle/a.test.ts']) expect(recordedFiles).toContain(required);
    for (const input of record.inputs) {
      const file = (isAbsolute(input.file) ? relative(root, input.file) : input.file).replaceAll('\\', '/');
      expect(input.sha256, input.file).toBe(inputs.get(file));
    }
    expect(record.reports.length).toBeGreaterThanOrEqual(3);
    const originals = record.reports.map(report => {
      expect(report.originalSha256).toBe(digest(report.originalPath));
      expect(report.retainedSha256).toBe(report.originalSha256);
      expect(files(evidence).some(path => digest(path) === report.retainedSha256)).toBe(true);
      return readFileSync(report.originalPath, 'utf8');
    }).join('\n');
    for (const title of ['CP-950/B1 first independent product case', 'CP-951/B1 second independent product case',
      'CP-950/probe first independent reference', 'CP-951/probe second independent reference',
      'CP-952/cln-probe independent Core Lightning reference']) expect(originals).toContain(title);
  } else {
    expect(result.status).toBe(1); expect(record.status).toBe('FAIL');
    if (variant === 'metadata-leak') expect(record.checks.some(check => /^leak-check(?::|$)/.test(check.name) && check.status === 'FAIL'),
      'A metadata sentinel leak requires its own failed leak check').toBe(true);
  }
  if (variant === 'metadata-leak') {
    const originals = record.reports.map(report => {
      const originalSha256 = digest(report.originalPath);
      expect(report.originalSha256, 'Recorded original identity must match its actual private bytes').toBe(originalSha256);
      return { label: report.label, originalPath: report.originalPath, originalSha256, retainedSha256: report.retainedSha256 };
    });
    // Keep only safe identities for this deliberately unsafe synthetic input.
    // The candidate's normal reports and every other control remain retained.
    const runtime = join(root, '.ratchet/packets');
    const rawIdentities = existsSync(runtime) ? files(runtime).map(path => ({ file: relative(root, path).replaceAll('\\', '/'), sha256: digest(path) })) : [];
    writeFileSync(join(scratch, 'metadata-control-proof.json'), JSON.stringify({ candidate, status: record.status,
      originalReports: originals, rawInputs: rawIdentities, safeArtifact: artifacts[0], safeArtifactSha256: digest(artifacts[0]!),
      failedLeakChecks: record.checks.filter(check => /^leak-check(?::|$)/.test(check.name) && check.status === 'FAIL').map(check => ({ name: check.name, status: check.status })) }));
    if (resolve(root) !== resolve(scratch, 'project')) throw new Error('Synthetic metadata project containment changed');
    rmSync(root, { recursive: true, force: true });
    expect(findLeaks({ root: process.cwd(), sentinels: 'test/sentinels.json', sentinelDir: process.env.MACWARDEN_SENTINEL_DIR,
      paths: [scratch], testTmp: scratch, commandOutput: result.stdout + result.stderr }),
    'All remaining synthetic control scratch must be free of sentinel encodings').toBeNull();
  }
  };
}

