import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, expect, it } from 'vitest';
import { artifact, installedCommand, relativePaths, repo, retainArtifactBytes } from './artifact.js';

afterAll(retainArtifactBytes);
// The first test to call artifact() packs, installs and cleanly rebuilds the package: about 1 to
// 2.5 minutes on a two-core CI runner. The limit only stops a hang.
const ARTIFACT_TIMEOUT_MS = 300_000;

type Package = { name: string; version: string; license: string; engines: { node: string };
  dependencies?: Record<string, string>; files: string[]; scripts: Record<string, string>;
  publishConfig?: { provenance?: boolean } };
const packageJson = () => JSON.parse(readFileSync(join(repo, 'package.json'), 'utf8')) as Package;
const manifest = () => JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as {
  vectors: Array<{ name: string; file: string; expectedGrade: string }> };
const vector = (name: string) => {
  const entry = manifest().vectors.find(item => item.name === name);
  expect(entry, `${name} must be in the committed vector manifest`).toBeDefined();
  return entry!;
};

function workflow(name: string): string {
  return readFileSync(join(repo, '.github/workflows', name), 'utf8');
}

function block(text: string, key: string, indent: number): string {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex(line => line === `${' '.repeat(indent)}${key}:`);
  expect(start, `${key} at indentation ${indent}`).toBeGreaterThanOrEqual(0);
  const end = lines.findIndex((line, index) => index > start && line.trim() !== '' &&
    /^\s*/.exec(line)![0].length <= indent);
  return lines.slice(start + 1, end < 0 ? undefined : end).join('\n');
}

function jobs(text: string): Record<string, string> {
  const body = block(text, 'jobs', 0);
  const result: Record<string, string> = {};
  const lines = body.split('\n');
  for (let at = 0; at < lines.length; at++) {
    const match = /^ {2}([\w-]+):\s*$/.exec(lines[at]);
    if (!match) continue;
    const next = lines.findIndex((line, index) => index > at && /^ {2}[\w-]+:\s*$/.test(line));
    result[match[1]] = lines.slice(at + 1, next < 0 ? undefined : next).join('\n');
  }
  return result;
}

function checkPinnedUses(text: string): void {
  const uses = [...text.matchAll(/^\s*-?\s*uses:\s*([^\s#]+)/gm)].map(match => match[1]);
  expect(uses.length).toBeGreaterThan(0);
  expect(uses.every(value => [
    'actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd',
    'actions/setup-node@a0853c24544627f65ddf259abe73b1d18a591444',
  ].includes(value))).toBe(true);
}

function checkDefaultPermissions(text: string): void {
  const permissions = block(text, 'permissions', 0);
  expect(permissions).toMatch(/^\s+contents:\s*read\s*$/m);
  expect(permissions).not.toMatch(/^\s+id-token:\s*write\s*$/m);
}

it('CP-014/B1 dry-run and extracted tarball have exactly the offline allow-list', () => {
  const a = artifact();
  const actual = relativePaths(a.extracted);
  expect(actual).toEqual(a.dryFiles);
  const named = ['package.json', 'rules/gitleaks.toml', 'rules/trufflehog.yaml', 'README.md', 'SECURITY.md',
    'LICENSE', 'CHANGELOG.md'];
  // Every command's --json schema, watch's event-line schema and the registry entry ship.
  const schemas = ['inspect', 'scan', 'inventory', 'bake', 'revoke', 'rotate', 'attenuate', 'watch', 'watch-event', 'recommend',
    'respond', 'registry-entry'].map(name => `schemas/output/${name}.schema.json`);
  for (const name of schemas) expect(actual).toContain(name);
  for (const name of named) expect(actual).toContain(name);
  expect(actual.some(path => path.startsWith('dist/'))).toBe(true);
  expect(actual.some(path => path.startsWith('dist/') && path.endsWith('/lnd-permissions.json')))
    .toBe(true);
  expect(actual.every(path => named.includes(path) || path.startsWith('dist/')
    || /^schemas\/output\/[a-z-]+\.schema\.json$/.test(path))).toBe(true);
  expect(actual.some(path => /^(test|src|scripts|\.ratchet|\.github|archive|docs)\//.test(path)))
    .toBe(false);
}, ARTIFACT_TIMEOUT_MS);

it('CP-014/B2 installed tarball runs version inspect scan and dormant inventory', () => {
  const version = installedCommand(['--version']);
  expect(version.status).toBe(0);
  expect(version.stdout.trim()).toBe('1.1.1');

  const addInvoice = vector('grade-uri-add-invoice');
  expect(addInvoice.expectedGrade).toBe('RECEIVE');
  const inspect = installedCommand(['inspect', join(repo, 'test/vectors', addInvoice.file), '--json']);
  expect(inspect.status).toBe(0);
  const document = JSON.parse(inspect.stdout) as { result: { grade: string; snapshot: string } };
  expect(document.result.grade).toBe(addInvoice.expectedGrade);
  expect(document.result.snapshot).toBe('0.21.4-beta');

  const readonly = vector('default-readonly');
  expect(readonly.expectedGrade).toBe('READ');
  const tree = join(artifact().root, 'scan-tree');
  mkdirSync(tree);
  try {
    writeFileSync(join(tree, 'readonly.env'),
      `MACAROON=${readFileSync(join(repo, 'test/vectors', readonly.file)).toString('hex')}\n`);
    const scan = installedCommand(['scan', tree, '--fail-on', 'READ']);
    expect(scan.status).toBe(1);
  } finally { rmSync(tree, { recursive: true, force: true }); }

  expect(installedCommand(['inventory']).status).toBe(2);
}, ARTIFACT_TIMEOUT_MS);

it('CP-014/B2 installed command detects a broken npm shim and preserves literal arguments', () => {
  const a = artifact();
  const shim = join(a.installed, 'node_modules', '.bin',
    process.platform === 'win32' ? 'macwarden.ps1' : 'macwarden');
  const original = readFileSync(shim);
  const args = ['argument with spaces', 'quotes \' and "', '$(exit 91)',
    '; & | < >', '%PATH% !literal!', '`backticks`'];
  try {
    writeFileSync(shim, process.platform === 'win32'
      ? 'foreach ($value in $args) { [Console]::Out.WriteLine($value) }\n' +
        '[Console]::Error.WriteLine("broken shim control")\nexit 73\n'
      : '#!/bin/sh\nprintf \'%s\\n\' "$@"\nprintf \'broken shim control\\n\' >&2\nexit 73\n');
    const result = installedCommand(args);
    expect(result.status).toBe(73);
    expect(result.stdout.replace(/\r\n/g, '\n')).toBe(`${args.join('\n')}\n`);
    expect(result.stderr.trim()).toBe('broken shim control');
  } finally { writeFileSync(shim, original); }
}, ARTIFACT_TIMEOUT_MS);

it('CP-014/B3 package metadata fixes version dependencies allow-list and future provenance', () => {
  const pkg = packageJson();
  const lock = JSON.parse(readFileSync(join(repo, 'package-lock.json'), 'utf8')) as {
    version: string; packages: Record<string, { version: string; dependencies?: Record<string, string> }> };
  expect(pkg.name).toBe('macwarden');
  expect(pkg.version).toBe('1.1.1');
  expect(lock.version).toBe('1.1.1');
  expect(lock.packages[''].version).toBe('1.1.1');
  expect(pkg.license).toBe('MIT');
  expect(pkg.engines.node).toBe('^22.23.2 || ^24.18.1 || >=26.5.1');
  expect(Object.keys(pkg.dependencies ?? {})).toHaveLength(0);
  expect(Object.keys(lock.packages[''].dependencies ?? {})).toHaveLength(0);
  expect(pkg.files.map(path => path.replace(/\/$/, '')).sort()).toEqual([
    'dist', 'schemas/output', 'rules/gitleaks.toml', 'rules/trufflehog.yaml', 'README.md', 'SECURITY.md', 'LICENSE', 'CHANGELOG.md',
  ].sort());
  expect(pkg.scripts.prepack).toMatch(/(?:npm run build|node scripts\/build\.mjs)/);
  expect(pkg.publishConfig?.provenance).toBe(true);
});

it('CP-014/B4 dormant release workflow pins trusted publishing and scoped token permission', () => {
  const text = workflow('release.yml');
  expect(block(block(text, 'on', 0), 'push', 2))
    .toMatch(/tags:\s*(?:\[\s*['"]?v\*['"]?\s*\]|\n\s*-\s*['"]?v\*['"]?)/);
  checkDefaultPermissions(text);
  checkPinnedUses(text);
  const entries = Object.values(jobs(text));
  const publishers = entries.filter(job => /npm publish\s+--provenance/.test(job));
  expect(publishers).toHaveLength(1);
  expect(publishers[0]).toMatch(/^\s+permissions:\s*\n(?:.|\n)*?^\s+id-token:\s*write\s*$/m);
  expect(entries.filter(job => /^\s+id-token:\s*write\s*$/m.test(job))).toHaveLength(1);
});

it('CP-014/B5 CI keeps its triggers and pins and tests the supported platforms and Node lines', () => {
  const text = workflow('ci.yml');
  const triggers = block(text, 'on', 0);
  const push = block(triggers, 'push', 2);
  expect(push).toContain('main');
  expect(triggers).toMatch(/^ {2}pull_request:/m);
  expect(triggers).toMatch(/^ {2}workflow_dispatch:/m);
  checkDefaultPermissions(text);
  checkPinnedUses(text);
  const entries = Object.values(jobs(text));
  // README and CONTRIBUTING: Linux and Windows are tested before each release; macOS is not part
  // of release validation. Both engine floors and both current Node lines run on Linux.
  const unit = entries.filter(job => ['ubuntu-latest', 'windows-latest'].every(platform => job.includes(platform)));
  expect(unit).toHaveLength(1);
  for (const node of ['22.23.2', '22.x', '24.18.1', '24.x']) expect(unit[0]).toContain(`'${node}'`);
  const steps = ['npm ci', 'npm run lint', 'npm run build', 'npm test'].map(step => unit[0].indexOf(`run: ${step}`));
  expect(steps.every(at => at >= 0)).toBe(true);
  expect([...steps].sort((a, b) => a - b)).toEqual(steps);
  expect(text).not.toMatch(/macos/i);
  expect(entries.some(job => job.includes('ubuntu-latest') &&
    job.indexOf('npm run fixture:up') >= 0 &&
    job.indexOf('npm run fixture:up') < job.indexOf('npm run test:oracle') &&
    job.indexOf('npm run test:oracle') < job.indexOf('npm run fixture:down'))).toBe(true);
  // The Core Lightning rune comparison runs in its own job against its own fixture, which is
  // brought down whatever the result; an LND oracle failure cannot skip it.
  const oracle = entries.filter(job => job.includes('run: npm run test:oracle'));
  expect(oracle).toHaveLength(1);
  expect(oracle[0]).not.toContain('test:cln-oracle');
  const cln = entries.filter(job => job.includes('run: npm run test:cln-oracle'));
  expect(cln).toHaveLength(1);
  const clnSteps = ['npm run build', 'npm run fixture:cln:up', 'npm run test:cln-oracle', 'npm run fixture:cln:down']
    .map(step => cln[0].indexOf(`run: ${step}`));
  expect(clnSteps.every(at => at >= 0)).toBe(true);
  expect([...clnSteps].sort((a, b) => a - b)).toEqual(clnSteps);
  expect(cln[0]).toMatch(/^ {6}- if: always\(\)\n {8}run: npm run fixture:cln:down$/m);
  expect(entries.some(job => job.includes('ubuntu-latest') &&
    job.includes('npm run test:gitleaks'))).toBe(true);
  expect(entries.every(job => !/^\s+id-token:\s*write\s*$/m.test(job))).toBe(true);
});

it('CP-014/B6 release documents give runnable offline examples and accurate local limits', () => {
  const readme = readFileSync(join(repo, 'README.md'), 'utf8');
  const security = readFileSync(join(repo, 'SECURITY.md'), 'utf8');
  const changelog = readFileSync(join(repo, 'CHANGELOG.md'), 'utf8');
  expect(readme).toContain('npm i -g macwarden@');
  expect(readme).toContain('npm audit signatures');
  expect(security).toContain('Report a vulnerability');
  expect(security).toMatch(/(?:future|when|if).{0,120}provenance/i);
  expect(changelog).toMatch(/^## 1\.0\.0\b/m);
  for (const name of ['inventory', 'bake', 'revoke', 'rotate'])
    expect(readme).toMatch(new RegExp(`\\b${name}\\b`, 'i'));
  expect(readme).toMatch(/local/i);
  expect(readme).toContain('Windows');
  expect(readme).toContain('Linux');
  expect(readme).not.toMatch(/(?:published|released)\s+(?:from|by|on)\s+(?:CI|GitHub Actions)/i);
  const examples = [...readme.matchAll(/^\s*(?:\$\s*)?macwarden\s+(inspect|scan)\s+([^\r\n#]+)/gm)];
  expect(examples.length).toBeGreaterThan(0);
  for (const [, verb, rest] of examples) {
    const args = rest.trim().split(/\s+/);
    const inputAt = args.findIndex((arg, index) => !arg.startsWith('-') &&
      (index === 0 || !['--fail-on', '--ignore-file'].includes(args[index - 1])));
    expect(inputAt).toBeGreaterThanOrEqual(0);
    args[inputAt] = verb === 'inspect'
      ? join(repo, 'test/vectors', vector('grade-uri-add-invoice').file)
      : join(repo, 'test/scan-fixtures/full');
    const result = installedCommand([verb, ...args]);
    expect(result.status, `${verb} README example must not exit 2`).not.toBe(2);
  }
}, ARTIFACT_TIMEOUT_MS);

it('CP-014/B16 prepack replaces stale dist with bytes from an independent clean build', () => {
  const a = artifact();
  expect([...a.packedDist.keys()]).toEqual([...a.cleanDist.keys()]);
  for (const [path, bytes] of a.cleanDist)
    expect(a.packedDist.get(path), `fresh packed ${path}`).toEqual(bytes);
  expect(a.packedDist.has('obsolete-cp014.js')).toBe(false);
  const addInvoice = vector('grade-uri-add-invoice');
  const result = installedCommand(['inspect', join(repo, 'test/vectors', addInvoice.file), '--json']);
  expect(result.status).toBe(0);
  expect((JSON.parse(result.stdout) as { result: { grade: string } }).result.grade)
    .toBe(addInvoice.expectedGrade);
}, ARTIFACT_TIMEOUT_MS);
