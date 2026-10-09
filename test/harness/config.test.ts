import { readFileSync, readdirSync, statSync } from 'node:fs';
import { resolve, relative, join } from 'node:path';
import { expect, it } from 'vitest';

const read = (path: string) => readFileSync(resolve(path), 'utf8');
const pinned = {
  typescript: '6.0.3', vitest: '5.0.3', vite: '8.3.2', eslint: '10.11.0',
  '@eslint/js': '10.0.1', 'typescript-eslint': '8.71.0',
  '@types/node': '22.20.5', globals: '17.13.0',
  ajv: '8.20.0',
};
const scripts = {
  test: 'vitest run --project product',
  'test:harness': 'vitest run --project harness-docs',
  'test:related': 'vitest related --run',
  'test:full': 'node scripts/full-validation.mjs',
  lint: 'eslint .',
  build: 'tsc -p tsconfig.json && tsc -p tsconfig.test.json',
  'test:oracle': 'vitest run --config vitest.oracle.config.ts',
  'test:gitleaks': 'vitest run --config vitest.gitleaks.config.ts',
  'fixture:up': 'node test/fixture/fixture.mjs up',
  'fixture:down': 'node test/fixture/fixture.mjs down',
};

function listFor(yaml: string, key: string): string[] {
  const lines = yaml.split(/\r?\n/);
  const index = lines.findIndex(line => new RegExp(`^\\s*${key}:\\s*(?:\\[|$)`).test(line));
  expect(index, `YAML key ${key}`).toBeGreaterThanOrEqual(0);
  const inline = lines[index].match(/:\s*\[([^\]]*)\]/);
  if (inline) return inline[1].split(',').map(value => value.trim().replace(/^['"]|['"]$/g, ''));
  const indent = lines[index].match(/^\s*/)?.[0].length ?? 0;
  const values: string[] = [];
  for (const line of lines.slice(index + 1)) {
    if (!line.trim()) continue;
    const nextIndent = line.match(/^\s*/)?.[0].length ?? 0;
    if (nextIndent <= indent) break;
    const item = line.match(/^\s*-\s+(.+?)\s*$/);
    if (item) values.push(item[1].replace(/^['"]|['"]$/g, ''));
  }
  return values;
}

function blockFor(yaml: string, key: string, indent: number): string {
  const lines = yaml.split(/\r?\n/);
  const start = lines.findIndex(line => line === `${' '.repeat(indent)}${key}:`);
  expect(start, `YAML block ${key}`).toBeGreaterThanOrEqual(0);
  let end = start + 1;
  while (end < lines.length) {
    const line = lines[end];
    if (line.trim() && (line.match(/^\s*/)?.[0].length ?? 0) <= indent) break;
    end += 1;
  }
  return lines.slice(start, end).join('\n').trimEnd();
}

it('CP-001/B10 pins the package, lockfile, scripts and strict TypeScript', () => {
  const pkg = JSON.parse(read('package.json'));
  const lock = JSON.parse(read('package-lock.json'));
  const tsconfig = JSON.parse(read('tsconfig.json'));
  expect(pkg).toMatchObject({
    name: 'macwarden', version: '1.1.1', type: 'module', license: 'MIT',
    engines: { node: '^22.23.2 || ^24.18.1 || >=26.5.1' },
  });
  expect(pkg.dependencies ?? {}).toEqual({});
  expect(typeof pkg.bin?.macwarden).toBe('string');
  expect(pkg.bin.macwarden).toMatch(/(?:^|\/)dist\/bin\.js$/);
  expect(pkg.devDependencies).toEqual(pinned);
  expect(pkg.scripts).toMatchObject(scripts);
  expect(lock.packages['']).toMatchObject({
    name: 'macwarden', version: '1.1.1', devDependencies: pinned,
  });
  expect(tsconfig.compilerOptions.strict).toBe(true);
});

it('CP-001/B11 records LF and binary paths and MIT licence', () => {
  const lines = read('.gitattributes').split(/\r?\n/);
  for (const line of [
    '* text=auto eol=lf', '*.macaroon binary',
    'test/vectors/** -text', 'test/scan-fixtures/** -text',
  ]) expect(lines).toContain(line);
  expect(read('LICENSE').startsWith('MIT License')).toBe(true);
});

it('CP-001/B12 runs the pinned CI matrix and commands', () => {
  const yaml = read('.github/workflows/ci.yml');
  const triggers = blockFor(yaml, 'on', 0);
  expect(triggers).toMatch(/^on:\n {2}push:\n {4}branches:/);
  expect(listFor(triggers, 'branches')).toEqual(['main']);
  expect(triggers).toMatch(/^ {2}pull_request:$/m);
  expect(triggers).toMatch(/^ {2}workflow_dispatch:$/m);
  expect(blockFor(yaml, 'permissions', 0)).toBe('permissions:\n  contents: read');

  const jobs = blockFor(yaml, 'jobs', 0);
  expect([...jobs.matchAll(/^ {2}([\w-]+):\s*$/gm)].map(match => match[1]))
    .toEqual(['test', 'oracle', 'gitleaks']);
  const testJob = blockFor(jobs, 'test', 2);
  const oracleJob = blockFor(jobs, 'oracle', 2);
  const gitleaksJob = blockFor(jobs, 'gitleaks', 2);
  expect(testJob).toMatch(/^ {4}runs-on: \$\{\{ matrix\.os \}\}$/m);
  // Every Node version on Linux; Windows on the minimum and the latest 22/24 line. macOS is not a
  // supported platform (README), so CI does not run it.
  expect(listFor(testJob, 'os')).toEqual(['ubuntu-latest']);
  expect([...testJob.matchAll(/^ {10}- \{ os: ([\w-]+), node: '([^']+)' \}$/gm)].map(m => `${m[1]} ${m[2]}`))
    .toEqual(['windows-latest 22.23.2', 'windows-latest 24.x']);
  expect(listFor(testJob, 'node')).toEqual(['22.23.2', '22.x', '24.18.1', '24.x']);
  expect(testJob).toMatch(/^ {10}node-version: \$\{\{ matrix\.node \}\}$/m);
  expect(oracleJob).toMatch(/^ {4}runs-on: ubuntu-latest$/m);
  expect(gitleaksJob).toMatch(/^ {4}runs-on: ubuntu-latest$/m);
  expect(oracleJob).toMatch(/^ {10}node-version: '22.23.2'$/m);
  expect(gitleaksJob).toMatch(/^ {10}node-version: '22.23.2'$/m);

  for (const job of [testJob, oracleJob, gitleaksJob]) {
    const uses = [...job.matchAll(/^\s*-?\s*uses:\s*(\S+)\s*$/gm)].map(match => match[1]);
    expect(uses).toEqual([
      'actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd',
      'actions/setup-node@a0853c24544627f65ddf259abe73b1d18a591444',
    ]);
    expect(job).toMatch(/^ {6}- uses: actions\/checkout@[^\r\n]+\n {8}with:\n {10}persist-credentials: false$/m);
    if (/^ {4}permissions:$/m.test(job)) {
      expect(blockFor(job, 'permissions', 4)).toBe('    permissions:\n      contents: read');
    }
  }
  const runsFor = (job: string) => [...job.matchAll(/^\s*-?\s*run:\s*(.+?)\s*$/gm)].map(match => match[1]);
  expect(runsFor(testJob)).toEqual(['npm ci', 'npm run lint', 'npm run build', 'npm test']);
  expect(runsFor(oracleJob)).toEqual(['npm ci', 'npm run build', 'npm run fixture:up', 'npm run test:oracle', 'npm run fixture:down']);
  expect(oracleJob).toMatch(/^ {6}- if: always\(\)\n {8}run: npm run fixture:down$/m);
  expect(runsFor(gitleaksJob)).toEqual(['npm ci', 'npm run build', '|', 'npm run test:gitleaks']);
  // The gitleaks tests run with private scratch and sentinel directories created inside the checkout.
  expect(gitleaksJob).toMatch(/^ {10}umask 077$/m);
  expect(gitleaksJob).toMatch(/MACWARDEN_TEST_TMP=\$\(mktemp -d "\$PWD\/\.ratchet\/packets\/gl-tmp-XXXXXX"\)/);
  expect(gitleaksJob).toMatch(/MACWARDEN_SENTINEL_DIR=\$\(mktemp -d "\$PWD\/\.ratchet\/packets\/gl-sent-XXXXXX"\)/);
});

it('CP-001/B13 restricts network imports to src/lnd and keeps runtime packages out of src', () => {
  const root = resolve('src');
  const files: string[] = [];
  function walk(dir: string): void {
    for (const entry of readdirSync(dir)) {
      const path = join(dir, entry);
      if (statSync(path).isDirectory()) walk(path);
      else if (/\.[cm]?tsx?$/.test(entry)) files.push(path);
    }
  }
  walk(root);
  expect(files.length).toBeGreaterThan(0);
  const forbidden = new Set(['node:http', 'node:https', 'node:net', 'node:tls', 'node:dns', 'node:dgram']);
  for (const file of files) {
    const sourcePath = relative(root, file).replace(/\\/g, '/');
    const source = readFileSync(file, 'utf8');
    const imports = [
      ...source.matchAll(/\bfrom\s*['"]([^'"]+)['"]/g),
      ...source.matchAll(/\bimport\s*(?:\(\s*)?['"]([^'"]+)['"]/g),
    ].map(match => match[1]);
    for (const specifier of imports) {
      if (!sourcePath.startsWith('lnd/')) {
        expect(forbidden.has(specifier), `${relative(root, file)} imports ${specifier}`).toBe(false);
      }
      expect(specifier.startsWith('.') || specifier.startsWith('node:'),
        `${relative(root, file)} imports package ${specifier}`).toBe(true);
    }
  }
});
