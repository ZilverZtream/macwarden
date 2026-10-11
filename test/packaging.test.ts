import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterAll, expect, it } from 'vitest';

const repo = resolve();
const pkg = JSON.parse(readFileSync(join(repo, 'package.json'), 'utf8')) as {
  name: string; version: string; description?: string; keywords?: string[]; homepage?: string;
  bugs?: { url?: string }; repository?: { type?: string; url?: string }; files: string[] };
const workflow = readFileSync(join(repo, '.github/workflows/release.yml'), 'utf8');
const scratch = mkdtempSync(join(process.env.MACWARDEN_TEST_TMP ?? tmpdir(), 'packaging-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

// npm provenance and trusted publishing compare repository.url with the GitHub repository
// that runs the workflow; the README links the same repository.
it('UX/packaging package metadata names the GitHub repository npm provenance checks', () => {
  expect(pkg.repository).toEqual({ type: 'git', url: 'git+https://github.com/ZilverZtream/macwarden.git' });
  expect(pkg.homepage).toBe('https://github.com/ZilverZtream/macwarden#readme');
  expect(pkg.bugs?.url).toBe('https://github.com/ZilverZtream/macwarden/issues');
  expect(pkg.description?.length).toBeGreaterThan(20);
  expect(pkg.keywords).toEqual(expect.arrayContaining(['lightning', 'lnd', 'macaroon']));
  expect(readFileSync(join(repo, 'README.md'), 'utf8')).toContain('https://github.com/ZilverZtream/macwarden');
});

it('UX/packaging the release job uses Node 22.14 or later and npm 11.5.1 or later', () => {
  const node = /node-version:\s*'(\d+)\.(\d+)\.(\d+)'/.exec(workflow);
  expect(node).not.toBeNull();
  const [major, minor] = [Number(node![1]), Number(node![2])];
  expect(major > 22 || (major === 22 && minor >= 14)).toBe(true);
  const npm = /npm install --global npm@(\d+)\.(\d+)\.(\d+)/.exec(workflow);
  expect(npm).not.toBeNull();
  const [a, b, c] = [Number(npm![1]), Number(npm![2]), Number(npm![3])];
  expect(a > 11 || (a === 11 && (b > 5 || (b === 5 && c >= 1)))).toBe(true);
  expect(workflow.indexOf('npm install --global npm@')).toBeLessThan(workflow.indexOf('npm publish'));
});

/** The `run: |` block of the publish job's `- name: Publish` step (the verify job's Pack step also runs a block). */
function publishScript(): string {
  const lines = workflow.split(/\r?\n/);
  const step = lines.findIndex(line => /^\s+- name: Publish$/.test(line));
  expect(step).toBeGreaterThan(-1);
  const start = lines.findIndex((line, index) => index > step && /^\s+run: \|$/.test(line));
  const indent = /^(\s*)/.exec(lines[start + 1])![1];
  const body: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (!line.startsWith(indent)) break;
    body.push(line.slice(indent.length));
  }
  expect(body.join('\n')).toContain('npm publish');
  return body.join('\n');
}

/**
 * Runs the Publish step's script as the publish job does: the verify job's tarball downloaded to
 * package/<tarball>, its name and SHA-256 passed in TARBALL and SHA256. `digest` overrides the
 * SHA-256 the verify job reported.
 */
function publish(version: string, ref: string, digest?: string): { status: number | null; args: string } {
  const dir = mkdtempSync(join(scratch, 'pub-'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'x', version }));
  mkdirSync(join(dir, 'bin'));
  // A stub npm records its arguments instead of publishing.
  writeFileSync(join(dir, 'bin', 'npm'), '#!/usr/bin/env bash\necho "$@" > npm-args\n');
  chmodSync(join(dir, 'bin', 'npm'), 0o755);
  const tarball = `x-${version}.tgz`;
  const bytes = Buffer.from(`synthetic tarball ${version}`);
  mkdirSync(join(dir, 'package'));
  writeFileSync(join(dir, 'package', tarball), bytes);
  writeFileSync(join(dir, 'publish.sh'), `set -euo pipefail\nexport PATH="$PWD/bin:$PATH"\n${publishScript()}\n`);
  const run = spawnSync('bash', ['publish.sh'], { cwd: dir, encoding: 'utf8',
    env: { ...process.env, GITHUB_REF_NAME: ref, TARBALL: tarball, SHA256: digest ?? createHash('sha256').update(bytes).digest('hex') },
    timeout: 30_000, windowsHide: true });
  let args = '';
  try { args = readFileSync(join(dir, 'npm-args'), 'utf8').trim(); } catch { /* not published */ }
  return { status: run.status, args };
}

it('UX/packaging a prerelease is published to the next dist-tag and a release to latest', () => {
  expect(publish('1.0.0-rc.1', 'v1.0.0-rc.1')).toEqual({ status: 0,
    args: 'publish --provenance --tag next --ignore-scripts ./package/x-1.0.0-rc.1.tgz' });
  expect(publish('1.0.0', 'v1.0.0')).toEqual({ status: 0, args: 'publish --provenance --tag latest --ignore-scripts ./package/x-1.0.0.tgz' });
});

it('UX/packaging a tarball whose SHA-256 differs from the one the verify job packed publishes nothing', () => {
  const result = publish('1.0.0', 'v1.0.0', '0'.repeat(64));
  expect(result.status).not.toBe(0);
  expect(result.args).toBe('');
});

it('UX/packaging the publish job checks that the tagged commit is on main before it publishes', () => {
  const job = workflow.slice(workflow.indexOf('\n  publish:\n'));
  expect(job).toMatch(/^ {10}fetch-depth: 0$/m);
  const ancestry = job.indexOf('run: git merge-base --is-ancestor "$GITHUB_SHA" origin/main');
  expect(ancestry).toBeGreaterThan(-1);
  expect(ancestry).toBeLessThan(job.indexOf('- name: Publish'));
});

it('UX/packaging a tag that does not match package.json publishes nothing', () => {
  const result = publish('1.0.0', 'v1.0.1');
  expect(result.status).not.toBe(0);
  expect(result.args).toBe('');
});
