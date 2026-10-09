import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterAll, expect, it } from 'vitest';
import { childEnvironment } from './helpers/environment.js';

// A pre-commit hook runs from the repository root and passes the staged file names.
// The documented hook passes --ignore-file .macwardenignore explicitly; parent
// directories are never searched, so no unnamed file can suppress a finding.
const repo = resolve();
const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string }[] };
const fingerprint = (name: string) => manifest.vectors.find(item => item.name === name)!.fingerprint;
const root = mkdtempSync(join(process.env.MACWARDEN_TEST_TMP ?? tmpdir(), 'pre-commit-'));
afterAll(() => rmSync(root, { recursive: true, force: true }));

function project(ignore: string | null) {
  const dir = mkdtempSync(join(root, 'p-'));
  mkdirSync(join(dir, '.git'));
  mkdirSync(join(dir, 'config', 'app'), { recursive: true });
  copyFileSync(join(repo, 'test/vectors/default-readonly.macaroon'), join(dir, 'config', 'app', 'readonly.macaroon'));
  copyFileSync(join(repo, 'test/vectors/default-invoice.macaroon'), join(dir, 'config', 'invoice.macaroon'));
  if (ignore !== null) writeFileSync(join(dir, '.macwardenignore'), ignore);
  return dir;
}

function scan(cwd: string, args: string[]) {
  const run = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'scan', '--json', ...args],
    { cwd, env: childEnvironment(), encoding: 'utf8', timeout: 30_000, windowsHide: true });
  return { status: run.status, result: JSON.parse(run.stdout).result as {
    findings: { fingerprint: string }[]; summary: { ignored: number } } | null };
}

it('UX/pre-commit-ignore staged file names honour the root ignore file named with --ignore-file', () => {
  const dir = project(`${fingerprint('default-readonly')} config/app/*.macaroon\n`);
  const files = ['config/app/readonly.macaroon', 'config/invoice.macaroon'];
  const hooked = scan(dir, ['--fail-on', 'READ', '--ignore-file', '.macwardenignore', ...files]);
  expect(hooked.status).toBe(1);
  expect(hooked.result!.summary.ignored).toBe(1);
  expect(hooked.result!.findings.map(item => item.fingerprint)).toEqual([fingerprint('default-invoice')]);
});

it('UX/pre-commit-ignore a parent .macwardenignore is never applied without --ignore-file', () => {
  const dir = project(`${fingerprint('default-readonly')}\n${fingerprint('default-invoice')}\n`);
  const plain = scan(dir, ['--fail-on', 'READ', 'config/app/readonly.macaroon', 'config']);
  expect(plain.status).toBe(1);
  expect(plain.result!.summary.ignored).toBe(0);
});

it('UX/pre-commit-ignore the shipped hook definition uses the explicit ignore file', () => {
  const hooks = readFileSync(join(repo, '.pre-commit-hooks.yaml'), 'utf8');
  expect(hooks).toMatch(/^- id: macwarden-scan$/m);
  expect(hooks).toMatch(/^ {2}entry: macwarden scan --fail-on READ --ignore-file \.macwardenignore$/m);
  expect(hooks).toMatch(/^ {2}pass_filenames: true$/m);
});
