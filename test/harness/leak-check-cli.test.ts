import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { childEnvironment } from '../helpers/environment.js';

// The standalone leak check (scripts/leak-check.mjs), which full validation and the
// leak tests rely on, run against a private disposable project.
const repo = resolve();
const sentinel = () => readFileSync(join(repo, 'test', 'sentinels', 'sentinel.macaroon'));
function put(path: string, data: string | Buffer): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, data);
}
function project(work: (root: string) => void): void {
  const base = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
  mkdirSync(base, { recursive: true });
  const root = mkdtempSync(join(base, 'leak-check-cli-'));
  try { work(root); } finally { rmSync(root, { recursive: true, force: true }); }
}
const leakCheck = (root: string, list: string, ...paths: string[]) => spawnSync(process.execPath,
  [join(repo, 'scripts', 'leak-check.mjs'), '--sentinels', list, ...paths],
  { cwd: root, encoding: 'utf8', timeout: 15_000, env: childEnvironment({ MACWARDEN_TEST_TMP: root }) });

it('CP-002/B11 standalone leak check excludes a declared output file', () => project(root => {
  const source = sentinel();
  const declaredPath = join(root, 'declared', 'out.macaroon');
  const sentinelList = join(root, 'test', 'sentinels.json');
  put(join(root, 'test', 'private', 'sentinel.bin'), source);
  put(sentinelList, JSON.stringify(['test/private/*.bin']));
  put(declaredPath, source.toString('hex'));
  expect(leakCheck(root, sentinelList, declaredPath).status).toBe(1);
  put(join(root, 'declared-out.txt'), declaredPath + '\n');
  expect(leakCheck(root, sentinelList, declaredPath).status).toBe(0);
}), 90_000);

it('LEAK/declared-hash an output declared by the SHA-256 of its path is excluded; a wrong hash is not', () => project(root => {
  // Tests of path redaction create files whose names hold a credential; they declare them by hash
  // so the declared-output manifest itself never carries the credential.
  const source = sentinel();
  const declaredPath = join(root, 'declared', `cfg-${source.toString('base64url').slice(0, 20)}.env`);
  const sentinelList = join(root, 'test', 'sentinels.json');
  put(join(root, 'test', 'private', 'sentinel.bin'), source);
  put(sentinelList, JSON.stringify(['test/private/*.bin']));
  put(declaredPath, source.toString('hex'));
  const hash = (path: string) => createHash('sha256').update(resolve(path), 'utf8').digest('hex');
  put(join(root, 'declared-out.txt'), `sha256:${hash(join(root, 'declared', 'other.env'))}\n`);
  expect(leakCheck(root, sentinelList, declaredPath).status).toBe(1);
  put(join(root, 'declared-out.txt'), `sha256:${hash(declaredPath)}\n`);
  expect(leakCheck(root, sentinelList, declaredPath).status).toBe(0);
  expect(readFileSync(join(root, 'declared-out.txt'), 'utf8')).not.toContain(source.toString('base64url').slice(0, 20));
}), 90_000);

it('CP-036/bootstrap-negative-controls an empty sentinel registration fails the standalone leak check', () => project(root => {
  const list = join(root, 'sentinels.json');
  put(list, '[]');
  const run = leakCheck(root, list, root);
  expect(run.status).toBe(1);
  expect((run.stdout || '') + (run.stderr || '')).not.toContain(sentinel().toString('base64'));
}), 30_000);
