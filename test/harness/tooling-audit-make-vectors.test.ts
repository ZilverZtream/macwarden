import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { replaceDirectory } from '../../scripts/make-vectors.mjs';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture() {
  const root = mkdtempSync(join(process.env.MACWARDEN_TEST_TMP ?? tmpdir(), 'tooling-vectors-')); roots.push(root);
  const out = join(root, 'vectors'), stage = join(root, 'stage');
  mkdirSync(out); writeFileSync(join(out, 'manifest.json'), 'old');
  mkdirSync(stage); writeFileSync(join(stage, 'manifest.json'), 'new');
  return { root, out, stage };
}

// Audit TOOLING-13: make-vectors removed test/vectors and then renamed a staging directory from
// the OS temp directory into place; on another file system (tmpfs, WSL) the rename failed with
// EXDEV and left no vectors at all. The swap now moves the old directory aside first and puts it
// back if the new one cannot be renamed into place.
it('TOOLING-13 a successful swap replaces the vectors and leaves no copy behind', () => {
  const { root, out, stage } = fixture();
  replaceDirectory(stage, out);
  expect(readFileSync(join(out, 'manifest.json'), 'utf8')).toBe('new');
  expect(existsSync(stage)).toBe(false);
  expect(readFileSync(join(root, 'vectors', 'manifest.json'), 'utf8')).toBe('new');
  expect(existsSync(`${out}.previous-${process.pid}`)).toBe(false);
});

it('TOOLING-13 a failed swap keeps the existing vectors', () => {
  const { out, stage } = fixture();
  rmSync(stage, { recursive: true });
  expect(() => replaceDirectory(stage, out)).toThrow(/ENOENT/);
  expect(readFileSync(join(out, 'manifest.json'), 'utf8')).toBe('old');
});
