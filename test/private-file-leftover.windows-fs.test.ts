// 1.2.1: the Windows owner-only helper created the file but its reply was unusable (CREATED with
// malformed JSON or an invalid SID) or it exited without one (killed by its 20 s timeout). Before,
// reserveOwnerOnly failed and left the empty file behind, so the next run refused the path with
// "output file already exists". Now the file the helper evidently created (absent before the call,
// a regular empty file after) is removed; anything that existed before, or holds data, is kept.
// Windows variant (scripts/platform-variants.mjs): the helper exists only there.
import { EventEmitter } from 'node:events';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { PassThrough } from 'node:stream';
import { expect, it, vi } from 'vitest';

type Plan = { lines: string[]; create?: string };
let plan: (path: string) => Plan = () => ({ lines: [] });

vi.mock('node:child_process', async original => {
  const real = await original<typeof import('node:child_process')>();
  return { ...real, execFile: (_exe: string, _args: string[], options: { env: Record<string, string> },
    callback: (error: unknown, stdout: string) => void) => {
    const child = new EventEmitter() as EventEmitter & { stdout: PassThrough; stdin: PassThrough };
    child.stdout = new PassThrough(); child.stdin = new PassThrough();
    const steps = plan(options.env.MACWARDEN_PRIVATE_OUT);
    setTimeout(() => {
      if (steps.create !== undefined) writeFileSync(options.env.MACWARDEN_PRIVATE_OUT, steps.create);
      let all = '';
      for (const line of steps.lines) { all += `${line}\n`; child.stdout.write(`${line}\n`); }
      const finish = () => setTimeout(() => callback(steps.lines.length ? null : new Error('timed out'), all), 5);
      if (steps.lines.some(line => line.startsWith('CREATED '))) child.stdin.on('finish', finish); else finish();
    }, 5);
    return child;
  } };
});

const { reserveOwnerOnly, PrivateFileError } = await import('../src/private-file.js');

const dir = () => {
  const root = process.env.MACWARDEN_TEST_TMP ?? join(resolve(), 'test/.tmp');
  mkdirSync(root, { recursive: true });
  return mkdtempSync(join(root, 'private-leftover-'));
};

const failures: Array<[string, Plan]> = [
  ['CREATED with malformed JSON', { create: '', lines: ['CREATED {"sid":"S-1-5-21-1'] }],
  ['CREATED with an invalid SID', { create: '', lines: ['CREATED {"sid":"bogus","noAcl":false}'] }],
  ['created, then exited without a reply', { create: '', lines: [] }],
];

for (const [name, steps] of failures) {
  it(`the helper's empty file is removed when ${name}`, async () => {
    const path = join(dir(), 'out.macaroon');
    plan = () => steps;
    await expect(reserveOwnerOnly(path)).rejects.toBeInstanceOf(PrivateFileError);
    expect(existsSync(path), 'empty file the helper created').toBe(false);
  });
}

it('a file that existed before the call is never removed', async () => {
  const path = join(dir(), 'out.macaroon');
  writeFileSync(path, '');
  plan = () => ({ lines: ['CREATED {"sid":"bogus"}'] });
  await expect(reserveOwnerOnly(path)).rejects.toBeInstanceOf(PrivateFileError);
  expect(existsSync(path)).toBe(true);
});

it('a file that holds data is never removed', async () => {
  const path = join(dir(), 'out.macaroon');
  plan = () => ({ create: 'not ours', lines: [] });
  await expect(reserveOwnerOnly(path)).rejects.toBeInstanceOf(PrivateFileError);
  expect(readFileSync(path, 'utf8')).toBe('not ours');
});
