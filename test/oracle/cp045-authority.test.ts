import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import { childEnvironment } from '../helpers/environment.js';
import { docker, ids, lncli, probe, scenario } from '../helpers/cp038-live.js';
import { declare, register } from '../helpers/cp038-online.js';
import { noEcho } from '../support/cp041-controls.js';
const fp = (b: Buffer) => 'fp:' + createHash('sha256').update(b).digest('hex').slice(0,16);

it('CP-045/rotation-authority-live real accepted wrong-root and forged old files cannot silently stage; valid proof stages and finishes', async () => scenario(async f => {
  const oldPath = f.old.outPath!, nextPath = f.next.outPath!;
  expect(probe(oldPath)).toBe('accepted'); expect(probe(nextPath)).toBe('accepted');
  const remote = `/tmp/cp045-${process.pid}.macaroon`;
  if (docker(['cp', nextPath, 'lnd:' + remote]).status !== 0) throw new Error('Fixture reference copy failed');
  try {
    const printed = lncli(['printmacaroon', '--macaroon_file=' + remote]);
    expect(String(printed.root_key_id)).toBe(f.next.rootKeyId);
    expect(String(printed.root_key_id) === f.old.rootKeyId).toBe(false);
  } finally { docker(['exec','-T','lnd','rm','-f',remote]); }
  function run(flags: string[]) {
    const child = spawnSync(process.execPath, [resolve('dist/bin.js'), 'rotate', 'Alice', ...flags, ...f.flags, '--json'],
      { env: childEnvironment(), encoding: 'utf8', timeout: 30000 });
    for (const path of [oldPath, nextPath]) noEcho(child.stdout + child.stderr, readFileSync(path));
    expect(child.status !== null).toBe(true);
    return { code: child.status, doc: JSON.parse(child.stdout) as { error: { code: number; step: string } | null } };
  }
  f.old.outPath = nextPath; f.old.fingerprint = f.next.fingerprint; f.save([f.old]);
  const before = readFileSync(f.registry), state = ids();
  expect(run(['--out', f.out, '--dry-run']).code).toBe(3);
  expect(readFileSync(f.registry).equals(before)).toBe(true); expect(ids()).toEqual(state); expect(existsSync(f.out)).toBe(false);
  const bytes = Buffer.from(readFileSync(oldPath)); bytes[bytes.length-1] ^= 1;
  const forgedPath = register(bytes); declare(forgedPath);
  if (docker(['cp', forgedPath, 'lnd:' + remote]).status !== 0) throw new Error('Fixture forged copy failed');
  try {
    const check = docker(['exec','-T','lnd','lncli','--network=regtest','--macaroonpath=' + remote,'getinfo']);
    expect(check.status !== null && check.status !== 0 && /signature mismatch/i.test(check.stderr),
      'independent lncli rejects specifically the forged signature').toBe(true);
  } finally { docker(['exec','-T','lnd','rm','-f',remote]); }
  f.old.outPath = forgedPath; f.old.fingerprint = fp(bytes); f.save([f.old]);
  const forgedRegistry = readFileSync(f.registry);
  // Reference correction: independently rejected signature refuses at S8;
  // it cannot trigger recorded-permission fallback after S7 reservation.
  const forged = run(['--out', f.out]);
  expect(forged.code).toBe(5);
  expect(forged.doc.error).toMatchObject({ code: 5, step: 'S8' });
  expect(readFileSync(f.registry).equals(forgedRegistry)).toBe(true); expect(ids()).toEqual(state); expect(existsSync(f.out)).toBe(false);
  expect(existsSync(`${f.registry}.lock`)).toBe(false);
  expect(probe(oldPath)).toBe('accepted'); expect(probe(nextPath)).toBe('accepted');
  f.old.outPath = oldPath; f.old.fingerprint = fp(readFileSync(oldPath)); f.save([f.old]);
  expect(run(['--out', f.out]).code).toBe(0);
  expect(probe(oldPath)).toBe('accepted'); expect(probe(f.out)).toBe('accepted');
  expect(run(['--finish','--yes']).code).toBe(0);
  expect(probe(oldPath)).toBe('rejected'); expect(probe(f.out)).toBe('accepted');
}), 180000);

it('CP-045/rotation-dry-run live proof dry-run and unproven decline preserve IDs registry and output', async () => scenario(async f => {
  f.save([f.old]); const before = readFileSync(f.registry), state = ids(), old = readFileSync(f.old.outPath!);
  const dry = spawnSync(process.execPath, [resolve('dist/bin.js'), 'rotate','Alice','--out',f.out,'--dry-run',...f.flags,'--json'],
    { env: childEnvironment(), encoding: 'utf8', timeout: 30000 });
  noEcho(dry.stdout + dry.stderr, old); expect(dry.status).toBe(0);
  expect(ids()).toEqual(state); expect(readFileSync(f.registry).equals(before)).toBe(true);
  expect(readFileSync(f.old.outPath!).equals(old)).toBe(true); expect(existsSync(f.out)).toBe(false);
  f.old.outPath = null; f.save([f.old]); const unproven = readFileSync(f.registry);
  const decline = spawnSync(process.execPath, [resolve('dist/bin.js'),'rotate','Alice','--out',f.out,...f.flags,'--json'],
    { env: childEnvironment(), encoding: 'utf8', timeout: 30000 });
  noEcho(decline.stdout + decline.stderr, old); expect(decline.status).toBe(6);
  expect(ids()).toEqual(state); expect(readFileSync(f.registry).equals(unproven)).toBe(true); expect(existsSync(f.out)).toBe(false);
}), 180000);
