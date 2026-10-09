import { fixtureTopology } from '../fixture/topology.mjs';
import { existsSync, readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import { scenario, ids, probe, docker, lncli } from '../helpers/cp038-live.js';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { childEnvironment } from '../helpers/environment.js';
import * as fs from 'node:fs/promises';
import { run as revoke } from '../../src/commands/revoke.js';
import { run as rotate } from '../../src/commands/rotate.js';
import { createLndAdapter } from '../../src/lnd/index.js';
import { deadProductLock } from '../helpers/cp042-lock-process.js';
import { Secret } from '../../src/secret.js';

function cli(f: Parameters<Parameters<typeof scenario>[0]>[0], command: string, args: string[]) {
  return spawnSync(process.execPath, [resolve('dist/bin.js'), command, ...args, ...f.flags, '--json'],
    { env: childEnvironment(), encoding: 'utf8', timeout: 20_000, windowsHide: true });
}
it('CP-042/recovery-dry-run-unchanged fallback rotation and absent-ID recovery preserve independent state', async () => scenario(async f => {
  const oldCopy = f.old.outPath!; f.old.outPath = null; f.save([f.old]);
  const before = readFileSync(f.registry), keys = ids();
  // SPEC V7: an absent unregistered ID has nothing to revoke, so its dry-run exits 5.
  for (const [command, args, status] of [['rotate', ['Alice', '--out', f.out, '--dry-run'], 0], ['revoke', ['912042', '--unregistered', '--dry-run'], 5]] as const) {
    const result = cli(f, command, [...args]); expect(result.status).toBe(status);
    expect(readFileSync(f.registry).equals(before)).toBe(true); expect(ids()).toEqual(keys);
    expect(existsSync(f.out)).toBe(false); expect(existsSync(f.registry + '.lock')).toBe(false);
  }
  expect(probe(oldCopy)).toBe('accepted');
}), 60_000);
it('CP-042/rotation-approval-live missing approval creates no key and explicit informed approval preserves old acceptance', async () => scenario(async f => {
  const oldCopy = f.old.outPath!; f.old.outPath = null; f.save([f.old]);
  const before = readFileSync(f.registry), keys = ids();
  const refused = cli(f, 'rotate', ['Alice', '--out', f.out]); expect(refused.status).toBe(6);
  expect(ids()).toEqual(keys); expect(readFileSync(f.registry).equals(before)).toBe(true);
  const cert = f.flags[f.flags.indexOf('--tls-cert') + 1]!;
  const lnd = createLndAdapter({ restUrl: `https://localhost:${fixtureTopology().restPort}`, tlsCert: readFileSync(cert), macaroon: new Secret(readFileSync(f.flags[f.flags.indexOf('--macaroon') + 1]!)) });
  let displayed = false;
  const prompt = Object.assign(async (question: string) => {
    expect(question).toContain(f.old.grade); for (const permission of f.old.permissions) expect(question).toContain(permission);
    expect(existsSync(f.out)).toBe(false); expect(existsSync(f.registry + '.lock')).toBe(false); expect(ids()).toEqual(keys);
    displayed = true; return 'Alice';
  }, { isTTY: true });
  if (process.platform === 'linux') {
    // util-linux script supplies an actual terminal to the built CLI. Windows
    // uses the explicitly injected prompt above; native terminal proof is separate.
    const args = [process.execPath, resolve('dist/bin.js'), 'rotate', 'Alice', '--out', f.out, ...f.flags, '--json'];
    const shellQuote = (value: string) => "'" + value.replaceAll("'", "'\"'\"'") + "'";
    const terminal = spawnSync('script', ['--quiet', '--return', '--command', args.map(shellQuote).join(' '), '/dev/null'],
      { env: childEnvironment(), input: 'Alice\n', encoding: 'utf8', timeout: 20_000 });
    expect(terminal.status).toBe(0);
    for (const value of [f.old.grade, ...f.old.permissions]) expect(terminal.stdout).toContain(value);
    expect(terminal.stdout).toMatch(/unproven|cannot|unable|not.*prov/i);
  } else {
    const staged = await rotate(['Alice', '--out', f.out, ...f.flags], { ...f.deps, lnd, prompt, env: {}, clock: () => new Date() });
    expect(displayed).toBe(true); expect(staged.error).toBeNull();
  } expect(probe(oldCopy)).toBe('accepted'); expect(probe(f.out)).toBe('accepted');
  const remote = `/tmp/cp042-print-${process.pid}.macaroon`;
  expect(docker(['cp', f.out, 'lnd:' + remote]).status).toBe(0);
  try { expect(lncli(['printmacaroon', '--macaroon_file=' + remote]).permissions).toEqual(f.old.permissions); }
  finally { expect(docker(['exec', '-T', 'lnd', 'rm', '-f', remote]).status).toBe(0); }
  const finished = cli(f, 'rotate', ['Alice', '--finish', '--yes']); expect(finished.status).toBe(0);
  expect(probe(oldCopy)).toBe('rejected'); expect(probe(f.out)).toBe('accepted');
}), 60_000);
it('CP-042/unregistered-repair-live completed real delete and failed save prints no rerun and a rerun has nothing to revoke', async () => scenario(async f => {
  const oldCopy = f.old.outPath!, target = f.old.rootKeyId; f.save([]);
  const cert = f.flags[f.flags.indexOf('--tls-cert') + 1]!;
  const lnd = createLndAdapter({ restUrl: `https://localhost:${fixtureTopology().restPort}`, tlsCert: readFileSync(cert), macaroon: new Secret(readFileSync(f.flags[f.flags.indexOf('--macaroon') + 1]!)) });
  let mutations = 0;
  const original = lnd.deleteMacaroonId.bind(lnd);
  lnd.deleteMacaroonId = async id => { mutations++; return original(id); };
  const broken = { ...fs, rename: async (...args: Parameters<typeof fs.rename>) => {
    if (String(args[1]) === f.registry) throw Object.assign(new Error('injected save failure'), { code: 'EIO' });
    return fs.rename(...args);
  } };
  const failed = await revoke([target, '--unregistered', '--yes', ...f.flags], { ...f.deps, lnd, fs: broken });
  expect(failed.error).toMatchObject({ code: 7, step: 'V13' }); expect(mutations).toBe(1);
  expect(ids()).not.toContain(target); expect(probe(oldCopy)).toBe('rejected');
  // SPEC V7: nothing remains to revoke, so no rerun command is printed.
  expect(failed.error!.message).not.toMatch(/macwarden revoke/); expect(failed.error!.message).toMatch(/no further action/i);
  const keys = ids(), before = readFileSync(f.registry);
  for (const extra of [['--dry-run'], [], ['--yes']]) {
    const checked = cli(f, 'revoke', [target, '--unregistered', ...extra]); expect(checked.status).toBe(5);
    expect(ids()).toEqual(keys); expect(readFileSync(f.registry).equals(before)).toBe(true);
  }
  expect(mutations).toBe(1); expect(f.rows()).toEqual([]);
}), 60_000);

it('CP-042/stale-lock-process-filesystem actual exited owner is recovered through the built CLI without test unlink', async () => scenario(async f => {
  await deadProductLock(f.registry);
  const result = cli(f, 'revoke', ['Alice', '--yes', '--break-lock']); expect(result.status).toBe(0);
  expect(existsSync(f.registry + '.lock')).toBe(false); expect(ids()).not.toContain(f.old.rootKeyId);
  expect(probe(f.old.outPath!)).toBe('rejected'); expect(probe(f.next.outPath!)).toBe('accepted');
}), 60_000);
