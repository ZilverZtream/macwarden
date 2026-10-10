import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { openRegistry } from '../src/registry/index.js';
import { ensureCanaryConfig } from '../src/watch/canary.js';
import { JournalError } from '../src/watch/payment-journal.js';
import { UsageStore, writeUsage } from '../src/watch/usage.js';
import { childEnvironment } from './helpers/environment.js';
import { root } from './helpers/cp038-online.js';
import { openJournal } from './helpers/payment-journal.js';
import { sddlTrustee } from './helpers/sddl.js';

// Audit 1.2.1: the registry, the usage file, the canary configuration and the payment journal
// relied on mode 0600, which Windows does not implement. The folder grants Everyone inheritable
// read and change-permissions; every sidecar written into it must still be owner-only.
const systemRoot = process.env.SystemRoot!;
const icacls = join(systemRoot, 'System32', 'icacls.exe');
const run = (file: string, args: string[]) => {
  const result = spawnSync(file, args, { encoding: 'utf8', timeout: 20_000, env: childEnvironment() });
  expect(result.error).toBeUndefined(); expect(result.status).toBe(0);
  return result.stdout;
};
const sid = run(join(systemRoot, 'System32', 'whoami.exe'), ['/user', '/fo', 'csv', '/nh']).trim().split(',').at(-1)!.replaceAll('"', '');
function sharedFolder(): string {
  const dir = mkdtempSync(join(root('MACWARDEN_TEST_TMP'), 'sidecar-private-'));
  run(icacls, [dir, '/grant', '*S-1-1-0:(OI)(CI)(RX,WDAC)']);
  return dir;
}
const saved = (path: string, dir: string) => {
  const file = join(dir, `acl-${Math.random().toString(16).slice(2)}.txt`);
  run(icacls, [path, '/save', file]);
  const text = readFileSync(file).toString('utf16le'); rmSync(file);
  return text;
};
const aces = (sddl: string) => sddl.match(/\([^)]*\)/g) ?? [];
const ownerOnly = (path: string, dir: string) => {
  const sddl = saved(path, dir);
  expect(sddl, path).toContain('D:P');
  expect(aces(sddl), path).toEqual([`(A;;FA;;;${sddlTrustee(sid)})`]);
};

it('SIDECAR/owner-only the usage file, the registry and the canary configuration are owner-only in a shared folder', async () => {
  const dir = sharedFolder();
  try {
    const registry = join(dir, 'registry.json');
    const view = await openRegistry(registry, { fs });
    await view.lock();
    try { await view.save(); } finally { await view.unlock(); }
    ownerOnly(registry, dir);
    const store = new UsageStore();
    store.record(`02${'ab'.repeat(32)}`, 'id:0123456789abcdef', '5', '/lnrpc.Lightning/GetInfo', new Date());
    const usage = `${registry}.usage.json`;
    await writeUsage(usage, store, fs);
    ownerOnly(usage, dir);
    // A replacement keeps it: the rename carries the temp file's protected DACL.
    store.record(`02${'ab'.repeat(32)}`, 'id:0123456789abcdef', '5', '/lnrpc.Lightning/GetInfo', new Date());
    await writeUsage(usage, store, fs);
    ownerOnly(usage, dir);
    const canary = `${registry}.canary.json`;
    await ensureCanaryConfig(canary);
    ownerOnly(canary, dir);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}, 60_000);

it('SIDECAR/owner-only a new payment journal is owner-only; an existing one another account can read is refused with the fix', async () => {
  const dir = sharedFolder();
  try {
    const path = join(dir, 'payments.journal');
    const journal = await openJournal(path);
    await journal.close();
    ownerOnly(path, dir);
    // Reopened: still owner-only, accepted.
    const again = await openJournal(path);
    await again.close();
    ownerOnly(path, dir);
    // A journal written by an earlier version inherits the folder's permissions (Everyone can read it).
    const exposed = join(dir, 'exposed.journal');
    writeFileSync(exposed, readFileSync(path));
    expect(saved(exposed, dir)).toMatch(/;WD\)|S-1-1-0/); // Everyone, inherited from the folder
    await expect(openJournal(exposed)).rejects.toThrow(JournalError);
    await expect(openJournal(exposed)).rejects.toThrow(/owner-only.*icacls/s);
    expect(existsSync(`${exposed}.lock`)).toBe(false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}, 60_000);
