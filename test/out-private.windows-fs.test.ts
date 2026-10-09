import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { reserveOut } from '../src/commands/bake/write-out.js';
import { run as attenuate } from '../src/commands/attenuate.js';
import { run as respond } from '../src/commands/respond.js';
import { Secret } from '../src/secret.js';
import { childEnvironment } from './helpers/environment.js';
import { entry, fixture, oldId, ownId, root } from './helpers/cp038-online.js';
import { sddlTrustee } from './helpers/sddl.js';

// Real Windows proof for RO-1 and RO-2. The folder grants Everyone inheritable read and
// change-permissions (WRITE_DAC), the precondition under which a second principal could
// open the new file before 1.1.1 restricted it. Only synthetic bytes are written.
const systemRoot = process.env.SystemRoot!;
const icacls = join(systemRoot, 'System32', 'icacls.exe');
const powershell = join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
const SYNTHETIC = Buffer.from('SYNTHETIC-NOT-A-MACAROON-RO1');
const run = (file: string, args: string[]) => {
  const result = spawnSync(file, args, { encoding: 'utf8', timeout: 20_000, env: childEnvironment() });
  expect(result.error).toBeUndefined(); expect(result.status).toBe(0);
  return result.stdout;
};
const sid = run(join(systemRoot, 'System32', 'whoami.exe'), ['/user', '/fo', 'csv', '/nh']).trim().split(',').at(-1)!.replaceAll('"', '');
function sharedFolder(): string {
  const dir = mkdtempSync(join(root('MACWARDEN_TEST_TMP'), 'out-private-'));
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

// Polls the path with READ_CONTROL access, the access every holder of a handle has, and
// prints the DACL of the first object it can read: the earliest state another principal
// could observe. A file created under the folder's inherited ACL shows inherited entries.
const watcherScript = String.raw`
$path = $env:MACWARDEN_WATCH_PATH
[Console]::Out.WriteLine('WATCHING'); [Console]::Out.Flush()
$start = [Environment]::TickCount
while ([Environment]::TickCount - $start -lt 30000) {
  try { $sddl = [IO.File]::GetAccessControl($path, [Security.AccessControl.AccessControlSections]::Access).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access); [Console]::Out.WriteLine('FIRST ' + $sddl); exit 0 } catch { }
}
[Console]::Out.WriteLine('TIMEOUT'); exit 2
`;

it('RO-1/owner-only-from-creation the first DACL any process can observe on a new --out file is owner-only and protected', async () => {
  const dir = sharedFolder();
  try {
    const out = join(dir, 'app.macaroon');
    const watcher = spawn(powershell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
      Buffer.from(watcherScript, 'utf16le').toString('base64')], { env: { ...childEnvironment(), MACWARDEN_WATCH_PATH: out }, windowsHide: true });
    let output = '';
    const line = (prefix: RegExp) => new Promise<string>((done, fail) => {
      const check = () => { const match = output.split(/\r?\n/).find(item => prefix.test(item)); if (match) done(match); };
      watcher.stdout.on('data', chunk => { output += String(chunk); check(); });
      watcher.once('exit', () => { check(); fail(new Error(`watcher ended: ${output}`)); });
      check();
    });
    await line(/^WATCHING$/);
    const reserved = await reserveOut(out);
    await reserved.reservation.write(new Secret(SYNTHETIC));
    const first = (await line(/^(FIRST|TIMEOUT)/)).replace(/^FIRST /, '');
    expect(first).toMatch(/^D:P/);
    expect(aces(first)).toEqual([`(A;;FA;;;${sddlTrustee(sid)})`]);
    expect(reserved.aclWarning).toBe(false);
    const final = saved(out, dir);
    expect(final).toContain('D:P'); expect(aces(final)).toEqual([`(A;;FA;;;${sddlTrustee(sid)})`]);
    expect(readFileSync(out).equals(SYNTHETIC)).toBe(true);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}, 30_000);

it('RO-1/owner-only-from-creation an entry added before the bytes are written fails closed: removed, nothing written', async () => {
  const dir = sharedFolder();
  try {
    const out = join(dir, 'app.macaroon');
    const writes: unknown[] = [];
    let added = false;
    const wrapped = { ...fs, async open(...args: Parameters<typeof fs.open>) {
      // macwarden's exclusive open: an account that could change the DACL adds itself now.
      if (!added && args[0] === out && typeof args[1] === 'number') { added = true; run(icacls, [out, '/grant', '*S-1-1-0:(R)']); }
      const handle = await fs.open(...args);
      const write = handle.writeFile.bind(handle);
      return Object.assign(handle, { writeFile: (data: Uint8Array) => { writes.push(data); return write(data); } });
    } } as typeof fs;
    await expect(reserveOut(out, wrapped)).rejects.toThrow(/did not keep owner-only permissions/);
    expect(added).toBe(true); expect(writes).toEqual([]); expect(existsSync(out)).toBe(false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}, 30_000);

it('RO-2/windows-names normalised, device and stream names are refused end to end; nothing else is touched', async () => {
  const dir = sharedFolder();
  try {
    writeFileSync(join(dir, 'app.macaroon'), 'older file');
    writeFileSync(join(dir, 'notes.txt'), 'existing unrelated file');
    const before = { sibling: saved(join(dir, 'app.macaroon'), dir), notes: saved(join(dir, 'notes.txt'), dir) };
    for (const name of ['app.macaroon.', 'app.macaroon ', 'NUL', 'con.macaroon', 'notes.txt:app.macaroon']) {
      const result = await attenuate([resolve('test/vectors/default-readonly.macaroon'), '--out', join(dir, name), '--expires', '1h'],
        { stdin: process.stdin, fs, env: {}, clock: () => new Date() });
      expect(result.error, name).toMatchObject({ code: 3, step: 'A3' });
    }
    expect(readdirSync(dir).sort()).toEqual(['app.macaroon', 'notes.txt']);
    expect(existsSync(join(dir, 'notes.txt:app.macaroon'))).toBe(false);
    expect(readFileSync(join(dir, 'app.macaroon'), 'utf8')).toBe('older file');
    expect(readFileSync(join(dir, 'notes.txt'), 'utf8')).toBe('existing unrelated file');
    expect(saved(join(dir, 'app.macaroon'), dir)).toBe(before.sibling);
    expect(saved(join(dir, 'notes.txt'), dir)).toBe(before.notes);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}, 30_000);

it('RO-2/windows-names respond refuses a label that names a Windows device before staging any replacement', async () => {
  const f = fixture();
  f.save([f.old, entry(4294967400n, 'CON')]);
  f.lnd.ids = [0n, ownId, oldId, 4294967400n];
  const outDir = join(f.dir, 'replacements');
  const result = await respond(['--out-dir', outDir, '--yes', ...f.flags], f.deps);
  expect(result.error).toMatchObject({ code: 3, step: 'P6' });
  expect(result.error!.message).toMatch(/reserved Windows device name/);
  expect(f.lnd.calls.filter(call => call === 'BakeMacaroon')).toEqual([]);
  expect(existsSync(outDir)).toBe(false);
});
