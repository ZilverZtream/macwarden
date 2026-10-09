import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as realFs from 'node:fs/promises';
import { EventEmitter } from 'node:events';
import { tmpdir } from 'node:os';
import { join, win32 } from 'node:path';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

// The Windows reservation runs one fixed System32 PowerShell helper. It creates the file
// with an owner-only security descriptor and reports the SID and ACL it read back, then,
// once macwarden holds the exclusive handle, reports the owner and ACL of the object at
// the path. This fake helper plays both replies from the scenario the test sets.
type Acl = { owner: string | null; protected: boolean; rules: { sid: string; allow: boolean; inherited: boolean; rights: number }[] } | null;
type Scenario = { create: boolean; sid?: unknown; noAcl?: boolean; created?: Acl; found?: Acl; raw?: string };
type Call = { file: string; args: string[]; options: { shell?: boolean; env?: Record<string, string> } };
const control = vi.hoisted(() => ({ calls: [] as Call[], verifies: 0, scenario: { create: true } as Scenario }));
vi.mock('node:child_process', async importOriginal => {
  const real = await importOriginal<typeof import('node:child_process')>();
  return { ...real, execFile: (file: string, args: string[], options: Call['options'],
    callback: (error: Error | null, stdout: string, stderr: string) => void) => {
    control.calls.push({ file, args: [...args], options });
    const scenario = control.scenario;
    const stdout = new EventEmitter();
    let output = ''; let ended = false;
    const emit = (line: string) => { output += line + '\n'; stdout.emit('data', line + '\n'); };
    const finish = (error: Error | null) => { if (!ended) { ended = true; queueMicrotask(() => callback(error, output, '')); } };
    const stdin = Object.assign(new EventEmitter(), {
      write(data: string) {
        if (data === 'verify\n') { control.verifies++; queueMicrotask(() => { emit('VERIFIED ' + JSON.stringify({ acl: scenario.found ?? null })); finish(null); }); }
        return true;
      },
      end() { finish(null); },
    });
    queueMicrotask(() => {
      if (!scenario.create) { emit('FAILED'); finish(new Error('helper failed')); return; }
      writeFileSync(options.env!.MACWARDEN_PRIVATE_OUT, '', { flag: 'wx' });
      emit(scenario.raw ?? 'CREATED ' + JSON.stringify({ sid: 'sid' in scenario ? scenario.sid : sid, noAcl: scenario.noAcl ?? false, acl: scenario.created ?? null }));
    });
    return { stdout, stdin };
  } };
});
import { reserveOut } from '../src/commands/bake/write-out.js';
import { Secret } from '../src/secret.js';

const systemRoot = 'C:\\Windows';
const powershell = win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
const sid = 'S-1-12-1-1234567890-987654321-1122334455-667788990';
const other = 'S-1-5-21-1111111111-2222222222-3333333333-1001';
const mine = (owner = sid): Acl => ({ owner, protected: true, rules: [{ sid, allow: true, inherited: false, rights: 2032127 }] });
const platform = Object.getOwnPropertyDescriptor(process, 'platform')!;
const saved = { SystemRoot: process.env.SystemRoot };
let dir: string;

beforeEach(() => {
  Object.defineProperty(process, 'platform', { ...platform, value: 'win32' });
  process.env.SystemRoot = systemRoot;
  control.calls.length = 0; control.verifies = 0; control.scenario = { create: true, created: mine(), found: mine() };
  dir = mkdtempSync(join(tmpdir(), 'mw-acl-'));
});
afterEach(() => {
  Object.defineProperty(process, 'platform', platform);
  for (const [key, value] of Object.entries(saved)) if (value === undefined) delete process.env[key]; else process.env[key] = value;
  rmSync(dir, { recursive: true, force: true });
});

it('CP-023/acl-sid the System32 helper creates the file owner-only for the SID it reports; nothing else runs', async () => {
  const out = join(dir, 'out.macaroon');
  const reserved = await reserveOut(out);
  expect(reserved.aclWarning).toBe(false);
  await reserved.reservation.write(new Secret(Buffer.from('synthetic test bytes')));
  expect(readFileSync(out, 'utf8')).toBe('synthetic test bytes');
  expect(control.calls.map(call => call.file)).toEqual([powershell]);
  expect(control.calls[0].options).toMatchObject({ shell: false });
  // The path reaches the helper only through its environment, never through its command line.
  expect(control.calls[0].options.env?.MACWARDEN_PRIVATE_OUT).toBe(out);
  expect(control.calls[0].args.join(' ')).not.toContain(out);
  expect(control.verifies).toBe(1);
});

it.each([['a malformed SID', { sid: 'S-1-5-21-x' }], ['no SID', { sid: null }], ['a non-JSON reply', { raw: 'CREATED {' }],
  ['a helper failure', { create: false }]] as const)(
  'CP-023/acl-sid %s fails closed without writing', async (_name, scenario) => {
    control.scenario = { ...control.scenario, ...scenario };
    const out = join(dir, 'out.macaroon');
    await expect(reserveOut(out)).rejects.toThrow(/owner-only permissions/);
    // Nothing was written; a file the helper may have created stays empty.
    expect(existsSync(out) ? readFileSync(out).length : 0).toBe(0);
    expect(control.calls).toHaveLength(1);
  });

it('CP-023/acl-sid warns acl-best-effort only on a volume that stores no permissions, without a verification', async () => {
  control.scenario = { create: true, noAcl: true, created: null };
  const reserved = await reserveOut(join(dir, 'out.macaroon'));
  expect(reserved.aclWarning).toBe(true);
  expect(control.verifies).toBe(0);
  await reserved.reservation.discard();
});

it.each([
  ['another account added after creation', { found: { owner: sid, protected: true, rules: [mine()!.rules[0], { sid: other, allow: true, inherited: false, rights: 1179785 }] } }],
  ['an inherited entry', { found: { owner: sid, protected: false, rules: [{ ...mine()!.rules[0], inherited: true }] } }],
  ['no access entry', { found: { owner: sid, protected: true, rules: [] } }],
] as Array<[string, Partial<Scenario>]>)('RO-1/acl-verified %s fails closed: the file is removed and nothing is written', async (_name, scenario) => {
  control.scenario = { ...control.scenario, ...scenario };
  const out = join(dir, 'out.macaroon');
  const { wrap, unlinked, writes } = wrapped({});
  await expect(reserveOut(out, wrap)).rejects.toThrow(/did not keep owner-only permissions/);
  expect(unlinked).toEqual([out]); expect(writes).toEqual([]); expect(existsSync(out)).toBe(false);
});

// Reservation decision logic on every platform: the exclusive open is the only
// handle that may receive bytes, and any doubt about it discards the reservation.
const EXLOCK = 0x10000000;
function wrapped(options: { busy?: boolean; swap?: boolean }) {
  const unlinked: string[] = []; const writes: unknown[] = [];
  const wrap: typeof import('node:fs/promises') = { ...realFs,
    async open(path: Parameters<typeof realFs.open>[0], flags?: string | number, mode?: number) {
      if (typeof flags === 'number' && (flags & EXLOCK)) {
        if (options.busy) throw Object.assign(new Error('busy'), { code: 'EBUSY' });
        if (options.swap) { await realFs.rename(path, `${String(path)}.orig`); await realFs.writeFile(path, 'attacker'); }
      }
      const handle = await realFs.open(path, flags as string, mode);
      const write = handle.writeFile.bind(handle);
      return Object.assign(handle, { writeFile: (data: unknown) => { writes.push(data); return write(data as string); } });
    },
    async unlink(path: Parameters<typeof realFs.unlink>[0]) { unlinked.push(String(path)); return realFs.unlink(path); },
  } as typeof import('node:fs/promises');
  return { wrap, unlinked, writes };
}

it('SAFE-06/out-share-window an exclusive reopen refused by another handle discards the empty reservation', async () => {
  const out = join(dir, 'busy.macaroon');
  const { wrap, unlinked, writes } = wrapped({ busy: true });
  await expect(reserveOut(out, wrap)).rejects.toThrow(/opened or replaced by another process/);
  expect(unlinked).toEqual([out]); expect(writes).toEqual([]); expect(existsSync(out)).toBe(false);
});

it('SAFE-06/out-share-window a different file at the path after restriction is neither written nor removed', async () => {
  // The object at the path is not owned by this user: it is not the file the helper created.
  control.scenario = { ...control.scenario, found: mine(other) };
  const out = join(dir, 'swapped.macaroon');
  const { wrap, unlinked, writes } = wrapped({ swap: true });
  await expect(reserveOut(out, wrap)).rejects.toThrow(/opened or replaced by another process/);
  // The replacement belongs to someone else: reserveOut neither writes to nor removes it.
  expect(unlinked).toEqual([]);
  expect(writes).toEqual([]); expect(readFileSync(out, 'utf8')).toBe('attacker');
});

it('SAFE-06/out-share-window a verification that cannot read the object fails closed without removing it', async () => {
  control.scenario = { ...control.scenario, found: null };
  const out = join(dir, 'unread.macaroon');
  const { wrap, unlinked, writes } = wrapped({});
  await expect(reserveOut(out, wrap)).rejects.toThrow(/opened or replaced by another process/);
  expect(unlinked).toEqual([]); expect(writes).toEqual([]);
});
