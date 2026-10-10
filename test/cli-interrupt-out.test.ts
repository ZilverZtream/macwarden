// 1.2.1: SIGINT while an --out check (lstat/realpath at B4, A3, N7) or the --out creation call
// (open, after the registry lock in bake) never returns. Before, these calls were not raced
// against the interrupt: no result was written, so the forced exit in bin.ts never fired and the
// process stayed alive holding the registry lock. Now the command reports exit 6, step
// `cancelled`, releases the lock and exits at once. A creation call that stalled may already have
// made the file (empty, owner-only: on Windows the helper creates it before the open); it cannot
// be removed, and the message says so.
import { fork } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { childEnvironment } from './helpers/environment.js';

const repo = resolve();
const bin = join(repo, 'dist/bin.js');
const child = join(repo, 'test/support/stalled-fs-child.mjs');
const admin = join(repo, 'test/vectors/default-admin.macaroon');
const cert = join(repo, 'test/fixture/cp016-wrong-ca.crt');

type Outcome = { code: number | null; elapsed: number; output: { command: string; ok: boolean; error: { code: number; step: string; message: string } } };

function scratch(): string {
  const root = process.env.MACWARDEN_TEST_TMP ?? join(repo, 'test/.tmp');
  mkdirSync(root, { recursive: true });
  return mkdtempSync(join(root, 'stalled-out-'));
}

async function interrupted(dir: string, args: string[], stall: { path: string; fn: 'lstat' | 'open' }): Promise<Outcome> {
  const home = join(dir, 'home');
  mkdirSync(home);
  const proc = fork(child, [bin, ...args], { cwd: dir, execArgv: [], stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    env: childEnvironment({ HOME: home, USERPROFILE: home, APPDATA: join(home, 'Roaming'), LOCALAPPDATA: join(home, 'Local'),
      XDG_CONFIG_HOME: join(home, '.config'), MACWARDEN_STALL_PATH: stall.path, MACWARDEN_STALL_FN: stall.fn }) });
  let stdout = '';
  proc.stdout!.on('data', chunk => { stdout += chunk; });
  proc.stderr!.resume();
  const exited = new Promise<number | null>(done => proc.on('exit', code => done(code)));
  try {
    await new Promise<void>((done, fail) => {
      proc.on('message', (message: { kind?: string }) => { if (message?.kind === 'stalled') done(); });
      exited.then(code => fail(new Error(`child exited ${code} before stalling: ${stdout}`)));
    });
    const signalled = Date.now();
    proc.send({ kind: 'signal', signal: 'SIGINT' });
    const code = await Promise.race([exited, new Promise<'alive'>(done => setTimeout(() => done('alive'), 2_000))]);
    expect(code, 'process still alive 2 s after SIGINT').toBe(6);
    return { code: code as number, elapsed: Date.now() - signalled, output: JSON.parse(stdout) };
  } finally { if (proc.exitCode === null) proc.kill(); }
}

const online = (registry: string) => ['--registry', registry, '--lnd-rest', '127.0.0.1:9', '--tls-cert', cert, '--macaroon', admin];

it('CLI/interrupt-out bake stalled at the B4 output check exits 6 at once and leaves nothing', async () => {
  const dir = scratch(), out = join(dir, 'new.macaroon'), registry = join(dir, 'registry.json');
  const result = await interrupted(dir, ['bake', '--label', 'app', '--preset', 'invoice-only', '--out', out,
    ...online(registry), '--json'], { path: out, fn: 'lstat' });
  expect(result.output).toMatchObject({ command: 'bake', ok: false, error: { code: 6, step: 'cancelled' } });
  expect(result.elapsed).toBeLessThan(2_000);
  expect(existsSync(out)).toBe(false);
  expect(readdirSync(dir).filter(name => name.startsWith('registry.json'))).toEqual([]);
}, 60_000);

it('CLI/interrupt-out bake stalled creating --out under the registry lock exits 6 and releases the lock', async () => {
  const dir = scratch(), out = join(dir, 'new.macaroon'), registry = join(dir, 'registry.json');
  const result = await interrupted(dir, ['bake', '--label', 'app', '--preset', 'invoice-only', '--out', out,
    ...online(registry), '--json'], { path: out, fn: 'open' });
  expect(result.output).toMatchObject({ command: 'bake', ok: false, error: { code: 6, step: 'cancelled' } });
  expect(result.output.error.message).toMatch(/empty and owner-only/);
  expect(existsSync(`${registry}.lock`), 'registry lock released').toBe(false);
  // The stalled call is the creation itself (POSIX) or the open after the helper created it (Windows):
  // whatever is there is empty.
  if (existsSync(out)) expect(statSync(out).size).toBe(0);
}, 60_000);

it('CLI/interrupt-out attenuate stalled at the A3 output check exits 6 at once', async () => {
  const dir = scratch(), out = join(dir, 'child.macaroon');
  const result = await interrupted(dir, ['attenuate', admin, '--out', out, '--expires', '1d', '--json'], { path: out, fn: 'lstat' });
  expect(result.output).toMatchObject({ command: 'attenuate', ok: false, error: { code: 6, step: 'cancelled' } });
  expect(existsSync(out)).toBe(false);
}, 60_000);

it('CLI/interrupt-out attenuate stalled creating --out exits 6 at once', async () => {
  const dir = scratch(), out = join(dir, 'child.macaroon');
  const result = await interrupted(dir, ['attenuate', admin, '--out', out, '--expires', '1d', '--json'], { path: out, fn: 'open' });
  expect(result.output).toMatchObject({ command: 'attenuate', ok: false, error: { code: 6, step: 'cancelled' } });
  expect(result.output.error.message).toMatch(/empty and owner-only/);
  if (existsSync(out)) expect(statSync(out).size).toBe(0);
}, 60_000);

it('CLI/interrupt-out inventory --report stalled at the N7 report-path check exits 6 at once', async () => {
  const dir = scratch(), out = join(dir, 'review.json'), registry = join(dir, 'registry.json');
  const result = await interrupted(dir, ['inventory', '--report', 'json', '--out', out, ...online(registry), '--json'],
    { path: out, fn: 'lstat' });
  expect(result.output).toMatchObject({ command: 'inventory', ok: false, error: { code: 6, step: 'cancelled' } });
  expect(existsSync(out)).toBe(false);
}, 60_000);
