import { LndError } from '../src/errors.js';
import { closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, readSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { expect, it, vi } from 'vitest';

const acl = vi.hoisted(() => ({
  calls: [] as Array<{ file: string; args: string[]; options: unknown }>,
  fail: false,
  // Runs as soon as the helper reports the file created: before macwarden opens it.
  onCreated: undefined as ((path: string) => void) | undefined,
}));

vi.mock('node:child_process', async importOriginal => {
  const real = await importOriginal<typeof import('node:child_process')>();
  return { ...real, execFile: (file: string, args: string[], options: { env?: Record<string, string> },
    callback: (error: Error | null, stdout: string, stderr: string) => void) => {
    acl.calls.push({ file, args, options });
    if (acl.fail) { queueMicrotask(() => callback(new Error('helper unavailable'), '', '')); return undefined; }
    const child = real.execFile(file, args, options, callback);
    let seen = '';
    child.stdout?.on('data', (chunk: string | Buffer) => {
      seen += String(chunk);
      const hook = acl.onCreated;
      if (hook && seen.includes('CREATED ')) { acl.onCreated = undefined; hook(options.env!.MACWARDEN_PRIVATE_OUT); }
    });
    return child;
  } };
});

function tmp(): string {
  if (!process.env.MACWARDEN_TEST_TMP) throw new Error('MACWARDEN_TEST_TMP is required');
  const path = resolve(process.env.MACWARDEN_TEST_TMP);
  mkdirSync(path, { recursive: true, mode: 0o700 });
  return path;
}

it.each([false, true])(
  'CP-023/B7 Windows owner-only creation helper fails %s: argument array without shell; a failure writes nothing',
  async fail => {
  const path = mkdtempSync(join(tmp(), 'cp023-acl-'));
  acl.calls.length = 0;
  acl.fail = fail;
  try {
    const registry = join(path, 'registry.json');
    const out = join(path, 'candidate.macaroon');
    writeFileSync(registry, '{"schema":1,"entries":[]}');
    const calls: string[] = [];
    const deps = { fs: { ...fs }, env: {} as Record<string, string>,
      clock: () => new Date('2026-10-04T00:00:00.000Z'),
      lnd: { getInfo: async () => {
        calls.push('GetInfo');
        expect(existsSync(out)).toBe(true);
        throw new LndError(4, 'transport', 'unauthorized');
      }, listPermissions: async () => { calls.push('ListPermissions'); return {}; } } };

    const command = await import('../src/commands/bake/index.js') as {
      run: (args: string[], deps: unknown) => Promise<{
        error: { code: number; step: string; message: string } | null;
        warnings: Array<string | { code: string; message?: string }>;
      }>;
    };
    const result = await command.run(['--label', 'Alice', '--preset', 'invoice-only',
      '--out', out, '--registry', registry, '--lnd-rest', '127.0.0.1:1',
      '--tls-cert', resolve('test/fixture/wrong-tls.cert'),
      '--macaroon', resolve('test/vectors/default-admin.macaroon')], deps);
    const executable = join(process.env.SystemRoot!, 'System32/WindowsPowerShell/v1.0/powershell.exe');
    // Every child is the System32 PowerShell (the registry lock's process-domain query uses it
    // too); exactly one is the owner-only creation helper for this output.
    for (const call of acl.calls) {
      expect(call.file).toBe(executable);
      expect(call.options).toMatchObject({ shell: false });
      // The path is passed through the helper's environment, not its command line.
      expect(call.args.join(' ')).not.toContain(out);
    }
    expect(acl.calls.filter(call => (call.options as { env?: Record<string, string> }).env?.MACWARDEN_PRIVATE_OUT === out)).toHaveLength(1);
    const warnings = result.warnings.map(warning => typeof warning === 'string' ? warning : warning.code);
    expect(warnings.includes('acl-best-effort')).toBe(false);
    if (fail) {
      // Without a verified owner-only file nothing is reserved, nothing is sent to LND.
      expect(result.error).toMatchObject({ code: 3, step: 'B7' });
      expect(result.error!.message).toMatch(/cannot reserve output file: .*owner-only/);
      expect(calls).toEqual([]);
    } else {
      expect(result.error).toMatchObject({ code: 4, step: 'B8' });
      expect(calls).toEqual(['GetInfo']);
    }
    expect(existsSync(out)).toBe(false);
    expect(existsSync(`${registry}.lock`)).toBe(false);
    expect(readFileSync(registry, 'utf8')).toBe('{"schema":1,"entries":[]}');
  } finally {
    acl.fail = false;
    rmSync(path, { recursive: true, force: true });
  }
}, 20000);

// A local process (here the owner itself, the only principal the ACL admits) that opens the
// new --out file before macwarden's exclusive open keeps that handle. The reservation must
// detect the handle and write nothing.
it.each(['watcher', 'none'] as const)('SAFE-06/out-share-window attenuate with %s handle opened before the exclusive open', async watcher => {
  const dir = mkdtempSync(join(tmp(), 'safe06-share-'));
  const out = join(dir, 'child.macaroon');
  let held: number | undefined;
  acl.calls.length = 0; acl.fail = false;
  acl.onCreated = path => { if (watcher === 'watcher') held = openSync(path, 'r'); };
  try {
    const { run } = await import('../src/commands/attenuate.js');
    const result = await run([resolve('test/vectors/default-readonly.macaroon'), '--out', out, '--expires', '1h'],
      { stdin: process.stdin, fs, env: { ...process.env }, clock: () => new Date() });
    if (watcher === 'none') {
      expect(result.error).toBeNull();
      expect(readFileSync(out).length).toBeGreaterThan(100);
    } else {
      expect(result.error).toMatchObject({ code: 3, step: 'A6' });
      expect(held).toBeTypeOf('number');
      // The watcher's handle never sees credential bytes.
      const buffer = Buffer.alloc(4096);
      expect(readSync(held!, buffer, 0, buffer.length, 0)).toBe(0);
      closeSync(held!); held = undefined;
      expect(existsSync(out)).toBe(false);
    }
  } finally {
    acl.onCreated = undefined;
    if (held !== undefined) closeSync(held);
    rmSync(dir, { recursive: true, force: true });
  }
});

it('SAFE-06/out-share-window no other handle can be opened while the reservation is held', async () => {
  const dir = mkdtempSync(join(tmp(), 'safe06-hold-'));
  const out = join(dir, 'held.macaroon');
  acl.calls.length = 0; acl.fail = false;
  try {
    const { reserveOut } = await import('../src/commands/bake/write-out.js');
    const reserved = await reserveOut(out);
    expect(() => openSync(out, 'r')).toThrow(/EBUSY/);
    await reserved.reservation.discard();
    expect(existsSync(out)).toBe(false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
