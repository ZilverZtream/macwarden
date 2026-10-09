import { existsSync, readFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { expect, it } from 'vitest';
import { main } from '../src/cli.js';
import { handlers } from '../src/commands/handlers.js';
import { run as bake } from '../src/commands/bake/index.js';
import { run as rotate } from '../src/commands/rotate.js';
import { run as revoke } from '../src/commands/revoke.js';
import { captureMain } from './support/capture.js';
import { fixture, oldId, nextId } from './helpers/cp038-online.js';

function latch() {
  let release!: () => void;
  const promise = new Promise<void>(resolve => { release = resolve; });
  return { promise, release };
}

it.each((['bake', 'stage'] as const).flatMap(mode =>
  (['output-write', 'registry-save'] as const).map(point => [mode, point] as const)))(
  'CP-038/A5-cancellation %s cancellation during paused post-verification %s preserves completed state', async (mode, point) => {
    const f = fixture(), reached = latch(), resume = latch();
    if (mode === 'bake') f.save([]);
    let paused = false;
    const pause = async () => {
      paused = true; reached.release(); await resume.promise;
    };
    f.deps.fs.open = (async (...args: Parameters<typeof fs.open>) => {
      const handle = await fs.open(...args);
      if (point !== 'output-write' || String(args[0]) !== f.out) return handle;
      return new Proxy(handle, { get(target, key) {
        const value: unknown = Reflect.get(target, key, target);
        if (key === 'writeFile') return async (...values: Parameters<typeof handle.writeFile>) => {
          await pause(); return target.writeFile(...values);
        };
        return typeof value === 'function' ? value.bind(target) : value;
      } });
    }) as typeof fs.open;
    f.deps.fs.rename = (async (...args: Parameters<typeof fs.rename>) => {
      if (point === 'registry-save' && String(args[1]) === f.registry) {
        const stored = JSON.parse(readFileSync(String(args[0]), 'utf8')) as { entries: Array<{ rootKeyId: string; verified: boolean }> };
        if (stored.entries.some(row => row.rootKeyId === String(f.lnd.baked[0]) && row.verified)) await pause();
      }
      return fs.rename(...args);
    }) as typeof fs.rename;
    const command = mode === 'bake' ? 'bake' : 'rotate';
    const original = handlers[command];
    handlers[command] = values => mode === 'bake' ? bake(values, f.deps) : rotate(values, f.deps);
    const args = mode === 'bake' ? ['--label', 'Bob', '--preset', 'invoice-only'] : ['Alice'];
    const running = captureMain(main, [command, ...args, '--out', f.out, ...f.flags, '--json']);
    try {
      await Promise.race([reached.promise, running.then(() => { throw new Error('command completed before filesystem pause'); })]);
      expect(paused).toBe(true);
      expect(f.lnd.baked).toHaveLength(1);
      expect(f.lnd.calls.filter(call => call === 'CheckMacaroonPermissions')).toHaveLength(mode === 'stage' ? 2 : 1);
      const callsBeforeCancellation = [...f.lnd.calls];
      const id = String(f.lnd.baked[0]);
      expect(f.rows().find(row => row.rootKeyId === id)).toMatchObject({ verified: false, outPath: null });
      process.emit('SIGTERM'); resume.release();
      const actual = await running;
      expect(f.lnd.calls).toEqual(callsBeforeCancellation);
      expect(actual.code).toBe(7);
      const document = JSON.parse(actual.stdout) as { ok: boolean; error: { code: number; message: string } };
      expect(document).toMatchObject({ ok: false, error: { code: 7 } });
      expect(document.error.message).toContain(`macwarden revoke ${id}`);
      expect(existsSync(f.registry + '.lock')).toBe(false);
      const row = f.rows().find(item => item.rootKeyId === id);
      expect(row).toBeDefined(); expect(row!.status).toBe('active');
      expect(f.lnd.ids.map(String)).toContain(id); expect(f.lnd.deleted).toEqual([]);
      if (existsSync(f.out)) {
        expect(readFileSync(f.out).byteLength).toBeGreaterThan(0);
        if (row!.outPath !== null) expect(row!.outPath).toBe(f.out);
      } else expect(row).toMatchObject({ verified: false, outPath: null });
      if (point === 'registry-save') {
        expect(existsSync(f.out)).toBe(true);
        expect(row).toMatchObject({ verified: true, outPath: f.out });
      }
      if (mode === 'stage') {
        expect(f.lnd.ids).toContain(oldId);
        expect(f.rows().find(item => item.rootKeyId === String(oldId))).toMatchObject({ status: 'active' });
      }
    } finally { resume.release(); await running; handlers[command] = original; }
  }, 10000);

it.each(['revoke', 'finish'] as const)(
  'CP-038/A9-B1-typed-online %s signature-mismatch rejection with accepted baseline and absent ID confirms revocation', async mode => {
    const f = fixture();
    if (mode === 'finish') f.save([f.old, f.next]);
    const original = f.lnd.checkMacaroon.bind(f.lnd);
    let baselineAccepted = false, rejectionSeen = false;
    f.lnd.checkMacaroon = async (mac, permissions) => {
      if (!f.lnd.deleted.length) {
        const checked = await original(mac, permissions);
        baselineAccepted = checked.valid; return checked;
      }
      expect(baselineAccepted).toBe(true); expect(f.lnd.ids).not.toContain(oldId);
      const checked = await original(mac, permissions);
      if (checked.valid) return checked;
      rejectionSeen = true;
      return { valid: false, reason: 'signature-mismatch', message: 'target signature rejected' };
    };
    const result = mode === 'revoke'
      ? await revoke(['Alice', '--yes', ...f.flags], f.deps)
      : await rotate(['Alice', '--finish', '--yes', ...f.flags], f.deps);
    expect(baselineAccepted).toBe(true); expect(rejectionSeen).toBe(true);
    expect(result.error).toBeNull(); expect(result.result).toMatchObject({ evidence: 'rejected' });
    expect(f.lnd.deleted).toEqual([oldId]); expect(f.lnd.ids).not.toContain(oldId);
    expect(f.rows().find(row => row.rootKeyId === String(oldId))).toMatchObject({ status: 'revoked' });
    if (mode === 'finish') expect(f.lnd.ids).toContain(nextId);
    expect(existsSync(f.registry + '.lock')).toBe(false);
  });
