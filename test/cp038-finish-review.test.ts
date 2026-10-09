import { existsSync, readFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { expect, it } from 'vitest';
import { main } from '../src/cli.js';
import { handlers } from '../src/commands/handlers.js';
import { run as rotate } from '../src/commands/rotate.js';
import { captureMain } from './support/capture.js';
import { fixture, nextId, oldId } from './helpers/cp038-online.js';

function latch() {
  let release!: () => void;
  const promise = new Promise<void>(resolve => { release = resolve; });
  return { promise, release };
}

it.each(['registry-save', 'unlock'] as const)(
  'CP-038/A5-cancellation completed finish cancellation during %s preserves the surviving replacement and safe recovery', async point => {
    const f = fixture(), reached = latch(), resume = latch();
    f.save([f.old, f.next]);
    const pause = async () => { reached.release(); await resume.promise; };
    f.deps.fs.rename = (async (...args: Parameters<typeof fs.rename>) => {
      await fs.rename(...args);
      if (point === 'registry-save' && String(args[1]) === f.registry) await pause();
    }) as typeof fs.rename;
    f.deps.fs.unlink = (async (...args: Parameters<typeof fs.unlink>) => {
      if (point === 'unlock' && String(args[0]) === f.registry + '.lock') await pause();
      return fs.unlink(...args);
    }) as typeof fs.unlink;
    const original = handlers.rotate;
    handlers.rotate = values => rotate(values, f.deps);
    const running = captureMain(main, ['rotate', 'Alice', '--finish', '--yes', ...f.flags, '--json']);
    try {
      await Promise.race([reached.promise, running.then(() => { throw new Error('finish completed before filesystem pause'); })]);
      const completed = f.rows();
      expect(completed).toHaveLength(2);
      expect(completed.find(row => row.rootKeyId === String(oldId))).toMatchObject({
        status: 'revoked', revokedAt: expect.any(String), revokeEvidence: 'rejected', replacedBy: String(nextId) });
      expect(completed.find(row => row.rootKeyId === String(nextId))).toMatchObject({
        status: 'active', verified: true, replaces: String(oldId), outPath: f.next.outPath });
      expect(f.lnd.deleted).toEqual([oldId]);
      expect(f.lnd.ids).toEqual([0n, nextId]);
      expect(existsSync(f.registry + '.lock')).toBe(true);
      process.emit('SIGTERM'); resume.release();
      const actual = await running;
      const document = JSON.parse(actual.stdout) as {
        ok: boolean; error: { code: number; step: string; message: string };
      };
      expect.soft(actual.code).toBe(7);
      expect.soft(document).toMatchObject({ ok: false, error: { code: 7, step: 'F12' } });
      expect.soft(document.error.message).toContain(String(oldId));
      expect.soft(document.error.message).toContain(String(nextId));
      expect.soft(document.error.message).toMatch(/revoked|deleted|absent/i);
      expect.soft(document.error.message).toMatch(/active|accepted|valid|finished|complete/i);
      expect.soft(document.error.message).toMatch(/macwarden (?:inventory|rotate Alice --finish)/);
      expect.soft(document.error.message).not.toMatch(new RegExp(`macwarden revoke\\s+(?:${nextId}|Alice)(?:\\s|$|[\x60.,;])`));
      expect(f.rows()).toEqual(completed);
      expect(f.lnd.deleted).toEqual([oldId]);
      expect(f.lnd.ids).toEqual([0n, nextId]);
      expect(readFileSync(f.next.outPath!).byteLength).toBeGreaterThan(0);
      expect(existsSync(f.registry + '.lock')).toBe(false);
    } finally { resume.release(); await running; handlers.rotate = original; }
  }, 10000);

it('CP-038/B7-spec-output uppercase registry node identity permits stage followed by completed finish', async () => {
  const f = fixture();
  f.old.nodePubkey = f.old.nodePubkey.toUpperCase();
  f.save(); f.lnd.ids = [0n, oldId];
  const original = handlers.rotate;
  handlers.rotate = values => rotate(values, f.deps);
  try {
    const staged = await captureMain(main, ['rotate', 'Alice', '--out', f.out, ...f.flags, '--json']);
    expect(staged.code).toBe(0);
    expect(f.lnd.baked).toHaveLength(1);
    const replacementId = f.lnd.baked[0]!;
    expect(f.lnd.ids).toEqual([0n, oldId, replacementId]);
    expect(f.lnd.deleted).toEqual([]);
    expect(f.rows().find(row => row.rootKeyId === String(replacementId)))
      .toMatchObject({ status: 'active', verified: true, replaces: String(oldId), outPath: f.out });
    const finished = await captureMain(main, ['rotate', 'Alice', '--finish', '--yes', ...f.flags, '--json']);
    const document = JSON.parse(finished.stdout) as {
      ok: boolean; error: unknown; result: unknown;
    };
    expect.soft(finished.code).toBe(0);
    expect.soft(document).toMatchObject({ ok: true, error: null, result: { stage: 'finished',
      old: { rootKeyId: String(oldId), status: 'revoked', replacedBy: String(replacementId) },
      new: { rootKeyId: String(replacementId), status: 'active', verified: true } } });
    expect.soft(f.lnd.deleted).toEqual([oldId]);
    expect.soft(f.lnd.ids).toEqual([0n, replacementId]);
    expect.soft(f.rows().find(row => row.rootKeyId === String(oldId)))
      .toMatchObject({ status: 'revoked', replacedBy: String(replacementId) });
    expect(f.rows().find(row => row.rootKeyId === String(replacementId)))
      .toMatchObject({ status: 'active', verified: true, outPath: f.out });
    expect(existsSync(f.registry + '.lock')).toBe(false);
  } finally { handlers.rotate = original; }
});
