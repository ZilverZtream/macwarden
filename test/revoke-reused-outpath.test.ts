import { copyFileSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { run as revoke } from '../src/commands/revoke.js';
import { run as rotate } from '../src/commands/rotate.js';
import { run as respond } from '../src/commands/respond.js';
import { declare, entry, fixture, nextId, oldId } from './helpers/cp038-online.js';

// RL-01 (SPEC 5 V6, 6 S4 and F7): a credential file at an entry's recorded outPath that holds a
// credential on ANOTHER root key ID (the path was reused, typically for the replacement the app
// now reads) is not the entry's file. The old credential is proven revoked by ID only. A file
// that carries the entry's own fingerprint on another root key ID means the entry was edited,
// and stays exit 3.

it('RL-01/revoke proves by ID only when the old file path now holds another credential', async () => {
  const f = fixture();
  // The operator deleted the old file and baked a new credential to the same path the app reads.
  const shared = join(f.dir, 'app.macaroon'); declare(shared);
  const old = { ...f.old, outPath: shared };
  const fresh = { ...entry(nextId, 'Bob') };
  copyFileSync(fresh.outPath!, shared); fresh.outPath = shared;
  f.save([old, fresh]);
  for (const target of ['Alice', String(oldId)]) {
    const planned = await revoke([target, '--dry-run', ...f.flags], f.deps);
    expect(planned.error).toBeNull();
    expect(planned.result).toMatchObject({ rootKeyId: String(oldId), proof: 'by-id-only' });
  }
  const result = await revoke(['Alice', '--yes', ...f.flags], f.deps);
  expect(result.error).toBeNull();
  expect(result.result).toMatchObject({ rootKeyId: String(oldId), evidence: 'by-id-only' });
  expect(f.lnd.deleted).toEqual([oldId]);
  // The other credential's file is untouched and its entry stays active.
  expect(f.rows().find(row => row.rootKeyId === String(nextId))).toMatchObject({ status: 'active', outPath: shared });
});

it('RL-01/rotate stage and finish work after staging the replacement at the old (missing) file path', async () => {
  const f = fixture();
  const appPath = join(f.dir, 'app.macaroon'); declare(appPath);
  // The old file is gone (copied off the host and deleted); the replacement goes where the app reads.
  const old = { ...f.old, outPath: appPath };
  f.save([old]);
  f.lnd.ids = [0n, oldId];
  const staged = await rotate(['Alice', '--out', appPath, ...f.flags], f.deps);
  expect(staged.error).toBeNull();
  // A second stage attempt and the finish now read the replacement at O's recorded path.
  const planned = await rotate(['Alice', '--finish', '--dry-run', ...f.flags], f.deps);
  expect(planned.error).toBeNull();
  const finished = await rotate(['Alice', '--finish', '--yes', ...f.flags], f.deps);
  expect(finished.error).toBeNull();
  expect(finished.result).toMatchObject({ stage: 'finished', evidence: 'by-id-only' });
  expect(f.lnd.deleted).toEqual([oldId]);
  rmSync(appPath, { force: true });
});

it('RL-01/respond --finish finishes a replacement staged at the old file path', async () => {
  const f = fixture();
  const appPath = join(f.dir, 'app.macaroon'); declare(appPath);
  f.save([{ ...f.old, outPath: appPath }]);
  f.lnd.ids = [0n, oldId];
  expect((await rotate(['Alice', '--out', appPath, ...f.flags], f.deps)).error).toBeNull();
  const finished = await respond(['--finish', '--yes', ...f.flags], f.deps);
  expect(finished.error).toBeNull();
  const item = (finished.result as { items: { status: string; proof: { proven: boolean } | null }[] }).items[0];
  expect(item.status).toBe('finished');
  expect(item.proof?.proven).toBe(true);
  expect(f.lnd.deleted).toEqual([oldId]);
});

it('RL-01/rotate stage treats another credential at the old path like a missing file (informed approval)', async () => {
  const f = fixture();
  const shared = join(f.dir, 'app.macaroon'); declare(shared);
  const fresh = entry(nextId, 'Bob');
  copyFileSync(fresh.outPath!, shared); fresh.outPath = shared;
  f.save([{ ...f.old, outPath: shared }, fresh]);
  f.lnd.ids = [0n, oldId, nextId];
  const questions: string[] = [];
  f.deps.prompt = Object.assign(async (question: string) => { questions.push(question); return 'Alice'; }, { isTTY: true });
  const planned = await rotate(['Alice', '--out', f.out, '--dry-run', ...f.flags], f.deps);
  expect(planned.error).toBeNull();
  expect(planned.result).toMatchObject({ permissionsProven: false });
  const staged = await rotate(['Alice', '--out', f.out, ...f.flags], f.deps);
  expect(staged.error).toBeNull();
  expect(questions).toEqual([expect.stringContaining('cannot prove the recorded authority')]);
});

it('RL-01/a file carrying the entry fingerprint on another root key ID is still refused as an edited entry', async () => {
  const f = fixture();
  // The entry claims the fingerprint of the file at its path, but that file is on another root key ID:
  // only an edit of the entry's root key ID (or fingerprint) produces this.
  const forged = { ...f.old, outPath: f.next.outPath, fingerprint: f.next.fingerprint };
  f.save([forged]);
  f.lnd.ids = [0n, oldId, nextId];
  const before = readFileSync(f.registry);
  const revoked = await revoke(['Alice', '--yes', ...f.flags], f.deps);
  expect(revoked.error).toMatchObject({ code: 3, step: 'V6' });
  expect(revoked.error!.message).toMatch(/trusted copy/);
  const staged = await rotate(['Alice', '--out', f.out, ...f.flags], f.deps);
  expect(staged.error).toMatchObject({ code: 3, step: 'S4' });
  expect(f.lnd.calls).not.toContain('BakeMacaroon');
  expect(f.lnd.deleted).toEqual([]);
  expect(readFileSync(f.registry).equals(before)).toBe(true);
});

it('RL-01/finish refuses an old file carrying the old fingerprint on another root key ID before deleting', async () => {
  const f = fixture();
  const third = entry(4294967343n, 'Carol');
  const pendingNext = { ...f.next };
  // O's entry claims Carol's file and fingerprint (an edited root key ID).
  f.save([{ ...f.old, outPath: third.outPath, fingerprint: third.fingerprint }, pendingNext]);
  f.lnd.ids = [0n, oldId, nextId];
  const finished = await rotate(['Alice', '--finish', '--yes', ...f.flags], f.deps);
  expect(finished.error).toMatchObject({ code: 3, step: 'F7' });
  expect(f.lnd.deleted).toEqual([]);
});
