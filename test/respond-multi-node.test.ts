import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { run as verify } from '../src/commands/verify.js';
import { run as revoke } from '../src/commands/revoke.js';
import { run as rotate } from '../src/commands/rotate.js';
import { run as respond } from '../src/commands/respond.js';
import { declareStagedFiles, declareStaging, fixture, nextId, oldId, register, responseBytes, vector } from './helpers/cp038-online.js';

// RL-04 (SPEC 5 V6, 6 S3/F3, 10 P8): one registry may hold several nodes (entries are keyed by
// nodePubkey and rootKeyId, and bake's label check is per node). Every label and ID lookup is
// scoped to the connected node, so another node's entries never block this node's commands.

afterEach(() => { declareStagedFiles(); });

const otherNode = '03' + 'cd'.repeat(32);

function tombstone() {
  return { nodePubkey: otherNode, label: null, rootKeyId: '1', permissions: ['info:read'], caveats: [],
    grade: 'READ', fingerprint: null, outPath: null, createdAt: '2026-10-01T00:00:00Z', verified: false,
    status: 'revoked' as const, revokedAt: '2026-10-01T00:00:00Z', revokeEvidence: 'by-id-only', replaces: null, replacedBy: null };
}

it('RL-04/verify\'s printed revoke command for an ID another node recorded runs on this node', async () => {
  const f = fixture();
  // Node A's registry holds an --unregistered tombstone for ID 1; small IDs exist on every node.
  f.save([f.old, tombstone() as never]);
  f.lnd.ids = [0n, 1n, BigInt(f.old.rootKeyId)];
  const leaked = register(responseBytes(1n, vector('preset-invoice-only').permissions));
  const checked = await verify([leaked, ...f.flags], f.deps);
  const guidance = (checked.result as { guidance: string[] }).guidance.join('\n');
  expect(guidance).toContain('macwarden revoke 1 --unregistered');
  const followed = await revoke(['1', '--unregistered', '--yes', ...f.flags], f.deps);
  expect(followed.error).toBeNull();
  expect(f.lnd.deleted).toEqual([1n]);
  // This node's tombstone is recorded beside the other node's, which is unchanged.
  const ones = f.rows().filter(row => row.rootKeyId === '1');
  expect(ones).toHaveLength(2);
  expect(ones.find(row => row.nodePubkey === otherNode)).toEqual(tombstone());
  expect(ones.find(row => row.nodePubkey === f.old.nodePubkey)).toMatchObject({ status: 'revoked', label: null });
});

it('RL-04/without --unregistered an ID registered only for another node is refused and the message says how to proceed', async () => {
  const f = fixture();
  f.save([f.old, tombstone() as never]);
  f.lnd.ids = [0n, 1n, BigInt(f.old.rootKeyId)];
  const refused = await revoke(['1', '--yes', ...f.flags], f.deps);
  expect(refused.error).toMatchObject({ code: 2, step: 'V6' });
  expect(refused.error!.message).toMatch(/another node/);
  expect(refused.error!.message).toMatch(/--unregistered/);
  expect(f.lnd.deleted).toEqual([]);
});

it('RL-04/a credential with the same label on another node does not block respond for this node', async () => {
  const f = fixture();
  const elsewhere = { ...f.old, nodePubkey: otherNode, rootKeyId: '4294967500' };
  f.save([f.old, elsewhere]);
  f.lnd.ids = [0n, BigInt(f.old.rootKeyId)];
  const out = await respond(['--out-dir', declareStaging(join(f.dir, 'staged')), '--yes', ...f.flags], f.deps);
  expect(out.error).toBeNull();
  const item = (out.result as { items: { rootKeyId: string; status: string }[] }).items[0];
  expect(item).toMatchObject({ rootKeyId: f.old.rootKeyId, status: 'staged' });
  const finished = await respond(['--finish', '--yes', ...f.flags], f.deps);
  expect(finished.error).toBeNull();
  expect(f.lnd.deleted).toEqual([oldId]);
  // The other node's credential is untouched.
  expect(f.rows().find(row => row.nodePubkey === otherNode)).toEqual(elsewhere);
});

it('RL-04/rotate stage and finish pick this node\'s entry when the label is active on another node too', async () => {
  const f = fixture();
  const elsewhere = { ...f.old, nodePubkey: otherNode };
  f.save([elsewhere, f.old]);
  f.lnd.ids = [0n, oldId];
  const staged = await rotate(['Alice', '--out', f.out, ...f.flags], f.deps);
  expect(staged.error).toBeNull();
  expect((staged.result as { old: { nodePubkey: string } }).old.nodePubkey).toBe(f.old.nodePubkey);
  const finished = await rotate(['Alice', '--finish', '--yes', ...f.flags], f.deps);
  expect(finished.error).toBeNull();
  expect(f.lnd.deleted).toEqual([oldId]);
  expect(f.rows().find(row => row.nodePubkey === otherNode)).toEqual(elsewhere);
  void nextId;
});

it('RL-04/a label active only on other nodes is not resolved on this node', async () => {
  const f = fixture();
  f.save([{ ...f.old, nodePubkey: otherNode }, { ...f.old, nodePubkey: '03' + 'ef'.repeat(32) }]);
  const result = await rotate(['Alice', '--out', f.out, '--dry-run', ...f.flags], f.deps);
  expect(result.error).toMatchObject({ code: 2, step: 'S3' });
  expect(f.lnd.calls).toEqual(['GetInfo']);
});
