import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { run as inventory } from '../src/commands/inventory.js';
import { render } from '../src/output/index.js';
import { declare, fixture, oldId, ownId, pubkey, vector } from './helpers/cp038-online.js';
import { expectSchemaValid } from './helpers/output-schema.js';

// Found in the live field check against LND 0.20.0 (Polar): macwarden's own session
// credential was reported as unknown, a canary's --verify result as an error, and a
// triggered canary looked like ordinary usage.
it('INVENTORY/own-credential the own root key ID is macwarden\'s own credential, not unknown, when the registry has no entry', async () => {
  const f = fixture();
  f.save([f.old]);
  f.lnd.ids = [0n, ownId, oldId];
  const result = await inventory(f.flags, f.deps);
  expectSchemaValid(result);
  const own = (result.result as { rootKeys: { rootKeyId: string; flags: string[] }[] }).rootKeys.find(row => row.rootKeyId === String(ownId))!;
  expect(own.flags).toEqual(['own-credential']);
  const line = render(result, 'text').split('\n').find(text => text.startsWith(String(ownId)))!;
  expect(line).toMatch(/macwarden's own credential$/);
  expect(line).not.toContain('unknown');
});

it('INVENTORY/canary-verify a canary is reported as verifiable only while watch runs, and LND is not asked', async () => {
  const f = fixture();
  const path = join(f.dir, 'canary.macaroon');
  writeFileSync(path, vector('preset-read-only').bytes, { mode: 0o600 });
  declare(path);
  const canary = { ...f.old, outPath: path, caveats: [{ type: 'lnd-custom', value: 'policy-3597f768 44d9b8b458bc3481' }] };
  f.save([canary]);
  f.lnd.ids = [0n, ownId, oldId];
  const calls = f.lnd.calls.length;
  const result = await inventory([...f.flags, '--verify'], f.deps);
  expectSchemaValid(result);
  const row = (result.result as { rootKeys: { rootKeyId: string; verify: string }[] }).rootKeys.find(item => item.rootKeyId === String(oldId))!;
  expect(row.verify).toBe('canary');
  expect(f.lnd.calls.slice(calls)).not.toContain('CheckMacaroonPermissions');
  expect(render(result, 'text')).toContain('canary: verifiable only while watch runs');
});

it('INVENTORY/canary-triggered a canary the guard denied is flagged, leads its row, ends the text and reaches the access review', async () => {
  const f = fixture();
  const canary = { ...f.old, caveats: [{ type: 'lnd-custom', value: 'policy-3597f768 44d9b8b458bc3481' }] };
  f.save([canary]);
  f.lnd.ids = [0n, ownId, oldId];
  // As watch writes it: the observer saw the call as ordinary usage, the guard denied it twice.
  writeFileSync(`${f.registry}.usage.json`, JSON.stringify({ schema: 1, dropped: 0,
    canaryUses: [{ nodePubkey: pubkey, rootKeyId: String(oldId), uses: 2, firstUse: '2026-10-05T11:00:00.000Z', lastUse: '2026-10-05T11:30:00.000Z' }],
    entries: [{ nodePubkey: pubkey, credential: 'id:1111111111111111', rootKeyId: String(oldId), method: '/lnrpc.Lightning/GetInfo',
      calls: 2, errors: 0, firstSeen: '2026-10-05T11:00:00.000Z', lastSeen: '2026-10-05T11:30:00.000Z' }] }));
  const result = await inventory([...f.flags, '--report', 'json'], f.deps);
  expectSchemaValid(result);
  const rows = (result.result as { rootKeys: { rootKeyId: string; flags: string[]; canary?: unknown }[] }).rootKeys;
  const row = rows.find(item => item.rootKeyId === String(oldId))!;
  expect(row.flags).toContain('canary-triggered');
  expect(row.canary).toEqual({ uses: 2, firstUse: '2026-10-05T11:00:00.000Z', lastUse: '2026-10-05T11:30:00.000Z' });
  expect(rows.filter(item => item.flags.includes('canary-triggered'))).toHaveLength(1);
  const text = render(await inventory(f.flags, f.deps), 'text').trimEnd().split('\n');
  const line = text.find(item => item.startsWith(String(oldId)))!;
  expect(line).toMatch(/ {2}CANARY TRIGGERED 2 times, last 2026-10-05T11:30:00\.000Z: assume this credential's location is compromised; active/);
  expect(text.at(-1)).toMatch(/^CANARY TRIGGERED: Alice; /);
  const review = (result.result as { report: { review: { credentials: { rootKeyId: string; flags: string[] }[];
    controls: { control: string; rootKeyIds: string[] }[]; totals: { flagged: Record<string, number> } } } }).report.review;
  expect(review.credentials.find(item => item.rootKeyId === String(oldId))!.flags).toContain('canary-triggered');
  expect(review.totals.flagged['canary-triggered']).toBe(1);
  expect(review.controls[0]).toMatchObject({ control: 'Incident response', rootKeyIds: [String(oldId)] });
});

it('INVENTORY/canary-quiet without recorded canary uses there is no flag, no summary line and no incident control', async () => {
  const f = fixture();
  f.save([{ ...f.old, caveats: [{ type: 'lnd-custom', value: 'policy-3597f768 44d9b8b458bc3481' }] }]);
  f.lnd.ids = [0n, ownId, oldId];
  const result = await inventory([...f.flags, '--report', 'json'], f.deps);
  const rows = (result.result as { rootKeys: { flags: string[] }[] }).rootKeys;
  expect(rows.some(item => item.flags.includes('canary-triggered'))).toBe(false);
  expect(render(result, 'text')).not.toContain('CANARY TRIGGERED');
  const review = (result.result as { report: { review: { controls: { control: string }[] } } }).report.review;
  expect(review.controls.map(item => item.control)).toEqual(['Least privilege', 'Periodic access review', 'Prompt removal']);
});
