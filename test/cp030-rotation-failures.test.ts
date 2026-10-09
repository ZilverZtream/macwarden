import { readFileSync } from 'node:fs';
import { expect, it, vi } from 'vitest';
import { render } from './helpers/render-adversarial.js';
import { pubkey } from './helpers/cp026-revoke-support.mjs';
import { invoke, oldId, scratch } from './helpers/cp028-rotate-support.js';

it('CP-030/FI-3 completed stage followed by later inventory exposes both active IDs and recovery commands', async () => scratch(async f => {
  const staged = await invoke(f); expect(staged.error).toBeNull();
  const before = readFileSync(f.registry), nextId = f.state.chosen;
  f.deps.lnd.getInfo = vi.fn(async () => ({ alias: 'fixture', version: '0.21.4-beta', pubkey: pubkey, network: 'regtest' }));
  const command = await import('../src/commands/inventory.js');
  const result = await command.run(f.args.slice(3), f.deps);
  expect(result.error).toBeNull();
  const rows = (result.result as unknown as { rootKeys: Array<{ rootKeyId: string; inLnd: boolean; flags: string[] }> }).rootKeys;
  expect(rows.find(row => row.rootKeyId === oldId)).toMatchObject({ inLnd: true, flags: expect.arrayContaining(['pending-replacement']) });
  expect(rows.find(row => row.rootKeyId === nextId)).toMatchObject({ inLnd: true, flags: expect.arrayContaining(['replacement']) });
  const report = render(staged, 'text');
  expect(report).toContain('macwarden rotate Alice --finish'); expect(report).toContain(`macwarden revoke ${nextId}`);
  expect(f.state.ids).toEqual(expect.arrayContaining([oldId, nextId]));
  expect(readFileSync(f.registry).equals(before)).toBe(true);
}));
