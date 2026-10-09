import { expect, it } from 'vitest';
import { render } from './helpers/render-adversarial.js';

it('CP-018/B9 provisional inventory output escapes alias controls and preserves a uint64 decimal ID', () => {
  const id = '9007199254740993';
  const envelope = {
    schema: 1 as const,
    command: 'inventory',
    ok: true,
    warnings: [],
    result: {
      node: { pubkey: '02' + 'ab'.repeat(32), alias: 'alice\u001b\u0085',
        network: 'regtest', version: '0.21.4-beta' },
      rootKeys: [{ rootKeyId: id, inLnd: true, flags: ['unknown'],
        verify: 'not-checked', entry: null }],
    },
    error: null,
  };
  const text = render(envelope, 'text');
  expect(text).toContain(id);
  expect(text).toContain('\\x1b');
  expect(text).toContain('\\x85');
  expect(text.includes('\u001b')).toBe(false);
  expect(text.includes('\u0085')).toBe(false);

  const json = JSON.parse(render(envelope, 'json')) as { result: { rootKeys: Array<{
    rootKeyId: string; inLnd: boolean; entry: unknown }> } };
  expect(json.result.rootKeys).toEqual([{ rootKeyId: id, inLnd: true,
    flags: ['unknown'], verify: 'not-checked', entry: null }]);
});
