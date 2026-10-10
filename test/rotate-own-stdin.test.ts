// rotate reads every credential through the injected stdin, never process.stdin directly (1.2.1).
import { Readable } from 'node:stream';
import { expect, it, vi } from 'vitest';
import * as online from '../src/online.js';
import { invoke, scratch } from './helpers/cp028-rotate-support.js';

vi.mock('../src/online.js', async importOriginal => {
  const actual = await importOriginal<typeof import('../src/online.js')>();
  return { ...actual, readOnlineCredential: vi.fn(actual.readOnlineCredential) };
});
vi.setConfig({ testTimeout: 60_000 });

it('rotate stage passes deps.stdin to the own-macaroon read at S6', async () => scratch(async f => {
  const stdin = Object.assign(Readable.from([]), { isTTY: false });
  Object.assign(f.deps, { stdin });
  const read = vi.mocked(online.readOnlineCredential); read.mockClear();
  const result = await invoke(f, ['--dry-run']);
  expect(result.error).toBeNull();
  expect(read).toHaveBeenCalled();
  for (const [, io] of read.mock.calls) expect(io.stdin).toBe(stdin);
}));
