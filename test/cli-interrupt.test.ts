import { expect, it, vi } from 'vitest';
import { Cancelled } from '../src/cancellation.js';
import { markMutationSent } from '../src/process-error-context.js';

// An interrupt that escapes a command (one landing in its first LND calls, which inventory,
// recommend and respond do not turn into a result of their own) is an interrupt, never the
// internal failure (exit 8) that would tell an operator something is broken.
vi.mock('../src/commands/handlers.js', async importOriginal => {
  const actual = await importOriginal<typeof import('../src/commands/handlers.js')>();
  return { handlers: { ...actual.handlers,
    inventory: async () => { throw new Cancelled(); },
    revoke: async () => { markMutationSent(); throw new Cancelled(); } } };
});

const { main } = await import('../src/cli.js');
const { captureMain } = await import('./support/capture.js');

it('CLI/interrupt an interrupt escaping a command before any LND change exits 6 cancelled, not 8 internal', async () => {
  const json = await captureMain(main, ['inventory', '--json']);
  expect(json.code).toBe(6);
  expect(JSON.parse(json.stdout)).toMatchObject({ command: 'inventory', ok: false, result: null,
    error: { code: 6, step: 'cancelled', message: 'interrupted' } });
  const text = await captureMain(main, ['inventory']);
  expect(text.code).toBe(6);
  expect(text.stdout + text.stderr).not.toContain('unexpected failure');
});

it('CLI/interrupt an interrupt escaping a command after an LND change may have been sent exits 7 with recovery', async () => {
  const json = await captureMain(main, ['revoke', '--json']);
  expect(json.code).toBe(7);
  expect(JSON.parse(json.stdout)).toMatchObject({ command: 'revoke', ok: false,
    error: { code: 7, step: 'cancelled', message: expect.stringContaining('run macwarden inventory') } });
});
