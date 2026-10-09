import { describe, expect, it, vi } from 'vitest';
import { captureMain } from './support/capture.js';

const marker = vi.hoisted(() => 'cafe'.repeat(16));

// The command map is the mocked boundary; no production test-only hook is needed.
vi.mock('../src/commands/handlers.js', () => ({
  handlers: {
    boom: async () => { throw new Error(`failure ${marker}`); },
  },
}));

import { main } from '../src/cli.js';

describe('CP-001 internal errors', () => {
  it('CP-001/B7 maps a thrown handler error to a redacted internal error', async () => {
    for (const args of [['boom', marker], ['boom', marker, '--json']]) {
      const actual = await captureMain(main, args);
      expect(actual.code).toBe(8);
      expect(actual.exitCalls).toBe(0);
      if (args.includes('--json')) {
        expect(actual.stderr).toBe('');
        const document = JSON.parse(actual.stdout) as {
          ok: boolean; error: { code: number; step: string };
        };
        expect(document.ok).toBe(false);
        expect(document.error).toMatchObject({ code: 8, step: 'internal' });
      } else {
        expect(actual.stdout).toBe('');
        expect(actual.stderr).toMatch(/^error: internal[^\r\n]*\r?\n$/);
      }
      const output = actual.stdout + actual.stderr;
      expect(output).not.toContain(marker);
      expect(output).not.toContain(`failure ${marker}`);
      expect(output).not.toMatch(/^\s{4}at /m);
    }
  });
});
