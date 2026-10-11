import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import { main } from '../src/cli.js';
import { captureMain } from './support/capture.js';

// Audit 1.4.0: the inspect CLI wrapper passed no environment, so NODE_OPTIONS and NODE_DEBUG were
// never checked on the production path (cli-runtime.test.ts injects env into run() itself).
it.each([['NODE_OPTIONS', '--no-warnings'], ['NODE_OPTIONS', '--report-on-fatalerror'], ['NODE_DEBUG', 'tls']])(
  'DECODE-AUDIT/env inspect through main() refuses %s=%s', async (name, value) => {
    const saved = process.env[name];
    process.env[name] = value;
    try {
      const result = await captureMain(main, ['inspect', resolve('test/vectors/default-readonly.macaroon'), '--json']);
      expect(result.code).toBe(2);
      expect(JSON.parse(result.stdout)).toMatchObject({ command: 'inspect', ok: false,
        error: { code: 2, message: 'unsafe Node diagnostic settings' } });
    } finally {
      if (saved === undefined) delete process.env[name]; else process.env[name] = saved;
    }
  });

it('DECODE-AUDIT/env inspect through main() runs with a clean environment', async () => {
  expect(process.env.NODE_OPTIONS ?? '').toBe('');
  const result = await captureMain(main, ['inspect', resolve('test/vectors/default-readonly.macaroon'), '--json']);
  expect(result.code).toBe(0);
});
