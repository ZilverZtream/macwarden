import { afterEach, expect, it, vi } from 'vitest';
import { main } from '../src/cli.js';
import { handlers } from '../src/commands/handlers.js';

afterEach(() => { vi.restoreAllMocks(); });

function result(dryRun: boolean) {
  return { schema: 1, command: 'attenuate', ok: true, warnings: [], error: null,
    result: { dryRun, out: dryRun ? null : '/tmp/copy.macaroon', parentFingerprint: '0123456789abcdef', added: [] } };
}

it.each([[false, /written copy is complete and kept/], [true, /interrupted before mutation/]] as const)(
  'ATTENUATE/interrupt-after-write dryRun=%s reports whether the copy was written', async (dryRun, message) => {
    let out = '';
    vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: string | Uint8Array) => { out += String(chunk); return true; }) as typeof process.stdout.write);
    vi.spyOn(handlers, 'attenuate').mockImplementation(async () => { process.emit('SIGHUP'); return result(dryRun) as never; });
    const code = await main(['attenuate', 'in.macaroon', '--out', 'copy.macaroon', '--expires', '1h', '--json']);
    expect(code).toBe(6);
    expect(JSON.parse(out)).toMatchObject({ ok: false, error: { code: 6, step: 'cancelled', message: expect.stringMatching(message) } });
  });
