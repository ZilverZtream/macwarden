import { afterEach, expect, it, vi } from 'vitest';
import { main } from '../src/cli.js';
import { handlers } from '../src/commands/handlers.js';

afterEach(() => { vi.restoreAllMocks(); });

// What respond returns when it observes an interrupt mid-batch (SPEC 10): Alice was
// staged, Bob was not run, exit 7 because LND changed for Alice.
function interruptedBatch() {
  const item = (label: string, rootKeyId: string, status: string, replacementRootKeyId: string | null) => ({
    label, rootKeyId, grade: 'READ', action: 'stage', status, replacementRootKeyId,
    outPath: replacementRootKeyId ? `/srv/out/${label}.macaroon` : null,
    note: status === 'not-run' ? 'interrupted before this credential: rerun the same command to continue' : null,
    error: null, proof: null });
  return { schema: 1, command: 'respond', ok: true, exitCode: 7, error: null,
    warnings: [{ code: 'interrupted', message: 'interrupted: credentials marked not-run were not changed; rerun the same command to continue' }],
    result: { mode: 'stage', dryRun: false, node: { pubkey: '02' + 'ab'.repeat(32), alias: 'n', network: 'regtest' },
      rootKey0: { present: true, ownOnRootKey0: false, guidance: [] }, own: { rootKeyId: '4294967296' },
      unknown: { rootKeyIds: [], guidance: '' }, revokedButPresent: { rootKeyIds: [], guidance: '' },
      bakingRisk: { rootKeyIds: [], guidance: [] }, outDir: '/srv/out',
      items: [item('Alice', '4294967297', 'staged', '4294967999'), item('Bob', '4294967298', 'not-run', null)], unproven: [] } };
}

function capture() {
  const sink = { out: '', err: '' };
  vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: string | Uint8Array) => { sink.out += String(chunk); return true; }) as typeof process.stdout.write);
  vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: string | Uint8Array) => { sink.err += String(chunk); return true; }) as typeof process.stderr.write);
  vi.spyOn(handlers, 'respond').mockImplementation(async () => { process.emit('SIGHUP'); return interruptedBatch() as never; });
  return sink;
}

it('RESPOND/interrupt the CLI keeps the per-credential outcome of an interrupted batch in JSON', async () => {
  const sink = capture();
  const code = await main(['respond', '--out-dir', '/srv/out', '--yes', '--json']);
  expect(code).toBe(7);
  const document = JSON.parse(sink.out);
  expect(document).toMatchObject({ ok: true, error: null });
  expect(document.result.items.map((item: { label: string; status: string }) => [item.label, item.status]))
    .toEqual([['Alice', 'staged'], ['Bob', 'not-run']]);
});

it('RESPOND/interrupt text output names what was staged and what was not run', async () => {
  const sink = capture();
  expect(await main(['respond', '--out-dir', '/srv/out', '--yes'])).toBe(7);
  expect(sink.out).toMatch(/Alice.*staged -> 4294967999/);
  expect(sink.out).toMatch(/Bob.*not-run/);
  expect(sink.err).toMatch(/interrupted/);
  expect(sink.out + sink.err).not.toMatch(/operation interrupted after mutation/);
});
