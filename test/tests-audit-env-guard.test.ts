import { join, resolve } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { main } from '../src/cli.js';
import { watch } from '../src/commands/watch.js';
import { captureMain } from './support/capture.js';

// Audit 1.4.0 (spec.md:37 and each command's ENV step): unsafe Node diagnostic settings in the
// environment (NODE_DEBUG naming http, https, tls or net, or any NODE_OPTIONS) are refused with
// exit 2 at the command's ENV step, before any file is read or LND is called, for watch (W2),
// respond (P2), verify (C2), recommend (R2) and attenuate (A2). The same matrix as revoke V2
// (cp026-revoke.test.ts). The commands run through main(), which hands them process.env.
const repo = resolve();
const missing = (name: string) => join(repo, `test/nonexistent-tests-audit.${name}`);
const connection = ['--lnd-rest', '127.0.0.1:1', '--tls-cert', missing('cert'), '--macaroon', missing('macaroon')];
const readonly = resolve('test/vectors/default-readonly.macaroon');

const commands = {
  watch: { step: 'W2', args: connection },
  respond: { step: 'P2', args: ['--dry-run', ...connection] },
  verify: { step: 'C2', args: [readonly, ...connection] },
  recommend: { step: 'R2', args: ['Alice', ...connection] },
  attenuate: { step: 'A2', args: [readonly, '--out', missing('out.macaroon'), '--expires', '1d', '--dry-run'] },
} as const;
type Command = keyof typeof commands;

const unsafe = [['NODE_DEBUG', 'http'], ['NODE_DEBUG', 'https'], ['NODE_DEBUG', 'tls'], ['NODE_DEBUG', 'net'],
  ['NODE_DEBUG', 'fs,NET'], ['NODE_DEBUG', 'ht*'], ['NODE_OPTIONS', '--report-on-fatalerror']] as const;

afterEach(() => { vi.unstubAllEnvs(); });

type Document = { command: string; ok: boolean; error: { code: number; step: string | null; message: string } | null };
/** Runs the command as the CLI does and returns its exit code and error. */
async function invoke(command: Command): Promise<{ code: number; error: Document['error'] }> {
  // watch writes its document through its unattended writer (fd 1), so its handler, the one
  // main() calls with process.env, is run directly; main() gives a refusal exit 2.
  if (command === 'watch') {
    const result = await watch([...commands.watch.args]);
    return { code: result.error?.code ?? 0, error: result.error };
  }
  const run = await captureMain(main, [command, ...commands[command].args, '--json']);
  const document = JSON.parse(run.stdout) as Document;
  expect(document.command).toBe(command);
  return { code: run.code, error: document.error };
}

it.each((Object.keys(commands) as Command[]).flatMap(command => unsafe.map(([key, value]) => [command, key, value] as const)))(
  'TESTS-AUDIT/env %s refuses %s=%s with exit 2 at its ENV step', async (command, key, value) => {
    vi.stubEnv(key, value);
    expect(await invoke(command)).toEqual({ code: 2,
      error: { code: 2, step: commands[command].step, message: 'unsafe Node diagnostic settings' } });
  });

it.each(Object.keys(commands) as Command[])('TESTS-AUDIT/env %s passes its ENV step with a harmless NODE_DEBUG', async command => {
  vi.stubEnv('NODE_DEBUG', 'fs');
  vi.stubEnv('NODE_OPTIONS', '');
  const { code, error } = await invoke(command);
  // The next step runs: the missing certificate or own macaroon (exit 4), or the offline dry run (exit 0).
  if (command === 'attenuate') expect({ code, error }).toEqual({ code: 0, error: null });
  else {
    expect(code).toBe(4);
    expect(error!.message).not.toBe('unsafe Node diagnostic settings');
  }
});
