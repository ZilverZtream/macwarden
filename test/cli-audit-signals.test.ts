// Pre-1.4 audit, CLI section: process-level behaviour of main around interrupts, a command that
// never resumes, a leading --json and the output flush limit. Each test loads a fresh copy of the
// CLI module graph, because the interrupt flag and the run state are per process.
import { join, resolve } from 'node:path';
import { readFileSync } from 'node:fs';
import { afterEach, expect, it, vi } from 'vitest';
import { expectDocumentValid } from './helpers/output-schema.js';

vi.mock('../src/watch/output-queue.js', async importOriginal => {
  const actual = await importOriginal<typeof import('../src/watch/output-queue.js')>();
  // watch's final summary is written straight to fd 1; keep it out of the test runner's output.
  return { ...actual, fdWriter: () => async (chunk: Buffer) => chunk.length };
});

afterEach(() => { vi.restoreAllMocks(); process.exitCode = undefined; });

const vector = join(resolve(), 'test/vectors/default-readonly.macaroon');

async function load() {
  vi.resetModules();
  const before = { beforeExit: process.listeners('beforeExit'), uncaught: process.listeners('uncaughtException') };
  const cli = await import('../src/cli.js');
  const { handlers } = await import('../src/commands/handlers.js');
  const { markMutationSent } = await import('../src/process-error-context.js');
  const added = <T>(now: T[], then: T[]) => now.filter(listener => !then.includes(listener));
  const [beforeExit] = added(process.listeners('beforeExit'), before.beforeExit) as Array<(code: number) => void>;
  const [uncaught] = added(process.listeners('uncaughtException'), before.uncaught) as Array<(error: Error) => void>;
  return { cli, handlers, markMutationSent, beforeExit, uncaught };
}

function capture() {
  const sink = { out: '', err: '', exits: [] as Array<number | string | null | undefined> };
  vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: string | Uint8Array) => { sink.out += String(chunk); return true; }) as typeof process.stdout.write);
  vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: string | Uint8Array) => { sink.err += String(chunk); return true; }) as typeof process.stderr.write);
  vi.spyOn(process, 'exit').mockImplementation(((code?: number | string | null) => { sink.exits.push(code); }) as typeof process.exit);
  return sink;
}

const documents = (text: string) => text.split('\n').filter(Boolean).map(line => JSON.parse(line) as Record<string, unknown>);

function respondResult(exitCode: number) {
  return { schema: 1, command: 'respond', ok: true, exitCode, error: null,
    warnings: [{ code: 'interrupted', message: 'interrupted: credentials marked not-run were not changed; rerun the same command to continue' }],
    result: { mode: 'stage', dryRun: false, node: { pubkey: '02' + 'ab'.repeat(32), alias: 'n', network: 'regtest' },
      rootKey0: { present: true, ownOnRootKey0: false, guidance: [] }, own: { rootKeyId: '4294967296' },
      unknown: { rootKeyIds: [], guidance: '' }, revokedButPresent: { rootKeyIds: [], guidance: '' },
      bakingRisk: { rootKeyIds: [], guidance: [] }, outDir: '/srv/out', items: [], unproven: [] } };
}

const blocked = () => {
  const gate: { release?: (value: unknown) => void; entered?: boolean } = {};
  const handler = () => new Promise(release => { gate.release = release; gate.entered = true; });
  return { gate, handler };
};

it('CLI-AUDIT/respond-interrupt an interrupted respond batch counts as an interrupted completion (bin.ts exits at once)', async () => {
  const { cli, handlers } = await load();
  capture();
  vi.spyOn(handlers, 'respond').mockImplementation(async () => { process.emit('SIGHUP'); return respondResult(6) as never; });
  expect(await cli.main(['respond', '--out-dir', '/srv/out', '--yes', '--json'])).toBe(6);
  expect(cli.interruptedCompletion()).toBe(true);
});

it('CLI-AUDIT/respond-interrupt a respond without an interrupt and a watch stopped by its signal are not interrupted completions', async () => {
  const first = await load();
  capture();
  vi.spyOn(first.handlers, 'respond').mockImplementation(async () => respondResult(0) as never);
  expect(await first.cli.main(['respond', '--out-dir', '/srv/out', '--yes', '--json'])).toBe(0);
  expect(first.cli.interruptedCompletion()).toBe(false);
  vi.restoreAllMocks();
  const second = await load();
  capture();
  vi.spyOn(second.handlers, 'watch').mockImplementation(async () => {
    process.emit('SIGHUP');
    return { schema: 1, command: 'watch', ok: true, warnings: [], error: null, result: null } as never;
  });
  await second.cli.main(['watch', '--json']);
  expect(second.cli.interruptedCompletion()).toBe(false);
});

it.each([[false, 6, 'interrupted'], [true, 7, 'run macwarden inventory']] as const)(
  'CLI-AUDIT/second-signal a command blocked in a call that ignores the interrupt ends on the second signal (mutation sent %s)',
  async (mutation, code, message) => {
    const { cli, handlers, markMutationSent } = await load();
    const sink = capture();
    const { gate, handler } = blocked();
    vi.spyOn(handlers, 'inventory').mockImplementation((() => { if (mutation) markMutationSent(); return handler(); }) as never);
    const running = cli.main(['inventory', '--json']);
    await vi.waitFor(() => expect(gate.entered).toBe(true));
    process.emit('SIGHUP');
    await new Promise(done => setImmediate(done));
    expect(sink.exits).toEqual([]);
    expect(sink.out).toBe('');
    process.emit('SIGINT');
    await vi.waitFor(() => expect(sink.exits).toEqual([code]));
    expect(documents(sink.out)).toEqual([expect.objectContaining({ command: 'inventory', ok: false,
      error: { code, step: 'cancelled', message: expect.stringContaining(message) } })]);
    expect(cli.interruptedCompletion()).toBe(true);
    // In the test process.exit returns: the command finishing later writes no second document.
    gate.release!({ schema: 1, command: 'inventory', ok: true, warnings: [], result: null, error: null });
    await running;
    expect(documents(sink.out)).toHaveLength(1);
  });

it('CLI-AUDIT/second-signal text mode writes the interrupt line once on stderr', async () => {
  const { cli, handlers } = await load();
  const sink = capture();
  const { gate, handler } = blocked();
  vi.spyOn(handlers, 'inventory').mockImplementation(handler as never);
  const running = cli.main(['inventory']);
  await vi.waitFor(() => expect(gate.entered).toBe(true));
  process.emit('SIGHUP');
  process.emit('SIGHUP');
  await vi.waitFor(() => expect(sink.exits).toEqual([6]));
  expect(sink.out).toBe('');
  expect(sink.err.match(/^error: /gm)).toHaveLength(1);
  expect(sink.err).toMatch(/interrupted/);
  gate.release!({ schema: 1, command: 'inventory', ok: true, warnings: [], result: null, error: null });
  await running;
  expect(sink.err.match(/^error: /gm)).toHaveLength(1);
});

it('CLI-AUDIT/second-signal watch is never cut short by a second signal', async () => {
  const { cli, handlers } = await load();
  const sink = capture();
  const { gate, handler } = blocked();
  vi.spyOn(handlers, 'watch').mockImplementation(handler as never);
  const running = cli.main(['watch', '--json']);
  await vi.waitFor(() => expect(gate.entered).toBe(true));
  process.emit('SIGHUP');
  process.emit('SIGHUP');
  await new Promise(done => setImmediate(done));
  expect(sink.exits).toEqual([]);
  gate.release!({ schema: 1, command: 'watch', ok: true, warnings: [], result: null, error: null });
  await running;
  expect(sink.exits).toEqual([]);
});

it.each([['--json'], [null]] as const)(
  'CLI-AUDIT/never-resumes an uncaught exception in a command whose promise never settles writes the internal error once (%s)',
  async flag => {
    const { cli, handlers, beforeExit, uncaught } = await load();
    expect(beforeExit).toBeTypeOf('function');
    const sink = capture();
    const { gate, handler } = blocked();
    vi.spyOn(handlers, 'inspect').mockImplementation(handler as never);
    const running = cli.main(['inspect', 'x', ...(flag ? [flag] : [])]);
    await vi.waitFor(() => expect(gate.entered).toBe(true));
    uncaught(new Error('boom'));
    expect(sink.out + sink.err).toBe('');
    // The event loop is empty and main has not resumed.
    beforeExit(8);
    beforeExit(8);
    await vi.waitFor(() => expect(sink.out + sink.err).not.toBe(''));
    expect(process.exitCode).toBe(8);
    if (flag) {
      expect(sink.err).toBe('');
      expect(documents(sink.out)).toEqual([expect.objectContaining({ command: 'inspect', ok: false,
        error: expect.objectContaining({ code: 8, step: 'internal' }) })]);
    } else {
      expect(sink.out).toBe('');
      expect(sink.err).toMatch(/^error: internal[^\n]*\n$/);
    }
    const written = sink.out + sink.err;
    gate.release!({ schema: 1, command: 'inspect', ok: true, warnings: [], result: { text: 'x' }, error: null });
    expect(await running).toBe(8);
    expect(sink.out + sink.err).toBe(written);
  });

it('CLI-AUDIT/never-resumes beforeExit outside a run, or after main wrote its result, writes nothing', async () => {
  const { cli, beforeExit } = await load();
  const sink = capture();
  beforeExit(0);
  expect(await cli.main(['--json'])).toBe(2);
  const written = sink.out;
  beforeExit(0);
  await new Promise(done => setImmediate(done));
  expect(sink.out).toBe(written);
  expect(process.exitCode).toBeUndefined();
});

it('CLI-AUDIT/leading-json a lone --json is a missing command and a leading --json applies to the command', async () => {
  const { cli } = await load();
  let sink = capture();
  expect(await cli.main(['--json'])).toBe(2);
  expect(documents(sink.out)).toEqual([{ schema: 1, command: null, ok: false, warnings: [], result: null,
    error: { code: 2, step: null, message: 'missing command' } }]);
  expect(sink.err).toBe('');
  vi.restoreAllMocks();
  sink = capture();
  expect(await cli.main(['--json', 'inspect', vector])).toBe(0);
  expect(documents(sink.out)).toEqual([expect.objectContaining({ command: 'inspect', ok: true })]);
  vi.restoreAllMocks();
  sink = capture();
  expect(await cli.main(['--json', 'nosuch'])).toBe(2);
  expect(documents(sink.out)).toEqual([expect.objectContaining({ command: null, error: { code: 2, step: null, message: 'unknown flag' } })]);
});

it('CLI-AUDIT/flush-limit the output flush limit holds when the wall clock does not advance', async () => {
  const { cli } = await load();
  vi.spyOn(Date, 'now').mockReturnValue(1_000_000);
  Object.defineProperty(process.stdout, 'writableLength', { configurable: true, get: () => 1 });
  try {
    const started = performance.now();
    await cli.flushStandardStreams();
    expect(performance.now() - started).toBeGreaterThanOrEqual(1_900);
  } finally {
    delete (process.stdout as unknown as Record<string, unknown>).writableLength;
  }
}, 20_000);

it('CLI-AUDIT/version-json --version with --json, in either order, prints one JSON document with the version', async () => {
  const { cli } = await load();
  const version = (JSON.parse(readFileSync(join(resolve(), 'package.json'), 'utf8')) as { version: string }).version;
  for (const args of [['--version', '--json'], ['--json', '--version']]) {
    vi.restoreAllMocks();
    const sink = capture();
    expect(await cli.main(args)).toBe(0);
    expect(sink.err).toBe('');
    const [document, ...rest] = documents(sink.out);
    expect(rest).toEqual([]);
    expect(document).toEqual({ schema: 1, command: null, ok: true, warnings: [], result: { version }, error: null });
    expectDocumentValid(document as { command: null });
  }
  vi.restoreAllMocks();
  const sink = capture();
  expect(await cli.main(['--version'])).toBe(0);
  expect(sink.out).toBe(`${version}
`);
  expect(sink.err).toBe('');
});
