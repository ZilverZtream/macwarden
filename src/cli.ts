import { Cancelled, withCancellation } from './cancellation.js';
import { nodeVersionWarning, unsafeNodeFlags } from './environment.js';
import { handlers } from './commands/handlers.js';
import { macwardenVersion } from './version.js';
import { error, render, renderChunks, warning, type Mode, type OutputResult } from './output/index.js';
import { fdWriter } from './watch/output-queue.js';
import { internalErrorMessage, withProcessErrorContext, type ProcessErrorContext } from './process-error-context.js';

// Synopses as docs/spec.md states them. Online commands also take the online flags.
const online = ' [--lnd-rest <host:port>] [--tls-cert <path>] [--macaroon <path>]';
const synopses: Record<string, string[]> = {
  inspect: ['inspect <file | -> [--json]',
    'inspect <hex | base64 | lndconnect://... | nostr+walletconnect://... | L402 <macaroon>:<preimage> | rune> --unsafe-arg [--json]'],
  scan: ['scan [paths...] [--fail-on ADMIN|SPEND|OPERATE|RECEIVE|READ] [--include-dirs] [--ignore-file <path>]'
    + ' [--git-history [--allow-shallow]] [--agent-configs] [--format text|json|sarif|github] [--json]'],
  inventory: [`inventory [--verify] [--expiring-within <n>(m|h|d)] [--report markdown|csv|json [--out <file>]] [--registry <path>] [--json]${online}`],
  bake: ['bake --label <name> (--preset <name> | --permissions <entity:action,...> [--uri </pkg.Svc/Method,...>] | --uri <...>)'
    + ` [--expires <n>(m|h|d)] --out <file> [--allow-admin] [--registry <path>] [--break-lock] [--dry-run] [--json]${online}`,
    `bake --label <name> --canary [--preset <name> | --permissions <...> | --uri <...>] [--expires <n>(m|h|d)] --out <file> [--registry <path>] [--dry-run] [--json]${online}`],
  revoke: ['revoke <label | root-key-id> [--target-file <file>] [--unregistered] [--yes] [--registry <path>]'
    + ` [--break-lock] [--dry-run] [--json]${online}`],
  rotate: [`rotate <label> --out <file> [--allow-admin] [--registry <path>] [--break-lock] [--dry-run] [--json]${online}`,
    `rotate <label> --finish [--yes] [--registry <path>] [--break-lock] [--dry-run] [--json]${online}`],
  attenuate: ['attenuate <file | -> --out <file> [--expires <n>(m|h|d)] [--ip <address> | --ip-range <cidr>] [--dry-run] [--unsafe-arg] [--json]'],
  watch: [`watch [--lnd-grpc <host:port>] [--registry <path>] [--middleware-name <name>] [--until <n>(s|m|h|d)] [--alert-command <path>] [--alerts-only] [--payment-journal <path>] [--json]${online}`],
  recommend: [`recommend (<label> | <root-key-id> | id:<16 hex> | --target-file <file>) [--accept-short-observation] [--registry <path>] [--json]${online}`],
  respond: [`respond --out-dir <directory> [--allow-admin] [--yes] [--registry <path>] [--break-lock] [--dry-run] [--json]${online}`,
    `respond --finish [--yes] [--registry <path>] [--break-lock] [--dry-run] [--json]${online}`],
  verify: [`verify <file | -> [--registry <path>] [--json]${online}`,
    `verify <hex | base64 | lndconnect://...> --unsafe-arg [--registry <path>] [--json]${online}`],
  reconcile: [`reconcile --payment-journal <path> [--since <time|n(m|h|d)>] [--until <time|n(m|h|d)>] [--registry <path>] [--json]${online}`],
};
const summaries: [string, string][] = [
  ['inspect', 'decode a macaroon, NWC URI, L402 token or Core Lightning rune offline and grade what it can do'],
  ['scan', 'find credentials in files and, with --git-history, in git history (offline)'],
  ['inventory', "list the node's root key IDs against the registry"],
  ['bake', 'issue a least-privilege macaroon on its own root key ID and record it'],
  ['revoke', 'delete a root key ID and record the revocation'],
  ['rotate', 'replace a macaroon in two steps: stage, then --finish'],
  ['attenuate', 'add expiry or IP caveats to a copy of a macaroon offline'],
  ['watch', 'observe which credential makes which call (read-only LND middleware); guard canaries'],
  ['recommend', 'suggest the least permissions a credential needs from observed usage'],
  ['respond', 'after a suspected leak: stage replacements for every credential, then --finish with proof'],
  ['verify', 'ask LND whether one credential file is still accepted (after a leak)'],
  ['reconcile', "match watch's payment journal against LND's payment records, per credential"],
];
const usage = ['Usage: macwarden <command> [options]', '       macwarden <command> --help', '       macwarden --help | --version',
  '', 'Commands:', ...summaries.map(([name, summary]) => `  ${name.padEnd(10)} ${summary}`)].join('\n');
const commandUsage = (name: string) => synopses[name].map((line, index) =>
  `${index ? '       ' : 'Usage: '}macwarden ${line}`).join('\n');
const textResult = (text: string): OutputResult => ({ command: null, ok: true, warnings: [], result: { text }, error: null });

// One reader of the installed version, which never throws (audit 1.3.2).
const packageVersion = macwardenVersion;

function failure(code: number, step: string | null, message: string, command: string | null = null): OutputResult {
  return {
    command,
    ok: false,
    warnings: [],
    result: null,
    error: { code, step, message },
  };
}

type Sink = Pick<NodeJS.WriteStream, 'write' | 'once' | 'off'>;

// A reader that stops early (`macwarden scan | head`) closes the pipe. Output to that
// stream stops quietly and the command keeps its computed exit status.
const closedStreams = new WeakSet<object>();

/** Writes chunks in order, waiting for 'drain' so large output is never buffered whole. */
export async function writeChunks(stream: Sink, chunks: Iterable<string>): Promise<void> {
  for (const chunk of chunks) {
    if (closedStreams.has(stream)) return;
    if (!stream.write(chunk)) {
      await new Promise<void>(resolve => {
        const done = () => { stream.off('drain', done); stream.off('close', done); stream.off('error', done); resolve(); };
        stream.once('drain', done);
        stream.once('close', done);
        stream.once('error', done);
      });
    }
  }
}

// Set once an interrupt result (exit 6 or 7, step `cancelled`) is written, or any other result of
// a command other than watch after an interrupt (respond reports its interrupted batch as its own
// result, exit 6 or 7): the command has stopped and run its cleanup (lock release, unwritten --out
// removal), but a file system call it abandoned (a stalled mount) may still be pending and keep
// the process alive (1.2.1).
let interruptWritten = false;

/** Whether this process wrote an interrupt result, or a command's result after an interrupt (not watch). */
export function interruptedCompletion(): boolean { return interruptWritten; }

/**
 * Resolves once stdout and stderr hold no unwritten output (or are closed), or after
 * FLUSH_LIMIT_MS. A write that stayed under the high-water mark emits no 'drain' when it
 * completes (pipes write asynchronously on POSIX), so completion is observed by polling the
 * queue length rather than by waiting for an event.
 */
export async function flushStandardStreams(): Promise<void> {
  // Monotonic: a wall clock stepped back would extend the wait past the limit.
  const deadline = performance.now() + FLUSH_LIMIT_MS;
  const pending = (stream: NodeJS.WriteStream) => !closedStreams.has(stream) && !stream.destroyed && stream.writableLength > 0;
  while ([process.stdout, process.stderr].some(pending) && performance.now() < deadline) {
    await new Promise<void>(resolve => setTimeout(resolve, 5));
  }
}

const FLUSH_LIMIT_MS = 2_000;

const MUTATION_INTERRUPTED = 'operation interrupted after mutation; completed state retained; run macwarden inventory to inspect state';

// The invocation main is running: its output mode, command and error context, and whether its one
// document has been written. A second signal and the beforeExit fallback write a document only
// when main has not; once they have, main writes nothing more (`closed`).
type ActiveRun = { mode: Mode; command: string | null; context: ProcessErrorContext; written: boolean; closed: boolean };
let activeRun: ActiveRun | undefined;

async function write(result: OutputResult, mode: Mode): Promise<void> {
  if (activeRun?.closed) return;
  if (activeRun) activeRun.written = true;
  return writeDocument(result, mode);
}

/**
 * A second SIGINT, SIGTERM or SIGHUP while the command is still blocked (a call that does not
 * observe cancellation, such as a file system call on a stalled mount): the interrupt result is
 * written, exit 6, or 7 once a change may have reached LND, and the process ends without waiting
 * for the command.
 */
async function forceInterrupt(run: ActiveRun): Promise<void> {
  if (run.written) return;
  run.written = run.closed = true;
  const code = run.context.mutationSent ? 7 : 6;
  await writeDocument(failure(code, 'cancelled', code === 7 ? MUTATION_INTERRUPTED : 'interrupted', run.command), run.mode)
    .catch(() => undefined);
  await flushStandardStreams();
  process.exit(completionStatus(code));
}

async function writeDocument(result: OutputResult, mode: Mode): Promise<void> {
  if (result.error?.step === 'cancelled' && (result.error.code === 6 || result.error.code === 7)) interruptWritten = true;
  // The first chunk is produced before anything is written: assertPlain and the
  // secret collection run first, so a rendering failure emits no partial output.
  const chunks = renderChunks(result, mode);
  const first = chunks.next();
  const all = first.done ? [] : (function* () { yield first.value; yield* chunks; })();
  if (mode === 'json') return writeChunks(process.stdout, all);
  await writeChunks(process.stderr, result.warnings.map(code => warning(code)));
  return writeChunks(result.ok ? process.stdout : process.stderr, all);
}

/** How long watch waits for its final summary to be written before giving up on the reader. */
export const WATCH_SUMMARY_WRITE_MS = 2_000;

/**
 * Writes a result off the event loop with a time limit. process.stdout writes to a pipe
 * synchronously on Windows (and on Linux once the pipe is full), so a reader that never
 * reads would block the event loop for good and nothing, not even an exit timer, could run.
 * fdWriter writes through the thread pool and retries EAGAIN with unref'd timers; after the
 * deadline the write is abandoned. Used for watch, which runs unattended.
 */
async function writeUnattended(result: OutputResult, mode: Mode, deadlineMs: number): Promise<void> {
  let stopped = false;
  const toStderr = mode !== 'json' && !result.ok;
  const parts: string[] = mode === 'json' ? [] : result.warnings.map(code => warning(code));
  const body = [...renderChunks(result, mode)].join('');
  const writes = async () => {
    if (parts.length) await fdWriter(2, undefined, undefined, () => stopped)(Buffer.from(parts.join(''), 'utf8'));
    let rest = Buffer.from(body, 'utf8');
    const writer = fdWriter(toStderr ? 2 : 1, undefined, undefined, () => stopped);
    while (rest.length && !stopped) rest = rest.subarray(await writer(rest));
  };
  // The deadline timer is not unref'd: it is what keeps the process alive while the write is
  // pending (the retry timers are unref'd), so the result settles before the process can end.
  // It is cleared as soon as the write finishes, so a healthy exit is not delayed.
  let deadline: ReturnType<typeof setTimeout> | undefined;
  await Promise.race([writes().catch(() => undefined),
    new Promise<void>(resolve => { deadline = setTimeout(() => { stopped = true; resolve(); }, deadlineMs); })]);
  clearTimeout(deadline);
}

let mainActive = false;
let internalFailure = false;
let activeContext: ProcessErrorContext | undefined;

function installProcessHandlers(): void {
  const report = (): void => {
    internalFailure = true;
    process.exitCode = 8;
    if (!mainActive) process.stderr.write(error('internal', internalErrorMessage(activeContext)));
  };
  process.on('uncaughtException', report);
  process.on('unhandledRejection', report);
  // The event loop emptied while a command's promise never settled (after an uncaught exception
  // in a callback, say): main will not resume to write its result, so the internal error is
  // written here, once, in the run's output mode.
  process.on('beforeExit', () => {
    const run = activeRun;
    if (!run || run.written) return;
    internalFailure = true;
    process.exitCode = 8;
    run.written = run.closed = true;
    void writeDocument(failure(8, 'internal', internalErrorMessage(run.context), run.command), run.mode).catch(() => undefined);
  });
  for (const stream of [process.stdout, process.stderr]) {
    stream.on('error', (failure: NodeJS.ErrnoException) => {
      if (failure.code === 'EPIPE') closedStreams.add(stream);
      else report();
    });
  }
  process.removeAllListeners('warning');
  process.on('warning', () => {});
}

installProcessHandlers();

/** `macwarden --json <command> …` is `macwarden <command> --json …`. */
export function normalizedArgv(rawArgv: readonly string[]): string[] {
  return rawArgv[0] === '--json' && rawArgv.length > 1 && Object.hasOwn(handlers, rawArgv[1])
    ? [rawArgv[1], '--json', ...rawArgv.slice(2)] : [...rawArgv];
}

export async function main(rawArgv: string[], runtime: { execArgv?: readonly string[]; nodeVersion?: string } = {}): Promise<number> {
  const argv = normalizedArgv(rawArgv);
  const boundary = argv.indexOf('--');
  const flagsEnd = boundary < 0 ? argv.length : boundary;
  const flags = argv.slice(0, flagsEnd);
  // scan --format json is the same as --json; the other formats are text-mode renderings.
  const formatAt = argv[0] === 'scan' ? flags.indexOf('--format') : -1;
  const format = formatAt > 0 ? argv[formatAt + 1] : undefined;
  const mode: Mode = flags.includes('--json') || format === 'json' ? 'json' : 'text';
  if (internalFailure) return 8;
  mainActive = true;
  const context: ProcessErrorContext = { mutationSent: false };
  const command = argv[0] && Object.hasOwn(handlers, argv[0]) ? argv[0] as keyof typeof handlers : null;
  const handler = command ? handlers[command] : undefined;
  const run: ActiveRun = { mode, command, context, written: false, closed: false };
  activeRun = run;
  const controller = new AbortController();
  let received = 0;
  const cancel = () => {
    controller.abort();
    // watch stops on a signal and then ends its alert commands (bin.ts); it is never cut short.
    if (++received >= 2 && command !== 'watch') void forceInterrupt(run);
  };
  const signals: NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGHUP'];
  for (const signal of signals) process.on(signal, cancel);
  activeContext = context;
  try {
    if (argv.length === 1 && argv[0] === '--version') {
      process.stdout.write(render({ command: null, ok: true, warnings: [], result: { text: packageVersion() }, error: null }, 'text'));
      return 0;
    }
    if (argv.length === 2 && argv.includes('--version') && argv.includes('--json')) {
      // The version as one JSON document, `result: {"version"}`; schemas/output/macwarden.schema.json.
      const version = { command: null, ok: true, warnings: [], result: { version: packageVersion() }, error: null };
      await write(version as unknown as OutputResult, 'json');
      return 0;
    }
    if (argv.length === 2 && argv.includes('--help') && argv.includes('--json')) {
      // Top-level help as one JSON document (MW110-10); schemas/output/macwarden.schema.json.
      const help = { command: null, ok: true, warnings: [], result: {
        usage: usage.split('\n').slice(0, 3).map(line => line.replace(/^(?:Usage: | +)/, '')),
        commands: summaries.map(([name, summary]) => ({ name, summary })) }, error: null };
      await write(help as unknown as OutputResult, 'json');
      return 0;
    }
    if (argv.length === 1 && argv[0] === '--help') {
      process.stdout.write(render(textResult(usage), 'text'));
      return 0;
    }
    if (command && argv.slice(1, flagsEnd).includes('--help')) {
      // With --json, help is one JSON document like every other output (MW110-10).
      if (mode === 'json') {
        // Rendered only as JSON, so it goes through the same JSON writer without a per-command result type.
        const help = { command, ok: true, warnings: [], result: { usage: synopses[command].map(line => `macwarden ${line}`) },
          error: null };
        await write(help as unknown as OutputResult, 'json');
        return 0;
      }
      process.stdout.write(render(textResult(commandUsage(command)), 'text'));
      return 0;
    }
    if (command === 'scan' && flags.includes('--json') && (format === 'sarif' || format === 'github')) {
      await write(failure(2, null, `--json cannot be combined with --format ${format}`, command), 'text');
      return 2;
    }
    if (command && handler) {
      // Node flags and an unsupported Node version are refused before any command runs (1.2.1):
      // the flags could expose what the command handles, and watch's HTTP/2 client depends on
      // the fixed Node releases package.json names.
      if (runtime.execArgv && unsafeNodeFlags(runtime.execArgv)) { await write(failure(2, null, 'unsafe Node diagnostic settings (node flags)', command), mode); return 2; }
      // --json is removed before the command parses its flags, so a repeat is refused here as every
      // other repeated flag is by its command (audit 1.3.2); watch parses --json itself.
      if (command !== 'watch' && flags.filter(arg => arg === '--json').length > 1) {
        await write(failure(2, null, '--json was given more than once', command), mode);
        return 2;
      }
      const unsupported = command === 'watch' && runtime.nodeVersion !== undefined ? nodeVersionWarning(runtime.nodeVersion) : null;
      // watch streams events while it runs, so it alone keeps --json to format them.
      const args = argv.slice(1).filter((arg, index) => arg !== '--json' || command === 'watch' ||
        (boundary >= 0 && index + 1 > boundary));
      const result = await withProcessErrorContext(context, () => withCancellation(controller.signal, () => handler(args)));
      if (unsupported && result.warnings) result.warnings.unshift(unsupported);
      if (internalFailure) {
        await write(failure(8, 'internal', internalErrorMessage(context), command), mode);
        return 8;
      }
      // watch runs until interrupted: a signal is its normal, clean stop (streams unregistered).
      // respond observes the interrupt itself and reports which credentials were staged,
      // finished or not run, with exit 7 or 6 (SPEC 10), so its result is kept as it is.
      if (controller.signal.aborted && result.ok && command !== 'watch' && command !== 'respond') {
        // attenuate changes nothing in LND; once its output file is written the copy is complete.
        const copied = command === 'attenuate' && (result.result as { dryRun?: unknown; out?: unknown } | null)?.dryRun === false &&
          typeof (result.result as { out?: unknown }).out === 'string';
        const interrupted = failure(context.mutationSent ? 7 : 6, 'cancelled',
          context.mutationSent ? MUTATION_INTERRUPTED
            : copied ? 'operation interrupted after the output file was written; the written copy is complete and kept'
              : 'interrupted', command);
        await write(interrupted, mode);
        return interrupted.error!.code;
      }
      if (result.ok && result.command === 'scan' && result.display?.format === 'sarif')
        result.display.toolVersion = packageVersion();
      // watch runs unattended; its summary goes to a reader that may never read again,
      // so the write is bounded. Everything else waits for its output as before.
      if (command === 'watch') {
        run.written = true;
        await writeUnattended(result, mode, WATCH_SUMMARY_WRITE_MS);
      } else {
        await write(result, mode);
        // A result written after an interrupt (respond's interrupted batch, exit 6 or 7) ends the
        // run like an interrupt result: bin.ts then exits without waiting for abandoned calls.
        if (controller.signal.aborted) interruptWritten = true;
      }
      return result.error?.code ?? result.exitCode ?? 0;
    }
    // Fixed reasons only: the argument itself is never echoed (it may be a credential).
    await write(failure(2, null, argv.length === 0 || argv.every(arg => arg === '--json') ? 'missing command'
      : argv[0].startsWith('-') ? 'unknown flag' : 'unknown command'), mode);
    if (mode === 'text') process.stderr.write(render(textResult(usage), 'text'));
    return 2;
  } catch (error) {
    // An interrupt that a command did not turn into its own result (one that landed in its first LND
    // calls) is still an interrupt, not an internal failure: exit 6, or 7 once a change may have reached LND.
    if (error instanceof Cancelled) {
      const interrupted = failure(context.mutationSent ? 7 : 6, 'cancelled', context.mutationSent ? MUTATION_INTERRUPTED : 'interrupted', command);
      await write(interrupted, mode);
      return interrupted.error!.code;
    }
    await write(failure(8, 'internal', internalErrorMessage(context), command), mode);
    return 8;
  } finally {
    for (const signal of signals) process.off(signal, cancel);
    if (activeRun === run) activeRun = undefined;
    mainActive = false;
  }
}

export function completionStatus(status: number): number { return internalFailure ? 8 : status; }
