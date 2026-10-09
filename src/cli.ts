import { withCancellation } from './cancellation.js';
import { readFileSync } from 'node:fs';
import { handlers } from './commands/handlers.js';
import { error, render, renderChunks, warning, type Mode, type OutputResult } from './output/index.js';
import { fdWriter } from './watch/output-queue.js';
import { internalErrorMessage, withProcessErrorContext, type ProcessErrorContext } from './process-error-context.js';

// Synopses as docs/spec.md states them. Online commands also take the online flags.
const online = ' [--lnd-rest <host:port>] [--tls-cert <path>] [--macaroon <path>]';
const synopses: Record<string, string[]> = {
  inspect: ['inspect <file | -> [--json]',
    'inspect <hex | base64 | lndconnect://... | nostr+walletconnect://... | rune> --unsafe-arg [--json]'],
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
  watch: [`watch [--lnd-grpc <host:port>] [--registry <path>] [--middleware-name <name>] [--until <n>(s|m|h|d)] [--alert-command <path>] [--alerts-only] [--json]${online}`],
  recommend: [`recommend (<label> | <root-key-id> | id:<16 hex> | --target-file <file>) [--accept-short-observation] [--registry <path>] [--json]${online}`],
  respond: [`respond --out-dir <directory> [--allow-admin] [--yes] [--registry <path>] [--break-lock] [--dry-run] [--json]${online}`,
    `respond --finish [--yes] [--registry <path>] [--break-lock] [--dry-run] [--json]${online}`],
  verify: [`verify <file | -> [--registry <path>] [--json]${online}`,
    `verify <hex | base64 | lndconnect://...> --unsafe-arg [--registry <path>] [--json]${online}`],
};
const summaries: [string, string][] = [
  ['inspect', 'decode a macaroon, NWC URI or Core Lightning rune offline and grade what it can do'],
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
];
const usage = ['Usage: macwarden <command> [options]', '       macwarden <command> --help', '       macwarden --help | --version',
  '', 'Commands:', ...summaries.map(([name, summary]) => `  ${name.padEnd(10)} ${summary}`)].join('\n');
const commandUsage = (name: string) => synopses[name].map((line, index) =>
  `${index ? '       ' : 'Usage: '}macwarden ${line}`).join('\n');
const textResult = (text: string): OutputResult => ({ command: null, ok: true, warnings: [], result: { text }, error: null });

const packageVersion = (): string =>
  (JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string }).version;

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

async function write(result: OutputResult, mode: Mode): Promise<void> {
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

export async function main(argv: string[]): Promise<number> {
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
  const controller = new AbortController();
  const cancel = () => controller.abort();
  const signals: NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGHUP'];
  for (const signal of signals) process.on(signal, cancel);
  activeContext = context;
  const command = argv[0] && Object.hasOwn(handlers, argv[0]) ? argv[0] as keyof typeof handlers : null;
  const handler = command ? handlers[command] : undefined;
  try {
    if (argv.length === 1 && argv[0] === '--version') {
      process.stdout.write(render({ command: null, ok: true, warnings: [], result: { text: packageVersion() }, error: null }, 'text'));
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
      // watch streams events while it runs, so it alone keeps --json to format them.
      const args = argv.slice(1).filter((arg, index) => arg !== '--json' || command === 'watch' ||
        (boundary >= 0 && index + 1 > boundary));
      const result = await withProcessErrorContext(context, () => withCancellation(controller.signal, () => handler(args)));
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
          context.mutationSent ? 'operation interrupted after mutation; completed state retained; run macwarden inventory to inspect state'
            : copied ? 'operation interrupted after the output file was written; the written copy is complete and kept'
              : 'operation interrupted before mutation', command);
        await write(interrupted, mode);
        return interrupted.error!.code;
      }
      if (result.ok && result.command === 'scan' && result.display?.format === 'sarif')
        result.display.toolVersion = packageVersion();
      // watch runs unattended; its summary goes to a reader that may never read again,
      // so the write is bounded. Everything else waits for its output as before.
      if (command === 'watch') await writeUnattended(result, mode, WATCH_SUMMARY_WRITE_MS);
      else await write(result, mode);
      return result.error?.code ?? result.exitCode ?? 0;
    }
    // Fixed reasons only: the argument itself is never echoed (it may be a credential).
    await write(failure(2, null, argv.length === 0 ? 'missing command'
      : argv[0].startsWith('-') ? 'unknown flag' : 'unknown command'), mode);
    if (mode === 'text') process.stderr.write(render(textResult(usage), 'text'));
    return 2;
  } catch {
    await write(failure(8, 'internal', internalErrorMessage(context), command), mode);
    return 8;
  } finally {
    for (const signal of signals) process.off(signal, cancel);
    mainActive = false;
  }
}

export function completionStatus(status: number): number { return internalFailure ? 8 : status; }
