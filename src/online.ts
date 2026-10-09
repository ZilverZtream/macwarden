import { readCredential, type InputIO } from './input/index.js';
import { cancellable } from './cancellation.js';
import { constants } from 'node:fs';
import { resolve } from 'node:path';
import type { LndAdapter } from './lnd/index.js';
import { LndError } from './errors.js';
import snapshot from './grade/lnd-permissions.json' with { type: 'json' };

export function endpoint(host: string): string | null {
  if (!/:[0-9]{1,5}$/.test(host)) return null;
  try {
    const url = new URL(`https://${host}`);
    return url.hostname && !url.username && !url.password && url.pathname === '/'
      && !url.search && !url.hash ? url.href : null;
  } catch { return null; }
}
export function credentialText(value: string): boolean {
  return value === '-' || /^lndconnect:\/\//i.test(value) || /^(?:0x)?02(?:[0-9a-f]{2})+$/i.test(value)
    || /^Ag[A-Za-z0-9+/_-]{20,}={0,2}$/.test(value);
}
/** Shared wording for refused labels; names the rule, never the value. */
export const LABEL_RULE = 'must start with a letter and contain only letters, digits, ".", "_" or "-" (at most 64 characters)';

/**
 * The first problem with the online connection arguments, or null. The message names the
 * flag and its environment variable and the rule, never the supplied value (SAFE-01).
 */
export function connectionProblem(host: string | undefined, cert: string | undefined, own: string | undefined): string | null {
  if (!host) return '--lnd-rest (or MACWARDEN_LND_REST) is required: the LND REST address as host:port';
  if (!cert) return '--tls-cert (or MACWARDEN_TLS_CERT) is required: the path to the LND tls.cert file';
  if (!own) return '--macaroon (or MACWARDEN_MACAROON) is required: the path to the macaroon file macwarden uses';
  if (own === '-') return '--macaroon must be a file path; stdin (-) is not accepted for macwarden\'s own macaroon';
  if (credentialText(own)) return '--macaroon must be a file path; a literal credential is refused';
  if (!endpoint(host)) return '--lnd-rest (or MACWARDEN_LND_REST) must be host:port, without scheme, path, query or user information';
  return null;
}

const CONNECTION = [
  { key: 'host', flag: '--lnd-rest', variable: 'MACWARDEN_LND_REST' },
  { key: 'cert', flag: '--tls-cert', variable: 'MACWARDEN_TLS_CERT' },
  { key: 'own', flag: '--macaroon', variable: 'MACWARDEN_MACAROON' },
  { key: 'grpc', flag: '--lnd-grpc', variable: 'MACWARDEN_LND_GRPC' },
] as const;
export type ConnectionSettings = { host?: string; cert?: string; own?: string; grpc?: string; problem: string | null };

/**
 * The node address, its TLS certificate and the credential macwarden presents come from one
 * source: when any of them is given as a flag, all of them must be flags, so a credential
 * exported for one node is never sent to a node named on the command line (and the reverse).
 * With no connection flag, all come from the environment. `grpc` (watch) joins the set when
 * `withGrpc` is true. A mixed invocation sets `problem`, naming the variables, never values.
 */
export function connectionSettings(flag: (name: string) => string | undefined, env: Record<string, string | undefined>,
  withGrpc = false): ConnectionSettings {
  const items = CONNECTION.filter(item => withGrpc || item.key !== 'grpc');
  const flagged = items.filter(item => flag(item.flag) !== undefined);
  const settings: ConnectionSettings = { problem: null };
  if (!flagged.length) {
    for (const item of items) settings[item.key] = env[item.variable];
    return settings;
  }
  for (const item of items) settings[item.key] = flag(item.flag);
  const mixed = items.filter(item => flag(item.flag) === undefined && env[item.variable] !== undefined && env[item.variable] !== '');
  if (mixed.length) settings.problem = `${flagged.map(item => item.flag).join(', ')} given on the command line, so ` +
    `${mixed.map(item => item.variable).join(', ')} from the environment is not used: connection settings come all from flags ` +
    `or all from the environment; give ${mixed.map(item => item.flag).join(', ')} too, or unset ${mixed.map(item => item.variable).join(', ')}`;
  return settings;
}

/** Wording for a value flag given twice or without a value. */
export function flagProblem(flag: string, kind: 'repeated' | 'missing'): string {
  return kind === 'repeated' ? `${flag} was given more than once` : `${flag} needs a value`;
}

export function nodeInfo(info: Awaited<ReturnType<LndAdapter['getInfo']>>) {
  if (!/^(02|03)[0-9a-fA-F]{64}$/.test(info.pubkey)) throw new LndError(5, 'get-info', 'invalid LND response');
  return { ...info, pubkey: info.pubkey.toLowerCase() };
}
export function nodePubkey(info: Awaited<ReturnType<LndAdapter['getInfo']>>): string { return nodeInfo(info).pubkey; }
export function drift(live: Record<string, string[]>): boolean {
  const expected = Object.entries(snapshot.methods);
  return expected.length !== Object.keys(live).length || expected.some(([method, permissions]) =>
    !live[method] || !samePermissions(permissions, live[method]));
}
export function samePermissions(a: string[], b: string[]): boolean {
  return [...new Set(a)].sort().join('\0') === [...new Set(b)].sort().join('\0');
}
export async function listIds(lnd: LndAdapter): Promise<bigint[]> { return lnd.listMacaroonIds(); }
export function failureDetails(error: unknown): { code: number; message: string } {
  if (!(error instanceof LndError)) throw error;
  return { code: error.code, message: error.code === 4
    ? 'LND transport, TLS or authentication failure' : 'LND request failed' };
}
export { readBoundedFile } from './bounded-file.js';

export function onlineAdapter(adapter: LndAdapter): LndAdapter {
  return {
    getInfo: () => cancellable(() => adapter.getInfo()),
    listPermissions: () => cancellable(() => adapter.listPermissions()),
    listMacaroonIds: () => cancellable(() => adapter.listMacaroonIds()),
    bakeMacaroon: (permissions, id) => cancellable(() => adapter.bakeMacaroon(permissions, id)),
    deleteMacaroonId: id => cancellable(() => adapter.deleteMacaroonId(id)),
    checkMacaroon: (mac, permissions) => cancellable(() => adapter.checkMacaroon(mac, permissions)),
  };
}

/**
 * Quotes one argument of a command macwarden prints for the operator to paste.
 * POSIX shells get single quotes with '"'"' for a quote. On Windows the commands are for
 * PowerShell (cmd.exe does not treat single quotes as quotes): inside single quotes
 * PowerShell also ends the string at U+2018..U+201B, so every one of them is doubled.
 * The bare set excludes ',' on Windows because PowerShell turns a,b into an array.
 * Control characters are escaped later by the text renderer, so they cannot inject.
 */
export function shellQuote(value: string, platform: NodeJS.Platform = process.platform): string {
  const bare = platform === 'win32' ? /^[A-Za-z0-9_./:-]+$/ : /^[A-Za-z0-9_./:,-]+$/;
  if (bare.test(value)) return value;
  if (platform === 'win32') return `'${value.replace(/['\u2018-\u201B]/g, quote => quote + quote)}'`;
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

/** A path argument for a printed recovery command, absolute so it runs from any directory. */
export function recoveryPath(path: string): string {
  return path === '-' ? path : resolve(path);
}

function onlineRecoveryCommand(request: { registry?: string; host: string; cert: string; own: string }, args: string[]): string {
  if (request.registry) args.push('--registry', recoveryPath(request.registry));
  const url = new URL(request.host);
  args.push('--lnd-rest', `${url.hostname}:${url.port || '443'}`, '--tls-cert', recoveryPath(request.cert),
    '--macaroon', recoveryPath(request.own));
  return args.map(value => shellQuote(value)).join(' ');
}

export function recoveryCommand(request: { registry?: string; host: string; cert: string; own: string }, id: string, unregistered = false): string {
  return onlineRecoveryCommand(request, ['macwarden', 'revoke', id, ...(unregistered ? ['--unregistered'] : [])]);
}

export function inventoryRecoveryCommand(request: { registry?: string; host: string; cert: string; own: string }): string {
  return onlineRecoveryCommand(request, ['macwarden', 'inventory']);
}

export function readOnlineCredential(path: string, io: InputIO) {
  return readCredential(path, { ...io, fs: { ...io.fs,
    open: ((file: Parameters<InputIO['fs']['open']>[0], flags: Parameters<InputIO['fs']['open']>[1], mode?: Parameters<InputIO['fs']['open']>[2]) =>
      io.fs.open(file, typeof flags === 'number' ? flags | constants.O_NONBLOCK : flags, mode)) as InputIO['fs']['open'],
  } }, { unsafeArg: false });
}

export function onlineWarnings<T extends { warnings: import('./output/index.js').OutputWarning[] }>(result: T): T {
  const messages: Record<string, string> = {
    'acl-best-effort': "the volume stores no Windows permissions (FAT or exFAT): anyone with access to the volume can read the file",
    'unsafe-arg': 'literal credentials can appear in shell history and process listings',
    'own-root-key-0': 'own credential uses root key ID 0',
    'snapshot-drift': 'LND permissions differ from the bundled snapshot',
    'canary-requires-watch': 'LND accepts this canary only while macwarden watch runs; a running watch picks it up within 60 seconds (or at its next reconnect), then denies and alerts on every use its permissions allow',
    'usage-unreadable': 'the watch usage file could not be read; last-used data is omitted',
  };
  return { ...result, warnings: result.warnings.map(warning => typeof warning === 'string'
    ? { code: warning, message: messages[warning] ?? warning } : warning) };
}
