import { execFile } from 'node:child_process';
import { join } from 'node:path';
import { LAB_ROOT, type NodeName } from '../src/config.ts';

/**
 * Operator access to the lab containers. These commands use each node's own
 * admin credential inside its container (lncli's default) and bitcoind's RPC
 * password: they are the node operator's tools, for funding, channels and
 * mining. The payment service never uses them; it gets the narrow
 * credentials setup bakes with macwarden.
 */

export const COMPOSE_FILE = join(LAB_ROOT, 'docker-compose.yml');
export const COMPOSE_PROJECT = 'macwarden-payment-lab';
const BITCOIN_RPC = ['-regtest', '-rpcuser=lab', '-rpcpassword=regtest-lab-only'];

export interface CommandResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** Runs a command without a shell; never throws for a non-zero exit. */
export function run(file: string, args: readonly string[], options: { timeoutMs?: number; env?: NodeJS.ProcessEnv } = {}): Promise<CommandResult> {
  return new Promise(resolve => {
    execFile(file, args, { cwd: LAB_ROOT, timeout: options.timeoutMs ?? 120_000, maxBuffer: 32 * 1024 * 1024, env: options.env,
      windowsHide: true, encoding: 'utf8' }, (error, stdout, stderr) => {
      const code = error === null ? 0 : typeof error.code === 'number' ? error.code : 1;
      resolve({ code, stdout, stderr: error !== null && stderr === '' ? error.message : stderr });
    });
  });
}

export function compose(args: readonly string[], timeoutMs?: number): Promise<CommandResult> {
  return run('docker', ['compose', '-f', COMPOSE_FILE, '-p', COMPOSE_PROJECT, ...args], { timeoutMs });
}

export async function composeOrThrow(args: readonly string[], timeoutMs?: number): Promise<string> {
  const result = await compose(args, timeoutMs);
  if (result.code !== 0) throw new Error(`docker compose ${args.join(' ')} failed: ${result.stderr.trim() || result.stdout.trim()}`);
  return result.stdout;
}

/** lncli on one node, as its operator. Returns parsed JSON output. */
export async function lncli(node: NodeName, args: readonly string[], timeoutMs?: number): Promise<Record<string, unknown>> {
  const result = await compose(['exec', '-T', node, 'lncli', '--network=regtest', ...args], timeoutMs);
  if (result.code !== 0) throw new Error(`lncli ${args[0] ?? ''} on ${node} failed: ${result.stderr.trim() || result.stdout.trim()}`);
  const parsed: unknown = JSON.parse(result.stdout);
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(`lncli ${args[0] ?? ''} returned no object`);
  return parsed as Record<string, unknown>;
}

/** lncli where a failure is an expected answer (for example "not found" while gossip propagates). */
export async function lncliMaybe(node: NodeName, args: readonly string[]): Promise<Record<string, unknown> | undefined> {
  try { return await lncli(node, args); } catch { return undefined; }
}

export async function bitcoinCli(args: readonly string[], wallet = true): Promise<string> {
  const result = await compose(['exec', '-T', 'bitcoind', 'bitcoin-cli', ...BITCOIN_RPC, ...(wallet ? ['-rpcwallet=lab'] : []), ...args]);
  if (result.code !== 0) throw new Error(`bitcoin-cli ${args[0] ?? ''} failed: ${result.stderr.trim() || result.stdout.trim()}`);
  return result.stdout.trim();
}

/** Mines blocks to the lab miner address and returns the new height. */
export async function mine(blocks: number): Promise<number> {
  const address = await bitcoinCli(['getnewaddress', 'miner', 'bech32']);
  await bitcoinCli(['generatetoaddress', String(blocks), address]);
  return Number(await bitcoinCli(['getblockcount'], false));
}

export function field(source: Record<string, unknown>, key: string): string {
  const value = source[key];
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  throw new Error(`field ${key} is missing`);
}
