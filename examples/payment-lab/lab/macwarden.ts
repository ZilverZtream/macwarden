import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { LAB_ROOT } from '../src/config.ts';
import { run } from './compose.ts';

/**
 * Runs macwarden from this repository's build (`npm run build` at the root),
 * or the bin.js named by MACWARDEN_JS, for example an installed copy at
 * `<npm prefix>/node_modules/macwarden/dist/bin.js`.
 */

export function macwardenScript(): string {
  const script = resolve(process.env.MACWARDEN_JS ?? join(LAB_ROOT, '..', '..', 'dist', 'bin.js'));
  if (!existsSync(script)) {
    throw new Error(`macwarden is not built at ${script}: run "npm ci && npm run build" at the repository root, `
      + 'or set MACWARDEN_JS to the dist/bin.js of an installed macwarden');
  }
  return script;
}

/**
 * The environment for macwarden: connection settings come from flags only, so
 * MACWARDEN_* connection variables are removed (macwarden refuses a mix of
 * flags and variables), and NODE_OPTIONS and NODE_DEBUG are removed because
 * macwarden refuses to run with them.
 */
function macwardenEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (key.startsWith('MACWARDEN_') || key === 'NODE_OPTIONS' || key === 'NODE_DEBUG') continue;
    env[key] = value;
  }
  return env;
}

export interface BakeRequest {
  label: string;
  preset: 'pay-only' | 'invoice-only' | 'read-only';
  expires: string;
  out: string;
  rest: string;
  tlsCert: string;
  sessionMacaroon: string;
  registry: string;
}

export interface BakeResult {
  rootKeyId: string;
  fingerprint: string;
  grade: string;
  permissions: string[];
}

/** The bake command as an operator would type it (paths, never credential bytes). */
export function bakeArgs(request: BakeRequest): string[] {
  return ['bake', '--label', request.label, '--preset', request.preset, '--expires', request.expires, '--out', request.out,
    '--lnd-rest', request.rest, '--tls-cert', request.tlsCert, '--macaroon', request.sessionMacaroon, '--registry', request.registry];
}

export async function bake(request: BakeRequest): Promise<BakeResult> {
  const result = await run(process.execPath, [macwardenScript(), ...bakeArgs(request), '--json'], { env: macwardenEnv() });
  let document: { ok?: unknown; result?: Record<string, unknown> | null; error?: { message?: unknown } | null };
  try { document = JSON.parse(result.stdout) as typeof document; } catch {
    throw new Error(`macwarden bake ${request.label} exited ${result.code} without JSON output: ${result.stderr.trim()}`);
  }
  if (result.code !== 0 || document.ok !== true || !document.result) {
    throw new Error(`macwarden bake ${request.label} failed (exit ${result.code}): ${String(document.error?.message ?? result.stderr.trim())}`);
  }
  const entry = document.result;
  return {
    rootKeyId: String(entry.rootKeyId),
    fingerprint: String(entry.fingerprint),
    grade: String(entry.grade),
    permissions: Array.isArray(entry.permissions) ? entry.permissions.map(String) : [],
  };
}
