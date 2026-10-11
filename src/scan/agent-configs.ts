// Well-known locations where AI agents and MCP clients keep server configuration,
// including the environment variables (NWC strings, macaroon paths or bytes) that
// grant an agent Lightning spending power. `scan --agent-configs` adds the ones that
// exist for the current user; it reads them like any other scan path (offline,
// read-only, protected names never opened). Sources are cited in docs/spec.md.
import { win32, posix } from 'node:path';
import { Cancelled, cancellable, checkCancellation } from '../cancellation.js';

export type AgentConfigLocation = { client: string; path: string };

export type AgentConfigEnvironment = {
  platform: NodeJS.Platform;
  home: string;
  cwd: string;
  env: Record<string, string | undefined>;
};

function joiner(platform: NodeJS.Platform): (...parts: string[]) => string {
  return platform === 'win32' ? win32.join : posix.join;
}

/** Every candidate location for this platform and user, in a fixed order. Existence is not checked. */
export function agentConfigCandidates({ platform, home, cwd, env }: AgentConfigEnvironment): AgentConfigLocation[] {
  const at = joiner(platform);
  const appData = platform === 'win32' ? env.APPDATA || at(home, 'AppData', 'Roaming') : undefined;
  const xdg = platform !== 'win32' && platform !== 'darwin' ? env.XDG_CONFIG_HOME || at(home, '.config') : undefined;
  // Per-OS application-data directory for desktop apps (Claude Desktop, VS Code, Zed).
  const appDir = (name: string) => platform === 'win32' ? at(appData!, name)
    : platform === 'darwin' ? at(home, 'Library', 'Application Support', name) : at(xdg!, name);
  const user: AgentConfigLocation[] = [
    { client: 'claude-desktop', path: at(appDir('Claude'), 'claude_desktop_config.json') },
    { client: 'claude-code', path: at(home, '.claude.json') },
    { client: 'claude-code', path: at(home, '.claude', 'settings.json') },
    { client: 'cursor', path: at(home, '.cursor', 'mcp.json') },
    { client: 'vscode', path: at(appDir('Code'), 'User', 'mcp.json') },
    { client: 'vscode', path: at(appDir('Code'), 'User', 'settings.json') },
    { client: 'windsurf', path: at(home, '.codeium', 'windsurf', 'mcp_config.json') },
    { client: 'continue', path: at(home, '.continue', 'config.yaml') },
    { client: 'continue', path: at(home, '.continue', 'config.json') },
    { client: 'gemini-cli', path: at(home, '.gemini', 'settings.json') },
    { client: 'codex', path: at(home, '.codex', 'config.toml') },
    { client: 'zed', path: platform === 'win32' ? at(appDir('Zed'), 'settings.json')
      : platform === 'darwin' ? at(home, '.config', 'zed', 'settings.json') : at(xdg!, 'zed', 'settings.json') },
    { client: 'lnget', path: at(home, '.lnget') },
  ];
  const project: AgentConfigLocation[] = [
    { client: 'claude-code', path: at(cwd, '.mcp.json') },
    { client: 'claude-code', path: at(cwd, '.claude', 'settings.json') },
    { client: 'claude-code', path: at(cwd, '.claude', 'settings.local.json') },
    { client: 'cursor', path: at(cwd, '.cursor', 'mcp.json') },
    { client: 'vscode', path: at(cwd, '.vscode', 'mcp.json') },
    { client: 'continue', path: at(cwd, '.continue', 'mcpServers') },
    { client: 'gemini-cli', path: at(cwd, '.gemini', 'settings.json') },
    { client: 'dotenv', path: at(cwd, '.env') },
  ];
  return [...user, ...project];
}

export type AgentConfigDiscovery = { found: AgentConfigLocation[]; absent: AgentConfigLocation[] };

// Errors that mean nothing is at the path. Any other error (EACCES, EIO, ELOOP) passes the
// location on to the scan, which then fails closed instead of reporting it absent.
const MISSING = new Set(['ENOENT', 'ENOTDIR']);
const missing = (error: unknown) => MISSING.has((error as NodeJS.ErrnoException | null)?.code ?? '');

/**
 * Splits the candidates into those that exist (any file type; scan applies its own rules) and
 * those that do not. A symbolic link whose target is missing (`stat` fails with ENOENT or
 * ENOTDIR) is absent. Each call races the invocation's cancellation signal like the scan's own
 * file system layer, so a stalled home or configuration mount cannot hold the command after an
 * interrupt: discovery rejects with Cancelled (exit 6), never records the location as absent.
 */
export async function discoverAgentConfigs(candidates: AgentConfigLocation[],
  lstat: (path: string) => Promise<unknown>, stat?: (path: string) => Promise<unknown>): Promise<AgentConfigDiscovery> {
  const found: AgentConfigLocation[] = [];
  const absent: AgentConfigLocation[] = [];
  const seen = new Set<string>();
  for (const candidate of candidates) {
    if (seen.has(candidate.path)) continue;
    seen.add(candidate.path);
    checkCancellation();
    try {
      const entry = await cancellable(() => lstat(candidate.path)) as { isSymbolicLink?: () => boolean } | null;
      if (stat && entry?.isSymbolicLink?.()) await cancellable(() => stat(candidate.path));
      found.push(candidate);
    } catch (error) {
      if (error instanceof Cancelled) throw error;
      if (missing(error)) absent.push(candidate); else found.push(candidate);
    }
  }
  return { found, absent };
}

export const defaultAgentConfigEnvironment = (home: string): AgentConfigEnvironment =>
  ({ platform: process.platform, home, cwd: process.cwd(), env: { ...process.env } });

