import { createHash, randomBytes } from 'node:crypto';
import * as fs from 'node:fs/promises';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { afterAll, expect, it } from 'vitest';
import { run } from '../src/commands/scan.js';
import { agentConfigCandidates } from '../src/scan/agent-configs.js';
import { mcpServerStringSpans, withinSpans } from '../src/scan/mcp-context.js';
import type { ScanResult } from '../src/scan/index.js';

const repo = resolve();
const scratch = mkdtempSync(join(resolve(process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp')), 'agent-configs-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

it('AGENT-CONFIGS/candidates are the documented per-OS locations', () => {
  const win = agentConfigCandidates({ platform: 'win32', home: 'C:\\Users\\op', cwd: 'D:\\proj',
    env: { APPDATA: 'C:\\Users\\op\\AppData\\Roaming' } }).map(item => item.path);
  expect(win).toEqual(expect.arrayContaining([
    'C:\\Users\\op\\AppData\\Roaming\\Claude\\claude_desktop_config.json',
    'C:\\Users\\op\\.claude.json',
    'C:\\Users\\op\\.cursor\\mcp.json',
    'C:\\Users\\op\\AppData\\Roaming\\Code\\User\\mcp.json',
    'C:\\Users\\op\\.codeium\\windsurf\\mcp_config.json',
    'C:\\Users\\op\\.lnget',
    'D:\\proj\\.mcp.json',
    'D:\\proj\\.vscode\\mcp.json',
    'D:\\proj\\.env',
  ]));
  const mac = agentConfigCandidates({ platform: 'darwin', home: '/Users/op', cwd: '/w', env: {} }).map(item => item.path);
  expect(mac).toEqual(expect.arrayContaining([
    '/Users/op/Library/Application Support/Claude/claude_desktop_config.json',
    '/Users/op/Library/Application Support/Code/User/mcp.json',
    '/Users/op/.cursor/mcp.json', '/w/.cursor/mcp.json']));
  const linux = agentConfigCandidates({ platform: 'linux', home: '/home/op', cwd: '/w', env: { XDG_CONFIG_HOME: '/cfg' } }).map(item => item.path);
  expect(linux).toEqual(expect.arrayContaining(['/cfg/Claude/claude_desktop_config.json', '/cfg/Code/User/mcp.json',
    '/cfg/zed/settings.json', '/home/op/.gemini/settings.json', '/home/op/.codex/config.toml']));
  expect(agentConfigCandidates({ platform: 'linux', home: '/home/op', cwd: '/w', env: {} }).map(item => item.path))
    .toContain('/home/op/.config/Code/User/mcp.json');
});

it('AGENT-CONFIGS/mcp server spans cover values under server entries only, with JSONC tolerated', () => {
  const text = [
    '{',
    '  // user settings',
    '  "editor.fontSize": 12,',
    '  "mcp": { "servers": { "alby": { "env": { "NWC": "inside" }, "args": ["x",], }, }, },',
    '  "servers": { "other": "outside" },',
    '}',
  ].join('\n');
  const spans = mcpServerStringSpans(text, false);
  const at = (needle: string) => {
    const line = text.split('\n').findIndex(row => row.includes(needle));
    return { line: line + 1, column: Array.from(text.split('\n')[line]).join('').indexOf(needle) + 1 };
  };
  expect(withinSpans(at('inside'), spans)).toBe(true);
  expect(withinSpans(at('"x"'), spans)).toBe(true);
  expect(withinSpans(at('outside'), spans)).toBe(false);
  expect(withinSpans(at('editor'), spans)).toBe(false);
  // In a file named mcp.json, top-level "servers" is VS Code's server map.
  expect(mcpServerStringSpans('{"servers":{"a":{"env":{"K":"v"}}}}', true)).toHaveLength(1);
  expect(mcpServerStringSpans('{"servers":{"a":{"env":{"K":"v"}}}}', false)).toHaveLength(0);
  expect(mcpServerStringSpans('{"mcpServers": {"a": {"env": {"K": "v"', false)).toEqual([]);
});

function home(): { home: string; project: string; secret: string; wallet: string; hex: string } {
  const root = mkdtempSync(join(scratch, 'home-'));
  const homeDir = join(root, 'home'), project = join(root, 'project');
  const secret = randomBytes(32).toString('hex'), wallet = randomBytes(32).toString('hex');
  const hex = readFileSync(join(repo, 'test/vectors/default-admin.macaroon')).toString('hex');
  const put = (path: string, content: string) => { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, content); };
  put(join(homeDir, '.cursor', 'mcp.json'), JSON.stringify({ mcpServers: { alby: { command: 'npx', args: ['-y', '@getalby/mcp'],
    env: { NWC_CONNECTION_STRING: `nostr+walletconnect://${wallet}?relay=wss%3A%2F%2Fr.example&secret=${secret}` } } } }, null, 2));
  put(join(homeDir, '.claude.json'), JSON.stringify({ notes: `pasted ${hex}` }, null, 2));
  put(join(project, '.env'), `LND_MACAROON_HEX=${hex}\n`);
  put(join(project, 'unrelated.env'), `LND_MACAROON_HEX=${hex}\n`);
  return { home: homeDir, project, secret, wallet, hex };
}

it('AGENT-CONFIGS/--agent-configs scans existing agent locations only, tags MCP server values and lists what was absent', async () => {
  const fake = home();
  const environment = () => ({ platform: process.platform, home: fake.home, cwd: fake.project,
    env: { APPDATA: join(fake.home, 'AppData', 'Roaming'), XDG_CONFIG_HOME: join(fake.home, '.config') } });
  const output = await run(['--agent-configs'], { fs, agentEnvironment: environment });
  expect(output.ok).toBe(true);
  const result = output.result as ScanResult;
  const nwcFingerprint = `fp:${createHash('sha256').update(Buffer.from(fake.secret, 'hex')).digest('hex').slice(0, 16)}`;
  const byFile = (name: string) => result.findings.filter(finding => finding.path.endsWith(name));
  expect(byFile('mcp.json')).toEqual([expect.objectContaining({ kind: 'nwc', fingerprint: nwcFingerprint, context: 'mcp-config' })]);
  expect(byFile('.claude.json')).toEqual([expect.objectContaining({ kind: 'macaroon-hex', fingerprint: 'fp:c1034ad4f2a2a06f' })]);
  expect(byFile('.claude.json')[0].context).toBeUndefined();
  expect(byFile('.env')).toHaveLength(1);
  // Without explicit paths only agent locations are scanned, not the working directory.
  expect(byFile('unrelated.env')).toEqual([]);
  expect(result.summary.agentConfigs?.found.map(item => item.path).sort()).toEqual(
    [join(fake.home, '.claude.json'), join(fake.home, '.cursor', 'mcp.json'), join(fake.project, '.env')].sort());
  expect(result.summary.agentConfigs?.absent.length).toBeGreaterThan(10);
  const text = JSON.stringify(output);
  for (const value of [fake.secret, fake.hex]) expect(text).not.toContain(value);
});

it('AGENT-CONFIGS/--agent-configs with paths scans both and keeps fail-on semantics', async () => {
  const fake = home();
  const environment = () => ({ platform: process.platform, home: fake.home, cwd: fake.project, env: {} });
  const output = await run([fake.project, '--agent-configs', '--fail-on', 'ADMIN'], { fs, agentEnvironment: environment });
  const result = output.result as ScanResult;
  const ending = (suffix: string) => result.findings.filter(finding => finding.path.replace(/\\/g, '/').endsWith(suffix));
  expect(ending('project/unrelated.env')).toHaveLength(1);
  // The project .env is reached both as a path and as an agent location; it is reported once.
  expect(ending('project/.env')).toHaveLength(1);
  expect(output.exitCode).toBe(1);
  expect((await run(['--agent-configs', '--agent-configs'], { fs })).error).toMatchObject({ code: 2 });
});
