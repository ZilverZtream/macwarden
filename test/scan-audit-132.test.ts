import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { main } from '../src/cli.js';
import { run } from '../src/commands/scan.js';
import { captureMain } from './support/capture.js';
import { scratch } from './support/cp039-audit.js';
import { token } from './helpers/l402-vectors.js';
import { restrictionText, rune } from './support/runes.js';

// Audit 1.3.2: scan --agent-configs with --git-history, the NODE_OPTIONS guard without injected
// env, a repeated --format, known secrets in rune facts and in summary.agentConfigs paths.

const environment = (home: string, cwd: string) => () => ({ platform: process.platform, home, cwd, env: {} });
const spaced = (hex: string) => hex.match(/../g)!.join(' ');
const nwc = (secret: string) => `nostr+walletconnect://${randomBytes(32).toString('hex')}?relay=wss%3A%2F%2Fr.example&secret=${secret}`;

function git(dir: string, ...args: string[]): void {
  const done = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false',
    '-c', 'core.autocrlf=false', ...args], { cwd: dir, encoding: 'utf8' });
  if (done.status !== 0) throw new Error(`git ${args[0]} failed: ${done.stderr}`);
}

it('scan --agent-configs --git-history scans history of the path arguments only, never of agent locations', async () => scratch(async dir => {
  const repo = join(dir, 'repo'), home = join(dir, 'home'), cwd = join(dir, 'cwd');
  mkdirSync(repo); mkdirSync(join(home, '.cursor'), { recursive: true }); mkdirSync(cwd);
  git(repo, 'init', '-q');
  writeFileSync(join(repo, 'note.txt'), 'nothing here\n');
  git(repo, 'add', '-A'); git(repo, 'commit', '-q', '-m', 'c1');
  writeFileSync(join(home, '.cursor', 'mcp.json'), '{}');
  const output = await run([repo, '--agent-configs', '--git-history'], { fs, agentEnvironment: environment(home, cwd), env: {} });
  expect(output.error).toBeNull();
  expect(output.exitCode).toBe(0);
  const summary = (output.result as { summary: { blobsScanned: number; agentConfigs: { found: { path: string }[] } } }).summary;
  expect(summary.agentConfigs.found.map(item => item.path)).toEqual([join(home, '.cursor', 'mcp.json')]);
  expect(summary.blobsScanned).toBe(1);
}));

it('scan --agent-configs --git-history without a path argument is a usage error, not a git failure', async () => scratch(async dir => {
  const home = join(dir, 'home'), cwd = join(dir, 'cwd');
  mkdirSync(join(home, '.cursor'), { recursive: true }); mkdirSync(cwd);
  writeFileSync(join(home, '.cursor', 'mcp.json'), '{}');
  const output = await run(['--agent-configs', '--git-history'], { fs, agentEnvironment: environment(home, cwd), env: {} });
  expect(output.error).toEqual({ code: 2, step: null, message: '--git-history with --agent-configs needs a path argument' });
}));

it('scan refuses unsafe NODE_OPTIONS when a programmatic caller passes no env', async () => scratch(async dir => {
  writeFileSync(join(dir, 'app.env'), 'NOTHING=here\n');
  const saved = process.env.NODE_OPTIONS;
  process.env.NODE_OPTIONS = '--heapsnapshot-signal=SIGUSR2';
  try {
    const output = await run([dir], { fs });
    expect(output.error).toEqual({ code: 2, step: null, message: 'unsafe Node diagnostic settings' });
  } finally {
    if (saved === undefined) delete process.env.NODE_OPTIONS; else process.env.NODE_OPTIONS = saved;
  }
}));

// macOS keeps desktop app data under the home directory, read from no environment variable.
it.skipIf(process.platform === 'darwin')('scan --agent-configs reads the agent environment from deps.env, not process.env', async () => scratch(async dir => {
  const appData = join(dir, 'appdata');
  mkdirSync(join(appData, 'Claude'), { recursive: true });
  const config = join(appData, 'Claude', 'claude_desktop_config.json');
  writeFileSync(config, '{}');
  const saved = process.cwd();
  process.chdir(dir);
  try {
    const output = await run(['--agent-configs'], { fs, env: { APPDATA: appData, XDG_CONFIG_HOME: appData } });
    expect(output.error).toBeNull();
    const configs = (output.result as { summary: { agentConfigs: { found: { path: string }[]; absent: { path: string }[] } } }).summary.agentConfigs;
    const all = [...configs.found, ...configs.absent].map(item => item.path);
    expect(all.some(path => path.startsWith(appData))).toBe(true);
  } finally {
    process.chdir(saved);
  }
}));

it.each([['json', 'json'], ['json', 'sarif']])('scan --format %s --format %s says the flag was repeated', async (first, second) => {
  const output = await run(['--format', first, '--format', second], { fs, env: {} });
  expect(output.error).toEqual({ code: 2, step: null, message: '--format was given more than once' });
});

it('scan --json never prints a known NWC secret or L402 preimage held in rune restrictions', async () => scratch(async dir => {
  // A secret whose bytes are printable ASCII: its latin1 form is 32 characters a rune shows as is.
  const ascii = 'abcdefghijklmnopqrstuvwxyzABCDEF';
  const secret = Buffer.from(ascii, 'latin1').toString('hex');
  const paid = token(132);
  const preimage = paid.preimage.toString('hex');
  const runeText = restrictionText([[['', '=', '9']], [['method', '=', 'getinfo']],
    [['note', '=', ascii]], [['memo', '=', spaced(secret)]], [['hash', '=', spaced(preimage)]]]);
  writeFileSync(join(dir, 'app.env'), `NWC_URL=${nwc(secret)}\nL402_TOKEN=${paid.header}\nCLN_RUNE=${rune(runeText)}\n`);
  const run = await captureMain(main, ['scan', dir, '--json']);
  const document = JSON.parse(run.stdout) as { result: { findings: { kind: string }[] } };
  expect(document.result.findings.map(finding => finding.kind)).toEqual(expect.arrayContaining(['nwc', 'l402', 'rune']));
  for (const leak of [ascii, secret, spaced(secret), preimage, spaced(preimage)]) expect(run.stdout).not.toContain(leak);
}));

it('scan --json collects an NWC secret inside a rune restriction and redacts its other forms', async () => scratch(async dir => {
  const secret = randomBytes(32).toString('hex');
  const runeText = restrictionText([[['', '=', '9']], [['method', '=', 'getinfo']],
    [['nwc', '=', nwc(secret)]], [['memo', '=', spaced(secret)]]]);
  writeFileSync(join(dir, 'app.env'), `CLN_RUNE=${rune(runeText)}\n`);
  const run = await captureMain(main, ['scan', dir, '--json']);
  const document = JSON.parse(run.stdout) as { result: { findings: { kind: string }[] } };
  expect(document.result.findings.map(finding => finding.kind)).toEqual(['rune']);
  expect(run.stdout).not.toContain(secret);
  expect(run.stdout).not.toContain(spaced(secret));
}));

it('scan --agent-configs redacts known secrets in summary.agentConfigs paths', async () => scratch(async dir => {
  const secret = randomBytes(32).toString('hex');
  // The home directory's name is the secret of an NWC URI found in a scanned file.
  const home = join(dir, secret), cwd = join(dir, 'cwd'), target = join(dir, 'target');
  mkdirSync(join(home, '.cursor'), { recursive: true }); mkdirSync(cwd); mkdirSync(target);
  writeFileSync(join(home, '.cursor', 'mcp.json'), '{}');
  writeFileSync(join(target, 'app.env'), `NWC_URL=${nwc(secret)}\n`);
  const output = await run([target, '--agent-configs'], { fs, agentEnvironment: environment(home, cwd), env: {} });
  expect(output.error).toBeNull();
  const configs = (output.result as { summary: { agentConfigs: { found: { client: string; path: string }[]; absent: { path: string }[] } } })
    .summary.agentConfigs;
  expect(configs.found).toEqual([{ client: 'cursor', path: join(dir, '[redacted]', '.cursor', 'mcp.json') }]);
  expect(configs.absent.length).toBeGreaterThan(0);
  expect(JSON.stringify(output.result)).not.toContain(secret);
}));
