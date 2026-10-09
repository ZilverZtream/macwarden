import { describe, expect, it } from 'vitest';
import { main } from '../src/cli.js';
import { captureMain } from './support/capture.js';
import { expectDocumentValid } from './helpers/output-schema.js';

const hexCandidate = '0201036c6e6402' + 'ab'.repeat(24);

// Written out literally: the expected help is the documented interface, not the code's constant.
const help = [
  'Usage: macwarden <command> [options]',
  '       macwarden <command> --help',
  '       macwarden --help | --version',
  '',
  'Commands:',
  '  inspect    decode a macaroon, NWC URI, L402 token or Core Lightning rune offline and grade what it can do',
  '  scan       find credentials in files and, with --git-history, in git history (offline)',
  "  inventory  list the node's root key IDs against the registry",
  '  bake       issue a least-privilege macaroon on its own root key ID and record it',
  '  revoke     delete a root key ID and record the revocation',
  '  rotate     replace a macaroon in two steps: stage, then --finish',
  '  attenuate  add expiry or IP caveats to a copy of a macaroon offline',
  '  watch      observe which credential makes which call (read-only LND middleware); guard canaries',
  '  recommend  suggest the least permissions a credential needs from observed usage',
  '  respond    after a suspected leak: stage replacements for every credential, then --finish with proof',
  '  verify     ask LND whether one credential file is still accepted (after a leak)',
  "  reconcile  match watch's payment journal against LND's payment records, per credential",
  '',
].join('\n');

describe('CP-001 CLI', () => {
  it('CP-001/B1 prints the package version', async () => {
    const actual = await captureMain(main, ['--version']);
    expect(actual).toMatchObject({ code: 0, stdout: '1.1.1\n', stderr: '' });
  });

  it('CP-001/B2 prints help on stdout', async () => {
    const actual = await captureMain(main, ['--help']);
    expect(actual).toMatchObject({ code: 0, stdout: help, stderr: '' });
    expect(actual.stdout).not.toContain('\\x0a');
  });

  it('CP-001/B3 reports missing command as usage', async () => {
    const actual = await captureMain(main, []);
    expect(actual).toMatchObject({ code: 2, stdout: '', stderr: `error: usage: missing command\n${help}` });
  });

  it('CP-001/B4 reports unknown command and flag without echo', async () => {
    for (const arg of ['frobnicate', '--frobnicate']) {
      const actual = await captureMain(main, [arg]);
      expect(actual.code).toBe(2);
      expect(actual.stdout).toBe('');
      expect(actual.stderr).toContain('Usage: macwarden');
      expect(actual.stdout + actual.stderr).not.toContain(arg);
    }
  });

  it('CP-001/B5 emits one exact JSON usage envelope', async () => {
    const actual = await captureMain(main, ['--json']);
    expect(actual.code).toBe(2);
    expect(actual.stderr).toBe('');
    const document: unknown = JSON.parse(actual.stdout);
    expect(typeof document).toBe('object');
    expect(document).toEqual({
      schema: 1,
      command: null,
      ok: false,
      warnings: [],
      result: null,
      error: { code: 2, step: null, message: expect.any(String) },
    });
    expect((document as { error: { message: string } }).error.message.length).toBeGreaterThan(0);
  });

  it('CP-001/B6 never echoes a credential-shaped unknown command', async () => {
    for (const args of [[hexCandidate], [hexCandidate, '--json']]) {
      const actual = await captureMain(main, args);
      expect(actual.code).toBe(2);
      if (args.includes('--json')) {
        expect(actual.stderr).toBe('');
        const document = JSON.parse(actual.stdout) as { command: unknown; error: { code: number } };
        expect(document.command).toBeNull();
        expect(document.error.code).toBe(2);
      }
      const output = actual.stdout + actual.stderr;
      expect(output).not.toContain(hexCandidate);
      expect(output).not.toContain(hexCandidate.toUpperCase());
      for (let i = 0; i <= hexCandidate.length - 16; i++) {
        expect(output).not.toContain(hexCandidate.slice(i, i + 16));
      }
    }
  });

  it('CP-001/B2 command help prints that command\'s synopsis and exits 0', async () => {
    const online = ' [--lnd-rest <host:port>] [--tls-cert <path>] [--macaroon <path>]';
    expect(await captureMain(main, ['rotate', '--help'])).toMatchObject({ code: 0, stderr: '', stdout:
      `Usage: macwarden rotate <label> --out <file> [--allow-admin] [--registry <path>] [--break-lock] [--dry-run] [--json]${online}\n` +
      `       macwarden rotate <label> --finish [--yes] [--registry <path>] [--break-lock] [--dry-run] [--json]${online}\n` });
    expect(await captureMain(main, ['attenuate', '--help'])).toMatchObject({ code: 0, stderr: '', stdout:
      'Usage: macwarden attenuate <file | -> --out <file> [--expires <n>(m|h|d)] [--ip <address> | --ip-range <cidr>] [--dry-run] [--unsafe-arg] [--json]\n' });
    for (const command of ['inspect', 'scan', 'inventory', 'bake', 'revoke']) {
      const actual = await captureMain(main, [command, '--help']);
      expect(actual.code).toBe(0);
      expect(actual.stdout).toMatch(new RegExp(`^Usage: macwarden ${command} `));
    }
    // After "--", --help is an operand (a path), not a request for help.
    expect((await captureMain(main, ['scan', '--', '--help'])).code).toBe(3);
  });

  it('CP-001/B2 MW110-10 command help with --json is one JSON document carrying the synopsis, for every command', async () => {
    const commands = ['inspect', 'scan', 'inventory', 'bake', 'revoke', 'rotate', 'attenuate', 'watch', 'recommend', 'respond', 'verify', 'reconcile'];
    for (const command of commands) {
      const text = await captureMain(main, [command, '--help']);
      const usage = text.stdout.trimEnd().split('\n').map(line => line.replace(/^(?:Usage: | {7})/, ''));
      for (const args of [[command, '--help', '--json'], [command, '--json', '--help']]) {
        const actual = await captureMain(main, args);
        expect(actual, args.join(' ')).toMatchObject({ code: 0, stderr: '' });
        const document = JSON.parse(actual.stdout) as { command: string };
        expect(document, args.join(' ')).toEqual({ schema: 1, command, ok: true, warnings: [], result: { usage }, error: null });
        expectDocumentValid(document);
      }
    }
    // scan --format json is --json too.
    expect(JSON.parse((await captureMain(main, ['scan', '--help', '--format', 'json'])).stdout)).toMatchObject({ command: 'scan', ok: true });
  });

  it('CP-001/B2 MW110-10 top-level --help --json is one JSON document listing every command', async () => {
    for (const args of [['--help', '--json'], ['--json', '--help']]) {
      const actual = await captureMain(main, args);
      expect(actual, args.join(' ')).toMatchObject({ code: 0, stderr: '' });
      const document = JSON.parse(actual.stdout) as { command: null; result: { usage: string[]; commands: { name: string; summary: string }[] } };
      expect(document).toMatchObject({ schema: 1, command: null, ok: true, warnings: [], error: null });
      expect(document.result.usage).toEqual(['macwarden <command> [options]', 'macwarden <command> --help', 'macwarden --help | --version']);
      // The same commands and summaries as the text help.
      const listed = help.split('\n').filter(line => /^ {2}\S/.test(line)).map(line => line.trim().split(/\s+/)[0]);
      expect(document.result.commands.map(item => item.name)).toEqual(listed);
      for (const item of document.result.commands) expect(help).toContain(`  ${item.name.padEnd(10)} ${item.summary}\n`);
      expectDocumentValid(document);
    }
    // A command-less usage error with --json validates against the same top-level schema.
    const unknown = await captureMain(main, ['frobnicate', '--json']);
    expect(unknown.code).toBe(2);
    expectDocumentValid(JSON.parse(unknown.stdout) as { command: null });
  });

  it('CP-001/B4 an unknown command or flag gets a fixed reason and the usage', async () => {
    expect(await captureMain(main, ['frobnicate'])).toMatchObject({ code: 2, stdout: '', stderr: `error: usage: unknown command\n${help}` });
    expect(await captureMain(main, ['--frobnicate'])).toMatchObject({ code: 2, stdout: '', stderr: `error: usage: unknown flag\n${help}` });
  });

  it('CP-001/B9 main resolves to a number and never exits the process', async () => {
    for (const args of [
      ['--version'], ['--help'], [], ['frobnicate'], ['--frobnicate'],
      ['--json'], [hexCandidate], [hexCandidate, '--json'],
    ]) {
      const actual = await captureMain(main, args);
      expect(typeof actual.code).toBe('number');
      expect(actual.exitCalls).toBe(0);
    }
  });
});
