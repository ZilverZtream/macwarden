import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { main } from '../../src/cli.js';
import { handlers } from '../../src/commands/handlers.js';

// Every command the CLI dispatches is documented the same way in its --help synopsis,
// README.md and docs/spec.md: same command set, same flags, SPEC sections numbered in order.
const root = resolve();
const readme = readFileSync(join(root, 'README.md'), 'utf8');
const spec = readFileSync(join(root, 'docs/spec.md'), 'utf8');
const commands = Object.keys(handlers);
// The shared online connection flags are documented once ("+ online flags") in SPEC.
const shared = new Set(['--lnd-rest', '--tls-cert', '--macaroon', '--registry']);
const flagsOf = (text: string) => new Set([...text.matchAll(/--[a-z][a-z-]*/g)].map(match => match[0]).filter(flag => !shared.has(flag)));

afterEach(() => { vi.restoreAllMocks(); });

async function help(command: string): Promise<string> {
  let out = '';
  vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: string | Uint8Array) => { out += String(chunk); return true; }) as typeof process.stdout.write);
  expect(await main([command, '--help'])).toBe(0);
  vi.restoreAllMocks();
  return out;
}

/** The `macwarden <command> ...` code spans SPEC gives as the command's synopses. */
function specSynopses(command: string): string[] {
  return [...spec.matchAll(new RegExp('`macwarden ' + command + ' [^`]*`', 'g'))].map(match => match[0]);
}

it('DOCS/command-consistency every dispatched command has help, a README entry and a SPEC section', async () => {
  expect(commands.length).toBeGreaterThanOrEqual(10);
  for (const command of commands) {
    expect((await help(command)).trim().length, `${command} --help`).toBeGreaterThan(0);
    expect(readme, `README entry for ${command}`).toMatch(new RegExp('^- `' + command + '[ `]', 'm'));
    expect(spec, `SPEC section for ${command}`).toMatch(new RegExp('^### \\d+\\. `' + command + '`', 'm'));
    expect(specSynopses(command).length, `SPEC synopsis for ${command}`).toBeGreaterThan(0);
  }
});

it('DOCS/command-consistency SPEC command sections are numbered 1..n without gaps', () => {
  const numbers = [...spec.matchAll(/^### (\d+)\. `([a-z]+)`/gm)].map(match => Number(match[1]));
  expect(numbers).toEqual(numbers.map((_, index) => index + 1));
  const documented = [...spec.matchAll(/^### \d+\. `([a-z]+)`/gm)].map(match => match[1]);
  expect([...documented].sort()).toEqual([...commands].sort());
});

it('DOCS/command-consistency each command has the same flags in --help and in its SPEC synopses', async () => {
  for (const command of commands) {
    const fromHelp = flagsOf(await help(command));
    const fromSpec = flagsOf(specSynopses(command).join(' '));
    expect([...fromHelp].sort(), `${command}: --help vs SPEC`).toEqual([...fromSpec].sort());
  }
});
