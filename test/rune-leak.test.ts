import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { findLeaks } from '../scripts/leak-check.mjs';
import { childEnvironment } from './helpers/environment.js';
import { declare, declareHashed, register, repo, root, scratch, sentinelList } from './support/cp039-audit.js';
import { freshRune } from './support/runes.js';

// docs/spec.md, Core Lightning runes > Output: no output (text, JSON, SARIF, GitHub annotations,
// errors) carries a rune, its authenticator or its decoded string, in any encoding the leak
// checker knows. Each test uses fresh runes, registered as sentinels for this run only.

function cli(args: string[], input?: string): string {
  const run = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), ...args],
    { cwd: repo, input, encoding: 'utf8', timeout: 20_000, maxBuffer: 50_000_000, env: childEnvironment() });
  if (run.error) throw run.error;
  return `${run.stdout ?? ''}${run.stderr ?? ''}`;
}

function registered(text: string) {
  const made = freshRune(text);
  register(made.bytes);
  register(made.authenticator);
  return made;
}

function leaks(output: string, paths: string[] = []) {
  return findLeaks({ sentinels: sentinelList, sentinelDir: root('MACWARDEN_SENTINEL_DIR'), root: repo,
    commandOutput: output, paths, testTmp: root() });
}

describe('RUNE/leak', () => {
  it('RUNE/leak scan text, JSON, SARIF and github output carry no rune, authenticator or decoded string', async () => scratch(async dir => {
    const spend = registered('=31&method=pay&pnameamount_msat<100000');
    const broad = registered('=32&method^list');
    const invalid = registered('=33&method');
    const file = join(dir, 'app.env');
    writeFileSync(file, [`CLN_RUNE=${spend.rune}`, `"rune": "${broad.rune}"`, `BAD_RUNE=${invalid.rune}`,
      `curl -H "Rune: ${spend.rune.replace(/=+$/, '')}" https://node/v1/pay`,
      `lightning-cli commando 02${'ab'.repeat(32)} listfunds '{}' ${broad.rune}`].join('\n') + '\n');
    declare(file);
    const outputs = ['text', 'json', 'sarif', 'github'].map(format => cli(['scan', dir, '--format', format]));
    expect(outputs[1]).toContain('"kind":"rune"');
    expect(outputs[1]).toContain('"kind":"rune-invalid"');
    expect(leaks(outputs.join('\n'))).toBeNull();
  }));

  it('RUNE/leak a scanned path holding a rune in rune context is redacted', async () => scratch(async dir => {
    const named = registered('=34&method=getinfo');
    const inside = registered('=35&method=pay');
    const file = join(dir, `cfg-rune=${named.rune.replace(/=+$/, '')}.env`);
    writeFileSync(file, `RUNE=${inside.rune}\n`);
    // The file name holds a rune: declared by hash, so the declared-output manifest never holds it.
    declareHashed(file);
    const output = ['text', 'json', 'sarif', 'github'].map(format => cli(['scan', dir, '--format', format])).join('\n');
    expect(output).toContain('[redacted]');
    expect(leaks(output)).toBeNull();
  }));

  it('RUNE/leak inspect text and JSON, and inspect errors, carry no rune', async () => scratch(async dir => {
    const made = registered('=36&method=pay|method=keysend&rate=5');
    const file = join(dir, 'app.rune');
    writeFileSync(file, `${made.rune}\n`);
    declare(file);
    const output = [cli(['inspect', file]), cli(['inspect', file, '--json']), cli(['inspect', '-'], made.rune),
      // A literal without --unsafe-arg is refused; the refusal must not echo it.
      cli(['inspect', made.rune]), cli(['inspect', made.rune, '--json']),
      // A malformed rune (a cut copy) fails with a decoding error that echoes nothing.
      cli(['inspect', '-'], made.rune.slice(0, -6))].join('\n');
    expect(output).toContain('rune (Core Lightning)');
    expect(leaks(output)).toBeNull();
  }));

  it('RUNE/leak a restriction value holding another credential is redacted', async () => scratch(async dir => {
    const nested = registered('=37&method=getinfo');
    const outer = registered(`=38&method=pay&pnamenote=${nested.rune}`);
    const file = join(dir, 'app.rune');
    writeFileSync(file, outer.rune);
    declare(file);
    const output = [cli(['inspect', file]), cli(['inspect', file, '--json'])].join('\n');
    expect(leaks(output)).toBeNull();
  }));
});

describe('RUNE/leak fuzz', () => {
  it('RUNE/leak 100 fuzz-generated runes (valid, mutated, nested) leak through no inspect, scan or redaction output', async () => {
    const { leakCampaign } = await import('../scripts/rune-leak-fuzz.mjs');
    const [{ scan }, { renderChunks, render }, { run }, { redactRuneContexts }] = await Promise.all([import('../src/scan/index.js'),
      import('../src/output/index.js'), import('../src/commands/inspect.js'), import('../src/scan/rune-context.js')]);
    const report = await leakCampaign({ scan, renderChunks, render, inspectRun: run, redactRuneContexts },
      { seed: 20261009, cases: 100, scratchRoot: root() });
    expect(report.cases).toBe(100);
    expect(report.leaks).toEqual([]);
  }, 60_000);
});
