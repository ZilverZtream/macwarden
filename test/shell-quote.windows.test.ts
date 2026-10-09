import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { shellQuote } from '../src/online.js';

// Values an attacker-influenced path or label could carry into a printed recovery command.
const values = ['plain/path.macaroon', 'a\u2019b', '\u2018quoted\u2019', '\u201Ab\u201B', "it's", 'R&D dir', 'x;y|z',
  '$(touch pwned)', '`whoami`', 'line1\nline2', 'a,b', '-dash', 'C:\\Program Files\\app\\x.macaroon', '@splat', '%TEMP%'];

// The real shell must receive exactly the original bytes; hex output avoids console code pages.
// Selected by the platform policy in scripts/platform-variants.mjs; counterpart: test/shell-quote.posix.test.ts.
it('RECOVERY/shell-quote PowerShell receives every printed argument byte for byte, curly quotes included', () => {
  const powershell = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  for (const value of values) {
    const quoted = shellQuote(value, 'win32');
    // Exactly how a printed command runs: the quoted value as an argument to a native program.
    const script = `& '${process.execPath.replaceAll("'", "''")}' -e "process.stdout.write(Buffer.from(process.argv[1]).toString('hex'))" -- ${quoted}`;
    const result = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
      { encoding: 'utf8', windowsHide: true });
    expect(result.status, value).toBe(0);
    expect(result.stdout.trim(), value).toBe(Buffer.from(value, 'utf8').toString('hex'));
  }
});

it('RECOVERY/shell-quote leaves only conservative bare words unquoted', () => {
  expect(shellQuote('macwarden', 'linux')).toBe('macwarden');
  expect(shellQuote('/srv/app.macaroon', 'linux')).toBe('/srv/app.macaroon');
  // PowerShell turns a,b into an array and @x into splatting, so both are quoted there.
  expect(shellQuote('a,b', 'win32')).toBe("'a,b'");
  expect(shellQuote('@splat', 'win32')).toBe("'@splat'");
  expect(shellQuote('a\u2019b', 'win32')).toBe("'a\u2019\u2019b'");
});
