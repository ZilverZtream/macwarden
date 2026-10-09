import { spawnSync } from 'node:child_process';
import { expect, it } from 'vitest';
import { shellQuote } from '../src/online.js';

// Values an attacker-influenced path or label could carry into a printed recovery command.
const values = ['plain/path.macaroon', 'a\u2019b', '\u2018quoted\u2019', '\u201Ab\u201B', "it's", 'R&D dir', 'x;y|z',
  '$(touch pwned)', '`whoami`', 'line1\nline2', 'a,b', '-dash', 'C:\\Program Files\\app\\x.macaroon', '@splat', '%TEMP%'];

// The real shell must receive exactly the original bytes; hex output avoids console code pages.
// Selected by the platform policy in scripts/platform-variants.mjs; counterpart: test/shell-quote.windows.test.ts.
it('RECOVERY/shell-quote a POSIX shell receives every printed argument byte for byte', () => {
  for (const value of values) {
    const quoted = shellQuote(value, 'linux');
    const result = spawnSync('sh', ['-c', `printf %s ${quoted} | od -An -tx1 | tr -d ' \\n'`], { encoding: 'utf8' });
    expect(result.status, value).toBe(0);
    expect(result.stdout, value).toBe(Buffer.from(value, 'utf8').toString('hex'));
  }
});
