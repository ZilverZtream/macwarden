// Parser review 2026-10-08, LOW-3: scan missed NWC connection strings in common escaped forms
// (HTML &amp;, JSON-escaped slashes, percent-encoding, "+" decoded to a space). The &amp; form
// even matched the detector and was then dropped without being counted. Each form grants
// spend authority, so each must be reported once, with no secret in any output.
import { createHash, randomBytes } from 'node:crypto';
import * as fs from 'node:fs/promises';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterAll, expect, it } from 'vitest';
import { run } from '../src/commands/scan.js';
import { render } from '../src/output/index.js';
import type { ScanResult } from '../src/scan/index.js';

const repo = resolve();
const scratch = mkdtempSync(join(resolve(process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp')), 'parsers-l3-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));
const B = '\\';

function forms(secret: string, wallet: string): Record<string, string> {
  const uri = `nostr+walletconnect://${wallet}?relay=wss://relay.example.com&secret=${secret}`;
  return {
    'nwc-plain.env': `NWC=${uri}\n`,
    'nwc-html-amp.html': `<a href="${uri.replace('&', '&amp;')}">connect</a>\n`,
    'nwc-html-double-amp.xml': `<v>${uri.replace('&', '&amp;amp;')}</v>\n`,
    'nwc-json-escaped-slashes.json': `${JSON.stringify({ mcpServers: { alby: { env: { NWC_CONNECTION_STRING: uri } } } }).replace(/\//g, `${B}/`)}\n`,
    'nwc-percent-encoded.json': `${JSON.stringify({ deeplink: `app://connect?uri=${encodeURIComponent(uri)}` })}\n`,
    'nwc-plus-as-space.env': `NWC=${uri.replace('+', ' ')}\n`,
    'nwc-plus-percent.env': `NWC=${uri.replace('+', '%2B')}\n`,
    'nwc-form-encoded.txt': `uri=${encodeURIComponent(uri).replace(/%20/g, '+')}&next=1\n`,
  };
}

it('PARSERS-L3/each escaped NWC form is reported exactly once with the secret\'s fingerprint, never the secret', async () => {
  const dir = mkdtempSync(join(scratch, 'forms-'));
  const secret = randomBytes(32).toString('hex');
  const wallet = randomBytes(32).toString('hex');
  const files = forms(secret, wallet);
  for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
  const output = await run([dir, '--json'], { fs });
  expect(output.ok).toBe(true);
  const result = output.result as ScanResult;
  const expected = `fp:${createHash('sha256').update(Buffer.from(secret, 'hex')).digest('hex').slice(0, 16)}`;
  for (const name of Object.keys(files)) {
    const found = result.findings.filter(finding => finding.path.endsWith(name));
    expect(found.map(finding => [finding.kind, finding.fingerprint]), name).toEqual([['nwc', expected]]);
    expect(found[0].line, name).toBe(1);
  }
  expect(result.findings).toHaveLength(Object.keys(files).length);
  expect(result.summary.dropped).toBe(0);
  const mcp = result.findings.find(finding => finding.path.endsWith('nwc-json-escaped-slashes.json'))!;
  expect(mcp.context).toBe('mcp-config');
  for (const mode of ['json', 'text'] as const) {
    const rendered = render(output as never, mode);
    expect(rendered.toLowerCase()).not.toContain(secret);
    expect(rendered.toLowerCase()).not.toContain(secret.slice(0, 32));
  }
});

it('PARSERS-L3/columns point at the escaped URI in the original line', async () => {
  const dir = mkdtempSync(join(scratch, 'columns-'));
  const secret = randomBytes(32).toString('hex');
  const wallet = randomBytes(32).toString('hex');
  const line = `x = "é ${`nostr+walletconnect://${wallet}?relay=wss://r&secret=${secret}`.replace(/\//g, `${B}/`)}"`;
  writeFileSync(join(dir, 'column.txt'), `first\n${line}\n`);
  const result = (await run([dir, '--json'], { fs })).result as ScanResult;
  expect(result.findings.map(finding => [finding.kind, finding.line, finding.column])).toEqual([['nwc', 2, 8]]);
});

it('PARSERS-L3/a URI matched in both raw and normalised form is reported once', async () => {
  const dir = mkdtempSync(join(scratch, 'dedupe-'));
  const secret = randomBytes(32).toString('hex');
  const wallet = randomBytes(32).toString('hex');
  // A plain URI on a line that also has a percent escape elsewhere.
  writeFileSync(join(dir, 'both.env'), `NWC=nostr+walletconnect://${wallet}?relay=wss%3A%2F%2Fr.example&secret=${secret} # 100%25\n`);
  const result = (await run([dir, '--json'], { fs })).result as ScanResult;
  expect(result.findings.map(finding => [finding.kind, finding.column])).toEqual([['nwc', 5]]);
});
