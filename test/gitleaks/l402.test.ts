import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import { runGitleaks } from './run.js';
import { repo } from './rules-support.js';

// The L402 rules of rules/gitleaks.toml on the committed synthetic L402 tree
// (test/scan-fixtures/generate-l402.mjs). gitleaks always runs with --redact.
const tree = resolve(repo, 'test/scan-fixtures/l402');
const manifest = JSON.parse(readFileSync(resolve(tree, 'manifest.json'), 'utf8')) as
  { gitleaks: { path: string; line: number; rule: string }[] };

// The credentials the tree holds, as text: the leak check must find none of them in the report.
function sentinels(): Buffer[] {
  const found: Buffer[] = [];
  for (const name of ['auth.env', 'access.log', 'client.json']) {
    for (const match of readFileSync(resolve(tree, name), 'utf8').matchAll(/([A-Za-z0-9+/]{40,}={0,2}):([0-9a-f]{64})/g)) {
      found.push(Buffer.from(match[1], 'base64'), Buffer.from(match[2], 'hex'));
    }
  }
  return found;
}

it('L402-gitleaks/pinned gitleaks finds every planted L402 item with the L402 rules, redacted', () => {
  const secrets = sentinels();
  expect(secrets.length).toBe(6);
  const hits = runGitleaks(tree, secrets);
  const found = new Set(hits.map(hit => `${hit.File.replace(/\\/g, '/').replace(/^.*\/tree\//, '')}:${hit.StartLine}:${hit.RuleID}`));
  for (const item of manifest.gitleaks) expect(found.has(`${item.path}:${item.line}:${item.rule}`), `${item.path}:${item.line} ${item.rule}`).toBe(true);
  for (const hit of hits) {
    expect(hit.Secret, `${hit.File}:${hit.StartLine} Secret`).toContain('REDACTED');
    expect(hit.Match, `${hit.File}:${hit.StartLine} Match`).toContain('REDACTED');
  }
});
