import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { scan } from '../src/scan/index.js';
import { runeCandidates } from '../src/scan/rune-context.js';
import { scratch } from './support/cp039-audit.js';
import { rune, runeFingerprint } from './support/runes.js';

// Synthetic runes with a fixed authenticator (test/support/runes.ts): no authority on any node.
const SPEND_TEXT = '=8&method=pay';
const SPEND_RUNE = rune(SPEND_TEXT);
const clock = () => new Date('2026-10-09T12:00:00Z');

const cases: [string, string, boolean][] = [
  ['mcp.json', `{"mcpServers":{"cln":{"command":"cln-mcp","args":["--rune", "${SPEND_RUNE}"]}}}\n`, true],
  ['mcp.json', `{"mcpServers":{"cln":{"args":["--rune","${SPEND_RUNE}"]}}}\n`, true],
  ['mcp.json', `{"mcpServers":{"cln":{"args":[\n  "--cln-rune" ,\t"${SPEND_RUNE}"\n]}}}\n`, true],
  ['config.toml', `args = ["--rune", "${SPEND_RUNE}"]\n`, false],
  ['config.yaml', `args: ['--rune', '${SPEND_RUNE}']\n`, false],
  ['outer.json', `{"cfg":"{\\"rune\\":\\"${SPEND_RUNE}\\"}"}\n`, false],
  ['outer.json', `{"cfg":"[\\"--rune\\", \\"${SPEND_RUNE}\\"]"}\n`, false],
];

for (const [name, text, mcp] of cases) {
  it(`a rune after a quoted rune option or in escaped JSON is found: ${JSON.stringify(text.slice(0, 48))}`, async () => scratch(async dir => {
    writeFileSync(join(dir, name), text);
    const findings = (await scan([dir], { clock })).findings;
    expect(findings.map(finding => [finding.kind, finding.grade, finding.fingerprint, finding.context]))
      .toEqual([['rune', 'SPEND', runeFingerprint(SPEND_TEXT), mcp ? 'mcp-config' : undefined]]);
  }));
}

it('a quoted word that is not a rune option does not open rune context', () => {
  for (const text of [`["rune", "${SPEND_RUNE}"]`, `["--runes", "${SPEND_RUNE}"]`, `["--rune" "${SPEND_RUNE}"]`,
    `["--rune", ${SPEND_RUNE}]`, `["--rune", x, "${SPEND_RUNE}"]`])
    expect(runeCandidates(text), text).toEqual([]);
});

// Audit 1.3.2: a rune key whose value is too short to be a rune moved the key search past a rune
// key inside that value, so the rune after it was neither found nor redacted.
it('a rune key after a short value of another rune key is still found', async () => scratch(async dir => {
  for (const text of [`rune=a/b/cln_rune="${SPEND_RUNE}"`, `rune: cln_rune: "${SPEND_RUNE}"`, `rune=x CLN_RUNE='${SPEND_RUNE}'`]) {
    expect(runeCandidates(text).map(candidate => candidate.text), text).toEqual([SPEND_RUNE]);
    writeFileSync(join(dir, 'app.env'), `${text}\n`);
    const findings = (await scan([dir], { clock })).findings;
    expect(findings.map(finding => [finding.kind, finding.fingerprint]), text).toEqual([['rune', runeFingerprint(SPEND_TEXT)]]);
  }
}));
