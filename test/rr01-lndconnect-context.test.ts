// RR-01: a valid lndconnect URI pasted where URIs usually live (markdown, prose, YAML flow,
// shell) or carrying standard base64 must be found, and a URI that fails to parse must not
// hide the credential inside it.
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { run as scanCommand } from '../src/commands/scan.js';
import { scan, type ScanResult } from '../src/scan/index.js';

const repo = resolve();
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string; expectedGrade: string }[] };
const vector = (name: string) => readFileSync(join(repo, 'test/vectors', `${name}.macaroon`));
const reference = (name: string) => manifest.vectors.find(entry => entry.name === name)!;
const admin = vector('default-admin');
const uri = (bytes: Buffer) => `lndconnect://node.example:10009?cert=MIIBabc&macaroon=${bytes.toString('base64url')}`;

async function temp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'rr01-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}
const brief = (result: ScanResult) => result.findings.map(({ kind, line, column, fingerprint, grade }) => ({ kind, line, column, fingerprint, grade }));

const contexts: [string, string, number][] = [
  ['md-backticks.md', 'Connect Zeus with `' + uri(admin) + '`\n', 20],
  ['md-link.md', `[connect](${uri(admin)})\n`, 11],
  ['md-link-period.md', `See [connect](${uri(admin)}).\n`, 15],
  ['prose-period.txt', `The URI is ${uri(admin)}.\n`, 12],
  ['prose-question.txt', `Is it ${uri(admin)}?!\n`, 7],
  ['yaml-flow.yml', `node: {uri: ${uri(admin)}, name: alice}\n`, 13],
  ['yaml-flow-end.yml', `node: {uri: ${uri(admin)}}\n`, 13],
  ['shell-semicolon.sh', `export LNDCONNECT=${uri(admin)};\n`, 19],
  ['json-array.json', `[${JSON.stringify(uri(admin))}]\n`, 3],
  ['angle.txt', `<${uri(admin)}>\n`, 2],
  ['bracket.txt', `[${uri(admin)}]\n`, 2],
  ['colon.txt', `${uri(admin)}: admin\n`, 1],
];

for (const [name, content, column] of contexts) {
  it(`RR-01 finds a valid lndconnect URI followed by punctuation: ${name}`, async () => temp(async dir => {
    const path = join(dir, name);
    writeFileSync(path, content);
    const result = await scan([path], {});
    expect(brief(result)).toEqual([{ kind: 'lndconnect', line: 1, column,
      fingerprint: reference('default-admin').fingerprint, grade: 'ADMIN' }]);
    expect(result.summary.dropped).toBe(0);
    const run = await scanCommand([path, '--fail-on', 'READ', '--json'], { fs });
    expect(run.exitCode).toBe(1);
  }));
}

it('RR-01 finds an lndconnect URI carrying standard base64, padded or not, raw or percent-encoded', async () => temp(async dir => {
  const standard = admin.toString('base64');
  expect(/[+/]/.test(standard), 'committed vector must exercise + or /').toBe(true);
  const forms = [standard, standard.replace(/=+$/, ''), encodeURIComponent(standard)];
  const lines = forms.map(form => `LND=lndconnect://node.example:10009?macaroon=${form}`);
  const path = join(dir, 'standard.env');
  writeFileSync(path, lines.join('\n'));
  const result = await scan([path], {});
  expect(brief(result)).toEqual(forms.map((_, index) => ({ kind: 'lndconnect', line: index + 1, column: 5,
    fingerprint: reference('default-admin').fingerprint, grade: 'ADMIN' })));
  expect(result.summary.dropped).toBe(0);
}));

it('RR-01 a URI that does not parse no longer hides the credential inside it', async () => temp(async dir => {
  const url = admin.toString('base64url');
  // No host, two macaroon parameters, and a value followed by an escaped space: none parses.
  const lines = [`lndconnect://?macaroon=${url}`, `lndconnect://h:1?macaroon=${url}&macaroon=${url}`,
    `lndconnect://h:1?macaroon=${url}%20`];
  const path = join(dir, 'broken.env');
  writeFileSync(path, lines.join('\n'));
  const result = await scan([path], {});
  const want = { fingerprint: reference('default-admin').fingerprint, grade: 'ADMIN' };
  expect(brief(result)).toEqual([
    { kind: 'macaroon-base64', line: 1, column: 24, ...want },
    { kind: 'macaroon-base64', line: 2, column: 27, ...want },
    { kind: 'macaroon-base64', line: 2, column: 27 + url.length + 10, ...want },
    { kind: 'macaroon-base64', line: 3, column: 27, ...want }]);
  expect(result.summary.dropped).toBe(3);
  const run = await scanCommand([path, '--fail-on', 'ADMIN', '--json'], { fs });
  expect(run.exitCode).toBe(1);
  // A cut-off credential inside a broken URI is still a candidate (fail closed).
  const cut = join(dir, 'cut.env');
  writeFileSync(cut, `lndconnect://?macaroon=${url.slice(0, 80)}`);
  expect((await scan([cut], {})).findings.map(f => f.kind)).toEqual(['undecodable-candidate']);
}));

it('RR-01 punctuation that is part of a valid URI is kept, and an URI without a credential is still dropped', async () => temp(async dir => {
  const path = join(dir, 'kept.env');
  // A trailing parameter absorbs the punctuation: the URI parses as written.
  writeFileSync(path, `${uri(admin)}&x=1).\nlndconnect://h:1?cert=AAAA.\n`);
  const result = await scan([path], {});
  expect(brief(result)).toEqual([{ kind: 'lndconnect', line: 1, column: 1,
    fingerprint: reference('default-admin').fingerprint, grade: 'ADMIN' }]);
  expect(result.summary.dropped).toBe(1);
}));
