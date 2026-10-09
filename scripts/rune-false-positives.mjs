// Measures how often macwarden's Core Lightning rune scanning (1.2.0) reports text that is not a
// rune. Run after `npm run build`:
//
//   node scripts/rune-false-positives.mjs [--per-class <n>] [--seed <n>] [--json]
//
// The corpus is generated deterministically from the seed: JWTs, random base64 and base64url
// of many lengths, hex digests, UUIDs, and token shapes of common services (AWS access keys,
// GitHub, Slack, Stripe, Google API keys, npm), BOLT11 invoices, Bitcoin addresses, SSH public
// keys and PEM bodies. Every value is placed in three settings:
//
//   no-context  ordinary configuration, code and prose without a rune key (TOKEN=…, "apiKey": …,
//               Authorization: Bearer …, a bare value in a sentence)
//   key         assigned to a rune key (RUNE=…, "rune": …, Rune: …) — what a mistaken or
//               placeholder value in a real rune setting looks like
//   command     a positional argument after lightning-cli commando / checkrune
//
// It reports, per setting and value class, how many values were reported as kind rune
// (recognised rune syntax) and as rune-invalid. In the key setting a rune-invalid finding is
// the intended fail-closed outcome; a kind rune finding there, or any finding in the other two
// settings, counts as a false positive. Nothing is written outside a private temporary directory.
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const HEX = '0123456789abcdef';
const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function prng(seed) {
  let state = seed >>> 0;
  return () => { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state / 2 ** 32; };
}

function generators(random) {
  const int = (low, high) => low + Math.floor(random() * (high - low + 1));
  const pick = alphabet => alphabet[Math.floor(random() * alphabet.length)];
  const chars = (alphabet, length) => Array.from({ length }, () => pick(alphabet)).join('');
  const bytes = length => Buffer.from(Array.from({ length }, () => Math.floor(random() * 256)));
  const json = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  return {
    jwt: () => `${json({ alg: pick(['HS256', 'RS256', 'ES256']), typ: 'JWT' })}.${json({ sub: chars(ALNUM, int(4, 12)), iat: int(1.6e9, 1.8e9),
      scope: chars('abcdefghij:', int(3, 30)) })}.${bytes(pick([32, 64, 256])).toString('base64url')}`,
    'random-base64url': () => bytes(int(32, 300)).toString('base64url'),
    'random-base64url-padded': () => { const raw = bytes(int(32, 300)).toString('base64url'); return raw + '='.repeat((4 - raw.length % 4) % 4); },
    'random-base64': () => bytes(int(32, 300)).toString('base64'),
    'random-alphabet-text': () => chars(B64URL, int(43, 200)),
    'hex-sha256': () => chars(HEX, 64),
    'hex-node-id': () => `0${pick('23')}${chars(HEX, 64)}`,
    uuid: () => [8, 4, 4, 4, 12].map(length => chars(HEX, length)).join('-'),
    'aws-access-key': () => `AKIA${chars('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 16)}`,
    'aws-secret-key': () => chars(B64, 40),
    'github-token': () => `ghp_${chars(ALNUM, 36)}`,
    'slack-token': () => `xoxb-${int(1e9, 9e9)}-${int(1e9, 9e9)}-${chars(ALNUM, 24)}`,
    'stripe-key': () => `sk_live_${chars(ALNUM, 99)}`,
    'google-api-key': () => `AIza${chars(`${ALNUM}-_`, 35)}`,
    'npm-token': () => `npm_${chars(ALNUM, 36)}`,
    'bolt11-invoice': () => `lnbcrt${int(1, 999)}u1p${chars(BECH32, int(180, 320))}`,
    'bitcoin-address': () => `bcrt1q${chars(BECH32, 38)}`,
    'ssh-public-key': () => `AAAAC3NzaC1lZDI1NTE5AAAAI${bytes(32).toString('base64').replace(/=+$/, '')}`,
    'pem-body-line': () => bytes(48).toString('base64'),
  };
}

const NO_CONTEXT = [
  value => `TOKEN=${value}`,
  value => `  "apiKey": "${value}",`,
  value => `Authorization: Bearer ${value}`,
  value => `The value ${value} was rotated yesterday.`,
  value => `secret: ${value}`,
  value => `export API_SECRET='${value}'`,
];
const KEY = [
  value => `RUNE=${value}`,
  value => `  "rune": "${value}",`,
  value => `Rune: ${value}`,
];
const COMMAND = [
  value => `lightning-cli commando 02${'ab'.repeat(32)} getinfo '{}' ${value}`,
  value => `lightning-cli checkrune ${value}`,
];

/**
 * Generates the corpus, scans it with the built scanner and counts findings per setting and class.
 * `distRoot` is the built package (dist/).
 */
export async function measure({ perClass = 2000, seed = 20261009, distRoot = resolve('dist'), scratchRoot = tmpdir() } = {}) {
  const { scan } = await import(pathToFileURL(join(distRoot, 'scan/index.js')).href);
  const random = prng(seed);
  const classes = generators(random);
  const dir = mkdtempSync(join(scratchRoot, 'rune-fp-'));
  const settings = { 'no-context': NO_CONTEXT, key: KEY, command: COMMAND };
  const report = { seed, perClass, settings: {} };
  try {
    for (const [setting, templates] of Object.entries(settings)) {
      const rows = {};
      for (const [name, generate] of Object.entries(classes)) {
        // One line per value; a file per class and setting keeps line numbers equal to value indexes.
        const lines = Array.from({ length: perClass }, (_, index) => templates[index % templates.length](generate()));
        const file = join(dir, `${setting}-${name}.txt`);
        writeFileSync(file, `${lines.join('\n')}\n`);
        const result = await scan([file], { clock: () => new Date('2026-10-09T00:00:00Z') });
        const rune = result.findings.filter(finding => finding.kind === 'rune').length;
        const invalid = result.findings.filter(finding => finding.kind === 'rune-invalid').length;
        rows[name] = { values: perClass, rune, runeInvalid: invalid };
      }
      const values = Object.values(rows).reduce((sum, row) => sum + row.values, 0);
      const rune = Object.values(rows).reduce((sum, row) => sum + row.rune, 0);
      const invalid = Object.values(rows).reduce((sum, row) => sum + row.runeInvalid, 0);
      const falsePositives = setting === 'key' ? rune : rune + invalid;
      report.settings[setting] = { values, rune, runeInvalid: invalid, falsePositives, rate: falsePositives / values, classes: rows };
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  return report;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const args = process.argv.slice(2);
  const option = (name, fallback) => { const at = args.indexOf(name); return at < 0 ? fallback : Number(args[at + 1]); };
  const report = await measure({ perClass: option('--per-class', 2000), seed: option('--seed', 20261009) });
  if (args.includes('--json')) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  else for (const [setting, row] of Object.entries(report.settings))
    process.stdout.write(`${setting.padEnd(10)} ${row.values} values: ${row.rune} reported as rune, ${row.runeInvalid} as rune-invalid; `
      + `false positives ${row.falsePositives} (${(row.rate * 100).toFixed(4)}%)\n`);
}
