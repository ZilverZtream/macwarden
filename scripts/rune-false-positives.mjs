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
//   key         assigned to a rune key (RUNE=…, ?rune=…, --rune …, <rune>…, "rune": …, Rune: …) — what a mistaken or
//               placeholder value in a real rune setting looks like
//   command     a positional argument after lightning-cli commando / checkrune
//
// It reports, per setting and value class, how many values were reported as kind rune
// (recognised rune syntax) and as rune-invalid. In the key setting a rune-invalid finding is
// the intended fail-closed outcome; a kind rune finding there, or any finding in the other two
// settings, counts as a false positive. Nothing is written outside a private temporary directory.
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
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
    'lnd-macaroon-hex': () => macaroon().toString('hex'),
    'lnd-macaroon-base64': () => macaroon().toString('base64'),
    'lnd-macaroon-base64url': () => macaroon().toString('base64url'),
    'l402-pair': () => `${macaroon().toString('base64')}:${chars(HEX, 64)}`,
  };
  // An LND macaroon (v2 binary layout: location "lnd", an identifier with a root key ID and
  // permissions, end of caveats, signature) with random contents.
  function macaroon() {
    const varint = value => { const out = []; do { out.push((value & 127) | (value >= 128 ? 128 : 0)); value = Math.floor(value / 128); } while (value); return Buffer.from(out); };
    const field = (kind, data) => Buffer.concat([varint(kind), varint(data.length), data]);
    const proto = (kind, data) => field(kind * 8 + 2, data);
    const ops = Array.from({ length: int(1, 6) }, () => proto(3, Buffer.concat([proto(1, Buffer.from(pick(['onchain', 'offchain', 'invoices', 'info', 'peers', 'message']))),
      proto(2, Buffer.from(pick(['read', 'write'])))])));
    const identifier = Buffer.concat([Buffer.from([3]), proto(1, bytes(16)), proto(2, Buffer.from(String(int(0, 1e6)))), ...ops]);
    return Buffer.concat([Buffer.from([2]), field(1, Buffer.from('lnd')), field(2, identifier), Buffer.from([0, 0]), field(6, bytes(32))]);
  }
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
  value => `https://node.example/api?rune=${value}&format=json`,
  value => `myapp --rune ${value}`,
  value => `<rune>${value}</rune>`,
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

// Recall: real-form runes (random authenticator, a decimal unique ID as createrune writes it,
// typical restrictions) in every supported context, with quoting, blank, line-ending and
// encoding variants. A rune counts as found when exactly its finding (kind rune, its fingerprint)
// is reported on its line.
const PEER = `02${'ab'.repeat(32)}`;
export const RECALL_CONTEXTS = {
  'env': value => [`RUNE=${value}`],
  'env-prefixed-quoted': value => [`CLN_RUNE="${value}"`],
  'shell-export': value => [`export LIGHTNING_RUNE='${value}'`],
  'env-blanks': value => [`RUNE = ${value}`],
  'env-trailing-comment': value => [`RUNE=${value}  # production node`],
  'env-unpadded': value => [`RUNE=${value.replace(/=+$/, '')}`],
  'json': value => [`{"node": {"rune": "${value}"}}`],
  'json-blanks': value => [`{ "rune" :  "${value}" , "x": 1 }`],
  'json-camel': value => [`{"clnRune":"${value}"}`],
  'json-pretty': value => ['{', '  "cln": {', `    "rune": "${value}",`, '    "host": "node"', '  }', '}'],
  'mcp-env': value => [`{"mcpServers":{"cln":{"command":"cln-mcp","env":{"CLN_RUNE":"${value}"}}}}`],
  'yaml': value => ['cln:', `  rune: ${value}`],
  'yaml-quoted': value => [`rune: '${value}'`],
  'yaml-tab': value => [`rune:\t${value}`],
  'toml': value => ['[cln]', `rune = "${value}"`],
  'header-curl': value => [`curl -sk -H "Rune: ${value}" https://localhost:3010/v1/getinfo`],
  'header-lower': value => [`curl -H 'rune:${value}' -X POST https://node:3010/v1/getinfo`],
  'header-raw-http': value => ['GET /v1/getinfo HTTP/1.1', 'Host: node', `Rune: ${value}`, ''],
  'cli-keyword': value => [`lightning-cli -k commando peer_id=${PEER} method=getinfo rune=${value}`],
  'pyln': value => [`node.call("commando", {"peer_id": pid, "method": "getinfo", "rune": "${value}"})`],
  'js-object': value => [`const client = new Commando({ rune: '${value}' });`],
  'flag': value => [`myapp --rune=${value} --verbose`],
  'url-query': value => [`https://app.example/?rune=${value}&x=1`],
  'url-percent-padding': value => [`https://app.example/?rune=${value.replace(/=/g, '%3D')}`],
  'commando-positional': value => [`lightning-cli commando ${PEER} getinfo '{}' ${value}`],
  'checkrune-positional': value => [`lightning-cli checkrune ${value}`],
  'showrunes-quoted': value => [`Run \`lightning-cli showrunes "${value}"\` to see it.`],
  'k8s-secret': value => ['data:', `  rune: ${Buffer.from(value).toString('base64')}`],
  'go-short-declaration': value => [`clnRune := "${value}"`],
  'make-assignment': value => [`CLN_RUNE := ${value}`],
  'option-blank': value => [`myapp --rune ${value} --verbose`],
  'option-blank-quoted': value => [`cln-mcp --cln-rune "${value}"`],
  'xml-element': value => [`<node><rune>${value}</rune></node>`],
  'systemd-environment': value => [`Environment="CLN_RUNE=${value}"`],
  'powershell-env': value => [`$env:CLN_RUNE = "${value}"`],
  'compose-environment': value => ['    environment:', `      - CLN_RUNE=${value}`],
};
const LINE_ENDS = { lf: '\n', crlf: '\r\n', cr: '\r' };

/** Restriction text in the form of real runes: a decimal unique ID first, then a typical policy. */
function realRestrictions(random) {
  const int = (low, high) => low + Math.floor(random() * (high - low + 1));
  const pick = items => items[Math.floor(random() * items.length)];
  const policies = [['method=getinfo'], ['method=pay|method=xpay', 'pnameamount_msat<100000'], ['method^list|method^get|method=summary', 'method/listdatastore'],
    ['method=invoice', 'rate=10'], ['time<1900000000', 'method=listfunds'], [`id=${PEER}`, 'method=listpeers'], [], ['method=pay', 'pnamedescription=café ☕']];
  return [`=${int(0, 999999)}`, ...pick(policies)].join('&');
}

/** Scans every rune in every context and variant; returns per-context counts of runes found and missed. */
export async function measureRecall({ perContext = 120, seed = 20261009, distRoot = resolve('dist'), scratchRoot = tmpdir() } = {}) {
  const { scan } = await import(pathToFileURL(join(distRoot, 'scan/index.js')).href);
  const random = prng(seed ^ 0x5eed);
  const dir = mkdtempSync(join(scratchRoot, 'rune-recall-'));
  const expected = [];
  try {
    let fileIndex = 0;
    for (const [context, place] of Object.entries(RECALL_CONTEXTS))
      for (let index = 0; index < perContext; index++) {
        const authenticator = Buffer.from(Array.from({ length: 32 }, () => Math.floor(random() * 256)));
        const bytes = Buffer.concat([authenticator, Buffer.from(realRestrictions(random), 'utf8')]);
        const raw = bytes.toString('base64url');
        const value = raw + '='.repeat((4 - raw.length % 4) % 4);
        const fingerprint = `fp:${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`;
        const ending = Object.keys(LINE_ENDS)[index % 3];
        const encoding = ['utf8', 'utf8-bom', 'utf16le-bom'][Math.floor(index / 3) % 3];
        const lines = place(value);
        const before = index % 2 ? ['# configuration', ''] : [];
        const all = [...before, ...lines, 'OTHER=value'];
        const text = all.join(LINE_ENDS[ending]) + LINE_ENDS[ending];
        const forms = [value, value.replace(/=+$/, ''), value.replace(/=/g, '%3D'), Buffer.from(value).toString('base64')];
        const line = before.length + lines.findIndex(item => forms.some(form => item.includes(form))) + 1;
        const file = join(dir, `${String(fileIndex++).padStart(6, '0')}-${context}.txt`);
        const data = encoding === 'utf8' ? Buffer.from(text, 'utf8') : encoding === 'utf8-bom' ? Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text, 'utf8')])
          : Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')]);
        writeFileSync(file, data);
        expected.push({ name: basename(file), context, ending, encoding, fingerprint, line });
      }
    const result = await scan([dir], { clock: () => new Date('2026-10-09T00:00:00Z') });
    const byFile = new Map();
    for (const finding of result.findings) {
      if (finding.kind !== 'rune' && finding.kind !== 'rune-invalid') continue;
      const name = basename(finding.path);
      if (!byFile.has(name)) byFile.set(name, []);
      byFile.get(name).push(finding);
    }
    const contexts = {};
    const missed = [];
    for (const item of expected) {
      const reported = byFile.get(item.name) ?? [];
      const found = reported.filter(finding => finding.kind === 'rune' && finding.fingerprint === item.fingerprint && finding.line === item.line);
      const row = contexts[item.context] ??= { runes: 0, found: 0, missed: 0 };
      row.runes++;
      if (found.length === 1 && reported.length === 1) row.found++;
      else {
        row.missed++;
        if (missed.length < 20) missed.push({ context: item.context, ending: item.ending, encoding: item.encoding,
          reported: reported.map(finding => `${finding.kind}@${finding.line}${finding.fingerprint === item.fingerprint ? '' : ' other fingerprint'}`) });
      }
    }
    const runes = expected.length;
    const found = Object.values(contexts).reduce((sum, row) => sum + row.found, 0);
    return { seed, perContext, runes, found, missedTotal: runes - found, rate: (runes - found) / runes, contexts, missed };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const args = process.argv.slice(2);
  const option = (name, fallback) => { const at = args.indexOf(name); return at < 0 ? fallback : Number(args[at + 1]); };
  const report = await measure({ perClass: option('--per-class', 2000), seed: option('--seed', 20261009) });
  const recall = await measureRecall({ perContext: option('--per-context', 120), seed: option('--seed', 20261009) });
  if (args.includes('--json')) process.stdout.write(`${JSON.stringify({ ...report, recall }, null, 2)}\n`);
  else {
    for (const [setting, row] of Object.entries(report.settings))
      process.stdout.write(`${setting.padEnd(10)} ${row.values} values: ${row.rune} reported as rune, ${row.runeInvalid} as rune-invalid; `
        + `false positives ${row.falsePositives} (${(row.rate * 100).toFixed(4)}%)\n`);
    process.stdout.write(`recall     ${recall.runes} runes in ${Object.keys(recall.contexts).length} contexts and variants: ${recall.found} found, `
      + `${recall.missedTotal} missed (${(recall.rate * 100).toFixed(4)}%)\n`);
    for (const [context, row] of Object.entries(recall.contexts)) if (row.missed) process.stdout.write(`  missed in ${context}: ${row.missed} of ${row.runes}\n`);
  }
}
