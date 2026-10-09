import { readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'node:fs';
import { join } from 'node:path';

const root = process.cwd();
const base = join(root, 'test/scan-fixtures');
const full = join(base, 'full');
const look = join(base, 'lookalike');
mkdirSync(full, { recursive: true });
mkdirSync(look, { recursive: true });
const vectors = join(root, 'test/vectors');
const manifest = JSON.parse(readFileSync(join(vectors, 'manifest.json'), 'utf8'));
const reference = name => {
  const item = manifest.vectors.find(vector => vector.name === name);
  if (!item) throw new Error('missing vector');
  return item;
};
const vector = name => readFileSync(join(vectors, `${name}.macaroon`));
for (const [file, name] of [
  ['admin.macaroon', 'default-admin'],
  ['ro.macaroon', 'default-readonly'],
  ['inv.macaroon', 'default-invoice'],
]) copyFileSync(join(vectors, `${name}.macaroon`), join(full, file));

const hex = vector('default-readonly').toString('hex');
const b64 = vector('default-invoice').toString('base64');
const uri = `lndconnect://h:10009?macaroon=${vector('preset-pay-only').toString('base64url')}`;
const nwc = `nostr+walletconnect://${'22'.repeat(32)}?secret=${Buffer.alloc(32, 0x11).toString('hex')}`;
const content = {
  'app.env': `H=${hex}\nB=${b64}\nL=${uri}\nN=${nwc}\n`,
  'app.yml': `h: ${hex}\nb: ${b64}\nl: ${uri}\nn: ${nwc}\n`,
  'app.json': `{\n"h":"${hex}",\n"b":"${b64}",\n"l":"${uri}",\n"n":"${nwc}"\n}\n`,
};
const kinds = [
  ['macaroon-hex', 'default-readonly', hex],
  ['macaroon-base64', 'default-invoice', b64],
  ['lndconnect', 'preset-pay-only', uri],
  ['nwc', null, nwc],
];
const files = [];
for (const [file, body] of Object.entries(content)) {
  writeFileSync(join(full, file), body);
  const lines = body.split('\n');
  const findings = kinds.map(([kind, name, value]) => {
    const line = lines.findIndex(text => text.includes(value));
    return { line: line + 1, column: lines[line].indexOf(value) + 1,
      kind, fingerprint: name ? reference(name).fingerprint : 'fp:02d449a31fbb267c',
      grade: name ? reference(name).expectedGrade : null };
  });
  files.push({ path: file, findings });
}
for (const [file, name] of [
  ['admin.macaroon', 'default-admin'],
  ['ro.macaroon', 'default-readonly'],
  ['inv.macaroon', 'default-invoice'],
]) files.push({ path: file, findings: [{ line: null, column: null, kind: 'macaroon-file',
  fingerprint: reference(name).fingerprint, grade: reference(name).expectedGrade }] });
files.push({ path: 'manifest.json', findings: [] });
files.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
writeFileSync(join(full, 'binary.dat'), Buffer.from([0, 0, 0]));
writeFileSync(join(full, 'private.key'), 'protected decoy');
mkdirSync(join(full, 'node_modules'), { recursive: true });
writeFileSync(join(full, 'node_modules', 'x.env'), hex);
const skipped = [{ path: 'binary.dat', reason: 'binary' },
  { path: 'node_modules', reason: 'excluded-dir' },
  { path: 'private.key', reason: 'never-open' }];
const byGrade = { ADMIN: 1, SPEND: 3, OPERATE: 0, RECEIVE: 4, READ: 4,
  UNASSESSED: 0, NWC: 3, UNDECODABLE: 0, L402: 0 };
writeFileSync(join(full, 'manifest.json'), JSON.stringify({
  source: 'test/vectors/manifest.json and stored printmacaroon facts; fixed NWC 32-byte sentinel',
  files, skipped, summary: { filesScanned: 7, filesSkipped: 3, dropped: 0,
    ignored: 0, findings: 15, distinct: 5, byGrade },
}, null, 2) + '\n');

writeFileSync(join(look, 'almost.env'), 'lndconnect://h:1?macaroon=AAAA\nnot a macaroon prefix\n');
writeFileSync(join(look, 'almost.yml'), 'nwc: nostr+walletconnect://nothex?secret=1234\n');
writeFileSync(join(look, 'manifest.json'), JSON.stringify({
  source: 'literal planted look-alikes',
  files: [{ path: 'almost.env', findings: [], dropped: 1 },
    { path: 'almost.yml', findings: [], dropped: 0 },
    { path: 'manifest.json', findings: [], dropped: 0 }],
  skipped: [], summary: { filesScanned: 3, filesSkipped: 0, dropped: 1,
    ignored: 0, findings: 0, distinct: 0, byGrade: Object.fromEntries(Object.keys(byGrade).map(key => [key, 0])) },
}, null, 2) + '\n');
