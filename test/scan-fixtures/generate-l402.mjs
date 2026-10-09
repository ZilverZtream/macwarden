// Generates test/scan-fixtures/l402: synthetic L402 credentials for the scan and gitleaks
// tests. Built independently of src/ (go-macaroon v2 framing and signature chain, Aperture's
// version 0 identifier and token store file) with a fixed throwaway root key, so every run
// writes the same bytes. Nothing here was issued by a real service.
// Run: node test/scan-fixtures/generate-l402.mjs
import { createHash, createHmac } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const out = join(dirname(fileURLToPath(import.meta.url)), 'l402');
const rootKey = Buffer.alloc(32, 0x5a);
const sha256 = (...parts) => parts.reduce((hash, part) => hash.update(part), createHash('sha256')).digest();
const fp = (...parts) => `fp:${sha256(...parts).toString('hex').slice(0, 16)}`;
const hmac = (key, data) => createHmac('sha256', key).update(data).digest();
const varint = value => { const bytes = []; do { let b = value % 128; value = Math.floor(value / 128); if (value) b |= 128; bytes.push(b); } while (value); return Buffer.from(bytes); };
const packet = (kind, data) => Buffer.concat([varint(kind), varint(data.length), data]);

function macaroon(identifier, caveats) {
  let signature = hmac(hmac(Buffer.from('macaroons-key-generator'), rootKey), identifier);
  const parts = [Buffer.from([2]), packet(1, Buffer.from('lsat')), packet(2, identifier), Buffer.from([0])];
  for (const caveat of caveats) {
    const id = Buffer.from(caveat);
    parts.push(packet(2, id), Buffer.from([0]));
    signature = hmac(signature, id);
  }
  parts.push(Buffer.from([0]), packet(6, signature));
  return Buffer.concat(parts);
}

function token(seed, caveats = ['services=fixture:0', 'fixture_capabilities=read', 'fixture_valid_until=1893456000']) {
  const preimage = sha256(Buffer.from(`l402 fixture preimage ${seed}`));
  const paymentHash = sha256(preimage);
  const tokenId = sha256(Buffer.from(`l402 fixture token id ${seed}`));
  const mac = macaroon(Buffer.concat([Buffer.alloc(2), paymentHash, tokenId]), caveats);
  return { preimage, paymentHash, mac, b64: mac.toString('base64'), hex: preimage.toString('hex') };
}

const header = token(1);
const legacy = token(2);
const pair = token(3);
const grpc = token(4);
const stored = token(5);
const grpcPaid = macaroon(Buffer.concat([Buffer.alloc(2), grpc.paymentHash, sha256(Buffer.from('l402 fixture token id 4'))]),
  ['services=fixture:0', `preimage=${grpc.hex}`]);

const files = [];
function text(path, lines, findings) {
  writeFileSync(join(out, path), lines.join('\n') + '\n');
  files.push({ path, findings: findings.map(({ needle, ...item }) => ({ ...item, column: lines[item.line - 1].indexOf(needle) + 1 })) });
}

mkdirSync(join(out, 'lnget', 'tokens', 'api.example.com'), { recursive: true });
text('auth.env', ['# synthetic L402 fixture', `L402_TOKEN=L402 ${header.b64}:${header.hex}`],
  [{ line: 2, needle: 'L402 Ag', kind: 'l402', form: 'authorization', status: 'live', fingerprint: fp(header.mac, header.preimage) }]);
text('access.log', ['GET /v1/data HTTP/1.1', 'Host: api.example.com', `Authorization: LSAT ${legacy.b64}:${legacy.hex}`],
  [{ line: 3, needle: 'LSAT ', kind: 'l402', form: 'authorization', status: 'live', fingerprint: fp(legacy.mac, legacy.preimage) }]);
text('client.json', ['{', `  "credential": "${pair.b64}:${pair.hex}"`, '}'],
  [{ line: 2, needle: pair.b64, kind: 'l402', form: 'pair', status: 'live', fingerprint: fp(pair.mac, pair.preimage) }]);
text('grpc.txt', [`macaroon: ${grpcPaid.toString('hex')}`],
  [{ line: 1, needle: '0201046c', kind: 'l402', form: 'macaroon', status: 'live', fingerprint: fp(grpcPaid) }]);
const tail = Buffer.alloc(24);
tail.writeBigUInt64BE(21_000n, 0);
tail.writeBigUInt64BE(1_000n, 8);
tail.writeBigInt64BE(1_700_000_000_000_000_000n, 16);
const length = Buffer.alloc(4);
length.writeUInt32BE(stored.mac.length);
writeFileSync(join(out, 'lnget', 'tokens', 'api.example.com', 'l402.token'),
  Buffer.concat([length, stored.mac, stored.paymentHash, stored.preimage, tail]));
files.push({ path: 'lnget/tokens/api.example.com/l402.token', findings: [{ line: null, kind: 'l402-file', form: 'token-file',
  status: 'live', fingerprint: fp(stored.mac, stored.preimage), column: null }] });
files.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));

// gitleaks reads text only; each rule's expected hits by file and line.
const gitleaks = [
  { path: 'access.log', line: 3, rule: 'macwarden-l402' },
  { path: 'access.log', line: 3, rule: 'macwarden-l402-macaroon-base64' },
  { path: 'auth.env', line: 2, rule: 'macwarden-l402' },
  { path: 'auth.env', line: 2, rule: 'macwarden-l402-macaroon-base64' },
  { path: 'client.json', line: 2, rule: 'macwarden-l402-macaroon-base64' },
  { path: 'grpc.txt', line: 1, rule: 'macwarden-l402-macaroon-hex' },
];
writeFileSync(join(out, 'manifest.json'), JSON.stringify({
  source: 'test/scan-fixtures/generate-l402.mjs: synthetic L402 tokens, fixed root key, fingerprints computed independently of src/',
  files, gitleaks,
  summary: { findings: 5, distinct: 5, countedAtRead: 5, byGrade: { L402: 5 } },
}, null, 2) + '\n');
