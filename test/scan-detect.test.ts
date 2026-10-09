import { createHash, createHmac } from 'node:crypto';
import { linkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { expect, it, vi } from 'vitest';
import { findLeaks } from "./helpers/leak-check.js";

const networkCalls = vi.hoisted(() => [] as string[]);
vi.mock('node:https', async importOriginal => {
  const original = await importOriginal<typeof import('node:https') & { default: typeof import('node:https') }>();
  const blocked = () => { networkCalls.push('https'); throw new Error('network called'); };
  return { ...original, request: blocked, get: blocked,
    default: { ...original.default, request: blocked, get: blocked } };
});
vi.mock('node:http', async importOriginal => {
  const original = await importOriginal<typeof import('node:http') & { default: typeof import('node:http') }>();
  const blocked = () => { networkCalls.push('http'); throw new Error('network called'); };
  return { ...original, request: blocked, get: blocked,
    default: { ...original.default, request: blocked, get: blocked } };
});
vi.mock('node:net', async importOriginal => {
  const original = await importOriginal<typeof import('node:net') & { default: typeof import('node:net') }>();
  const blocked = () => { networkCalls.push('net'); throw new Error('network called'); };
  return { ...original, connect: blocked, createConnection: blocked,
    default: { ...original.default, connect: blocked, createConnection: blocked } };
});

type Finding = { path: string; line: number | null; column: number | null; kind: string;
  fingerprint: string; grade: string | null; rootKeyId: string | null;
  permissions: string[] | null; caveats: unknown[] | null; warnings: string[]; unassessed: string[] };
type Result = { findings: Finding[]; skipped: { path: string; reason: string }[];
  summary: { filesScanned: number; filesSkipped: number; dropped: number; ignored: number;
    findings: number; distinct: number; byGrade: Record<string, number> }; failOn: null };
type Scanner = { scan: (paths: string[], opts: object) => Promise<Result> };
const repo = resolve();
const vectors = join(repo, 'test/vectors');
const testTmp = process.env.MACWARDEN_TEST_TMP || join(tmpdir(), 'macwarden-test-tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const manifest = JSON.parse(readFileSync(join(vectors, 'manifest.json'), 'utf8')) as {
  vectors: { name: string; fingerprint: string; expectedGrade: string }[] };
const vector = (name: string) => readFileSync(join(vectors, `${name}.macaroon`));
const reference = (name: string) => manifest.vectors.find(entry => entry.name === name)!;
const printed = (name: string) => JSON.parse(readFileSync(join(vectors, `${name}.printmacaroon.json`), 'utf8')) as {
  root_key_id: string; permissions: string[]; caveats: string[] | null };
const slash = (path: string) => path.split(sep).join('/');
const hashText = (value: string) => `fp:${createHash('sha256').update(value, 'utf8').digest('hex').slice(0, 16)}`;
const nwcSecret = Buffer.alloc(32, 0x11);
const nwcText = `nostr+walletconnect://${'22'.repeat(32)}?relay=wss%3A%2F%2Fr&secret=${nwcSecret.toString('hex')}`;
const nwcFingerprint = 'fp:02d449a31fbb267c';

const scanner = (): Promise<Scanner> => import('../src/scan/index.js') as Promise<Scanner>;
async function scan(paths: string[]): Promise<Result> { return (await scanner()).scan(paths, {}); }
async function temp<T>(work: (dir: string) => Promise<T>): Promise<T> {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp009-'));
  try { return await work(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}
function file(dir: string, name: string, content: string | Buffer): string {
  const path = join(dir, name);
  writeFileSync(path, content);
  return path;
}
function projection(finding: Finding) {
  return { path: slash(finding.path), line: finding.line, column: finding.column,
    kind: finding.kind, fingerprint: finding.fingerprint, grade: finding.grade };
}
function fact(finding: Finding, name: string): void {
  expect(finding.fingerprint).toBe(reference(name).fingerprint);
  expect(finding.grade).toBe(reference(name).expectedGrade);
  expect(finding.rootKeyId).toBe(printed(name).root_key_id);
  expect(finding.permissions).toEqual(printed(name).permissions);
  expect(finding.caveats).toEqual([]);
  expect(finding.warnings).toEqual(['root-key-0']);
  expect(finding.unassessed).toEqual([]);
}
function nullFacts(finding: Finding): void {
  expect(finding.grade).toBeNull();
  expect(finding.rootKeyId).toBeNull();
  expect(finding.permissions).toBeNull();
  expect(finding.caveats).toBeNull();
  expect(finding.warnings).toEqual([]);
  expect(finding.unassessed).toEqual([]);
}
function summary(result: Result, findings: number, distinct: number, dropped = 0, files = 1): void {
  expect(result.summary).toMatchObject({ findings, distinct, dropped, ignored: 0,
    filesScanned: files, filesSkipped: 0 });
  expect(result.skipped).toEqual([]);
  expect(result.failOn).toBeNull();
}
function corpus(dir: string): string[] {
  const readonly = vector('default-readonly').toString('hex');
  const invoice = vector('default-invoice').toString('base64');
  const pay = vector('preset-pay-only').toString('base64url');
  const adminHex = vector('default-admin').toString('hex');
  const adminB64 = vector('default-admin').toString('base64');
  return [
    file(dir, 'a.env', `first\nsecond\nLND_MACAROON=${readonly}\n`),
    file(dir, 'c.yml', `first\nmac: ${invoice}\n`),
    file(dir, 'd.json', `{"m":"${vector('default-invoice').toString('base64url')}"}`),
    file(dir, 'e.env', `URL="lndconnect://h:10009?cert=AAAA&macaroon=${pay}"`),
    file(dir, 'f.txt', `<lndconnect://h:10009?macaroon=${pay}>`),
    file(dir, 'g.yml', `${nwcText}"`),
    file(dir, 'h.json', `"${nwcText}"`),
    file(dir, 'i.txt', `${adminHex.slice(0, 120)}\n${adminHex.slice(120)}`),
    file(dir, 'j.txt', `${adminB64.slice(0, 76)}\n${adminB64.slice(76)}`),
    file(dir, 'k.env', 'lndconnect://h:1?macaroon=AAAA'),
    file(dir, 'l.env', 'lndconnect://h:1?cert=AAAA'),
  ];
}

// Build a controlled first-party caveat from the v2 packet layout. The source
// vector has no caveats, so its signature can attenuate the new condition.
function packet(kind: number, data: Buffer): Buffer {
  const varint = (value: number): Buffer => {
    const digits: number[] = [];
    do { digits.push((value & 127) | (value >= 128 ? 128 : 0)); value = Math.floor(value / 128); } while (value);
    return Buffer.from(digits);
  };
  return Buffer.concat([varint(kind), varint(data.length), data]);
}
function firstPacket(bytes: Buffer, offset: number): { kind: number; end: number; value: Buffer } {
  const readVarint = (start: number): { value: number; end: number } => {
    let value = 0, scale = 1, cursor = start;
    for (let count = 0; count < 10 && cursor < bytes.length; count++) {
      const digit = bytes[cursor++];
      value += (digit & 127) * scale;
      if (!(digit & 128)) return { value, end: cursor };
      scale *= 128;
    }
    throw new Error('controlled vector packet varint is unsuitable');
  };
  const kind = readVarint(offset);
  const length = readVarint(kind.end);
  if (length.end + length.value > bytes.length) throw new Error('controlled vector packet length is unsuitable');
  return { kind: kind.value, end: length.end + length.value,
    value: bytes.subarray(length.end, length.end + length.value) };
}
function addFirstParties(base: Buffer, conditions: string[]): Buffer {
  if (base[0] !== 2) throw new Error('controlled vector header is unsuitable');
  let offset = 1;
  if (base[offset] === 1) offset = firstPacket(base, offset).end;
  if (firstPacket(base, offset).kind !== 2) throw new Error('controlled vector identifier is missing');
  offset = firstPacket(base, offset).end;
  if (base[offset++] !== 0 || base[offset] !== 0) throw new Error('controlled vector has caveats');
  const signature = firstPacket(base, offset + 1);
  if (signature.kind !== 6 || signature.value.length !== 32 || signature.end !== base.length)
    throw new Error('controlled vector signature is unsuitable');
  let attenuated = signature.value;
  const caveats = conditions.flatMap(condition => {
    const identifier = Buffer.from(condition, 'utf8');
    attenuated = createHmac('sha256', attenuated).update(identifier).digest();
    return [packet(2, identifier), Buffer.from([0])];
  });
  return Buffer.concat([base.subarray(0, offset), ...caveats, Buffer.from([0]),
    packet(6, attenuated)]);
}
function addFirstParty(base: Buffer, condition: string): Buffer {
  return addFirstParties(base, [condition]);
}

it('CP-009/B1 hex file argument decodes readonly facts and counts', async () => temp(async dir => {
  const path = file(dir, 'a.env', `first\nsecond\nLND_MACAROON=${vector('default-readonly').toString('hex')}`);
  const result = await scan([path]);
  summary(result, 1, 1);
  expect(result.findings.map(projection)).toEqual([{ path: slash(path), line: 3, column: 14,
    kind: 'macaroon-hex', fingerprint: reference('default-readonly').fingerprint, grade: 'READ' }]);
  fact(result.findings[0], 'default-readonly');
}));

it('CP-009/B2 base64 and base64url decode to one distinct invoice fingerprint', async () => temp(async dir => {
  const paths = [file(dir, 'c.yml', `first\nmac: ${vector('default-invoice').toString('base64')}`),
    file(dir, 'd.json', `{"m":"${vector('default-invoice').toString('base64url')}"}`)];
  const result = await scan(paths);
  summary(result, 2, 1, 0, 2);
  expect(result.findings.map(f => [f.kind, f.line, f.column])).toEqual([
    ['macaroon-base64', 2, 6], ['macaroon-base64', 1, 7]]);
  for (const finding of result.findings) fact(finding, 'default-invoice');
}));

it('CP-009/B3 lndconnect takes precedence over its macaroon parameter', async () => temp(async dir => {
  const pay = vector('preset-pay-only').toString('base64url');
  const paths = [file(dir, 'e.env', `URL="lndconnect://h:10009?cert=AAAA&macaroon=${pay}"`),
    file(dir, 'f.txt', `<lndconnect://h:10009?macaroon=${pay}>`)];
  const result = await scan(paths);
  summary(result, 2, 1, 0, 2);
  expect(result.findings.map(f => [f.kind, f.line, f.column])).toEqual([
    ['lndconnect', 1, 6], ['lndconnect', 1, 2]]);
  for (const finding of result.findings) fact(finding, 'preset-pay-only');
}));

// RR-01 reversed the original B3 decision: some generators write the standard base64
// alphabet, and a scan must not pass a usable credential. A literal plus is kept (never a space).
it('CP-009/B3 lndconnect finds a literal plus in a standard-base64 parameter', async () => temp(async dir => {
  const standard = vector('default-readonly').toString('base64');
  expect(standard.includes('+'), 'committed vector must exercise literal plus').toBe(true);
  const path = file(dir, 'standard.env', `URL="lndconnect://h:10009?macaroon=${standard}"`);
  const result = await scan([path]);
  summary(result, 1, 1, 0);
  expect(result.findings.map(f => [f.kind, f.column, f.fingerprint])).toEqual([
    ['lndconnect', 6, reference('default-readonly').fingerprint]]);
}));

it('CP-009/B4 NWC fingerprints the 32 secret bytes and leaves decoded facts null', async () => temp(async dir => {
  const paths = [file(dir, 'g.yml', `${nwcText}"`), file(dir, 'h.json', `"${nwcText}"`)];
  const result = await scan(paths);
  summary(result, 2, 1, 0, 2);
  expect(result.findings.map(f => [f.kind, f.line, f.column, f.fingerprint])).toEqual([
    ['nwc', 1, 1, nwcFingerprint], ['nwc', 1, 2, nwcFingerprint]]);
  for (const finding of result.findings) nullFacts(finding);
}));

it('CP-009/B5 wrapped credentials become candidates and bad lndconnect URIs are dropped', async () => temp(async dir => {
  const hex = vector('default-admin').toString('hex');
  const b64 = vector('default-admin').toString('base64');
  const paths = [file(dir, 'i.txt', `${hex.slice(0, 120)}\n${hex.slice(120)}`),
    file(dir, 'j.txt', `${b64.slice(0, 76)}\n${b64.slice(76)}`),
    file(dir, 'k.env', 'lndconnect://h:1?macaroon=AAAA'),
    file(dir, 'l.env', 'lndconnect://h:1?cert=AAAA')];
  const result = await scan(paths);
  summary(result, 2, 2, 2, 4);
  expect(result.findings.map(f => [f.kind, f.line, f.column, f.fingerprint])).toEqual([
    ['undecodable-candidate', 1, 1, hashText(hex.slice(0, 120))],
    ['undecodable-candidate', 1, 1, hashText(b64.slice(0, 76))]]);
  for (const finding of result.findings) nullFacts(finding);
}));

it('CP-009/B6 lookalikes and short prefixes produce no findings or drops', async () => temp(async dir => {
  const lines = ['a'.repeat(40), 'b'.repeat(40), 'c'.repeat(40),
    `0201036c6e6402${'a'.repeat(39)}`, `AgEDbG5kA${'A'.repeat(39)}`,
    'lndconnect', `nostr+walletconnect://${'22'.repeat(32)}?secret=${'1'.repeat(63)}`,
    `nostr+walletconnect://${'22'.repeat(32)}?secret=${'1'.repeat(65)}`,
    '123e4567-e89b-12d3-a456-426614174000'];
  const result = await scan([file(dir, 'm.txt', lines.join('\n'))]);
  summary(result, 0, 0);
  expect(result.findings.length).toBe(0);
}));

it('CP-009/B7 BOMs and CRLF LF CR line ends preserve line and column', async () => temp(async dir => {
  const value = vector('default-readonly').toString('hex');
  const text = (end: string) => `first${end}    ${value}${end}third`;
  const utf16be = Buffer.from(`\ufeff${text('\n')}`, 'utf16le');
  for (let i = 0; i + 1 < utf16be.length; i += 2) [utf16be[i], utf16be[i + 1]] = [utf16be[i + 1], utf16be[i]];
  const files = [
    file(dir, 'utf8.txt', text('\n')),
    file(dir, 'utf8bom.txt', `\ufeff${text('\n')}`),
    file(dir, 'utf16le.txt', Buffer.from(`\ufeff${text('\n')}`, 'utf16le')),
    file(dir, 'utf16be.txt', utf16be),
    file(dir, 'crlf.txt', text('\r\n')),
    file(dir, 'cr.txt', text('\r')),
  ];
  for (const path of files) {
    const result = await scan([path]);
    summary(result, 1, 1);
    expect(result.findings.map(f => [f.line, f.column, f.fingerprint])).toEqual([
      [2, 5, reference('default-readonly').fingerprint]]);
  }
}));

it('CP-009/B8 columns count Unicode code points after multibyte characters', async () => temp(async dir => {
  const path = file(dir, 'unicode.txt', `é€😀 KEY=${vector('default-readonly').toString('hex')}`);
  const result = await scan([path]);
  summary(result, 1, 1);
  expect(result.findings.map(f => [f.line, f.column, f.fingerprint])).toEqual([
    [1, 9, reference('default-readonly').fingerprint]]);
}));

it('CP-009/B9 overlapping 65536-code-point windows report boundary hits once', async () => temp(async dir => {
  const invoice = vector('default-invoice').toString('base64');
  const readonly = vector('default-readonly').toString('hex');
  function line(fill: string): string {
    let value = fill.repeat(32_698) + ` ${invoice} `;
    value += fill.repeat(69_998 - Array.from(value).length) + ` ${readonly} `;
    return value + fill.repeat(200_000 - Array.from(value).length);
  }
  const paths = [file(dir, 'ascii.txt', line('.')), file(dir, 'astral.txt', line('😀'))];
  for (const path of paths) {
    const result = await scan([path]);
    summary(result, 2, 2);
    expect(result.findings.map(f => [f.line, f.column, f.fingerprint])).toEqual([
      [1, 32_700, reference('default-invoice').fingerprint],
      [1, 70_000, reference('default-readonly').fingerprint]]);
  }
}));

it('CP-009/B10 findings sort by UTF-8 path bytes then line and column', async () => temp(async dir => {
  const readonly = vector('default-readonly').toString('hex');
  const invoice = vector('default-invoice').toString('base64');
  const mixed = file(dir, 'z.txt', `${invoice} ${readonly}`);
  const paths = ['ä.env', 'a.env', 'B.env'].map(name => file(dir, name, readonly));
  const result = await scan([...paths, mixed]);
  summary(result, 5, 2, 0, 4);
  expect(result.findings.map(f => [slash(f.path), f.line, f.column])).toEqual([
    [slash(paths[2]), 1, 1], [slash(paths[1]), 1, 1], [slash(mixed), 1, 1],
    [slash(mixed), 1, invoice.length + 2], [slash(paths[0]), 1, 1]]);
}));

it('CP-009/B10 repeated regular-file arguments scan once under the first argument', async () => temp(async dir => {
  const path = file(dir, 'repeated.env', vector('default-readonly').toString('hex'));
  const result = await scan([path, path]);
  summary(result, 1, 1);
  expect(result.findings.map(projection)).toEqual([{ path: slash(path), line: 1, column: 1,
    kind: 'macaroon-hex', fingerprint: reference('default-readonly').fingerprint, grade: 'READ' }]);
  fact(result.findings[0], 'default-readonly');
}));

it('CP-009/B11 JSON results never contain vector or NWC secret encodings', async () => temp(async dir => {
  const paths = corpus(dir);
  const result = await scan(paths);
  summary(result, 9, 6, 2, 11);
  const sentinelDir = join(dir, 'sentinels');
  mkdirSync(sentinelDir);
  for (const name of ['default-admin', 'default-readonly', 'default-invoice', 'preset-pay-only'])
    writeFileSync(join(sentinelDir, `${name}.macaroon`), vector(name));
  writeFileSync(join(sentinelDir, 'nwc.bin'), nwcSecret);
  expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
    commandOutput: JSON.stringify(result), testTmp, root: repo }), 'credential leaked').toBeNull();
}));

it('CP-009/B11 returned scan facts redact a credential inside a decoded caveat', async () => temp(async dir => {
  const inner = vector('default-invoice');
  const innerHex = inner.toString('hex');
  const outer = addFirstParty(vector('default-readonly'), `lnd-custom safeA${innerHex}Bsafe`);
  const path = file(dir, 'outer.env', outer.toString('hex'));
  const result = await scan([path]);
  summary(result, 1, 1);
  const finding = result.findings[0];
  expect(finding.kind).toBe('macaroon-hex');
  expect(finding.fingerprint).toBe(`fp:${createHash('sha256').update(outer).digest('hex').slice(0, 16)}`);
  expect(finding.grade).toBe('READ');
  expect(finding.caveats?.length).toBe(1);
  const caveat = finding.caveats?.[0] as { type?: string; value?: string } | undefined;
  expect(caveat?.type).toBe('lnd-custom');
  const json = JSON.stringify(result);
  expect(json.includes(innerHex), 'inner credential leaked from returned scan object').toBe(false);
  expect(caveat?.value === 'safeA[redacted]Bsafe', 'safe caveat context must survive').toBe(true);
  expect(json.includes('safeA[redacted]Bsafe'), 'safe JSON context must survive').toBe(true);
}));

it('CP-009/B11 returned caveats redact an NWC secret confirmed by a URI in the same credential', async () => temp(async dir => {
  const sentinelDir = join(dir, 'sentinels');
  mkdirSync(sentinelDir);
  writeFileSync(join(sentinelDir, 'nwc.bin'), nwcSecret);
  const outer = addFirstParty(vector('default-readonly'),
    `before:${nwcSecret.toString('hex')}:after ${nwcText}`);
  const path = file(dir, 'outer.env', outer.toString('hex'));
  const result = await scan([path]);
  summary(result, 1, 1);
  const finding = result.findings[0];
  expect(finding.kind).toBe('macaroon-hex');
  expect(finding.fingerprint).toBe(`fp:${createHash('sha256').update(outer).digest('hex').slice(0, 16)}`);
  expect(finding.grade).toBe('READ');
  expect(finding.caveats?.length).toBe(1);
  const caveat = finding.caveats?.[0] as { type?: string; value?: string } | undefined;
  expect(caveat?.type).toBe('unknown');
  expect(caveat?.value === 'before:[redacted]:after [redacted]',
    'safe caveat context must survive').toBe(true);
  const json = JSON.stringify(result);
  expect(json.toLowerCase().includes(nwcSecret.toString('hex')),
    'confirmed NWC hex secret leaked from returned scan object').toBe(false);
  const leak = findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
    commandOutput: json, testTmp, root: repo });
  expect(leak, 'confirmed NWC secret leaked from returned scan object').toBeNull();
}));

it('CP-009/B11 returned caveats redact a recognisable NWC URI secret', async () => temp(async dir => {
  const sentinelDir = join(dir, 'sentinels');
  mkdirSync(sentinelDir);
  writeFileSync(join(sentinelDir, 'nwc.bin'), nwcSecret);
  const outer = addFirstParty(vector('default-readonly'), `lnd-custom ${nwcText}`);
  const path = file(dir, 'encoded.env', outer.toString('hex'));
  const result = await scan([path]);
  summary(result, 1, 1);
  const finding = result.findings[0];
  expect(finding.kind).toBe('macaroon-hex');
  expect(finding.fingerprint).toBe(`fp:${createHash('sha256').update(outer).digest('hex').slice(0, 16)}`);
  expect(finding.grade).toBe('READ');
  expect(finding.caveats?.length).toBe(1);
  const caveat = finding.caveats?.[0] as { type?: string; value?: string } | undefined;
  expect(caveat?.type).toBe('lnd-custom');
  const leak = findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
    commandOutput: JSON.stringify(result), testTmp, root: repo });
  expect(leak, 'identifiable NWC secret leaked from returned scan object').toBeNull();
}));

it('CP-009/B11 ordinary filenames retain their reported path', async () => temp(async dir => {
  const ordinary = file(dir, 'ordinary.env', vector('default-readonly').toString('hex'));
  const result = await scan([ordinary]);
  summary(result, 1, 1);
  expect(result.findings[0].path).toBe(slash(ordinary));
}));

const filenameSecret = vector('grade-malformed-uri-read');
const filenameBase64 = filenameSecret.toString('base64');
const filenameBase64url = filenameSecret.toString('base64url');
const filenameEncodings = [
  { label: 'base64url unpadded', value: filenameBase64url },
  { label: 'base64url padded', value: `${filenameBase64url}${'='.repeat((4 - filenameBase64url.length % 4) % 4)}` },
  { label: 'lower hex', value: filenameSecret.toString('hex') },
  { label: 'upper hex', value: filenameSecret.toString('hex').toUpperCase() },
];
if (!filenameBase64.includes('/')) filenameEncodings.push(
  { label: 'standard base64 padded', value: filenameBase64 },
  { label: 'standard base64 unpadded', value: filenameBase64.replace(/=+$/, '') },
);

for (const encoding of filenameEncodings) {
  it(`CP-009/B11 returned paths never expose ${encoding.label} macaroon filenames`, async () => temp(async dir => {
    const sentinelDir = join(dir, 'sentinels');
    mkdirSync(sentinelDir);
    writeFileSync(join(sentinelDir, 'filename.macaroon'), filenameSecret);
    const content = vector('default-readonly').toString('hex');
    const path = file(dir, `${encoding.value}.env`, content);
    expect(statSync(path).isFile()).toBe(true);
    let result: Result | undefined;
    let rejection: unknown;
    try {
      result = await scan([path]);
    } catch (error) {
      rejection = error;
    }
    let returned: string;
    if (result) {
      returned = JSON.stringify(result);
    } else {
      // A safe refusal is permitted, but an error must not echo its path argument.
      expect(rejection instanceof Error, 'scanner must return a result or an error').toBe(true);
      returned = `${String(rejection)}\n${String((rejection as Error).stack ?? '')}\n${JSON.stringify(rejection)}`;
    }
    expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
      commandOutput: returned, root: repo }),
    'encoded macaroon filename leaked from returned scan object or error').toBeNull();
    if (result) {
      summary(result, 1, 1);
      expect(result.findings[0]).toMatchObject({ line: 1, column: 1,
        kind: 'macaroon-hex', fingerprint: reference('default-readonly').fingerprint,
        grade: 'READ' });
    }
  }));
}

it('CP-009/B12 text scanning is offline and leaves bytes and mtimes unchanged', async () => temp(async dir => {
  const paths = corpus(dir);
  const before = new Map(readdirSync(dir).map(name => [name, {
    bytes: readFileSync(join(dir, name)), mtime: statSync(join(dir, name)).mtimeMs }]));
  networkCalls.length = 0;
  const first = await scan(paths);
  const second = await scan(paths);
  expect(second.findings.map(projection)).toEqual(first.findings.map(projection));
  expect(second.summary).toEqual(first.summary);
  expect(networkCalls).toHaveLength(0);
  expect(readdirSync(dir)).toEqual([...before.keys()]);
  for (const [name, old] of before) {
    expect(readFileSync(join(dir, name)).equals(old.bytes), name).toBe(true);
    expect(statSync(join(dir, name)).mtimeMs, name).toBe(old.mtime);
  }
}));

// Choose a 32-byte test sentinel whose standard base64 uses both alphabet
// characters that differ from base64url. No encoded form enters diagnostics.
function redactionSentinel(): Buffer {
  for (let i = 0; i < 1000; i++) {
    const candidate = createHash('sha256').update(`CP-009/B13 sentinel ${i}`).digest();
    const standard = candidate.toString('base64');
    if (standard.includes('+') && standard.includes('/')) return candidate;
  }
  throw new Error('B13 sentinel generation failed');
}
const redactionSecret = redactionSentinel();
const standardB64 = redactionSecret.toString('base64');
const urlB64 = redactionSecret.toString('base64url');
const redactionEncodings = [
  { name: 'lower hex', value: redactionSecret.toString('hex'), left: 'a', right: 'b' },
  { name: 'upper hex', value: redactionSecret.toString('hex').toUpperCase(), left: 'A', right: 'B' },
  { name: 'padded base64', value: standardB64, left: 'A', right: 'Z' },
  { name: 'unpadded base64', value: standardB64.replace(/=+$/, ''), left: 'A', right: 'Z' },
  { name: 'padded base64url', value: `${urlB64}=`, left: 'A', right: 'Z' },
  { name: 'unpadded base64url', value: urlB64, left: 'A', right: 'Z' },
];
const redactionBoundaries = [
  { name: 'bare', before: '', after: '' },
  { name: 'left-adjacent', before: 'left', after: '' },
  { name: 'right-adjacent', before: '', after: 'right' },
] as const;

for (const encoding of redactionEncodings) for (const boundary of redactionBoundaries) {
  it(`CP-009/B13 returned facts redact ${encoding.name} ${boundary.name} NWC secret`, async () => temp(async dir => {
    const sentinelDir = process.env.MACWARDEN_SENTINEL_DIR || join(dir, 'sentinels');
    mkdirSync(sentinelDir, { recursive: true });
    writeFileSync(join(sentinelDir, 'cp009-b13-nwc.bin'), redactionSecret);
    const before = boundary.before ? encoding.left : '';
    const after = boundary.after ? encoding.right : '';
    const outer = addFirstParties(vector('default-readonly'), [
      `${before}${encoding.value}${after}`, 'lnd-custom harmless-note',
      `lnd-custom nostr+walletconnect://${'22'.repeat(32)}?secret=${redactionSecret.toString('hex')}`,
    ]);
    const path = file(dir, 'outer.env', outer.toString('hex'));
    const result = await scan([path]);
    summary(result, 1, 1);
    const finding = result.findings[0];
    expect(finding.path).toBe(slash(path));
    expect(finding.line).toBe(1);
    expect(finding.column).toBe(1);
    expect(finding.kind).toBe('macaroon-hex');
    expect(finding.fingerprint).toBe(`fp:${createHash('sha256').update(outer).digest('hex').slice(0, 16)}`);
    expect(finding.grade).toBe('READ');
    expect(finding.rootKeyId).toBe(printed('default-readonly').root_key_id);
    expect(finding.permissions).toEqual(printed('default-readonly').permissions);
    expect(finding.caveats?.length).toBe(3);
    const caveats = finding.caveats as { type?: string; value?: string }[] | null;
    expect(caveats?.[0].type).toBe('unknown');
    expect(caveats?.[0].value?.includes('[redacted]'),
      'confirmed secret must be redacted in the adjacent caveat').toBe(true);
    expect(caveats?.some(c => c.type === 'lnd-custom' && c.value === 'harmless-note')).toBe(true);
    const returned = JSON.stringify(result);
    const allForms = [redactionSecret.toString('hex'), redactionSecret.toString('hex').toUpperCase(),
      standardB64, standardB64.replace(/=+$/, ''), `${urlB64}=`, urlB64];
    expect(allForms.some(form => returned.includes(form)),
      'recognizable NWC secret encoding leaked from returned scan object').toBe(false);
    expect(findLeaks({ sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
      commandOutput: returned, root: repo }),
    'NWC sentinel leaked from returned scan object').toBeNull();
  }));
}

it('CP-009/B14 repeated and equivalent path spellings scan once under the first argument', async () => temp(async dir => {
  const first = file(dir, 'one.env', vector('default-readonly').toString('hex'));
  const equivalent = `${dir}${sep}.${sep}one.env`;
  const result = await scan([first, first, equivalent]);
  summary(result, 1, 1);
  expect(result.findings.map(projection)).toEqual([{ path: slash(first), line: 1, column: 1,
    kind: 'macaroon-hex', fingerprint: reference('default-readonly').fingerprint, grade: 'READ' }]);
  fact(result.findings[0], 'default-readonly');
}));

it('CP-009/B14 hard-linked regular-file names scan once under the first argument', async () => temp(async dir => {
  const second = file(dir, 'a-second.env', vector('default-readonly').toString('hex'));
  const first = join(dir, 'z-first.env');
  linkSync(second, first);
  const result = await scan([first, second, second]);
  summary(result, 1, 1);
  expect(result.findings.map(projection)).toEqual([{ path: slash(first), line: 1, column: 1,
    kind: 'macaroon-hex', fingerprint: reference('default-readonly').fingerprint, grade: 'READ' }]);
  fact(result.findings[0], 'default-readonly');
}));

it('CP-009/B14 distinct long ordinary filenames retain their first argument paths', async () => temp(async dir => {
  const content = vector('default-readonly').toString('hex');
  const first = file(dir, `${'b'.repeat(43)}.env`, content);
  const second = file(dir, `${'a'.repeat(43)}.env`, content);
  const alias = join(dir, 'same-as-first.env');
  linkSync(first, alias);
  const result = await scan([first, second, alias, first, second]);
  summary(result, 2, 1, 0, 2);
  expect(result.findings.map(projection)).toEqual([
    { path: slash(second), line: 1, column: 1, kind: 'macaroon-hex',
      fingerprint: reference('default-readonly').fingerprint, grade: 'READ' },
    { path: slash(first), line: 1, column: 1, kind: 'macaroon-hex',
      fingerprint: reference('default-readonly').fingerprint, grade: 'READ' },
  ]);
  for (const finding of result.findings) fact(finding, 'default-readonly');
}));
