import { createHash, createHmac } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { expect } from 'vitest';
import { childEnvironment } from '../helpers/environment.js';
import { scratchDirectory, root } from './cp039-scratch.js';
export { scratchDirectory, root } from './cp039-scratch.js';
export const repo = resolve();
export const sentinelPath = join(repo, 'test/sentinels/sentinel.macaroon');
export const sentinelList = join(repo, 'test/sentinels.json');
export const sentinel = () => readFileSync(sentinelPath);
export const fingerprint = (b: Uint8Array) => 'fp:' + createHash('sha256').update(b).digest('hex').slice(0, 16);
export function register(b: Buffer) {
  writeFileSync(join(root('MACWARDEN_SENTINEL_DIR'), `cp041-${fingerprint(b).slice(3)}.macaroon`), b, { mode: 0o600 });
}
export function vector(name = 'default-readonly') {
  const manifest = JSON.parse(readFileSync(join(repo, 'test/vectors/manifest.json'), 'utf8')) as {
    vectors: { name: string; file: string; canonicalLength: number; fingerprint: string }[] };
  const v = manifest.vectors.find(v => v.name === name);
  if (!v) throw new Error('Missing committed reference');
  const bytes = readFileSync(join(repo, 'test/vectors', v.file));
  const printed = JSON.parse(readFileSync(join(repo, 'test/vectors', name + '.printmacaroon.json'), 'utf8')) as {
    root_key_id: string; permissions: string[]; caveats: string[] | null };
  return { ...v, bytes, canonical: bytes.subarray(0, v.canonicalLength), printed };
}
export function variants() {
  const v = vector();
  return [v.canonical, Buffer.concat([v.canonical, Buffer.from([17, 33, 127])]),
    Buffer.concat([v.canonical, Buffer.from('independent trailing data')])];
}
// SPEC's first-party signature chain, built without any product decoder/encoder.
export function independentCaveat() {
  const v = vector(), condition = 'time-before 2030-01-01T00:00:00Z';
  const caveat = Buffer.from(condition);
  const signature = createHmac('sha256', v.canonical.subarray(-32)).update(caveat).digest();
  const bytes = Buffer.concat([v.canonical.subarray(0, -35), Buffer.from([2, caveat.length]), caveat,
    Buffer.from([0, 0, 6, 32]), signature]);
  return { bytes, condition, fingerprint: fingerprint(bytes) };
}
export type Form = { name: string; encode(bytes: Buffer): string | Buffer };
function base32(bytes: Buffer) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let acc = 0, bits = 0, text = '';
  for (const byte of bytes) { acc = (acc << 8) | byte; bits += 8;
    while (bits >= 5) { bits -= 5; text += alphabet[(acc >>> bits) & 31]; } }
  if (bits) text += alphabet[(acc << (5 - bits)) & 31];
  return text;
}
export const peerForms: Form[] = [
  ...['|', '.', '_', '/'].map(separator => ({ name: `hex ${separator === '|' ? 'pipe' : separator === '.' ? 'dot' : separator === '_' ? 'underscore' : 'slash'}`,
    encode: (b: Buffer) => [...b].map(n => n.toString(16).padStart(2, '0')).join(separator) })),
  { name: 'comma 0x array', encode: b => '[' + [...b].map(n => '0x' + n.toString(16).padStart(2, '0')).join(', ') + ']' },
  ...[' ', ';'].map(separator => ({ name: separator === ' ' ? 'space decimal' : 'semicolon decimal', encode: (b: Buffer) => [...b].join(separator) })),
  { name: 'dash base64', encode: b => b.toString('base64').match(/.{1,8}/g)!.join('-') },
];
export const leakForms: Form[] = [
  { name: 'raw', encode: b => b }, { name: 'hex', encode: b => b.toString('hex') },
  { name: 'base64', encode: b => b.toString('base64') }, { name: 'base64url', encode: b => b.toString('base64url') },
  { name: 'wrapped', encode: b => b.toString('base64').match(/.{1,12}/g)!.join('\n    ') },
  { name: 'JSON', encode: b => JSON.stringify(b.toString('latin1')) },
  ...(['hex', 'base64'] as const).flatMap(encoding => ['LE', 'BE'].map(order => ({ name: `UTF16${order} ${encoding}`,
    encode: (b: Buffer) => { const text = Buffer.from(b.toString(encoding), 'utf16le');
      return order === 'LE' ? Buffer.concat([Buffer.from([255, 254]), text]) : Buffer.concat([Buffer.from([254, 255]), text.swap16()]); } }))),
  { name: 'octal', encode: b => [...b].map(n => '\\' + n.toString(8).padStart(3, '0')).join('') },
  { name: 'HTML decimal', encode: b => [...b].map(n => `&#${n};`).join('') },
  { name: 'HTML hex', encode: b => [...b].map(n => `&#x${n.toString(16)};`).join('') },
  { name: 'percent-u', encode: b => [...b].map(n => '%u' + n.toString(16).padStart(4, '0')).join('') },
  { name: 'base32', encode: base32 }, ...peerForms,
];
export function noEcho(text: string, bytes: Buffer, forms = leakForms) {
  for (const form of forms) { const encoded = form.encode(bytes);
    const value = typeof encoded === 'string' ? encoded : encoded.toString('latin1');
    expect.soft(text.includes(value) || text.includes(JSON.stringify(value).slice(1, -1)), `${form.name} recoverable bytes absent`).toBe(false);
  }
}
export function builtInspect(path: string) {
  const run = spawnSync(process.execPath, [join(repo, 'dist/bin.js'), 'inspect', path, '--json'],
    { cwd: repo, env: childEnvironment(), encoding: 'utf8', timeout: 10_000 });
  expect(run.status, 'built inspect exit').toBe(0); expect(run.stderr.length, 'single stdout document').toBe(0);
  noEcho(run.stdout, readFileSync(path));
  return JSON.parse(run.stdout) as { schema: number; ok: boolean; error: unknown; result: {
    fingerprint: string; warnings: string[]; rootKeyId: string; permissions: string[];
    caveats: { type: string; value: string }[] } };
}
export function leakStatus(path: string, dir: string, list = sentinelList) {
  const run = spawnSync(process.execPath, [join(repo, 'scripts/leak-check.mjs'), '--sentinels', list, path],
    { cwd: repo, env: childEnvironment({ MACWARDEN_TEST_TMP: dir, MACWARDEN_SENTINEL_DIR: join(dir, 'runtime') }),
      encoding: 'utf8', timeout: 15_000 });
  noEcho(run.stdout + run.stderr, sentinel());
  return run.status;
}
export async function scratch<T>(work: (dir: string) => T | Promise<T>): Promise<T> {
  const owned = scratchDirectory('cp041-');
  try { return await work(owned.dir); } finally { owned.cleanup(); }
}
