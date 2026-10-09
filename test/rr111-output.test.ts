// Output fixes of 1.1.1 for scan (robustness review 2026-10-09): RR-06 SARIF file URIs,
// RR-09 GitHub annotation file property, RR-11 invisible format characters in text output.
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import Ajv from 'ajv';
import { expect, it } from 'vitest';
import { renderChunks, type OutputResult } from '../src/output/index.js';
import { fileUri } from '../src/output/scan-formats.js';
import type { ScanFinding, ScanResult } from '../src/scan/index.js';

function finding(path: string): ScanFinding {
  return { path, line: 1, column: 5, kind: 'undecodable-candidate', fingerprint: 'fp:0123456789abcdef', grade: null,
    rootKeyId: null, permissions: null, caveats: null, warnings: [], unassessed: [] };
}

function result(paths: string[]): ScanResult {
  return { findings: paths.map(finding), skipped: [],
    summary: { filesScanned: paths.length, filesSkipped: 0, dropped: 0, ignored: 0, findings: paths.length, distinct: 1,
      byGrade: { ADMIN: 0, SPEND: 0, OPERATE: 0, RECEIVE: 0, READ: 0, UNASSESSED: 0, NWC: 0, UNDECODABLE: paths.length, L402: 0 } },
    failOn: null };
}

function render(paths: string[], format: 'sarif' | 'github' | 'text', root = '/work/repo'): string {
  return [...renderChunks({ command: 'scan', ok: true, warnings: [], error: null, result: result(paths),
    ...(format === 'text' ? {} : { display: { format, scanRoot: root, toolVersion: '0.0.0' } }) } as OutputResult, 'text')].join('');
}

function sarifValidator() {
  // The official OASIS schema is draft-04; Ajv 8 reads it once `id` is `$id`.
  const schema = JSON.parse(readFileSync(join(resolve(), 'test/vendor/sarif-schema-2.1.0.json'), 'utf8')) as Record<string, unknown>;
  const { id, $schema: _ignored, ...rest } = schema;
  void _ignored;
  return new (Ajv as unknown as typeof import('ajv').default)({ strict: false, validateFormats: false, allErrors: true })
    .compile({ $id: id as string, ...rest });
}

type Sarif = { runs: { originalUriBaseIds: Record<string, { uri: string }>;
  results: { locations: { physicalLocation: { artifactLocation: { uri: string; uriBaseId?: string } } }[] }[] }[] };

it('RR-111/output RR-06 SARIF URIs resolve to the scanned files for relative, ../ and absolute paths', () => {
  const root = resolve(tmpdir(), 'rr111 work', 'r\u00e9po');
  const paths = ['../sibling dir/plain.env', 'sub/../in side.env', 'app/x,y%.env', join(root, 'abs.env'),
    join(dirname(root), 'outside \u00e9.env'), '..'];
  const log = JSON.parse(render(paths, 'sarif', root)) as Sarif;
  const validate = sarifValidator();
  expect(validate(log), JSON.stringify(validate.errors?.slice(0, 3))).toBe(true);
  const run = log.runs[0]!;
  const base = run.originalUriBaseIds['%SRCROOT%']!.uri;
  expect(base).toBe(pathToFileURL(root).href + '/');
  // Each URI, resolved against its declared base, is the file URI of the path resolved from the root.
  const resolved = run.results.map(item => {
    const { uri, uriBaseId } = item.locations[0]!.physicalLocation.artifactLocation;
    if (uriBaseId !== undefined) expect(uriBaseId).toBe('%SRCROOT%');
    else expect(uri).toMatch(/^file:\/\//);
    return decodeURIComponent(new URL(uri, uriBaseId === undefined ? undefined : base).href);
  });
  expect(resolved).toEqual(paths.map(path => decodeURIComponent(pathToFileURL(resolve(root, path)).href)));
  expect(run.results.map(item => item.locations[0]!.physicalLocation.artifactLocation.uriBaseId))
    .toEqual([undefined, '%SRCROOT%', '%SRCROOT%', '%SRCROOT%', undefined, undefined]);
});

it('RR-111/output RR-06 file URIs for Windows drive, UNC and long paths and POSIX names with a backslash', () => {
  expect(fileUri('C:\\Users\\a b\\x,y.env')).toBe('file:///C:/Users/a%20b/x%2Cy.env');
  expect(fileUri('C:/Users/\u00e9.env')).toBe('file:///C:/Users/%C3%A9.env');
  expect(fileUri('\\\\server\\share\\a b.env')).toBe('file://server/share/a%20b.env');
  expect(fileUri('\\\\?\\C:\\x y\\z.env')).toBe('file:///C:/x%20y/z.env');
  expect(fileUri('\\\\?\\UNC\\srv\\sh\\f.env')).toBe('file://srv/sh/f.env');
  expect(fileUri('/tmp/back\\slash \u00e9.env')).toBe('file:///tmp/back%5Cslash%20%C3%A9.env');
  expect(fileUri('/')).toBe('file:///');
});

it('RR-111/output RR-09 a GitHub annotation names the real file with only GitHub property escaping', () => {
  const lines = render(['new\nline.env', 'tab\there.env', 'cr\rx.env', 'x c:o,m%.env'], 'github').split('\n');
  const files = lines.filter(line => line.startsWith('::')).map(line => /file=([^,]*),/.exec(line)![1]);
  expect(files).toEqual(['new%0Aline.env', 'tab\there.env', 'cr%0Dx.env', 'x c%3Ao%2Cm%25.env']);
  // GitHub decodes exactly these escapes; decoding gives the file names back.
  const decode = (value: string) => value.replace(/%0D/g, '\r').replace(/%0A/g, '\n').replace(/%3A/g, ':')
    .replace(/%2C/g, ',').replace(/%25/g, '%');
  expect(files.map(decode)).toEqual(['new\nline.env', 'tab\there.env', 'cr\rx.env', 'x c:o,m%.env']);
});

it('RR-111/output RR-11 invisible format characters in a path are escaped in text output', () => {
  const codes = [0xad, 0x200b, 0x200d, 0x2060, 0x2063, 0x206a, 0xfeff, 0x34f, 0x115f, 0x3164, 0xfe0f, 0xfff9, 0x180e,
    0xe0041, 0xe0001, 0xe0100, 0x1d173];
  // As for every escaped character: \xNN below U+0100, \uNNNN in the BMP, \u{N} beyond it.
  const escape = (code: number) => code < 0x100 ? `\\x${code.toString(16)}`
    : code <= 0xffff ? `\\u${code.toString(16).padStart(4, '0')}` : `\\u{${code.toString(16)}}`;
  const text = render(codes.map((code, index) => `admin${index}${String.fromCodePoint(code)}.macaroon`), 'text');
  for (const [index, code] of codes.entries()) {
    expect(text).toContain(`admin${index}${escape(code)}.macaroon`);
    expect(text).not.toContain(String.fromCodePoint(code));
  }
  // Escapes that already existed are unchanged; visible non-ASCII stays as it is.
  const visible = `é${String.fromCodePoint(0x1f600)}`;
  expect(render([`a\x1bb‮c${visible}.env`], 'text')).toContain(`a\\x1bb\\u202ec${visible}.env`);
});
