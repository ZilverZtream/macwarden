import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { dockerArgs } from './gitleaks/run.js';
import { expectedRegex, jsRegex, kinds, repo, rules, ruleText, scanPatterns } from './gitleaks/rules-support.js';

const fixture = resolve(repo, 'test/scan-fixtures');
const ids = kinds.map(kind => `macwarden-${kind}`);

function textFiles(dir: string): string[] {
  return readdirSync(dir).flatMap(name => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return textFiles(path);
    if (name.toLowerCase().endsWith('.macaroon')) return [];
    const bytes = readFileSync(path);
    if (bytes.includes(0) && !(bytes[0] === 0xff && bytes[1] === 0xfe) &&
        !(bytes[0] === 0xfe && bytes[1] === 0xff)) return [];
    return [path];
  });
}

function lines(path: string): string[] {
  const bytes = readFileSync(path);
  const encoding = bytes[0] === 0xff && bytes[1] === 0xfe ? 'utf-16le'
    : bytes[0] === 0xfe && bytes[1] === 0xff ? 'utf-16be' : 'utf-8';
  return new TextDecoder(encoding).decode(bytes).replace(/^\uFEFF/, '').split(/\r\n|\n|\r/);
}

function spans(regex: RegExp, line: string): Array<[number, number]> {
  const copy = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : `${regex.flags}g`);
  return [...line.matchAll(copy)].map(match => [match.index, match.index + match[0].length]);
}

it('CP-013/B1 rule pack has the exact detector regexes (four LND and NWC, three L402)', () => {
  expect(rules()).toEqual(kinds.map((kind, at) => ({ id: ids[at], regex: expectedRegex[kind] })));
});

it('CP-013/B2 gitleaks and scan regexes have identical spans on every fixture text line', async () => {
  const scan = await scanPatterns();
  const pack = rules();
  for (const path of textFiles(fixture)) {
    for (const [at, line] of lines(path).entries()) {
      for (const [index, rule] of pack.entries()) {
        expect(spans(jsRegex(rule.regex), line),
          `${relative(fixture, path)}:${at + 1} ${rule.id}`).toEqual(spans(scan[index], line));
      }
    }
  }
});

it('CP-013/B3 rule header and README require redacted gitleaks output', () => {
  const header = ruleText().split(/^\s*\[\[rules\]\]/m)[0];
  expect(header.startsWith('#')).toBe(true);
  expect(header).toContain('--redact');
  expect(header).toMatch(/without\s+(?:--redact|it)[\s\S]*prints[\s\S]*stores[\s\S]*matched credential/i);
  const readme = readFileSync(resolve(repo, 'README.md'), 'utf8');
  for (const line of readme.split(/\r?\n/)) {
    if (/\bgitleaks\b.*(?:\b(?:run|dir|detect|protect)\b|--config)/i.test(line))
      expect(line).toContain('--redact');
  }
});

it('CP-013/B4 script, Docker invocation and runtime dependencies are pinned', () => {
  const pkg = JSON.parse(readFileSync(resolve(repo, 'package.json'), 'utf8')) as {
    scripts: Record<string, string>; dependencies?: Record<string, string> };
  expect(pkg.scripts['test:gitleaks']).toBe('vitest run --config vitest.gitleaks.config.ts');
  expect(readFileSync(resolve(repo, 'vitest.gitleaks.config.ts'), 'utf8'))
    .toContain('test/gitleaks/**/*.test.ts');
  expect(Object.keys(pkg.dependencies ?? {})).toHaveLength(0);
  const args = dockerArgs(resolve(repo, 'test-tmp-placeholder'));
  const requiredImage = 'zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f';
  expect(args).toContain(requiredImage);
  expect(args).toContain('--redact');
  expect(args.slice(args.indexOf(requiredImage) + 1)).toEqual([
    'dir', '/tree', '--config', '/rules/gitleaks.toml', '--redact', '--no-banner',
    '--report-format', 'json', '--report-path', '/report/gitleaks-report.json', '--exit-code', '0']);
});
