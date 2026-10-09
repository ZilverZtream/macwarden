import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { expectedRegex, jsRegex, kinds, scanPatterns } from './gitleaks/rules-support.js';

const repo = resolve();

// A minimal reader for the fixed shape of rules/trufflehog.yaml: detector name, a
// keywords list and one regex per detector, all YAML single-quoted scalars.
function detectors(): { name: string; keywords: string[]; regex: string }[] {
  const text = readFileSync(join(repo, 'rules/trufflehog.yaml'), 'utf8');
  const quoted = (value: string) => {
    const match = /^'((?:[^']|'')*)'$/.exec(value.trim());
    if (!match) throw new Error(`not a single-quoted scalar: ${value}`);
    return match[1].replace(/''/g, "'");
  };
  return text.split(/^ {2}- name: /m).slice(1).map(block => {
    const name = block.split('\n')[0].trim();
    const keywords = [...block.matchAll(/^ {6}- (.+)$/gm)].map(match => quoted(match[1]));
    const regexes = [...block.matchAll(/^ {6}\w+: (.+)$/gm)].map(match => quoted(match[1]));
    if (regexes.length !== 1) throw new Error(`${name}: expected one regex`);
    return { name, keywords, regex: regexes[0] };
  });
}

it('TRUFFLEHOG-RULES/the custom detectors carry the exact SPEC regexes (four LND and NWC, three L402)', () => {
  expect(detectors().map(({ name, regex }) => ({ name, regex })))
    .toEqual(kinds.map(kind => ({ name: `macwarden-${kind}`, regex: expectedRegex[kind] })));
});

it('TRUFFLEHOG-RULES/every keyword occurs in every match of its detector, so the prefilter never drops a hit', async () => {
  const scan = await scanPatterns();
  const fixtures = join(repo, 'test/scan-fixtures');
  const files = (dir: string): string[] => readdirSync(dir).flatMap(name => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? files(path) : [path];
  });
  let matched = 0;
  for (const [index, detector] of detectors().entries()) {
    expect(detector.keywords.length).toBeGreaterThan(0);
    for (const path of files(fixtures)) {
      for (const match of readFileSync(path, 'latin1').matchAll(jsRegex(detector.regex))) {
        matched++;
        expect(detector.keywords.some(keyword => match[0].toLowerCase().includes(keyword.toLowerCase())), `${detector.name} ${path}`).toBe(true);
        expect(scan[index].test(match[0])).toBe(true);
      }
    }
  }
  expect(matched).toBeGreaterThan(10);
});
