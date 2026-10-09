import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { jsRegex, repo, rules, ruleText } from './gitleaks/rules-support.js';

// Parses the TOML fields the CP-013 helper ignores: [extend], description and keywords.
function blocks(): string[] {
  return ruleText().split(/^\s*\[\[rules\]\]\s*$/m).slice(1);
}

function keywords(block: string): string[] {
  const line = /^\s*keywords\s*=\s*\[(.*)\]\s*$/m.exec(block)?.[1];
  if (line === undefined) return [];
  return [...line.matchAll(/'([^']*)'|"([^"]*)"/g)].map(match => match[1] ?? match[2]);
}

function fixtureLines(dir: string): string[] {
  return readdirSync(dir).flatMap(name => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return fixtureLines(path);
    const bytes = readFileSync(path);
    if (bytes.includes(0)) return [];
    return bytes.toString('utf8').split(/\r\n|\n|\r/);
  });
}

it('UX/gitleaks-pack extends the gitleaks defaults instead of replacing them', () => {
  const header = ruleText().split(/^\s*\[\[rules\]\]/m)[0];
  // Without this table gitleaks uses only these four rules and drops every built-in rule.
  expect(header).toMatch(/^\[extend\]\s*\r?\n\s*useDefault\s*=\s*true\s*$/m);
});

it('UX/gitleaks-pack every rule has a description and a lowercase keyword prefilter', () => {
  expect(blocks()).toHaveLength(4);
  for (const block of blocks()) {
    expect(block).toMatch(/^\s*description\s*=\s*'[^']+'\s*$/m);
    const words = keywords(block);
    expect(words.length).toBeGreaterThan(0);
    for (const word of words) expect(word).toBe(word.toLowerCase());
  }
});

it('UX/gitleaks-pack the keyword prefilter never drops a match the rule regex finds', () => {
  // gitleaks lowercases the text and skips a rule unless one keyword occurs in it.
  const lines = fixtureLines(resolve(repo, 'test/scan-fixtures'));
  const pack = rules();
  let matched = 0;
  for (const [index, block] of blocks().entries()) {
    const words = keywords(block);
    for (const line of lines) {
      for (const match of line.matchAll(jsRegex(pack[index].regex))) {
        matched++;
        expect(words.some(word => match[0].toLowerCase().includes(word)), `${pack[index].id}: ${match[0].slice(0, 12)}`).toBe(true);
      }
    }
  }
  expect(matched).toBeGreaterThan(10);
});
