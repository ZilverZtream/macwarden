import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export const repo = resolve();
export const image = 'zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f';
export const kinds = ['macaroon-hex', 'macaroon-base64', 'lndconnect', 'nwc', 'l402', 'l402-macaroon-hex', 'l402-macaroon-base64'] as const;
export const expectedRegex: Record<string, string> = {
  'macaroon-hex': '(?i)0201036c6e6402[0-9a-f]{40,}',
  'macaroon-base64': 'AgEDbG5kA[A-Za-z0-9+/_-]{40,}={0,2}',
  lndconnect: '(?i)lndconnect://[^\\s"\'<>]+',
  nwc: '(?i)(?:nostr\\+walletconnect|nostrwalletconnect):(?://)?[0-9a-f]{64}/?\\?[^\\s"\'<>]*?secret=[0-9a-f]{64}(?:[^0-9a-f]|$)',
  l402: '(?i)\\b(?:l402|lsat)[ \\t]+[A-Za-z0-9+/_=-]{40,}(?:,[A-Za-z0-9+/_=-]{40,})*:[0-9a-f]{64}\\b',
  'l402-macaroon-hex': '(?i)0201046c73617402420000[0-9a-f]{40,}',
  'l402-macaroon-base64': 'AgEEbHNhdAJCAA[A-Za-z0-9+/_-]{40,}={0,2}',
};

/** The scan patterns (src/scan/patterns.ts) in the order of kinds, each identical to its rule. */
export async function scanPatterns(): Promise<RegExp[]> {
  const patterns = await import('../../src/scan/patterns.js');
  return [patterns.macaroonHex, patterns.macaroonBase64, patterns.lndconnect, patterns.nwc,
    patterns.l402Header, patterns.l402MacaroonHex, patterns.l402MacaroonBase64];
}

function tomlString(value: string): string {
  if (value.startsWith("'''")) {
    if (!value.endsWith("'''")) throw new Error('unterminated TOML literal');
    return value.slice(3, -3);
  }
  if (value.startsWith("'")) {
    if (!value.endsWith("'")) throw new Error('unterminated TOML literal');
    return value.slice(1, -1);
  }
  if (value.startsWith('"')) return JSON.parse(value) as string;
  throw new Error('regex is not a TOML string');
}

export function ruleText(): string {
  return readFileSync(resolve(repo, 'rules/gitleaks.toml'), 'utf8');
}

export function rules(): Array<{ id: string; regex: string }> {
  return ruleText().split(/^\s*\[\[rules\]\]\s*$/m).slice(1).map(block => {
    const id = /^\s*id\s*=\s*(.+?)\s*$/m.exec(block)?.[1];
    const regex = /^\s*regex\s*=\s*(.+?)\s*$/m.exec(block)?.[1];
    if (!id || !regex) throw new Error('rule lacks id or regex');
    return { id: tomlString(id), regex: tomlString(regex) };
  });
}

export function jsRegex(source: string): RegExp {
  const insensitive = source.startsWith('(?i)');
  return new RegExp(insensitive ? source.slice(4) : source, insensitive ? 'gi' : 'g');
}
