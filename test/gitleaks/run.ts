import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { findLeaks } from "../helpers/leak-check.js";
import { image, repo } from './rules-support.js';

const tree = resolve(repo, 'test/scan-fixtures/full');
const ruleDir = resolve(repo, 'rules');

export function dockerArgs(reportDir: string): string[] {
  return ['run', '--rm', '--mount', `type=bind,src=${tree},dst=/tree,readonly`,
    '--mount', `type=bind,src=${ruleDir},dst=/rules,readonly`,
    '--mount', `type=bind,src=${reportDir},dst=/report`, image,
    'dir', '/tree', '--config', '/rules/gitleaks.toml', '--redact', '--no-banner',
    '--report-format', 'json', '--report-path', '/report/gitleaks-report.json', '--exit-code', '0'];
}

export type Hit = { RuleID: string; File: string; StartLine: number; Secret: string; Match: string };

export function runGitleaks(): Hit[] {
  const testTmp = process.env.MACWARDEN_TEST_TMP;
  const sentinelRoot = process.env.MACWARDEN_SENTINEL_DIR;
  if (!testTmp || !sentinelRoot) throw new Error('MACWARDEN_TEST_TMP and MACWARDEN_SENTINEL_DIR are required');
  mkdirSync(testTmp, { recursive: true });
  mkdirSync(sentinelRoot, { recursive: true });
  const reportDir = mkdtempSync(join(testTmp, 'cp013-gitleaks-'));
  const sentinelDir = mkdtempSync(join(sentinelRoot, 'cp013-'));
  try {
    for (const name of ['default-readonly', 'default-invoice', 'preset-pay-only'])
      writeFileSync(join(sentinelDir, `${name}.macaroon`),
        readFileSync(resolve(repo, 'test/vectors', `${name}.macaroon`)));
    writeFileSync(join(sentinelDir, 'nwc.bin'), Buffer.alloc(32, 0x11));
    const result = spawnSync('docker', dockerArgs(reportDir), { encoding: 'utf8', maxBuffer: 1024 * 1024 });
    if (result.error || result.status !== 0)
      throw new Error(`redacted gitleaks Docker run failed (exit ${result.status ?? 'unavailable'})`);
    const report = readFileSync(join(reportDir, 'gitleaks-report.json'), 'utf8');
    const leak = findLeaks({ sentinels: resolve(repo, 'test/sentinels.json'), sentinelDir,
      paths: [join(reportDir, 'gitleaks-report.json')], commandOutput: result.stdout + result.stderr,
      root: repo });
    if (leak) throw new Error(`gitleaks output leak (${leak.encoding})`);
    const hits = JSON.parse(report) as Hit[];
    if (!Array.isArray(hits)) throw new Error('gitleaks report is not a JSON array');
    return hits;
  } finally {
    rmSync(reportDir, { recursive: true, force: true });
    rmSync(sentinelDir, { recursive: true, force: true });
  }
}
