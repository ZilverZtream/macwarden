import * as fs from 'node:fs/promises';
import { unsafeNodeDiagnostics } from '../environment.js';
import { homedir } from 'node:os';
import { agentConfigCandidates, discoverAgentConfigs, type AgentConfigEnvironment } from '../scan/agent-configs.js';
import { Cancelled } from '../cancellation.js';
import { InputError } from '../input/index.js';
import { scan, FindingsLimitError, GitHistoryError, IgnoreFileError, type ScanResult } from '../scan/index.js';
import type { OutputResult } from '../output/index.js';

type Threshold = NonNullable<ScanResult['failOn']>['threshold'];
const ladder: Threshold[] = ['ADMIN', 'SPEND', 'OPERATE', 'RECEIVE', 'READ'];

function fail(code: number, step: string | null, message: string): OutputResult {
  return { command: 'scan', ok: false, warnings: [], result: null,
    error: { code, step, message } };
}

export type ScanFormat = 'text' | 'json' | 'sarif' | 'github';
const formats: ScanFormat[] = ['text', 'json', 'sarif', 'github'];

type ScanDeps = { fs: typeof fs; agentEnvironment?: () => AgentConfigEnvironment; env?: Record<string, string | undefined> };
const defaultAgentEnvironment = (): AgentConfigEnvironment =>
  ({ platform: process.platform, home: homedir(), cwd: process.cwd(), env: { ...process.env } });

export async function run(args: string[], deps: ScanDeps = { fs, env: { ...process.env } }): Promise<OutputResult & { exitCode?: number }> {
  // ENV check (1.2.1): a heap snapshot or profile taken through NODE_OPTIONS would hold every credential found here.
  if (deps.env && unsafeNodeDiagnostics(deps.env)) return fail(2, null, 'unsafe Node diagnostic settings');
  const paths: string[] = [];
  let format: ScanFormat | undefined;
  let agentConfigs = false;
  let threshold: Threshold | undefined;
  let includeDirs = false;
  let gitHistory = false;
  let allowShallow = false;
  let ignoreFile: string | undefined;
  let endOfFlags = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!endOfFlags && arg === '--json') continue;
    if (!endOfFlags && arg === '--') { endOfFlags = true; continue; }
    if (!endOfFlags && arg === '--include-dirs') { includeDirs = true; continue; }
    if (!endOfFlags && arg === '--format') {
      const value = args[++i];
      if (format !== undefined || !formats.includes(value as ScanFormat))
        return fail(2, null, '--format takes one of text, json, sarif, github');
      format = value as ScanFormat;
      continue;
    }
    if (!endOfFlags && arg === '--agent-configs') {
      if (agentConfigs) return fail(2, null, 'repeated --agent-configs');
      agentConfigs = true; continue;
    }
    if (!endOfFlags && arg === '--git-history') {
      if (gitHistory) return fail(2, null, '--git-history was given more than once');
      gitHistory = true; continue;
    }
    if (!endOfFlags && arg === '--allow-shallow') {
      if (allowShallow) return fail(2, null, '--allow-shallow was given more than once');
      allowShallow = true; continue;
    }
    if (!endOfFlags && arg === '--ignore-file') {
      const value = args[++i];
      if (ignoreFile !== undefined) return fail(2, null, '--ignore-file was given more than once');
      if (!value || value.startsWith('-')) return fail(2, null, '--ignore-file needs a file path');
      ignoreFile = value;
      continue;
    }
    if (!endOfFlags && arg === '--fail-on') {
      const value = args[++i];
      if (threshold) return fail(2, null, '--fail-on was given more than once');
      // Grades are matched in any case: --fail-on spend equals --fail-on SPEND.
      const grade = value?.toUpperCase();
      if (!ladder.includes(grade as Threshold)) return fail(2, null, `--fail-on takes one grade: ${ladder.join(', ')} (any case)`);
      threshold = grade as Threshold;
      continue;
    }
    if (!endOfFlags && arg.startsWith('-'))
      return fail(2, null, 'unknown flag; scan takes: [paths...] --fail-on --include-dirs --ignore-file --git-history --allow-shallow --json (use -- before a path starting with -)');
    paths.push(arg);
  }
  if (allowShallow && !gitHistory) return fail(2, null, '--allow-shallow requires --git-history');
  try {
    // With --agent-configs and no paths, only the agent locations are scanned.
    const discovery = agentConfigs
      ? await discoverAgentConfigs(agentConfigCandidates((deps.agentEnvironment ?? defaultAgentEnvironment)()),
        path => deps.fs.lstat(path))
      : undefined;
    const targets = [...(paths.length || agentConfigs ? paths : ['.']), ...(discovery?.found.map(item => item.path) ?? [])];
    const result = await scan(targets, { fs: deps.fs, includeDirs, ignoreFile, gitHistory, allowShallow });
    if (discovery) result.summary.agentConfigs = { found: discovery.found, absent: discovery.absent };
    const warnings = result.summary.shallowHistory ? ['shallow-history'] : [];
    if (threshold) {
      const rung = ladder.indexOf(threshold);
      const count = result.findings.filter(finding => {
        if (finding.grade === 'UNASSESSED' || finding.kind === 'undecodable' ||
          finding.kind === 'undecodable-candidate') return true;
        // An L402 token with a usable preimage is a live service-access secret, counted as READ;
        // one without (a challenge, a pending token, a wrong preimage) grants nothing alone.
        const grade = finding.kind === 'nwc' ? 'SPEND' : finding.l402 ? finding.l402.countedAs : finding.grade;
        return grade !== null && ladder.indexOf(grade) <= rung;
      }).length;
      result.failOn = { threshold, count };
    }
    return { command: 'scan', ok: true, warnings, result, error: null, exitCode: result.failOn && result.failOn.count > 0 ? 1 : 0,
      ...(format === 'sarif' || format === 'github' ? { display: { format, scanRoot: process.cwd() } } : {}) };
  } catch (error) {
    if (error instanceof Cancelled) return fail(6, 'cancelled', 'interrupted');
    if (error instanceof InputError) return fail(3, error.stage, error.message);
    if (error instanceof IgnoreFileError) return fail(3, 'ignore-file', error.message);
    if (error instanceof GitHistoryError) return fail(3, 'git-history', error.message);
    if (error instanceof FindingsLimitError) return fail(3, 'findings-limit', error.message);
    return fail(8, 'internal', 'unexpected failure');
  }
}
