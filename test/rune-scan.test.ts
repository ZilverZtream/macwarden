import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';
import { main } from '../src/cli.js';
import { decodeRuneText, RUNE_TEXT_LIMIT } from '../src/decode/rune.js';
import { renderChunks, type OutputResult } from '../src/output/index.js';
import { scan, type ScanFinding } from '../src/scan/index.js';
import { runeCandidates } from '../src/scan/rune-context.js';
import { captureMain } from './support/capture.js';
import { repo, scratch } from './support/cp039-audit.js';
import { rune, runeFingerprint } from './support/runes.js';

// docs/spec.md, Commands > 2. scan > Core Lightning runes: contextual candidates only, full
// structural parse, invalid values in rune context reported, never silently dropped.

const validateScan = new (Ajv2020 as unknown as typeof import('ajv/dist/2020.js').default)({ strict: false }).compile(
  JSON.parse(readFileSync(join(repo, 'schemas/output/scan.schema.json'), 'utf8')));
const clock = () => new Date('2026-10-09T12:00:00Z');
const READ_TEXT = '=7&method=getinfo';
const READ_RUNE = rune(READ_TEXT);
const SPEND_RUNE = rune('=8&method=pay');

async function scanText(name: string, text: string): Promise<ScanFinding[]> {
  return scratch(async dir => {
    writeFileSync(join(dir, name), text);
    const result = await scan([dir], { clock });
    return result.findings.filter(finding => finding.kind === 'rune' || finding.kind === 'rune-invalid');
  });
}

describe('RUNE/scan contexts', () => {
  const contexts: [string, string, string][] = [
    ['.env', `RUNE=${READ_RUNE}\n`, 'env key'],
    ['.env', `CLN_RUNE="${READ_RUNE}"\n`, 'prefixed env key, quoted'],
    ['.env', `export LIGHTNING_RUNE='${READ_RUNE}'\n`, 'shell export'],
    ['config.json', `{"node": {"rune": "${READ_RUNE}"}}\n`, 'JSON property'],
    ['config.json', `{"clnRune":"${READ_RUNE}"}\n`, 'camelCase JSON property'],
    ['values.yaml', `cln:\n  rune: ${READ_RUNE}\n`, 'YAML'],
    ['config.toml', `rune = "${READ_RUNE}"\n`, 'TOML'],
    ['call.sh', `curl -sk -H "Rune: ${READ_RUNE}" https://localhost:3010/v1/getinfo\n`, 'clnrest Rune header'],
    ['call.sh', `curl -H 'rune:${READ_RUNE}' -X POST https://node:3010/v1/getinfo\n`, 'lower-case header without blank'],
    ['call.sh', `lightning-cli -k commando peer_id=02${'ab'.repeat(32)} method=getinfo rune=${READ_RUNE}\n`, 'commando keyword argument'],
    ['app.py', `node.call("commando", {"peer_id": pid, "method": "getinfo", "rune": "${READ_RUNE}"})\n`, 'pyln JSON-RPC parameters'],
    ['app.ts', `const client = new Commando({ rune: '${READ_RUNE}' });\n`, 'JavaScript object'],
    ['run.sh', `myapp --rune=${READ_RUNE} --verbose\n`, 'command-line flag'],
    ['http.txt', `GET /v1/getinfo HTTP/1.1\r\nHost: node\r\nRune: ${READ_RUNE}\r\n\r\n`, 'raw HTTP request'],
    ['run.sh', `lightning-cli commando 02${'ab'.repeat(32)} getinfo '{}' ${READ_RUNE}\n`, 'commando positional argument'],
    ['run.sh', `lightning-cli checkrune ${READ_RUNE} 02${'ab'.repeat(32)} getinfo\n`, 'checkrune positional argument'],
    ['notes.md', `Run \`lightning-cli showrunes "${READ_RUNE}"\` to see it.\n`, 'showrunes positional argument'],
  ];
  for (const [name, text, label] of contexts) {
    it(`RUNE/scan finds a rune in ${label}`, async () => {
      const findings = await scanText(name, text);
      expect(findings).toHaveLength(1);
      const [finding] = findings;
      expect(finding).toMatchObject({ kind: 'rune', grade: 'READ', fingerprint: runeFingerprint(READ_TEXT), rootKeyId: null,
        permissions: null, caveats: null, warnings: [], unassessed: [] });
      expect(finding.rune).toMatchObject({ recognition: 'rune-syntax', uniqueId: '7', methods: 'listed', allowedMethods: ['getinfo'],
        verification: 'unchecked', methodTable: 'cln-v26.06.8' });
      const line = text.split(/\r\n|\n/)[finding.line! - 1];
      expect([...line].slice(finding.column! - 1).join('').startsWith(READ_RUNE.replace(/=+$/, ''))).toBe(true);
    });
  }

  it('RUNE/scan columns count code points, as for macaroons', async () => {
    const findings = await scanText('x.env', `😀 é RUNE=${READ_RUNE}\n`);
    expect(findings[0].column).toBe(10);
  });

  it('RUNE/scan padded and unpadded copies of one rune have one fingerprint', async () => {
    const findings = await scanText('x.env', `A_RUNE=${READ_RUNE}\nB_RUNE=${READ_RUNE.replace(/=+$/, '')}\n`);
    expect(findings.map(finding => finding.fingerprint)).toEqual([runeFingerprint(READ_TEXT), runeFingerprint(READ_TEXT)]);
  });

  it('RUNE/scan the base64 of a rune in a Kubernetes Secret is decoded once', async () => {
    const encoded = Buffer.from(SPEND_RUNE).toString('base64');
    const findings = await scanText('secret.yaml', `kind: Secret\ndata:\n  CLN_RUNE: ${encoded}\n`);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ kind: 'rune', grade: 'SPEND', fingerprint: runeFingerprint('=8&method=pay') });
  });
});

describe('RUNE/scan command context follows checkrune\'s unique ID rule', () => {
  // param_rune: strtoull over the whole unique ID, at most 2^63-1, "" reads as 0. Core Lightning
  // checks every such rune, so a positional argument holding one is reported.
  for (const id of ['1234567890123456789', '9223372036854775807', ' 7', '+7', '', '007']) {
    it(`RUNE/scan a commando argument with unique ID ${JSON.stringify(id)} is reported`, async () => {
      const findings = await scanText('run.sh', `lightning-cli commando 02${'ab'.repeat(32)} getinfo '{}' ${rune(`=${id}&method=getinfo`)}\n`);
      expect(findings.map(finding => [finding.kind, finding.grade])).toEqual([['rune', 'READ']]);
    });
  }
  for (const id of ['9223372036854775808', 'abc', '7 ', '+', ' ']) {
    it(`RUNE/scan a commando argument with unique ID ${JSON.stringify(id)}, which checkrune refuses, is not reported`, async () => {
      expect(await scanText('run.sh', `lightning-cli commando 02${'ab'.repeat(32)} getinfo '{}' ${rune(`=${id}&method=getinfo`)}\n`)).toEqual([]);
    });
  }
});

describe('RUNE/scan no context, no finding', () => {
  const negatives: [string, string][] = [
    ['bare rune text', `${READ_RUNE}\n`],
    ['bare rune in prose', `the value ${READ_RUNE} is here\n`],
    ['prune is not a rune key', `prune=${READ_RUNE}\n`],
    ['runes is not a rune key', `runes=${READ_RUNE}\n`],
    ['rune_id is not a rune key', `rune_id=${READ_RUNE}\n`],
    ['comparison', `if rune == ${READ_RUNE}: pass\n`],
    ['arrow', `rune => ${READ_RUNE}\n`],
    ['all-caps compound without separator', `CLNRUNE=${READ_RUNE}\n`],
    ['placeholder', 'RUNE=${CLN_RUNE}\n'],
    ['short value', 'rune: string\n"rune": "abc"\n'],
    ['schema property', '"rune": { "type": "string" }\n'],
    ['positional argument of another command', `git commit -m ${READ_RUNE}\n`],
    ['commando argument that is not a checkable rune', `lightning-cli commando 02${'ab'.repeat(32)} getinfo '{}' ${'Q'.repeat(60)}\n`],
    ['commando argument glued to other text', `lightning-cli commando x/${READ_RUNE}\n`],
  ];
  for (const [label, text] of negatives) {
    it(`RUNE/scan reports nothing for ${label}`, async () => {
      expect(await scanText('x.txt', text)).toEqual([]);
    });
  }
});

describe('RUNE/scan invalid values in rune context are reported', () => {
  const invalid: [string, string, string][] = [
    ['standard alphabet', `RUNE=${READ_RUNE.slice(0, 10)}+/${READ_RUNE.slice(12)}\n`, 'not-base64url'],
    ['restriction syntax', `RUNE=${rune('=1&method')}\n`, 'restriction-syntax'],
    ['misplaced unique ID', `RUNE=${rune('method=pay&=1')}\n`, 'unique-id-placement'],
    ['NUL byte', `RUNE=${rune('=1&f=a\0b')}\n`, 'nul-byte'],
    ['malformed base64 tail', `RUNE=${READ_RUNE.replace(/=+$/, '').slice(0, -2)}A\n`, 'not-base64url'],
    ['oversized value', `RUNE=${'A'.repeat(RUNE_TEXT_LIMIT + 10)}\n`, 'exceeds-bounds'],
  ];
  for (const [label, text, reason] of invalid) {
    it(`RUNE/scan a ${label} value in rune context is a rune-invalid finding, UNASSESSED`, async () => {
      const findings = await scanText('x.env', text);
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({ kind: 'rune-invalid', grade: 'UNASSESSED', rootKeyId: null, unassessed: [],
        rune: { recognition: 'invalid', reason, verification: 'unchecked' } });
    });
  }

  it('RUNE/scan an oversized value never yields a policy from a cut prefix', async () => {
    const findings = await scanText('x.env', `RUNE=${rune(`=1&method=getinfo&f=${'a'.repeat(RUNE_TEXT_LIMIT)}`)}\n`);
    expect(findings.map(finding => [finding.kind, finding.grade])).toEqual([['rune-invalid', 'UNASSESSED']]);
  });

  it('RUNE/scan a quoted value without its closing quote, or folded onto the next line, is graded at least UNASSESSED', async () => {
    for (const text of [`"rune": "${READ_RUNE}\\u0041"\n`, `rune: ${READ_RUNE}\n  QUJDREVG\n`, `RUNE=${READ_RUNE}$X\n`]) {
      const findings = await scanText('x.txt', text);
      expect(findings, text).toHaveLength(1);
      expect(findings[0].grade, text).toBe('UNASSESSED');
      expect((findings[0].rune as { warnings: string[] }).warnings, text).toContain('possibly-truncated');
    }
  });

  it('RUNE/scan a value under a rune key that parses but has no numeric unique ID is rune-invalid, not an ADMIN rune', async () => {
    // About 40% of SHA-256 digests and node IDs placed under a rune key parse as restriction text
    // with unknown fields, which used to report them as broad ADMIN runes. checkrune refuses every
    // value without a numeric unique ID (param_rune), so none of them is a rune a node would check.
    const digest = Array.from({ length: 200 }, (_, index) => createHash('sha256').update(String(index)).digest('hex'))
      .find(hex => { const decoded = decodeRuneText(hex); return decoded.ok && decoded.facts.uniqueId === null; })!;
    const cases: [string, string][] = [[digest, 'no-unique-id'], [rune('method^list'), 'no-unique-id'],
      [rune('=abc&method=pay'), 'unique-id-not-numeric'], [rune('=9223372036854775808&method=pay'), 'unique-id-not-numeric']];
    for (const [value, reason] of cases) {
      const findings = await scanText('x.env', `RUNE=${value}\n"rune": "${value}"\nRune: ${value}\n`);
      expect(findings.map(finding => [finding.kind, finding.grade, (finding.rune as { reason?: string }).reason]), reason)
        .toEqual(Array(3).fill(['rune-invalid', 'UNASSESSED', reason]));
    }
    // The base64 of such text in a Kubernetes Secret is not a rune either.
    const secret = Buffer.from(rune('method=pay')).toString('base64');
    expect((await scanText('secret.yaml', `  rune: ${secret}\n`)).map(finding => finding.kind)).toEqual(['rune-invalid']);
  });

  it('RUNE/scan a rune whose per unit is an Object.prototype name is reported, and the rest of the file is still scanned', async () => {
    const findings = await scanText('x.env', `RUNE=${rune('=1&per=5constructor')}\nOTHER_RUNE=${SPEND_RUNE}\n`);
    expect(findings.map(finding => [finding.line, finding.kind, finding.grade])).toEqual([[1, 'rune', 'READ'], [2, 'rune', 'SPEND']]);
    expect(findings[0].rune).toMatchObject({ methods: 'none' });
  });

  it('RUNE/scan a percent-encoded padding character does not mark the value as cut', async () => {
    const findings = await scanText('x.txt', `https://app/?rune=${READ_RUNE.replace(/=/g, '%3D')}\n`);
    expect(findings[0]).toMatchObject({ kind: 'rune', grade: 'READ' });
  });
});

describe('RUNE/scan truncation', () => {
  it('RUNE/scan a following KEY=value line is not a continuation; a bare base64 line is', async () => scratch(async dir => {
    // A rune at the end of its line is graded as read unless the next line could be the rest of
    // the value: only base64 characters, with '=' at most as trailing padding.
    writeFileSync(join(dir, 'app.env'), `PAY_RUNE=${SPEND_RUNE}\nOTHER_KEY=value\nREAD_RUNE=${READ_RUNE}\nAAAABBBBCCCC==\n`);
    const findings = (await scan([dir], { clock })).findings.filter(finding => finding.kind === 'rune');
    expect(findings).toHaveLength(2);
    const [pay, read] = findings;
    expect(pay).toMatchObject({ grade: 'SPEND' });
    const warnings = (finding: ScanFinding) => (finding.rune && 'warnings' in finding.rune ? finding.rune.warnings : []) as string[];
    expect(warnings(pay)).not.toContain('possibly-truncated');
    expect(read).toMatchObject({ grade: 'UNASSESSED' });
    expect(warnings(read)).toContain('possibly-truncated');
  }));
});

describe('RUNE/scan output', () => {
  it('RUNE/scan JSON output validates, counts grades and fails --fail-on as graded', async () => scratch(async dir => {
    writeFileSync(join(dir, 'app.env'), `READ_RUNE=${READ_RUNE}\nPAY_RUNE=${SPEND_RUNE}\nBAD_RUNE=${'A'.repeat(50)}\n`);
    const result = await captureMain(main, ['scan', dir, '--json', '--fail-on', 'SPEND']);
    expect(result.code).toBe(1);
    const parsed = JSON.parse(result.stdout);
    expect(validateScan(parsed), JSON.stringify(validateScan.errors)).toBe(true);
    expect(parsed.result.summary.byGrade).toMatchObject({ READ: 1, SPEND: 1, UNASSESSED: 1 });
    expect(parsed.result.failOn).toEqual({ threshold: 'SPEND', count: 2 });
  }));

  it('RUNE/scan an ignore entry suppresses a rune by fingerprint', async () => scratch(async dir => {
    writeFileSync(join(dir, 'app.env'), `RUNE=${SPEND_RUNE}\n`);
    writeFileSync(join(dir, '.macwardenignore'), `${runeFingerprint('=8&method=pay')} app.env\n`);
    const result = await captureMain(main, ['scan', dir, '--json', '--fail-on', 'READ']);
    expect(result.code).toBe(0);
    expect(JSON.parse(result.stdout).result.summary.ignored).toBe(1);
  }));

  it('RUNE/scan a rune in an MCP server entry is tagged as agent configuration', async () => scratch(async dir => {
    writeFileSync(join(dir, 'mcp.json'), JSON.stringify({ mcpServers: { cln: { command: 'cln-mcp', env: { CLN_RUNE: SPEND_RUNE } } } }, null, 2));
    const findings = (await scan([dir], { clock })).findings.filter(finding => finding.kind === 'rune');
    expect(findings).toHaveLength(1);
    expect(findings[0].context).toBe('mcp-config');
  }));

  it('RUNE/scan text, SARIF and github formats describe runes without the rune', async () => scratch(async dir => {
    writeFileSync(join(dir, 'app.env'), `RUNE=${SPEND_RUNE}\nOLD_RUNE=${rune('=9&method=pay&time<1700000000')}\nX_RUNE=${'A'.repeat(50)}\n`);
    const result = await scan([dir], { clock });
    const output = (format: 'text' | 'sarif' | 'github') => [...renderChunks({ command: 'scan', ok: true, warnings: [], result, error: null,
      ...(format === 'text' ? {} : { display: { format, scanRoot: dir } }) } as OutputResult, 'text')].join('');
    const text = output('text');
    expect(text).toMatch(/rune {2}fp:[0-9a-f]{16} SPEND \(unique ID 8; may allow SPEND; not checked against the node\)/);
    expect(text).toContain('deadline passed according to local clock');
    expect(text).toMatch(/rune-invalid {2}fp:[0-9a-f]{16} UNASSESSED \(treat as SPEND or worse\) \(in rune context, does not parse as a rune/);
    const sarif = JSON.parse(output('sarif'));
    const rules = sarif.runs[0].tool.driver.rules.map((rule: { id: string }) => rule.id);
    expect(rules).toEqual(expect.arrayContaining(['macwarden/rune/spend', 'macwarden/rune-invalid']));
    expect(sarif.runs[0].results.map((item: { ruleId: string }) => item.ruleId)).toEqual(expect.arrayContaining(['macwarden/rune/spend', 'macwarden/rune-invalid']));
    const github = output('github');
    expect(github).toMatch(/::error file=app\.env,line=1,col=6,title=macwarden rune::SPEND fp:[0-9a-f]{16} unique ID 8/);
    for (const rendered of [text, JSON.stringify(sarif), github]) {
      expect(rendered.includes(SPEND_RUNE.replace(/=+$/, '').slice(0, 43))).toBe(false);
      expect(rendered.includes(Buffer.alloc(32, 0x5a).toString('hex'))).toBe(false);
    }
  }));
});

describe('RUNE/scan candidate extraction is linear', () => {
  function work(size: number): number {
    const text = 'rune=rune=rune='.repeat(size) + 'A'.repeat(size) + ' rune: '.repeat(size);
    let best = Infinity;
    for (let round = 0; round < 5; round++) {
      const started = process.hrtime.bigint();
      runeCandidates(text);
      best = Math.min(best, Number(process.hrtime.bigint() - started));
    }
    return best;
  }

  it('RUNE/scan quadrupling adversarial input at most about quadruples the work (compared in-process)', () => {
    work(20_000);
    const small = work(50_000);
    const large = work(200_000);
    // Linear work gives a ratio near 4; quadratic work would give about 16.
    expect(large / small).toBeLessThan(9);
  });
});
