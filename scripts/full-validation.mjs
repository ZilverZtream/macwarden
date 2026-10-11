import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { assignShards, readDurations } from './oracle-shards.mjs';
import { runNode } from './run-node.mjs';
import { fileURLToPath } from 'node:url';
import { createPrivateDirectory } from './private-scratch.mjs';
import { findLeaks, leakScans, sentinelRedactor } from './leak-check.mjs';
import { run, runNpm, commandTimeout, oracleCommandTimeout, fullSuite, skippedSourceCount, candidateInputsClean, safeSerialize, collectedCaseName, resolveVitestConfig, npmVitestConfigArgs, collectedNameDuplicates } from './validation-support.mjs';

const scriptRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const vitestCli = join(scriptRoot, 'node_modules', 'vitest', 'vitest.mjs');

// LND fixture owners for the oracle shards, one regtest node each. Owners 3 and 4 stay free:
// CP-050/fixture-shard-isolation (test/oracle/cp050-policy.test.ts) starts them itself.
// Six start in parallel in about 15 s and pass reliably; more cannot help much, since the host
// CPU, not Docker, bounds the oracle files. The plan drops owners it has no files for.
export const lndOwners = ['1', '2', '5', '6', '7', '8'];

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const readJson = path => JSON.parse(readFileSync(path, 'utf8'));
const git = (root, args) => {
  const result = spawnSync('git', args, { cwd: root, encoding: 'utf8', timeout: 30_000, windowsHide: true });
  if (result.status !== 0) throw new Error('candidate identity unavailable');
  return result.stdout.trim();
};
async function validate(args) {
  let root = resolve();
  let evidence;
  const seen = new Set();
  for (let i = 0; i < args.length; i += 2) {
    if (!['--root', '--evidence-dir'].includes(args[i]) || !args[i + 1] || seen.has(args[i])) return 2;
    seen.add(args[i]);
    if (args[i] === '--root') root = resolve(args[i + 1]);
    else evidence = resolve(args[i + 1]);
  }
  evidence ||= join(root, '.ratchet', 'evidence', 'full');
  // The complete unit run needs about 7 minutes on
  // Windows, so full validation defaults to the documented 600000 ms maximum.
  const timeout = process.env.MACWARDEN_VALIDATION_TIMEOUT_MS === undefined ? 600_000 : commandTimeout();
  const oracleTimeout = oracleCommandTimeout(timeout);
  if (timeout === null || oracleTimeout === null) return refuse('invalid MACWARDEN_VALIDATION_TIMEOUT_MS');
  if (!['win32', 'linux'].includes(process.platform)) return refuse(`unsupported platform ${process.platform} (Linux and Windows only)`);
  if (process.platform === 'linux' && process.getuid() === 0) return refuse('refusing to run as root');
  // Evidence inside the work tree must be git-ignored: otherwise its untracked files would be
  // excused by the cleanliness check while a later commit could pick them up.
  const evidencePath = relative(root, evidence);
  if (!evidencePath.startsWith('..') && !isAbsolute(evidencePath)
    && spawnSync('git', ['check-ignore', '-q', '--', evidencePath || '.'], { cwd: root, timeout: 30_000, windowsHide: true }).status !== 0)
    return refuse('the evidence directory is inside the work tree and not ignored by git');
  let candidate;
  let inputs;
  try {
    candidate = git(root, ['rev-parse', 'HEAD']);
    if (!candidateInputsClean(root, [evidence])) return refuse('the candidate has uncommitted or untracked changes');
    inputs = git(root, ['ls-files', '-z']).split('\0').filter(Boolean).map(file => ({ file,
      sha256: hash(readFileSync(join(root, file))) }));
  } catch { return refuse('cannot read the candidate with git'); }
  // New attempt directories retain every previous failed or invalid run.
  mkdirSync(evidence, { recursive: true });
  const attempt = await createPrivateDirectory(evidence, 'attempt-');
  // The toolchain that produced this evidence: Node, npm and the exact dependency lockfile.
  const npmVersion = run('npm', ['--version'], root, process.env, undefined, 60_000);
  const toolchain = { node: process.version, npm: npmVersion.exitCode === 0 ? npmVersion.output.trim() : null,
    lockfileSha256: existsSync(join(root, 'package-lock.json')) ? hash(readFileSync(join(root, 'package-lock.json'))) : null };
  const result = { level: 'full', platform: process.platform, candidate, toolchain, inputs, status: 'FAIL',
    startedAt: new Date().toISOString(), commands: [], checks: [], reports: [], inventories: [] };
  const runtimeParent = join(root, '.ratchet', 'packets');
  mkdirSync(runtimeParent, { recursive: true });
  const runtime = await createPrivateDirectory(runtimeParent, 'full-runtime-');
  result.lifecycle = { runtime, retention: 'private originals retained', owners: [] };
  const contexts = [];
  // Failed commands' own output, for a redacted tail in the failure message.
  const failedOutputs = [];
  const context = async owner => {
    const scratch = await createPrivateDirectory(runtime, `macwarden-full-${owner}-`);
    const sentinels = await createPrivateDirectory(runtime, `macwarden-sentinels-${owner}-`);
    const env = { ...process.env, MACWARDEN_TEST_TMP: scratch, MACWARDEN_SENTINEL_DIR: sentinels };
    delete env.MACWARDEN_FIXTURE_SHARD;
    // LND fixture shards are numbered; the Core Lightning fixture has its own fixed project.
    if (/^[1-8]$/.test(owner)) env.MACWARDEN_FIXTURE_SHARD = owner;
    const ctx = { owner, scratch, sentinels, env, output: '' };
    contexts.push(ctx);
    result.lifecycle.owners.push({ owner, scratch, sentinels, createdAt: new Date().toISOString() });
    return ctx;
  };
  const perform = async (ctx, argv, deadline = timeout, directVitest = false) => {
    // Asynchronous either way: the unit and oracle phases share this event loop.
    const invocation = directVitest
      ? await runNode([vitestCli, ...argv], root, ctx.env, deadline)
      : await runNpm(argv, root, ctx.env, deadline);
    result.commands.push({ owner: ctx.owner, argv, exitCode: invocation.exitCode, timedOut: invocation.timedOut,
      ...(directVitest ? { program: process.execPath, cli: vitestCli } : {}) });
    ctx.output += invocation.output;
    if (invocation.exitCode !== 0) {
      const name = `command:${ctx.owner}:${argv.join(' ')}`;
      result.checks.push({ name, status: 'FAIL' });
      failedOutputs.push({ ctx, name, exitCode: invocation.exitCode, timedOut: invocation.timedOut, output: invocation.output });
    }
    return invocation.exitCode === 0;
  };
  const inventory = async (ctx, config, label) => {
    const file = join(ctx.scratch, `${label}-inventory.json`);
    if (!await perform(ctx, ['list', '--no-staticParse', '--cache=false', '--config', config, `--json=${file}`], timeout, true)) throw new Error('inventory unavailable');
    const items = readJson(file);
    if (!Array.isArray(items) || !items.length || items.some(item => typeof item.file !== 'string' || typeof item.name !== 'string'))
      throw new Error('invalid inventory');
    result.inventories.push({ label, sha256: hash(readFileSync(file)), items });
    return items;
  };
  const report = (ctx, path, label, expected) => {
    const original = readFileSync(path);
    const data = JSON.parse(original);
    const observed = (data.testResults || []).flatMap(suite => (suite.assertionResults || []).map(test => ({
      file: resolve(root, suite.name), name: test.fullName || test.title,
      inventoryName: collectedCaseName(test), status: test.status })));
    const key = item => `${resolve(root, item.file)}\0${item.inventoryName ?? item.name}`;
    const expectedKeys = expected.map(key).sort();
    const observedKeys = observed.map(key).sort();
    const complete = expectedKeys.length > 0 && new Set(expectedKeys).size === expectedKeys.length &&
      JSON.stringify(expectedKeys) === JSON.stringify(observedKeys) && data.success === true &&
      data.numTotalTests === observed.length && data.numPassedTests === observed.length &&
      data.numFailedTests === 0 && data.numPendingTests === 0 && !data.numFailedTestSuites &&
      observed.every(test => test.status === 'passed');
    result.checks.push({ name: `${label}:complete`, status: complete ? 'PASS' : 'FAIL' });
    const options = { root, sentinels: join(root, 'test/sentinels.json'), sentinelDir: ctx.sentinels };
    const safe = findLeaks({ ...options, commandOutput: original.toString('utf8') })
      ? safeSerialize(data, options) : original.toString('utf8');
    // Originals remain in private scratch; evidence records both identities.
    writeFileSync(join(attempt, `${label}-report.json`), safe);
    result.reports.push({ label, originalPath: path, originalSha256: hash(original), retainedSha256: hash(safe),
      cases: observed.map(item => ({ ...item, file: relative(root, item.file).replaceAll('\\', '/') })) });
    return observed;
  };
  try {
    const unit = await context('unit');
    // Fail fast: two checks the end of the run repeats, made before any test phase so a
    // run that cannot pass stops in seconds rather than after every phase.
    result.checks.push({ name: 'no-skipped-source:early', status: skippedSourceCount(root) ? 'FAIL' : 'PASS' });
    const names = collectedNameDuplicates(root, unit.env, unit.scratch, timeout);
    for (const { output, ...command } of names.commands) {
      result.commands.push({ owner: unit.owner, program: process.execPath, ...command });
      unit.output += output;
    }
    // Counts only: a test name is metadata the evidence must not echo.
    result.checks.push({ name: 'unique-test-names:early', status: names.collected && !names.duplicates.length ? 'PASS' : 'FAIL',
      detail: names.collected ? `${names.duplicates.length} duplicate names among ${names.count}` : 'test collection failed' });
    if (result.checks.some(check => check.status !== 'PASS')) throw new Error('fail fast');
    await perform(unit, ['run', 'build']);
    await perform(unit, ['run', 'lint']);
    const unitConfig = resolveVitestConfig(root);
    const oracleConfig = resolveVitestConfig(root, 'oracle');
    const harnessConfig = resolveVitestConfig(root, 'harness', true);
    const clnConfig = resolveVitestConfig(root, 'cln');
    const units = await inventory(unit, unitConfig, 'unit');
    const oracles = await inventory(unit, oracleConfig, 'oracle');
    const clnOracles = await inventory(unit, clnConfig, 'cln-oracle');
    const oracleFileCoverage = (files, label, kind = 'oracle') => {
      const checks = [];
      fullSuite(root, kind, { testResults: files.map(name => ({
        name, assertionResults: []
      })) }, checks);
      result.checks.push(...checks.filter(check => check.name === 'suite-inventory')
        .map(check => ({ ...check, name: `${label}:file-inventory` })));
    };
    oracleFileCoverage(oracles.map(item => item.file), 'oracle-collection');
    oracleFileCoverage(clnOracles.map(item => item.file), 'oracle-cln-collection', 'cln-oracle');
    // Explicit per-owner file lists, balanced by measured duration: each oracle file has
    // exactly one owner, so stateful files never share a node, and the plan check proves it.
    const relativeFile = file => relative(root, resolve(root, file)).replaceAll('\\', '/');
    const oracleFiles = [...new Set(oracles.map(item => relativeFile(item.file)))].sort();
    const plan = assignShards(oracleFiles, readDurations(root), lndOwners.length)
      .map((shard, index) => ({ owner: lndOwners[index], files: shard.files, predictedSeconds: Math.round(shard.seconds) }));
    const planned = plan.flatMap(shard => shard.files).sort();
    result.checks.push({ name: 'oracle-shard-plan', status: plan.length > 0 && new Set(planned).size === planned.length &&
      JSON.stringify(planned) === JSON.stringify(oracleFiles) ? 'PASS' : 'FAIL', detail: JSON.stringify(plan) });
    // The phases run side by side, each with its own owners: the Core Lightning shard and the LND
    // fixture startups overlap the unit and harness commands, gitleaks overlaps the LND oracle
    // files. The LND files themselves wait for the unit and harness commands: they compete for
    // the host CPU (they spawn the CLI constantly), and measured on 24 threads they pushed the
    // unit command past its 600000 ms deadline (646 s beside six shards, 398 s alone) while
    // saving only a tenth of the wall time.
    let releaseOracleFiles;
    const unitCommandsDone = new Promise(resolveGate => { releaseOracleFiles = resolveGate; });
    const unitPhase = async () => {
      let unitData;
      // Released however the unit commands end, so a unit failure never strands the oracle phase.
      try {
        const unitReport = join(unit.scratch, 'unit-report.json');
        await perform(unit, ['run', '--config', unitConfig, '--cache=false', '--reporter=json', `--outputFile=${unitReport}`], timeout, true);
        report(unit, unitReport, 'unit', units);
        unitData = readJson(unitReport);
        if (harnessConfig) {
          const harness = await inventory(unit, harnessConfig, 'harness');
          const harnessReport = join(unit.scratch, 'harness-report.json');
          await perform(unit, ['run', 'test:harness', '--', ...npmVitestConfigArgs(root, 'test:harness', harnessConfig), '--cache=false', '--reporter=json', `--outputFile=${harnessReport}`]);
          report(unit, harnessReport, 'harness', harness);
          const data = readJson(harnessReport);
          unitData = { success: unitData.success && data.success,
            testResults: [...unitData.testResults, ...data.testResults],
            numTotalTests: unitData.numTotalTests + data.numTotalTests,
            numPassedTests: unitData.numPassedTests + data.numPassedTests,
            numFailedTests: unitData.numFailedTests + data.numFailedTests,
            numPendingTests: unitData.numPendingTests + data.numPendingTests,
            numFailedTestSuites: unitData.numFailedTestSuites + data.numFailedTestSuites };
        }
      } finally { releaseOracleFiles(); }
      fullSuite(root, 'unit', unitData, result.checks);
      const gitleaksCommand = readJson(join(root, 'package.json')).scripts?.['test:gitleaks'];
      const gitleaksConfig = typeof gitleaksCommand === 'string'
        ? /(?:^|\s)--config\s+([\w./-]+)(?:\s|$)/.exec(gitleaksCommand)?.[1] : null;
      if (!gitleaksConfig || !existsSync(join(root, gitleaksConfig))) throw new Error('gitleaks inventory configuration unavailable');
      const gitleaks = await inventory(unit, gitleaksConfig, 'gitleaks');
      const gitleaksReport = join(unit.scratch, 'gitleaks-report.json');
      await perform(unit, ['run', 'test:gitleaks', '--', '--cache=false', '--reporter=json', `--outputFile=${gitleaksReport}`], oracleTimeout);
      report(unit, gitleaksReport, 'gitleaks', gitleaks);
    };
    const oraclePhase = async () => {
      const oracleObserved = [];
      // The Core Lightning rune comparison runs beside the LND shards against its own disposable
      // regtest fixture (fixture:cln:up, test:cln-oracle, fixture:cln:down), recorded like them.
      const clnShard = async () => {
        const ctx = await context('cln');
        const path = join(ctx.scratch, 'cln-oracle-report.json');
        try {
          if (await perform(ctx, ['run', 'fixture:cln:up'])) {
            await perform(ctx, ['run', 'test:cln-oracle', '--', ...npmVitestConfigArgs(root, 'test:cln-oracle', clnConfig), '--cache=false', '--reporter=json', `--outputFile=${path}`], oracleTimeout);
          }
        } finally {
          await perform(ctx, ['run', 'fixture:cln:down']);
        }
        if (!existsSync(path)) throw new Error('cln oracle report missing');
        const observed = report(ctx, path, 'oracle-cln', clnOracles);
        oracleFileCoverage(observed.map(item => item.file), 'oracle-cln-aggregate', 'cln-oracle');
      };
      const shards = await Promise.allSettled([clnShard(), ...plan.map(async ({ owner, files }) => {
        const ctx = await context(owner);
        const path = join(ctx.scratch, 'oracle-report.json');
        try {
          if (await perform(ctx, ['run', 'fixture:up'])) {
            await unitCommandsDone;
            await perform(ctx, ['run', 'test:oracle', '--', ...npmVitestConfigArgs(root, 'test:oracle', oracleConfig), '--cache=false', '--reporter=json', `--outputFile=${path}`, ...files], oracleTimeout);
          }
        } finally {
          await perform(ctx, ['run', 'fixture:down']);
        }
        if (!existsSync(path)) throw new Error('shard report missing');
        // Expected cases come from the plan, not from the report: a file the shard skipped or
        // one it ran without owning both fail this shard's completeness check.
        const owned = new Set(files);
        oracleObserved.push(...report(ctx, path, `oracle-${owner}`, oracles.filter(item => owned.has(relativeFile(item.file)))));
      })]);
      if (shards.some(shard => shard.status === 'rejected')) throw new Error('shard validation failed');
      const keys = items => items.map(item => `${resolve(root, item.file)}\0${item.inventoryName ?? item.name}`).sort();
      const actual = keys(oracleObserved);
      result.checks.push({ name: 'oracle-union', status: new Set(actual).size === actual.length &&
        JSON.stringify(actual) === JSON.stringify(keys(oracles)) ? 'PASS' : 'FAIL' });
      oracleFileCoverage(oracleObserved.map(item => item.file), 'oracle-aggregate');
    };
    // Both phases always finish (fixtures torn down, reports recorded) before either failure counts.
    const phases = await Promise.allSettled([unitPhase(), oraclePhase()]);
    if (phases.some(phase => phase.status === 'rejected')) throw new Error('phase validation failed');
    result.checks.push({ name: 'no-skipped-source', status: skippedSourceCount(root) ? 'FAIL' : 'PASS' });
    const unchanged = git(root, ['rev-parse', 'HEAD']) === candidate &&
      candidateInputsClean(root, [evidence, runtime]) &&
      inputs.every(item => hash(readFileSync(join(root, item.file))) === item.sha256);
    result.checks.push({ name: 'frozen-inputs', status: unchanged ? 'PASS' : 'FAIL' });
  } catch {
    result.checks.push({ name: 'validation-completeness', status: 'FAIL' });
  } finally {
    // Every owner's output is written, and its redacted copy retained, before any scan,
    // so each owner's scan also covers every owner's retained log. The scans then run
    // at once on one worker pool; each result is what findLeaks returns or throws for
    // that owner, and checks are recorded in owner order as before.
    const scans = contexts.map(ctx => {
      const options = { root, sentinels: join(root, 'test/sentinels.json'), sentinelDir: ctx.sentinels,
        testTmp: ctx.scratch, evidenceDir: attempt };
      try {
        writeFileSync(join(ctx.scratch, 'original-output.log'), ctx.output);
        const safe = sentinelRedactor(options)(ctx.output);
        writeFileSync(join(attempt, `${ctx.owner}-output.log`), safe);
        return { ctx, options, safe };
      } catch (error) {
        return { ctx, options, error };
      }
    });
    const ready = scans.filter(scan => !scan.error);
    let outcomes;
    try {
      outcomes = await leakScans(ready.map(({ ctx, options }) => ({ ...options, commandOutput: ctx.output, paths: [ctx.scratch, attempt] })));
    } catch (error) {
      outcomes = ready.map(() => ({ error }));
    }
    for (const scan of scans) {
      const { ctx } = scan;
      const outcome = scan.error ? { error: scan.error } : outcomes[ready.indexOf(scan)];
      if ('error' in outcome) {
        // The scan refused or could not read the tree (a link inside scratch, an unreadable file):
        // fail closed, and say why, since the evidence otherwise shows only FAIL.
        result.checks.push({ name: `leak-check:${ctx.owner}`, status: 'FAIL',
          detail: `leak scan failed: ${outcome.error instanceof Error ? outcome.error.message : String(outcome.error)}` });
        continue;
      }
      result.checks.push({ name: `leak-check:${ctx.owner}`, status: outcome.hit ? 'FAIL' : 'PASS' });
      result.reports.push({ label: `${ctx.owner}-output`, originalPath: join(ctx.scratch, 'original-output.log'), originalSha256: hash(ctx.output), retainedSha256: hash(scan.safe) });
    }
    result.status = result.checks.length && result.checks.every(check => check.status === 'PASS') ? 'PASS' : 'FAIL';
    result.finishedAt = new Date().toISOString();
    result.lifecycle.finishedAt = result.finishedAt;
    let safeResult = result;
    for (const ctx of contexts) {
      const options = { root, sentinels: join(root, 'test/sentinels.json'), sentinelDir: ctx.sentinels };
      try {
        if (findLeaks({ ...options, commandOutput: JSON.stringify(safeResult) })) {
          result.status = 'FAIL';
          safeResult.status = 'FAIL';
          safeResult.checks.push({ name: `leak-check:metadata:${ctx.owner}`, status: 'FAIL' });
        }
        // Scrub string values before serializing; surrounding JSON stays intact.
        safeResult = JSON.parse(safeSerialize(safeResult, options));
      } catch {
        result.status = 'FAIL';
        // Only generated identities survive if textual safety cannot be verified.
        safeResult = { level: 'full', platform: process.platform, candidate, toolchain, status: 'FAIL',
          startedAt: result.startedAt, finishedAt: result.finishedAt, commands: [],
          inputs: inputs.map(item => ({ sha256: item.sha256 })),
          reports: result.reports.map(item => ({ originalSha256: item.originalSha256,
            retainedSha256: item.retainedSha256 })),
          inventories: result.inventories.map(item => ({ sha256: item.sha256 })),
          checks: [{ name: 'leak-check:metadata', status: 'FAIL' }] };
        break;
      }
    }
    safeResult.status = result.status;
    // Written whole or not at all: an interrupted write never leaves a truncated record.
    writeFileSync(join(attempt, 'full-validation.json.partial'), `${JSON.stringify(safeResult, null, 2)}\n`);
    renameSync(join(attempt, 'full-validation.json.partial'), join(attempt, 'full-validation.json'));
  }
  if (result.status !== 'PASS') {
    // Check names only: the evidence file holds the details.
    const failed = result.checks.filter(check => check.status !== 'PASS').map(check => check.name);
    process.stderr.write(`full validation FAIL: ${failed.join(', ') || 'see evidence'}; evidence in ${attempt}\n`);
    for (const failure of failedOutputs) process.stderr.write(commandTail(root, failure));
  }
  return result.status === 'PASS' ? 0 : 1;
}

/**
 * The end of a failed command's output, redacted with its owner's sentinels, so that a
 * failure can be diagnosed from the message alone. A tail that still holds a registered
 * credential after redaction is withheld; the evidence logs keep the whole redacted output.
 */
function commandTail(root, { ctx, name, exitCode, timedOut, output }) {
  const heading = `--- ${name}: ${timedOut ? 'timed out' : `exit ${exitCode}`}`;
  try {
    const options = { root, sentinels: join(root, 'test/sentinels.json'), sentinelDir: ctx.sentinels };
    const tail = sentinelRedactor(options)(output).slice(-2_000).trimEnd();
    if (findLeaks({ ...options, commandOutput: tail })) return `${heading}; output withheld (possible credential)\n`;
    return tail ? `${heading}; output tail:\n${tail}\n` : `${heading}; no output\n`;
  } catch {
    return `${heading}; output withheld (leak check unavailable)\n`;
  }
}

/** One line naming why validation did not start. */
function refuse(reason) {
  process.stderr.write(`full validation not started: ${reason}\n`);
  return 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.exitCode = await validate(process.argv.slice(2)); }
  catch { process.exitCode = 1; }
}
