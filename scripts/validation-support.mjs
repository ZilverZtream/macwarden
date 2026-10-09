// Shared helpers for scripts/full-validation.mjs: bounded process execution,
// complete-report checks, the no-skips source scan and safe evidence output.
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import ts from 'typescript';
import { findLeaks, sentinelRedactor } from './leak-check.mjs';
import { platformVariants } from './platform-variants.mjs';

export function resolveVitestConfig(root, kind = 'unit', optional = false) {
  const bases = { unit: 'vitest.config', oracle: 'vitest.oracle.config', harness: 'vitest.harness.config' };
  if (!Object.hasOwn(bases, kind)) throw new Error('unknown Vitest configuration');
  const candidates = ['ts', 'mts', 'cts', 'js', 'mjs', 'cjs'].map(extension =>
    join(root, `${bases[kind]}.${extension}`)).filter(path => existsSync(path));
  if (!candidates.length && optional) return null;
  if (candidates.length !== 1) throw new Error('Vitest configuration unavailable or ambiguous');
  const path = candidates[0];
  const canonical = realpathSync(path);
  const matches = process.platform === 'win32' ? canonical.toLowerCase() === resolve(path).toLowerCase()
    : canonical === resolve(path);
  if (!lstatSync(path).isFile() || !matches)
    throw new Error('Vitest configuration must be a root file');
  return path;
}

export function npmVitestConfigArgs(root, script, config) {
  const command = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).scripts?.[script];
  if (typeof command !== 'string') throw new Error('test script unavailable');
  const declared = [...command.matchAll(/(?:^|\s)--config(?:=|\s+)(?:"([^"]+)"|'([^']+)'|([^\s]+))/g)];
  if (!declared.length) return ['--config', config];
  if (declared.length !== 1 || resolve(root, declared[0][1] || declared[0][2] || declared[0][3]) !== config)
    throw new Error('test script configuration differs from inventory');
  return [];
}

export function collectedCaseName(test) {
  return Array.isArray(test.ancestorTitles) && typeof test.title === 'string'
    ? [...test.ancestorTitles, test.title].join(' > ')
    : test.fullName || test.title;
}

function npmCli() {
  const candidates = [join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    '/usr/share/nodejs/npm/bin/npm-cli.js', '/usr/lib/node_modules/npm/bin/npm-cli.js'];
  return candidates.find(path => path && existsSync(path));
}

// MACWARDEN_VALIDATION_TIMEOUT_MS bounds every general command (1 to 600000 ms).
export function commandTimeout() {
  const value = process.env.MACWARDEN_VALIDATION_TIMEOUT_MS;
  if (value === undefined) return 180_000;
  if (!/^[1-9][0-9]*$/.test(value)) return null;
  const milliseconds = Number(value);
  return Number.isSafeInteger(milliseconds) && milliseconds <= 600_000 ? milliseconds : null;
}

// MACWARDEN_ORACLE_TIMEOUT_MS bounds the whole oracle command (1 to 2400000 ms).
export function oracleCommandTimeout(generalTimeout) {
  const value = process.env.MACWARDEN_ORACLE_TIMEOUT_MS;
  if (value === undefined) return process.env.MACWARDEN_VALIDATION_TIMEOUT_MS === undefined ? 2_400_000 : generalTimeout;
  if (!/^[1-9][0-9]*$/.test(value)) return null;
  const milliseconds = Number(value);
  return Number.isSafeInteger(milliseconds) && milliseconds <= 2_400_000 ? milliseconds : null;
}

export function run(program, args, root, env, input, timeout = 180_000) {
  const cli = program === 'npm' ? npmCli() : null;
  if (program === 'npm' && !cli) return { exitCode: 1, output: '', timedOut: false };
  const result = spawnSync(program === 'npm' ? process.execPath : program,
    program === 'npm' ? [cli, ...args] : args,
    { cwd: root, env, input, encoding: 'utf8', timeout, maxBuffer: 32_000_000 });
  return { exitCode: Number.isInteger(result.status) ? result.status : 1,
    output: (result.stdout || '') + (result.stderr || ''),
    timedOut: result.error?.code === 'ETIMEDOUT' };
}

export function runNpm(args, root, env, timeout) {
  const cli = npmCli();
  if (!cli) return Promise.resolve({ exitCode: 1, output: '', timedOut: false });
  return new Promise(resolveResult => {
    const output = [];
    let outputSize = 0;
    let outputLimitExceeded = false;
    let timedOut = false;
    let settled = false;
    let child;
    let timer;
    const killTree = () => {
      if (!child?.pid) return;
      if (process.platform === 'win32') {
        // npm starts scripts in descendants; killing only npm leaves those scripts running.
        const killed = spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'],
          { windowsHide: true, encoding: 'utf8', timeout: 5_000 });
        if (killed.status !== 0) child.kill('SIGKILL');
      } else {
        // detached gives npm and its descendants an owned process group.
        try { process.kill(-child.pid, 'SIGKILL'); }
        catch (error) { if (error.code !== 'ESRCH') child.kill('SIGKILL'); }
      }
    };
    const append = data => {
      if (outputLimitExceeded) return;
      const chunk = Buffer.isBuffer(data) ? data : Buffer.from(data);
      const kept = chunk.subarray(0, 32_000_000 - outputSize);
      output.push(kept);
      outputSize += kept.length;
      if (kept.length < chunk.length) {
        outputLimitExceeded = true;
        killTree();
      }
    };
    const finish = code => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolveResult({ exitCode: timedOut || outputLimitExceeded ? 1 : Number.isInteger(code) ? code : 1,
        output: Buffer.concat(output).toString('utf8'), timedOut });
    };
    try {
      child = spawn(process.execPath, [cli, ...args], {
        cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'], detached: process.platform !== 'win32',
        windowsHide: true,
      });
    } catch {
      return resolveResult({ exitCode: 1, output: '', timedOut: false });
    }
    child.stdout.on('data', append);
    child.stderr.on('data', append);
    child.on('error', () => finish(1));
    child.on('close', finish);
    timer = setTimeout(() => {
      if (settled) return;
      timedOut = true;
      killTree();
    }, timeout);
  });
}

function suites(report) {
  return Array.isArray(report?.testResults)
    ? report.testResults.filter(suite => suite && typeof suite === 'object') : [];
}

export function assertions(report) {
  return suites(report).flatMap(suite => Array.isArray(suite.assertionResults)
    ? suite.assertionResults.filter(test => test && typeof test.status === 'string' &&
      (typeof test.fullName === 'string' || typeof test.title === 'string')) : []);
}

export function testFiles(root, directory = join(root, 'test')) {
  if (!existsSync(directory)) return [];
  return readdirSync(directory, { withFileTypes: true }).flatMap(item => {
    const path = join(directory, item.name);
    const localPath = relative(root, path).replaceAll('\\', '/');
    // These documented private instrumentation directories are excluded by
    // both Vitest projects. Other directories and platform suffixes stay visible.
    if (localPath === 'test/.tmp' || localPath === 'test/.sentinels') return [];
    if (item.isDirectory()) return testFiles(root, path);
    return item.isFile() && /\.(?:test|spec)\.[cm]?[jt]sx?$/.test(item.name)
      ? [relative(root, path).replaceAll('\\', '/')] : [];
  });
}

function mapped(title, id, name) {
  const escape = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`^${escape(id)}/${escape(name)}(?:\\s|$)`).test(title);
}

/**
 * Checks that a Vitest JSON report is complete and passing and that every test
 * file of its kind ran. Kind 'unit' covers every file outside test/oracle and
 * test/gitleaks, minus this platform's variants, whose counterparts must have
 * passed their required case. Kind 'oracle' covers every file in test/oracle.
 */
export function fullSuite(root, kind, report, checks) {
  const tests = assertions(report);
  const titles = tests.map(test => test.fullName || test.title);
  const countsValid = report?.success === true && tests.length > 0 && new Set(titles).size === titles.length &&
    report.numTotalTests === tests.length && report.numPassedTests === tests.filter(test => test.status === 'passed').length &&
    report.numFailedTests === 0 && report.numPendingTests === tests.filter(test => test.status !== 'passed').length &&
    (!report.numFailedTestSuites) && tests.every(test => test.status === 'passed');
  checks.push({ name: 'selected-suite', status: countsValid ? 'PASS' : 'FAIL',
    detail: `${tests.length} assertions; complete passing JSON report required` });
  const candidates = testFiles(root).filter(file => kind === 'unit'
    ? !file.startsWith('test/oracle/') && !file.startsWith('test/gitleaks/')
    : file.startsWith('test/oracle/'));
  const variants = kind === 'unit' ? platformVariants(process.platform).filter(item => candidates.includes(item.file)) : [];
  const excluded = variants.map(item => item.file);
  const required = candidates.filter(file => !excluded.includes(file));
  const observed = new Set(suites(report).map(suite => {
    const path = resolve(root, typeof suite.name === 'string' ? suite.name : '');
    return relative(root, path).replaceAll('\\', '/');
  }));
  const missing = required.filter(file => !observed.has(file));
  checks.push({ name: 'suite-inventory', status: required.length && !missing.length ? 'PASS' : 'FAIL',
    detail: JSON.stringify({ included: required, missing }) });
  if (kind === 'unit') {
    const covered = variants.every(item => suites(report).some(suite =>
      relative(root, resolve(root, typeof suite.name === 'string' ? suite.name : '')).replaceAll('\\', '/') === item.counterpart &&
      Array.isArray(suite.assertionResults) && suite.assertionResults.some(test =>
        test.status === 'passed' && mapped(test.fullName || '', ...item.requiredCase.split('/')))));
    checks.push({ name: 'platform-variants', status: covered ? 'PASS' : 'FAIL',
      detail: JSON.stringify({ platform: process.platform, excluded: variants }) });
  }
}

// Scrub textual values and keys before serialization so encoded credentials in
// one failure message cannot destroy the surrounding JSON or safe counts.
function scrubStrings(value, redact) {
  if (typeof value === 'string') return redact(value);
  if (Array.isArray(value)) return value.map(item => scrubStrings(item, redact));
  if (value && typeof value === 'object') {
    const entries = Object.entries(value).map(([key, item]) => [redact(key), scrubStrings(item, redact)]);
    if (new Set(entries.map(([key]) => key)).size !== entries.length) throw new Error('redacted key collision');
    return Object.fromEntries(entries);
  }
  return value;
}

export function safeSerialize(value, options) {
  const scrubbed = scrubStrings(value, sentinelRedactor(options));
  const serialized = JSON.stringify(scrubbed, null, 2);
  JSON.parse(serialized);
  if (findLeaks({ ...options, commandOutput: serialized })) throw new Error('unsafe serialization');
  return serialized;
}

// Counts .only, .skip and .todo on Vitest test functions in the source, including
// renamed imports and namespace imports, so no test can be disabled in code.
function sourceModifierCount(path) {
  const source = ts.createSourceFile(path, readFileSync(path, 'utf8'), ts.ScriptTarget.Latest, true);
  const testNames = new Set(['it', 'test', 'describe', 'suite']);
  const namespaces = new Set();
  for (const statement of source.statements) {
    if (!ts.isImportDeclaration(statement) || statement.moduleSpecifier.text !== 'vitest') continue;
    const bindings = statement.importClause?.namedBindings;
    if (bindings && ts.isNamespaceImport(bindings)) namespaces.add(bindings.name.text);
    else if (bindings && ts.isNamedImports(bindings)) {
      for (const element of bindings.elements) {
        if (testNames.has((element.propertyName || element.name).text)) testNames.add(element.name.text);
      }
    }
  }
  const property = node => ts.isPropertyAccessExpression(node) ? node.name.text
    : ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression) ? node.argumentExpression.text : null;
  function isTestChain(node) {
    if (ts.isIdentifier(node)) return testNames.has(node.text);
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      if (ts.isIdentifier(node.expression) && namespaces.has(node.expression.text) && testNames.has(property(node))) return true;
      return isTestChain(node.expression);
    }
    if (ts.isCallExpression(node) || ts.isTaggedTemplateExpression(node) || ts.isParenthesizedExpression(node)) {
      return isTestChain(ts.isTaggedTemplateExpression(node) ? node.tag : node.expression);
    }
    return false;
  }
  let count = 0;
  function visit(node) {
    if (['only', 'skip', 'todo'].includes(property(node)) && isTestChain(node.expression)) count++;
    ts.forEachChild(node, visit);
  }
  visit(source);
  return count;
}

export function skippedSourceCount(root) {
  const dir = join(root, 'test');
  if (!existsSync(dir)) return 0;
  let count = 0;
  function walk(path) {
    for (const item of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, item.name);
      if (item.isDirectory()) walk(child);
      else if (/\.(?:test|spec)\.[cm]?[jt]sx?$/.test(item.name)) {
        count += sourceModifierCount(child);
      }
    }
  }
  walk(dir); return count;
}

// True when the checkout has no changes and its only untracked files lie inside ownedPaths.
export function candidateInputsClean(root, ownedPaths = []) {
  const changed = run('git', ['diff', '--quiet', 'HEAD'], root, process.env);
  const untracked = run('git', ['ls-files', '--others', '--exclude-standard', '-z'], root, process.env);
  if (changed.exitCode !== 0 || untracked.exitCode !== 0) return false;
  return untracked.output.split('\0').filter(Boolean).every(file => ownedPaths.some(base => {
    const path = relative(resolve(base), resolve(root, file));
    return path === '' || (!path.startsWith('..') && !isAbsolute(path));
  }));
}
