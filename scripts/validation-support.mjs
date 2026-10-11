// Shared helpers for scripts/full-validation.mjs: bounded process execution,
// complete-report checks, the no-skips source scan and safe evidence output.
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { findLeaks, sentinelRedactor } from './leak-check.mjs';
import { platformVariants, requiredPlatformFiles } from './platform-variants.mjs';

export function resolveVitestConfig(root, kind = 'unit', optional = false) {
  const bases = { unit: 'vitest.config', oracle: 'vitest.oracle.config', harness: 'vitest.harness.config', cln: 'vitest.cln.config' };
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

// The npm that ships with the running Node: beside node.exe on Windows, and in
// <prefix>/lib/node_modules under <prefix>/bin/node on Linux (the official archives,
// nvm and actions/setup-node). Distribution packages keep npm in a system directory.
function npmCli() {
  const candidates = [join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    join(dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    '/usr/share/nodejs/npm/bin/npm-cli.js', '/usr/lib/node_modules/npm/bin/npm-cli.js'];
  return candidates.find(path => path && existsSync(path));
}
const npmMissing = () => ({ exitCode: 1, output: `npm CLI not found for ${process.execPath}\n`, timedOut: false });

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
  if (program === 'npm' && !cli) return npmMissing();
  const result = spawnSync(program === 'npm' ? process.execPath : program,
    program === 'npm' ? [cli, ...args] : args,
    { cwd: root, env, input, encoding: 'utf8', timeout, maxBuffer: 32_000_000 });
  return { exitCode: Number.isInteger(result.status) ? result.status : 1,
    output: (result.stdout || '') + (result.stderr || ''),
    timedOut: result.error?.code === 'ETIMEDOUT' };
}

export function runNpm(args, root, env, timeout) {
  const cli = npmCli();
  if (!cli) return Promise.resolve(npmMissing());
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

// The documented private instrumentation directories, which both Vitest projects exclude
// (vitest.config.ts, privateScratch). The suite inventory and the no-skips scan both skip
// them through this one list; other directories and platform suffixes stay visible.
export const PRIVATE_TEST_SCRATCH = Object.freeze(['test/.tmp', 'test/.sentinels']);
const privateScratch = (root, path) => PRIVATE_TEST_SCRATCH.includes(relative(root, path).replaceAll('\\', '/'));

export function testFiles(root, directory = join(root, 'test')) {
  if (!existsSync(directory)) return [];
  return readdirSync(directory, { withFileTypes: true }).flatMap(item => {
    const path = join(directory, item.name);
    if (privateScratch(root, path)) return [];
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
 * file of its kind ran. Kind 'unit' covers every file outside test/oracle,
 * test/cln-oracle and test/gitleaks, minus this platform's variants, whose
 * counterparts must have passed their required case. Kind 'oracle' covers every
 * file in test/oracle, kind 'cln-oracle' every file in test/cln-oracle.
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
    ? !file.startsWith('test/oracle/') && !file.startsWith('test/cln-oracle/') && !file.startsWith('test/gitleaks/')
    : file.startsWith(kind === 'cln-oracle' ? 'test/cln-oracle/' : 'test/oracle/'));
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
    // This platform's own variants must exist, not be excluded, and run at least one passing test.
    const platformFiles = requiredPlatformFiles(process.platform);
    const absent = platformFiles.filter(file => !candidates.includes(file) || excluded.includes(file) ||
      !suites(report).some(suite => relative(root, resolve(root, typeof suite.name === 'string' ? suite.name : ''))
        .replaceAll('\\', '/') === file && Array.isArray(suite.assertionResults)
        && suite.assertionResults.some(test => test.status === 'passed')));
    checks.push({ name: 'platform-required', status: absent.length ? 'FAIL' : 'PASS',
      detail: JSON.stringify({ platform: process.platform, required: platformFiles, absent }) });
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

// Properties a test chain may use: each case still runs and reports its own result.
const TEST_CHAIN_PROPERTIES = new Set(['each', 'for', 'concurrent', 'sequential']);
// Capability skips and early returns allowed per file, as { skipIf, return } counts. Empty: the
// ones that predated this check moved onto the platform-variant contract
// (scripts/platform-variants.mjs) or became requirements of the platform (audit 1.4.0), so
// every skipIf and early return in any file counts.
/** @type {Readonly<Record<string, Readonly<{ skipIf?: number; return?: number }>>>} */
export const SOURCE_SKIP_ALLOWANCE = Object.freeze({});

// Counts every way a source can disable, invert or empty a Vitest test: .only,
// .skip, .todo, .fails, .skipIf, .runIf and any other property not in
// TEST_CHAIN_PROPERTIES; computed access; aliases or other non-call uses of
// it/test/describe/suite (renamed and namespace imports included); empty literal
// .each/.for tables; the context skip(); and a return before the end of a test
// body. Anything unrecognised on a test chain counts, so the check fails closed.
function sourceModifierFindings(path, file = '') {
  const source = ts.createSourceFile(path, readFileSync(path, 'utf8'), ts.ScriptTarget.Latest, true);
  const testNames = new Set(['it', 'test', 'describe', 'suite']);
  // A global name the file declares itself (a parameter, a destructured helper)
  // is not the Vitest global; imported names are added back below.
  const declares = node => {
    if ((ts.isVariableDeclaration(node) || ts.isParameter(node) || ts.isBindingElement(node) || ts.isFunctionDeclaration(node))
      && node.name && ts.isIdentifier(node.name)) testNames.delete(node.name.text);
    ts.forEachChild(node, declares);
  };
  declares(source);
  const namespaces = new Set();
  for (const statement of source.statements) {
    if (!ts.isImportDeclaration(statement) || statement.moduleSpecifier.text !== 'vitest') continue;
    const bindings = statement.importClause?.namedBindings;
    if (bindings && ts.isNamespaceImport(bindings)) namespaces.add(bindings.name.text);
    else if (bindings && ts.isNamedImports(bindings)) {
      for (const element of bindings.elements) {
        if (['it', 'test', 'describe', 'suite'].includes((element.propertyName || element.name).text)) testNames.add(element.name.text);
      }
    }
  }
  const unwrap = node => {
    while (node && (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isSatisfiesExpression(node)
      || ts.isNonNullExpression(node) || ts.isTypeAssertionExpression(node))) node = node.expression;
    return node;
  };
  // The root of a test chain: a test binding, or namespace.testName.
  const isTestRoot = node => ts.isIdentifier(node) && testNames.has(node.text)
    || ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.expression) && namespaces.has(node.expression.text)
      && testNames.has(node.name.text);
  function isTestChain(node) {
    node = unwrap(node);
    if (!node) return false;
    if (isTestRoot(node)) return true;
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) return isTestChain(node.expression);
    if (ts.isCallExpression(node) || ts.isTaggedTemplateExpression(node)) {
      return isTestChain(ts.isTaggedTemplateExpression(node) ? node.tag : node.expression);
    }
    return false;
  }
  const findings = [];
  const allowance = { skipIf: 0, return: 0, ...SOURCE_SKIP_ALLOWANCE[file] };
  let current;
  const violation = reason => {
    findings.push({ file, line: source.getLineAndCharacterOfPosition(current.getStart(source)).line + 1, reason });
  };
  // A name being declared, or a property name, rather than a reference.
  const declarationName = node => {
    const parent = node.parent;
    if (ts.isBindingElement(parent) && parent.propertyName === node) return true;
    return parent.name === node && (ts.isPropertySignature(parent) || ts.isPropertyAssignment(parent)
      || ts.isPropertyDeclaration(parent) || ts.isMethodDeclaration(parent) || ts.isMethodSignature(parent)
      || ts.isGetAccessor(parent) || ts.isSetAccessor(parent) || ts.isEnumMember(parent) || ts.isPropertyAccessExpression(parent)
      || ts.isBindingElement(parent) || ts.isVariableDeclaration(parent) || ts.isParameter(parent) || ts.isFunctionDeclaration(parent))
      || ts.isQualifiedName(parent) && parent.right === node;
  };
  // A return that is not the last statement of a test body leaves the rest unrun.
  const earlyReturn = body => {
    if (!body || !ts.isBlock(body)) return false;
    let found = false;
    const visit = node => {
      if (found || node !== body && ts.isFunctionLike(node)) return;
      if (ts.isReturnStatement(node) && body.statements.at(-1) !== node) found = true;
      ts.forEachChild(node, visit);
    };
    visit(body);
    return found;
  };
  function visit(node) {
    current = node;
    // A test binding used other than as a call or as the object of an allowed property.
    if (ts.isIdentifier(node) && testNames.has(node.text) && !ts.isImportSpecifier(node.parent) && !isTestRoot(node.parent)
      && !declarationName(node)) {
      let use = node, parent = node.parent;
      while (ts.isParenthesizedExpression(parent) || ts.isAsExpression(parent) || ts.isNonNullExpression(parent)) { use = parent; parent = parent.parent; }
      const called = ts.isCallExpression(parent) && parent.expression === use || ts.isTaggedTemplateExpression(parent) && parent.tag === use;
      const accessed = (ts.isPropertyAccessExpression(parent) || ts.isElementAccessExpression(parent)) && parent.expression === use;
      const namespaceName = ts.isPropertyAccessExpression(parent) && parent.name === node;
      if (!called && !accessed && !namespaceName) violation(`${node.text} used other than as a test call`);
    }
    if ((ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) && !isTestRoot(node) && isTestChain(node.expression)) {
      const name = ts.isPropertyAccessExpression(node) ? node.name.text : null;
      if (name === 'skipIf' && allowance.skipIf > 0) allowance.skipIf--;
      else if (name === null || !TEST_CHAIN_PROPERTIES.has(name)) violation(name === null ? 'computed test-chain property' : `.${name} on a test chain`);
      else if ((name === 'each' || name === 'for') && ts.isCallExpression(node.parent) && node.parent.expression === node) {
        const table = unwrap(node.parent.arguments[0]);
        if (!table || ts.isArrayLiteralExpression(table) && table.elements.length === 0) violation(`empty .${name} table`);
      }
    }
    // The test context's skip(), called or destructured, under any name.
    if (ts.isPropertyAccessExpression(node) && node.name.text === 'skip' && !isTestChain(node.expression)) violation('context skip()');
    if (ts.isBindingElement(node) && (node.propertyName ?? node.name).getText(source) === 'skip') violation('context skip binding');
    // The test body passed to a test call.
    if (ts.isCallExpression(node) && isTestChain(node.expression)) {
      for (const argument of node.arguments) {
        const body = unwrap(argument);
        if (body && (ts.isArrowFunction(body) || ts.isFunctionExpression(body)) && earlyReturn(body.body)) {
          if (allowance.return > 0) allowance.return--; else violation('return before the end of a test body');
        }
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(source);
  return findings;
}

export function skippedSourceCount(root) {
  return skippedSourceFindings(root).length;
}

/** Each place in a test source that disables, inverts or empties a test: { file, line, reason }. */
export function skippedSourceFindings(root) {
  const dir = join(root, 'test');
  if (!existsSync(dir)) return [];
  const findings = [];
  function walk(path) {
    for (const item of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, item.name);
      // Scratch fixtures left by an interrupted or concurrent run are outside the suite.
      if (privateScratch(root, child)) continue;
      if (item.isDirectory()) walk(child);
      else if (/\.(?:test|spec)\.[cm]?[jt]sx?$/.test(item.name)) {
        findings.push(...sourceModifierFindings(child, relative(root, child).replaceAll('\\', '/')));
      }
    }
  }
  walk(dir); return findings;
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

/**
 * Tests a Vitest JSON report did not run to a pass: skipped, pending, todo or
 * failed. A test in a file with a recorded capability skip (SOURCE_SKIP_ALLOWANCE)
 * may be skipped up to that file's count. Returns [{ file, name, status }].
 */
export function unfinishedTests(root, report) {
  const unfinished = [];
  if (!suites(report).length || report?.numTodoTests) unfinished.push({ file: '', name: 'report', status: 'incomplete' });
  for (const suite of suites(report)) {
    const file = relative(root, resolve(root, typeof suite.name === 'string' ? suite.name : '')).replaceAll('\\', '/');
    let allowed = SOURCE_SKIP_ALLOWANCE[file]?.skipIf ?? 0;
    for (const test of Array.isArray(suite.assertionResults) ? suite.assertionResults : []) {
      if (test?.status === 'passed') continue;
      if ((test?.status === 'pending' || test?.status === 'skipped') && allowed > 0) { allowed--; continue; }
      unfinished.push({ file, name: String(test?.fullName ?? test?.title ?? ''), status: String(test?.status) });
    }
  }
  return unfinished;
}

// CLI for CI: node scripts/validation-support.mjs --no-pending <vitest-json-report>...
// Exits 1 when a report is missing, unreadable or holds a test that did not pass.
if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url)) && process.argv[2] === '--no-pending') {
  const reports = process.argv.slice(3);
  let failed = reports.length === 0;
  for (const path of reports) {
    let unfinished;
    try { unfinished = unfinishedTests(process.cwd(), JSON.parse(readFileSync(path, 'utf8'))); }
    catch { unfinished = [{ file: path, name: 'report', status: 'unreadable' }]; }
    for (const test of unfinished) console.error(`${test.status}: ${test.file} ${test.name}`);
    if (unfinished.length) failed = true;
  }
  process.exitCode = failed ? 1 : 0;
}
