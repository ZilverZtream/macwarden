import { spawnSync } from 'node:child_process';
import { copyFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { captureMain } from './support/capture.js';

const repo = resolve();
const testTmp = process.env.MACWARDEN_TEST_TMP || join(repo, 'test/.tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const eslint = join(repo, 'node_modules/eslint/bin/eslint.js');

function lint(source: string, filename: string) {
  return spawnSync(process.execPath, [eslint, '--stdin', '--stdin-filename', filename],
    { cwd: repo, input: source, encoding: 'utf8', timeout: 30_000 });
}

it('CP-016/B9 static network imports fail outside adapter and only HTTPS passes inside it', () => {
  for (const name of ['http', 'https', 'net', 'tls', 'dns', 'dgram']) {
    for (const specifier of [name, `node:${name}`]) {
      const source = `import * as transport from '${specifier}';\nvoid transport;\n`;
      const blocked = lint(source, 'src/decode/cp016-network-probe.ts');
      expect(blocked.status, `${specifier} outside adapter`).not.toBe(0);
      const adapter = lint(source, 'src/lnd/cp016-network-probe.ts');
      expect(adapter.status, `${specifier} inside adapter`).toBe(name === 'https' ? 0 : 1);
    }
  }
}, 180_000);

it('CP-016/B13 global network and dynamic module loading cannot bypass the source boundary', () => {
  const probes = [
    'void fetch("https://example.invalid");',
    'void globalThis.fetch("https://example.invalid");',
    'void new WebSocket("wss://example.invalid");',
    'void new EventSource("https://example.invalid");',
    'void navigator.sendBeacon("https://example.invalid", "x");',
    'void import("node:https");',
    'void import("https");',
    'const name = "node:https"; void import(name);',
    'const load = require; void load("node:https");',
  ];
  for (const source of probes) {
    const result = lint(source, 'src/scan/cp016-network-probe.ts');
    expect(result.status, `source: ${source}`).not.toBe(0);
  }
  expect(lint('import https from "node:https"; void https;',
    'src/lnd/cp016-network-probe.ts').status).toBe(0);
}, 120_000);

it('CP-016/B17 build type-checks ordinary test and nested helper errors and accepts the clean control', () => {
  mkdirSync(testTmp, { recursive: true });
  const scratch = mkdtempSync(join(testTmp, 'cp016-typecheck-'));
  const source = join(scratch, 'source');
  try {
    mkdirSync(source);
    cpSync(join(repo, 'src'), join(source, 'src'), { recursive: true });
    copyFileSync(join(repo, 'package.json'), join(source, 'package.json'));
    for (const config of readdirSync(repo).filter(name => /^tsconfig.*\.json$/.test(name)))
      copyFileSync(join(repo, config), join(source, config));
    for (const config of readdirSync(repo).filter(name => /^vitest.*\.config\.ts$/.test(name)))
      copyFileSync(join(repo, config), join(source, config));
    const copyCodeSources = (dir: string) => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const path = join(dir, entry.name);
        if (entry.isDirectory()) {
          if (resolve(path) !== resolve(testTmp)) copyCodeSources(path);
        } else if (entry.isFile() && /\.(?:ts|tsx|mts|cts|js|mjs|cjs)$/.test(entry.name)) {
          const destination = join(source, path.slice(repo.length + 1));
          mkdirSync(dirname(destination), { recursive: true });
          copyFileSync(path, destination);
        }
      }
    };
    copyCodeSources(join(repo, 'scripts'));
    copyCodeSources(join(repo, 'test'));
    symlinkSync(join(repo, 'node_modules'), join(source, 'node_modules'),
      process.platform === 'win32' ? 'junction' : 'dir');
    const probes = [
      join(source, 'test/typecheck-probe.test.ts'),
      join(source, 'test/helpers/typecheck-probe.ts'),
    ];
    const build = () => spawnSync(npm, ['run', 'build'],
      { cwd: source, encoding: 'utf8', timeout: 120_000, shell: process.platform === 'win32' });
    const clean = build();
    const cleanErrors = ((clean.stdout || '') + (clean.stderr || '')).split(/\r?\n/)
      .map(line => line.match(/^(.+?)\(\d+,\d+\): error (TS\d+):/)?.slice(1, 3).join(' '))
      .filter(Boolean).join(', ');
    expect(clean.status, `clean build ${cleanErrors}`).toBe(0);
    for (const probe of probes) {
      writeFileSync(probe, 'export const typeCheckProbe: string = 42;\n', { flag: 'wx' });
    }
    const bad = build();
    expect(bad.status).not.toBe(0);
    const diagnostics = ((bad.stdout || '') + (bad.stderr || '')).replaceAll('\\', '/');
    expect(diagnostics).toContain('TS2322');
    for (const probe of probes)
      expect(diagnostics).toContain(probe.slice(source.length + 1).replaceAll('\\', '/'));
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}, 300_000);

it('CP-016/B11 joint preimage warning remains inactive while offchain evidence is unresolved', async () => {
  const facts = JSON.parse(readFileSync(join(repo, 'test/oracle/facts/observations.json'), 'utf8')) as {
    preimageRead: { preimageMatchesKnown: boolean; offchainReadConfirmed: boolean };
  };
  expect(facts.preimageRead.preimageMatchesKnown).toBe(true);
  expect(facts.preimageRead.offchainReadConfirmed).toBe(false);

  const { grade } = await import('../src/grade/index.js') as {
    grade: (permissions: string[]) => { grade: string; warnings: string[] };
  };
  for (const permission of ['invoices:read', 'offchain:read']) {
    const result = grade([permission]);
    expect(result.grade).toBe('READ');
    expect(result.warnings).not.toContain('preimage-exposure');
  }
});

async function invoke(args: string[]) {

  const module = await import('../src/cli.js') as { main: (args: string[]) => Promise<number> };
  return captureMain(module.main, args);
}

it('CP-016/B18 first double dash preserves a literal --json path for inspect and scan', async () => {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp016-dash-'));
  const prior = process.cwd();
  try {
    writeFileSync(join(dir, '--json'), readFileSync(join(repo, 'test/vectors/default-readonly.macaroon')).toString('hex'));
    process.chdir(dir);
    for (const command of ['inspect', 'scan']) {
      const text = await invoke([command, '--', '--json']);
      expect(text.code, `${command} text`).toBe(0);
      expect(text.stdout).toContain('fp:');
      expect(() => JSON.parse(text.stdout)).toThrow();
      const json = await invoke([command, '--json', '--', '--json']);
      expect(json.code, `${command} JSON`).toBe(0);
      expect(json.stderr).toBe('');
      expect(json.stdout).toContain('fp:');
      expect(JSON.parse(json.stdout)).toMatchObject({ schema: 1, command, ok: true, error: null });
    }
  } finally {
    process.chdir(prior);
    rmSync(dir, { recursive: true, force: true });
  }
});

it('CP-016/B19 shared dispatch retains usage, input and decode error exit mapping', async () => {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp016-errors-'));
  try {
    const invalid = join(dir, 'invalid.macaroon');
    writeFileSync(invalid, 'invalid input');
    for (const [args, code, step] of [
      [['inspect', '--json'], 2, null],
      [['inspect', '--json', join(dir, 'missing.macaroon')], 3, 'input-read'],
      [['inspect', '--json', invalid], 3, 'v2-header'],
      [['scan', '--json', join(dir, 'missing')], 3, 'input-read'],
    ] as const) {
      const run = await invoke([...args]);
      expect(run.code).toBe(code);
      expect(run.stderr).toBe('');
      expect(JSON.parse(run.stdout)).toMatchObject({ schema: 1, ok: false,
        error: { code, step } });
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

it('CP-016/B19 typed command errors keep compatible module identities', async () => {
  const sharedPath = '../src/errors.js';
  const inputPath = '../src/input/index.js';
  const decodePath = '../src/decode/index.js';
  const shared = await import(/* @vite-ignore */ sharedPath) as Record<string, unknown>;
  const input = await import(/* @vite-ignore */ inputPath) as Record<string, unknown>;
  const decode = await import(/* @vite-ignore */ decodePath) as Record<string, unknown>;
  for (const name of ['UsageError', 'InputError', 'DecodeError'])
    expect(typeof shared[name], name).toBe('function');
  expect(input.UsageError).toBe(shared.UsageError);
  expect(input.InputError).toBe(shared.InputError);
  expect(decode.DecodeError).toBe(shared.DecodeError);
});
