import { fork, type ChildProcess } from 'node:child_process';
import { join } from 'node:path';
import type { Linter } from 'eslint';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { repo } from './support/cp039-audit.js';

let lint: ChildProcess;
type Reply = { ready?: boolean; messages?: Linter.LintMessage[]; error?: string };
function reply(): Promise<Reply> {
  return new Promise((done, fail) => {
    const cleanup = () => { lint.off('message', message); lint.off('error', error); lint.off('exit', exit); };
    const message = (value: Reply) => { cleanup(); done(value); };
    const error = () => { cleanup(); fail(new Error('CP-039 lint child failed')); };
    const exit = () => { cleanup(); fail(new Error('CP-039 lint child exited before diagnostics')); };
    lint.once('message', message); lint.once('error', error); lint.once('exit', exit);
  });
}
beforeAll(async () => {
  // One native Node child pays the cold config/parser cost once, without Vitest evaluating their module graph.
  lint = fork(join(repo, 'test/support/cp039-lint.mjs'), [], {
    cwd: repo, execArgv: [], windowsHide: true, stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
  });
  expect((await reply()).ready, 'lint child initialized').toBe(true);
});
afterAll(async () => {
  if (lint && lint.exitCode === null && lint.signalCode === null) {
    const closed = new Promise<void>(done => lint.once('exit', () => done()));
    lint.kill(); await closed;
  }
});
async function messages(code: string, site = 'src/output/cp039-boundary-probe.ts') {
  const response = reply(); lint.send({ code, site });
  const result = await response;
  if (result.error || !result.messages) throw new Error(result.error ?? 'Missing lint diagnostics');
  return result.messages.filter(m => m.severity === 2 && m.ruleId !== '@typescript-eslint/no-unused-vars' &&
    m.ruleId !== '@typescript-eslint/no-explicit-any');
}
for (const [name, code] of [
  ['eval', 'eval("1")'], ['Function constructor', 'new Function("return 1")'],
  ['http2 import', 'import { connect } from "node:http2"; connect("https://localhost")'],
  ['builtin module accessor', 'process.getBuiltinModule("node:https")'],
  ['aliased global fetch', 'const g = globalThis; g.fetch("https://localhost")'],
  ['computed global fetch', 'globalThis["fe" + "tch"]("https://localhost")'],
  ['child process', 'import { spawn } from "node:child_process"; spawn("probe")'],
  ['worker', 'import { Worker } from "node:worker_threads"; new Worker("probe")'],
  ['inspector', 'import { open } from "node:inspector"; open()'],
  ['https dynamic import', 'await import("node:https")'],
  ['global fetch', 'fetch("https://localhost")'],
  ['DNS import', 'import { lookup } from "node:dns"; lookup("localhost", () => {})'],
  ['socket import', 'import { connect } from "node:net"; connect(1)'],
  ['TLS import', 'import { connect } from "node:tls"; connect(1)'],
  ['datagram import', 'import { createSocket } from "node:dgram"; createSocket("udp4")'],
  ['output handle import', 'import { reserveOut } from "../commands/bake/write-out.js"; void reserveOut'],
  ['dynamic output handle import', 'await import("../commands/bake/write-out.js")'],
] as const) {
  it(`CP-039/A7-capabilities rejects ${name} outside its approved module`, async () => {
    expect((await messages(code)).length > 0, 'restricted capability must have a lint error').toBe(true);
  });
}
it('CP-039/A7-capabilities permits ordinary dynamic JSON property access', async () => {
  expect(await messages('const data = JSON.parse("{}"); const key = "result"; void data[key];')).toEqual([]);
});
it('CP-039/A7-capabilities permits HTTPS in lnd and the writer only in bake and rotate', async () => {
  expect(await messages('import { request } from "node:https"; void request;', 'src/lnd/cp039-probe.ts')).toEqual([]);
  for (const site of ['src/commands/bake/index.ts', 'src/commands/rotate.ts']) {
    const path = site.includes('/bake/') ? './write-out.js' : './bake/write-out.js';
    expect(await messages(`import { reserveOut } from "${path}"; void reserveOut;`, site)).toEqual([]);
  }
});
it('CP-039/A7-capabilities enforces a configured private byte import boundary', async () => {
  // The routed A7 clarification supplies this capability path; assert denial directly.
  for (const code of [
    'import { revealSecret } from "../secret-capability.js"; void revealSecret;',
    'import * as bytes from "../secret-capability.js"; void bytes;',
    'await import("../secret-capability.js");',
  ]) {
    expect((await messages(code)).length > 0,
      'unauthorized capability import rejected').toBe(true);
  }
});
