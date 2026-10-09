import { fork, type ChildProcess } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import type { IncomingMessage, RequestOptions } from 'node:http';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import type { Linter } from 'eslint';
import { afterAll, beforeAll, expect, it, vi } from 'vitest';
import { main } from '../src/cli.js';
import { render, type OutputResult } from '../src/output/index.js';
import { captureMain } from './support/capture.js';
import { pubkey, register, repo, scratch } from './support/cp039-audit.js';

type Encoding = 'decimal-array' | 'nested-json-latin1';
const encodings: Encoding[] = ['decimal-array', 'nested-json-latin1'];
const bytes = () => readFileSync(join(repo, 'test/vectors/default-admin.macaroon'));

// These representations and the recovery check are independent of product recognition.
function echo(credential: Buffer, encoding: Encoding): string {
  return encoding === 'decimal-array'
    ? JSON.stringify([...credential])
    : JSON.stringify(JSON.stringify(credential.toString('latin1')));
}
function recoverable(output: string, credential: Buffer): boolean {
  let normalized = output;
  for (let layer = 0; layer < 4; layer++) {
    if (normalized.includes(credential.toString('latin1')) ||
        normalized.includes(credential.toString('hex')) ||
        normalized.includes(credential.toString('base64'))) return true;
    for (const candidate of normalized.matchAll(/\[\s*\d+(?:\s*,\s*\d+)*\s*\]/g)) {
      const values = candidate[0].slice(1, -1).split(',').map(value => Number(value.trim()));
      if (values.every(value => value >= 0 && value <= 255) && Buffer.from(values).equals(credential)) return true;
    }
    // Decode one JSON/text escape layer per pass; never invoke the product parser.
    normalized = normalized.replace(/\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|(["\\/bfnrt]))/g,
      (_match, unicode: string | undefined, hex: string | undefined, simple: string | undefined) => {
        if (unicode || hex) return String.fromCharCode(parseInt(unicode ?? hex!, 16));
        const escapes: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
        return escapes[simple!];
      });
  }
  return false;
}

const transport = vi.hoisted(() => ({ encoding: 'valid' as Encoding | 'valid', paths: [] as string[], headerMatchesVector: false }));
vi.mock('node:https', async importOriginal => {
  const original = await importOriginal<typeof import('node:https')>();
  const request = (url: string | URL | RequestOptions,
    optionsOrCallback: RequestOptions | ((response: IncomingMessage) => void),
    callbackMaybe?: (response: IncomingMessage) => void) => {
    const options = typeof optionsOrCallback === 'function' ? url as RequestOptions : optionsOrCallback;
    const callback = typeof optionsOrCallback === 'function' ? optionsOrCallback : callbackMaybe;
    const path = typeof url === 'string' || url instanceof URL ? new URL(url).pathname : url.path;
    if (!callback || !path) throw new Error('Incomplete mocked HTTPS request');
    const headers = options.headers as Record<string, unknown> | undefined;
    const header = Object.entries(headers ?? {}).find(([key]) => key.toLowerCase() === 'grpc-metadata-macaroon')?.[1];
    if (typeof header !== 'string') throw new Error('Missing request authentication header');
    const credential = Buffer.from(header, 'hex');
    transport.headerMatchesVector = credential.equals(bytes());
    transport.paths.push(path);
    let body: unknown;
    if (path === '/v1/getinfo') body = { identity_pubkey: pubkey, alias: 'ordinary-peer', version: '0.21.4-beta',
      chains: [{ chain: 'bitcoin', network: transport.encoding === 'valid' ? 'regtest' : echo(credential, transport.encoding) }] };
    else if (path === '/v1/macaroon/permissions') body = { method_permissions: {} };
    else if (path === '/v1/macaroon/ids') body = { root_key_ids: ['0'] };
    else throw new Error('Unexpected request in read-only inventory regression');
    const req = Object.assign(new EventEmitter(), {
      write() { return true; },
      end() {
        queueMicrotask(() => {
          const response = Object.assign(Readable.from([Buffer.from(JSON.stringify(body))]), { statusCode: 200 });
          callback(response as IncomingMessage);
        });
      },
      destroy() { return req; },
    });
    return req;
  };
  return { ...original, request, default: { ...original, request } };
});

async function inventory(mode: 'text' | 'json', encoding: Encoding | 'valid') {
  return scratch(async dir => {
    transport.encoding = encoding; transport.paths = []; transport.headerMatchesVector = false;
    // The real CLI, adapter, inventory command and renderer execute; only HTTPS is replaced.
    return captureMain(main, ['inventory', '--lnd-rest', 'localhost:1', '--tls-cert',
      join(repo, 'test/fixture/wrong-tls.cert'), '--macaroon', join(repo, 'test/vectors/default-admin.macaroon'),
      '--registry', join(dir, 'missing-registry.json'), ...(mode === 'json' ? ['--json'] : [])]);
  });
}
for (const encoding of encodings) for (const mode of ['text', 'json'] as const) {
  it(`CP-039/A4-peer-echo inventory safely refuses ${encoding} network metadata in ${mode}`, async () => {
    const observed = await inventory(mode, encoding);
    expect(transport.headerMatchesVector, 'echo derives from the actual disposable request credential').toBe(true);
    expect.soft(recoverable(observed.stdout + observed.stderr, bytes()), 'credential must not be recoverable from output').toBe(false);
    expect.soft(observed.code === 4 || observed.code === 5, 'invalid peer data produces a safe LND failure').toBe(true);
    expect.soft(transport.paths.length === 1 && transport.paths[0] === '/v1/getinfo', 'stop at the adapter before normal inventory calls').toBe(true);
    if (mode === 'json') {
      const document = JSON.parse(observed.stdout);
      expect.soft(document.ok === false && document.result === null && document.error !== null, 'JSON contains only a failed inventory envelope').toBe(true);
    } else expect.soft(observed.stdout.length === 0 && observed.stderr.length > 0, 'text has a safe error without normal inventory output').toBe(true);
  });
}
it('CP-039/A4-peer-echo inventory permits valid regtest network metadata in text and JSON', async () => {
  for (const mode of ['text', 'json'] as const) {
    const observed = await inventory(mode, 'valid');
    expect(observed.code === 0 && transport.headerMatchesVector, 'valid request succeeds').toBe(true);
    expect(recoverable(observed.stdout + observed.stderr, bytes()), 'valid response keeps authentication private').toBe(false);
    if (mode === 'json') {
      const document = JSON.parse(observed.stdout);
      expect(document.ok === true && document.error === null && document.result.node.network === 'regtest' &&
        document.result.node.alias === 'ordinary-peer', 'ordinary peer facts remain visible').toBe(true);
    } else expect(observed.stdout.includes('regtest') && observed.stdout.includes('ordinary-peer'), 'ordinary peer facts remain visible').toBe(true);
  }
});

function failure(message: string): OutputResult {
  return { schema: 1, command: 'inventory', ok: false, warnings: [], result: null,
    error: { code: 5, step: 'N4', message } };
}
for (const encoding of encodings) for (const mode of ['text', 'json'] as const) {
  it(`CP-039/A3-leak-encodings shared rendering removes ${encoding} while preserving ${mode} context`, () => {
    const credential = bytes();
    const message = `ordinary-left ${echo(credential, encoding)} ordinary-right [1,2,3]`;
    // Establish that the independent recovery control recognizes the planted representation.
    expect(recoverable(message, credential), 'planted representation reconstructs the complete vector').toBe(true);
    const output = render(failure(message), mode);
    expect.soft(recoverable(output, credential), 'rendered credential must not be recoverable').toBe(false);
    const visible = mode === 'json' ? JSON.parse(output).error.message as string : output;
    expect.soft(visible.includes('ordinary-left ') && visible.includes(' ordinary-right [1,2,3]'), 'surrounding ordinary data remains visible').toBe(true);
  });
}
it('CP-039/A3-leak-encodings shared rendering preserves small ordinary decimal arrays in text and JSON', () => {
  const message = 'ordinary-left [1,2,3] ordinary-right';
  for (const mode of ['text', 'json'] as const) {
    const output = render(failure(message), mode);
    const visible = mode === 'json' ? JSON.parse(output).error.message as string : output;
    expect(visible.includes(message), 'ordinary decimal data is not a credential').toBe(true);
  }
});

let lint: ChildProcess;
type Reply = { ready?: boolean; messages?: Linter.LintMessage[]; error?: string };
function reply(): Promise<Reply> {
  return new Promise((done, fail) => {
    const cleanup = () => { lint.off('message', message); lint.off('error', error); lint.off('exit', exit); };
    const message = (value: Reply) => { cleanup(); done(value); };
    const error = () => { cleanup(); fail(new Error('Lint regression child failed')); };
    const exit = () => { cleanup(); fail(new Error('Lint regression child exited without diagnostics')); };
    lint.once('message', message); lint.once('error', error); lint.once('exit', exit);
  });
}
beforeAll(async () => {
  register(bytes());
  lint = fork(join(repo, 'test/support/cp039-lint.mjs'), [], {
    cwd: repo, execArgv: [], windowsHide: true, stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
  });
  expect((await reply()).ready, 'configured lint guard initialized').toBe(true);
});
afterAll(async () => {
  if (lint && lint.exitCode === null && lint.signalCode === null) {
    const closed = new Promise<void>(done => lint.once('exit', () => done()));
    lint.kill(); await closed;
  }
});
async function diagnostics(code: string) {
  const pending = reply(); lint.send({ code, site: 'src/output/security-boundary-probe.ts' });
  const result = await pending;
  if (result.error || !result.messages) throw new Error('Configured lint guard did not return diagnostics');
  return result.messages.filter(message => message.severity === 2 && message.ruleId !== null &&
    message.ruleId !== '@typescript-eslint/no-unused-vars' && message.ruleId !== '@typescript-eslint/no-explicit-any');
}
it('CP-039/A7-capabilities rejects the reported computed constructor network capability bypass', async () => {
  // Lint this source only: never execute its request or open a connection.
  const code = 'const key = "constructor"; const Execute = Object.getPrototypeOf(() => {})[key]; ' +
    'const peer = Execute("return process")().getBuiltinModule("node:https"); peer.request({hostname:"localhost",port:1});';
  expect((await diagnostics(code)).length > 0, 'configured boundary guard rejects the derived Function capability').toBe(true);
});
it('CP-039/A7-capabilities rejects the reported concatenated constructor key network capability bypass', async () => {
  // Lint the reported source only: never execute its request or open a connection.
  const code = 'const key = "con" + "structor"; const Execute = Object.getPrototypeOf(() => {})[key]; ' +
    'const peer = Execute("return process")().getBuiltinModule("node:https"); peer.request({hostname:"localhost",port:1});';
  expect((await diagnostics(code)).length > 0, 'configured boundary guard rejects the concatenated constructor key capability').toBe(true);
});
it('CP-039/A7-capabilities rejects the reported constant identifier concatenation constructor key network capability bypass', async () => {
  // Lint the reviewer-provided source only; never execute its request or open a connection.
  const code = 'const prefix = "con"; const key = prefix + "structor"; const Execute = Object.getPrototypeOf(() => {})[key]; ' +
    'const peer = Execute("return process")().getBuiltinModule("node:https"); peer.request({hostname:"localhost",port:1});';
  expect((await diagnostics(code)).length > 0, 'configured boundary guard rejects the constant identifier concatenation constructor key capability').toBe(true);
});
it('CP-039/A7-capabilities permits ordinary indexed JSON data alongside the computed constructor regression', async () => {
  const code = 'const data = JSON.parse("{}"); const key = "result"; void data[key];';
  expect((await diagnostics(code)).length === 0, 'ordinary indexed JSON data remains permitted').toBe(true);
});
