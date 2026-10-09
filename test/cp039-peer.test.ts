import { afterAll, beforeAll, expect, it } from 'vitest';
import type { OutputResult } from '../src/output/index.js';
import { Secret } from '../src/secret.js';
import { render } from '../src/output/index.js';
import { run as bake } from '../src/commands/bake/index.js';
import { auditEncodings, context, noCredential, pubkey, scratch, sentinel } from './support/cp039-audit.js';
import { localPeer } from './support/cp039-peer.js';

let peer: Awaited<ReturnType<typeof localPeer>>;
beforeAll(async () => { peer = await localPeer(); });
afterAll(async () => { await peer?.close(); });
async function failure(call: () => Promise<unknown>) {
  let caught: unknown;
  try { await call(); } catch (error) { caught = error; }
  expect(caught !== undefined, 'peer response must be rejected').toBe(true);
  noCredential(String(caught));
  return caught as { code: number };
}
const info = { identity_pubkey: pubkey, alias: 'fixture', version: '0.21.4-beta', chains: [{ network: 'regtest' }] };
for (const message of ["root key with id 424242 doesn't exist", 'permission denied',
  'macaroon has expired', 'constraint check failed: macaroon has expired']) {
  it(`CP-039/B4-auth-classification HTTP500 own ${message.startsWith('root') ? 'root missing' : message} maps exit4`, async () => {
    peer.state.status = 500; peer.state.body = JSON.stringify({ message });
    expect.soft((await failure(() => peer.adapter().getInfo())).code).toBe(4);
    expect.soft((await failure(() => peer.adapter().checkMacaroon(new Secret(sentinel()), ['info:read']))).code).toBe(4);
  });
}
for (const [name, message, reason] of [
  ['root missing', "root key with id 9 doesn't exist", 'root-key-missing'],
  ['signature mismatch', 'signature mismatch', 'signature-mismatch'],
] as const) {
  it(`CP-039/B4-auth-classification ${name} proves target rejection only at pinned HTTP400`, async () => {
    peer.state.body = JSON.stringify({ code: 3, message });
    peer.state.status = 400;
    expect(await peer.adapter().checkMacaroon(new Secret(sentinel()), ['info:read']))
      .toMatchObject({ valid: false, reason });
    for (const status of [401, 403, 404, 409, 500, 502]) {
      peer.state.status = status;
      let rejected = false;
      try {
        const result = await peer.adapter().checkMacaroon(new Secret(sentinel()), ['info:read']);
        rejected = result.valid === false && ['root-key-missing', 'signature-mismatch'].includes(result.reason);
      } catch (error) {
        if ([401, 403].includes(status)) expect((error as { code: number }).code).toBe(4);
      }
      expect.soft(rejected, `HTTP${status} cannot establish target rejection`).toBe(false);
    }
    peer.state.status = 400; peer.state.body = JSON.stringify({ message: 'unknown target error' });
    expect(await peer.adapter().checkMacaroon(new Secret(sentinel()), ['info:read']))
      .toMatchObject({ valid: false, reason: 'other' });
  });
}
for (const [name, body] of [
  ['duplicate top-level key', '{"root_key_ids":["0"],"root_key_ids":["9"]}'],
  ['escaped duplicate key', '{"root_key_ids":["0"],"root_key_\\u0069ds":["9"]}'],
  ['trailing garbage', '{"root_key_ids":["0"]} trailing'],
  ['second JSON document', '{"root_key_ids":["0"]}{"root_key_ids":["9"]}'],
] as const) {
  it(`CP-039/B5-strict-response rejects IDs ${name}`, async () => {
    peer.state.status = 200; peer.state.body = body;
    expect((await failure(() => peer.adapter().listMacaroonIds())).code).toBe(5);
  });
}
it('CP-039/B5-strict-response accepts one strict IDs document including uint64 maximum', async () => {
  peer.state.status = 200; peer.state.body = ' \n{"root_key_ids":["0","18446744073709551615"]}\r\n';
  expect(await peer.adapter().listMacaroonIds()).toEqual([0n, 18446744073709551615n]);
});
for (const [name, changes] of [
  ['malformed pubkey', { identity_pubkey: 'not-a-public-key' }],
  ['uncompressed pubkey', { identity_pubkey: '04' + 'ab'.repeat(32) }],
  ['alias controls', { alias: 'terminal\u001b[31m' }], ['version controls', { version: 'bad\u0085version' }],
  ['oversized alias', { alias: 'A'.repeat(4096) }], ['oversized version', { version: 'V'.repeat(4096) }],
] as const) {
  it(`CP-039/A4-peer-echo refuses ${name} at the adapter boundary`, async () => {
    peer.state.status = 200; peer.state.body = JSON.stringify({ ...info, ...changes });
    expect((await failure(() => peer.adapter().getInfo())).code).toBe(5);
  });
}
it('CP-039/A4-peer-echo accepts a valid compressed pubkey and printable bounded node metadata', async () => {
  peer.state.status = 200;
  peer.state.body = JSON.stringify(info);
  expect(await peer.adapter().getInfo()).toEqual({ pubkey, alias: 'fixture', network: 'regtest', version: '0.21.4-beta' });
});
it('CP-039/A4-peer-echo bake refuses malformed peer identity before ID allocation in text and JSON', async () => scratch(async dir => {
  const f = context(dir);
  peer.state.status = 200; peer.state.body = JSON.stringify({ ...info, identity_pubkey: sentinel().toString('latin1') });
  peer.state.seen = [];
  const result = await bake(['--label', 'Alice', '--preset', 'invoice-only', '--out', f.out, ...f.online],
    { ...f.deps, lnd: peer.adapter() });
  expect.soft(result.error?.code).toBe(5); expect.soft(result.error?.step).toBe('B8');
  expect(peer.state.seen, 'no ID listing or mutating request after malformed GetInfo').toEqual(['/v1/getinfo']);
  for (const mode of ['text', 'json'] as const) noCredential(render(result, mode));
}));
for (const [name, encoded] of auditEncodings(sentinel())) {
  it(`CP-039/A4-peer-echo rejects ${name} pubkey before returning peer facts`, async () => {
    const echo = typeof encoded === 'string' ? encoded : encoded.toString('latin1');
    peer.state.status = 200; peer.state.body = JSON.stringify({ ...info, identity_pubkey: echo });
    expect((await failure(() => peer.adapter().getInfo())).code).toBe(5);
  });
  it(`CP-039/A4-peer-echo redacts ${name} alias version and bake recovery in text and JSON`, () => {
    const echo = typeof encoded === 'string' ? encoded : encoded.toString('latin1');
    for (const field of ['alias', 'version'] as const) {
      const envelope = { schema: 1 as const, command: 'inventory' as const, ok: true as const, warnings: [], display: { now: Date.parse('2026-10-05T00:00:00Z') },
        result: { node: { pubkey, alias: 'safe-alias', network: 'regtest', version: 'safe-version', [field]: `safe-left ${echo} safe-right` },
          rootKeys: [] }, error: null } satisfies OutputResult;
      const json = JSON.parse(render(envelope, 'json')) as typeof envelope;
      const value = json.result.node[field];
      expect.soft(value.startsWith('safe-left ') && value.endsWith(' safe-right') && value.includes('[redacted]'),
        `${field} safe context and redaction marker`).toBe(true);
      noCredential(value, sentinel(), true);
      const text = render(envelope, 'text'); noCredential(text, sentinel(), true);
      if (field === 'alias') expect.soft(text.includes('safe-left ') && text.includes(' safe-right') && text.includes('[redacted]'),
        'text safe context and redaction marker').toBe(true);
    }
    const recovery = { schema: 1 as const, command: 'bake' as const, ok: false as const, warnings: [], result: null,
      error: { code: 7, step: 'B16', message: `recovery entry: safe-left ${echo} safe-right; macwarden revoke Alice` } } satisfies OutputResult;
    const document = JSON.parse(render(recovery, 'json')) as typeof recovery;
    expect(document).toMatchObject({ schema: 1, command: 'bake', ok: false, result: null, error: { code: 7, step: 'B16' } });
    expect.soft(document.error.message.startsWith('recovery entry: safe-left ') &&
      document.error.message.endsWith(' safe-right; macwarden revoke Alice') && document.error.message.includes('[redacted]'),
      'safe JSON recovery context and exact follow-up').toBe(true);
    noCredential(document.error.message, sentinel(), true);
    const text = render(recovery, 'text'); noCredential(text, sentinel(), true);
    expect.soft(text.includes('recovery entry: safe-left ') && text.includes(' safe-right; macwarden revoke Alice') &&
      text.includes('[redacted]'), 'safe text recovery context and exact follow-up').toBe(true);
  });
}
