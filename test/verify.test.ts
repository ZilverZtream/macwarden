import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { afterAll, expect, it } from 'vitest';
import { run, ROOT_KEY_0_ACCEPTED, CAN_BAKE_ACCEPTED, CAN_BAKE_ROOT_KEY_0, LOCAL_EXPIRY_UNCONFIRMED, REJECTED_INCONCLUSIVE,
  SIGNATURE_MISMATCH_INCONCLUSIVE, SIGNATURE_MISMATCH_ROOT_KEY_0, OWN_ROOT_KEY_INCONCLUSIVE, ROOT_KEY_0_INCONCLUSIVE,
  SIGNATURE_MISMATCH_HOW_TO_CONCLUDE, ROOT_KEY_MISSING_CONTRADICTED } from '../src/commands/verify.js';
import { LndError } from '../src/errors.js';
import type { LndAdapter } from '../src/lnd/index.js';
import { render, type VerifyResult } from '../src/output/index.js';
import { adapter } from './helpers/adapter.js';
import { entry, ownId, oldId, pubkey, register, responseBytes, root, vector } from './helpers/cp038-online.js';
import { expectSchemaValid } from './helpers/output-schema.js';

// Owner request 2026-10-08 (macwarden 1.1.0): verify asks LND whether one credential is still accepted.
type Check = Awaited<ReturnType<LndAdapter['checkMacaroon']>>;
const dir = mkdtempSync(join(root('MACWARDEN_TEST_TMP'), 'verify-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));
const registry = join(dir, 'registry.json');
const vectorPath = (name: string) => resolve('test/vectors', `${name}.macaroon`);
const adminOwn = register(responseBytes(ownId, vector('default-admin').permissions));
const clock = () => new Date('2026-10-04T00:00:00Z');

function fake(options: { ids?: bigint[]; check?: Check | Error; info?: Error } = {}) {
  const calls: string[] = [];
  const checked: string[][] = [];
  const lnd = adapter({
    getInfo: async () => { calls.push('GetInfo'); if (options.info) throw options.info;
      return { pubkey, alias: 'fixture', network: 'regtest', version: '0.21.4-beta' }; },
    listPermissions: async () => { calls.push('ListPermissions');
      return JSON.parse(readFileSync(resolve('src/grade/lnd-permissions.json'), 'utf8')).methods; },
    listMacaroonIds: async () => { calls.push('ListMacaroonIDs'); return options.ids ?? [0n, oldId, ownId]; },
    checkMacaroon: async (_mac, permissions) => {
      calls.push('CheckMacaroonPermissions'); checked.push(permissions);
      if (options.check instanceof Error) throw options.check;
      return options.check ?? { valid: true };
    },
  });
  return { calls, checked, lnd };
}

async function verify(args: string[], lnd: LndAdapter, own = adminOwn, stdin: Readable & { isTTY?: boolean } = Object.assign(Readable.from([]), { isTTY: true })) {
  const result = await run([...args, '--registry', registry, '--lnd-rest', '127.0.0.1:1',
    '--tls-cert', resolve('test/fixture/wrong-tls.cert'), '--macaroon', own], { lnd, fs: { ...fs }, env: {}, clock, stdin });
  expectSchemaValid(result);
  return result;
}
const value = (result: Awaited<ReturnType<typeof verify>>) => result.result as VerifyResult;
const exit = (result: Awaited<ReturnType<typeof verify>>) => result.error?.code ?? result.exitCode ?? 0;
function saveRegistry(entries: unknown[]) { writeFileSync(registry, JSON.stringify({ schema: 1, entries }), { mode: 0o600 }); }

it('VERIFY/accepted a registered credential LND accepts exits 1 with the revoke command for its label', async () => {
  const alice = entry(oldId);
  saveRegistry([alice]);
  const { calls, checked, lnd } = fake();
  const result = await verify([alice.outPath!], lnd);
  expect(result.ok).toBe(true);
  expect(exit(result)).toBe(1);
  expect(value(result)).toMatchObject({ status: 'accepted', rejection: null, conclusive: true, rootKeyListed: true,
    rootKeyId: String(oldId), fingerprint: alice.fingerprint, grade: 'RECEIVE', ownCredential: false, canBake: false,
    registry: { label: 'Alice', status: 'active', match: 'fingerprint' } });
  // The credential's own decoded permissions are the permission list LND checks.
  expect(checked).toEqual([vector('preset-invoice-only').permissions]);
  expect(calls).toEqual(['GetInfo', 'ListPermissions', 'ListMacaroonIDs', 'CheckMacaroonPermissions']);
  expect(value(result).guidance.join('\n')).toContain(`macwarden revoke ${oldId} (registered as Alice`);
  const text = render(result, 'text');
  expect(text).toContain('status       ACCEPTED by LND: this credential is live');
  expect(text).toContain('registry     Alice (active, same credential)');
  expect(text).toContain(`next         Revoke it: macwarden revoke ${oldId} (registered as Alice`);
});

it('VERIFY/rejected a credential whose root key ID is gone exits 0 and says LND rejects it now', async () => {
  saveRegistry([]);
  const target = register(responseBytes(oldId, vector('preset-invoice-only').permissions));
  const { lnd } = fake({ ids: [0n, ownId], check: { valid: false, reason: 'root-key-missing', message: 'x' } });
  const result = await verify([target], lnd);
  expect(exit(result)).toBe(0);
  expect(value(result)).toMatchObject({ status: 'rejected', rejection: 'root-key-missing', conclusive: true, rootKeyListed: false, registry: null });
  expect(value(result).guidance).toEqual(['LND rejects this credential now: its root key ID no longer exists. It can no longer be used against this node.']);
  expect(render(result, 'text')).toContain('status       rejected by LND (root-key-missing)');
});

it('VERIFY/rejected a signature mismatch is not conclusive while the root key ID is listed: regeneration keeps every ID (RT-01)', async () => {
  saveRegistry([]);
  // Root key ID 0 after changepassword --new_mac_root_key: still listed, so the mismatch cannot be
  // told apart from an altered copy of a live admin.macaroon.
  const { lnd } = fake({ check: { valid: false, reason: 'signature-mismatch', message: 'x' } });
  const result = await verify([vectorPath('default-readonly')], lnd);
  expect(exit(result)).toBe(1);
  expect(value(result)).toMatchObject({ status: 'rejected', rejection: 'signature-mismatch', conclusive: false, rootKeyId: '0', rootKeyListed: true });
  expect(value(result).guidance).toEqual([SIGNATURE_MISMATCH_INCONCLUSIVE, SIGNATURE_MISMATCH_HOW_TO_CONCLUDE, SIGNATURE_MISMATCH_ROOT_KEY_0]);
  expect(value(result).guidance.join('\n')).not.toMatch(/macwarden revoke 0\b/);
  // Once the root key ID is no longer listed the mismatch is conclusive.
  const target = register(responseBytes(oldId, vector('preset-invoice-only').permissions));
  const gone = await verify([target], fake({ ids: [0n, ownId], check: { valid: false, reason: 'signature-mismatch', message: 'x' } }).lnd);
  expect(exit(gone)).toBe(0);
  expect(value(gone)).toMatchObject({ rejection: 'signature-mismatch', conclusive: true, rootKeyListed: false });
  expect(value(gone).guidance[0]).toContain('its root key ID is no longer listed');
  // Without ListMacaroonIDs (own credential lacks macaroon:read) there is no counter-evidence either way: inconclusive.
  const narrow = register(responseBytes(4294967502n, ['info:read', 'uri:/lnrpc.Lightning/CheckMacaroonPermissions']));
  const unlisted = await verify([target], fake({ check: { valid: false, reason: 'signature-mismatch', message: 'x' } }).lnd, narrow);
  expect(exit(unlisted)).toBe(1);
  expect(value(unlisted)).toMatchObject({ rejection: 'signature-mismatch', conclusive: false, rootKeyListed: null });
});

it('VERIFY/RT-01 an altered copy of a live registered credential (signature mismatch, root key ID listed) is not cleared', async () => {
  const alice = entry(oldId);
  saveRegistry([alice]);
  const bytes = Buffer.from(readFileSync(alice.outPath!));
  bytes[bytes.length - 1] ^= 0x01;
  const copy = register(bytes);
  const result = await verify([copy], fake({ check: { valid: false, reason: 'signature-mismatch', message: 'x' } }).lnd);
  expect(exit(result)).toBe(1);
  expect(value(result)).toMatchObject({ status: 'rejected', rejection: 'signature-mismatch', conclusive: false, rootKeyListed: true,
    registry: { label: 'Alice', status: 'active', match: 'root-key-id' } });
  expect(value(result).guidance[0]).toBe(SIGNATURE_MISMATCH_INCONCLUSIVE);
  expect(value(result).guidance).toContain(`To make sure: macwarden revoke ${oldId}.`);
  expect(value(result).guidance.join('\n')).not.toContain('It can no longer be used against this node');
  expect(render(result, 'text')).toContain('REJECTED BY THIS CHECK ONLY (signature-mismatch)');
});

it('VERIFY/root-key-0 an accepted default macaroon explains that only regenerating every root key invalidates it', async () => {
  saveRegistry([]);
  const { lnd } = fake();
  const result = await verify([vectorPath('default-readonly')], lnd);
  expect(exit(result)).toBe(1);
  expect(value(result)).toMatchObject({ status: 'accepted', rootKeyId: '0', canBake: false });
  expect(value(result).warnings).toContain('root-key-0');
  expect(value(result).guidance.slice(1)).toEqual(ROOT_KEY_0_ACCEPTED);
  const guidance = value(result).guidance.join('\n');
  expect(guidance).toContain('lncli changepassword --new_mac_root_key');
  expect(guidance).toContain('invalidates every other macaroon on the node');
  // Never a revoke command for root key ID 0 (SAFE-03).
  expect(guidance).not.toMatch(/macwarden revoke 0/);
});

it('VERIFY/can-bake an accepted credential holding macaroon:generate points to respond, not only revoke', async () => {
  saveRegistry([]);
  const target = register(responseBytes(4294967400n, ['info:read', 'macaroon:generate']));
  const { lnd } = fake({ ids: [0n, ownId, 4294967400n] });
  const result = await verify([target], lnd);
  expect(exit(result)).toBe(1);
  expect(value(result)).toMatchObject({ status: 'accepted', grade: 'ADMIN', canBake: true, registry: null });
  expect(value(result).guidance).toContain(CAN_BAKE_ACCEPTED);
  expect(value(result).guidance.join('\n')).toContain('macwarden revoke 4294967400 --unregistered');
  expect(value(result).guidance.join('\n')).toContain('macwarden respond');
  // On root key 0 the regeneration is the remedy: the baking note says it covers baked credentials too.
  const admin = await verify([vectorPath('default-admin')], fake().lnd);
  expect(value(admin).guidance.slice(1)).toEqual([...ROOT_KEY_0_ACCEPTED, CAN_BAKE_ROOT_KEY_0]);
});

it('VERIFY/expired a credential LND reports expired (naming its own time-before caveat) is conclusive, with the caveat from the offline decode', async () => {
  saveRegistry([]);
  const { lnd } = fake({ check: { valid: false, reason: 'expired', caveat: '2026-10-02T17:38:38.792272998Z', message: 'x' } });
  const result = await verify([vectorPath('time-before')], lnd);
  expect(exit(result)).toBe(0);
  expect(value(result)).toMatchObject({ status: 'rejected', rejection: 'expired', conclusive: true });
  expect(value(result).caveats).toEqual([{ type: 'time-before', value: '2026-10-02T17:38:38.792272998Z', expired: true }]);
  expect(value(result).guidance[0]).toContain('a time-before caveat has passed');
  expect(render(result, 'text')).toMatch(/caveats +time-before 2026-10-02T17:38:38.792272998Z \(expired\)/);
  // MW110-02: an unspecific rejection is not upgraded to expiry by the local clock alone.
  const local = await verify([vectorPath('time-before')], fake({ check: { valid: false, reason: 'other', message: 'x' } }).lnd);
  expect(exit(local)).toBe(1);
  expect(value(local)).toMatchObject({ status: 'rejected', rejection: 'other', conclusive: false });
  expect(value(local).guidance).toEqual([REJECTED_INCONCLUSIVE, LOCAL_EXPIRY_UNCONFIRMED, ROOT_KEY_0_INCONCLUSIVE]);
});

it('VERIFY/inconclusive a rejection that may depend on the caller (IP lock, custom caveat) exits 1 and says to treat it as live', async () => {
  saveRegistry([]);
  for (const name of ['ipaddr', 'lnd-custom']) {
    const { lnd } = fake({ check: { valid: false, reason: 'other', message: 'x' } });
    const result = await verify([vectorPath(name)], lnd);
    expect(exit(result), name).toBe(1);
    expect(value(result)).toMatchObject({ status: 'rejected', rejection: 'other', conclusive: false });
    expect(value(result).guidance[0]).toBe(REJECTED_INCONCLUSIVE);
    expect(render(result, 'text')).toContain('REJECTED BY THIS CHECK ONLY (other)');
  }
});

it('VERIFY/nwc a Nostr Wallet Connect URI is refused as not an LND credential, before any LND call', async () => {
  const secret = randomBytes(32).toString('hex');
  const path = join(dir, 'nwc.txt');
  writeFileSync(path, `nostr+walletconnect://${'ab'.repeat(32)}?relay=wss%3A%2F%2Frelay.example.com&secret=${secret}`, { mode: 0o600 });
  try {
    const { calls, lnd } = fake();
    const result = await verify([path], lnd);
    expect(result.error).toMatchObject({ code: 3, step: 'input-form' });
    expect(result.error?.message).toContain('not an LND credential');
    expect(calls).toEqual([]);
    expect(render(result, 'text') + render(result, 'json')).not.toContain(secret);
  } finally { rmSync(path, { force: true }); }
});

it('VERIFY/own-permissions an own credential without macaroon:read fails the OWN check with exit 4 and no LND call', async () => {
  const own = register(responseBytes(4294967500n, ['info:read', 'invoices:read']));
  const { calls, lnd } = fake();
  const result = await verify([vectorPath('default-readonly')], lnd, own);
  expect(result.error).toMatchObject({ code: 4, step: 'C4' });
  expect(result.error?.message).toContain('/lnrpc.Lightning/CheckMacaroonPermissions requires macaroon:read');
  expect(calls).toEqual([]);
  // A uri: grant for exactly CheckMacaroonPermissions is enough; ListMacaroonIDs is then skipped.
  const narrow = register(responseBytes(4294967501n, ['info:read', 'uri:/lnrpc.Lightning/CheckMacaroonPermissions']));
  const second = fake();
  const allowed = await verify([vectorPath('default-readonly')], second.lnd, narrow);
  expect(exit(allowed)).toBe(1);
  expect(value(allowed).rootKeyListed).toBeNull();
  expect(second.calls).toEqual(['GetInfo', 'ListPermissions', 'CheckMacaroonPermissions']);
  expect(render(allowed, 'text')).toContain('root key     not checked');
});

it('VERIFY/connection a transport or authentication failure exits 4; an LND error on the check exits 5', async () => {
  const down = await verify([vectorPath('default-readonly')], fake({ info: new LndError(4, 'get-info', 'LND transport failure') }).lnd);
  expect(down.error).toMatchObject({ code: 4, step: 'C6', message: 'LND transport, TLS or authentication failure' });
  const refused = await verify([vectorPath('default-readonly')], fake({ check: new LndError(5, 'check-macaroon', 'LND request rejected') }).lnd);
  expect(refused.error).toMatchObject({ code: 5, step: 'C7', message: 'LND request failed' });
});

it('VERIFY/own-credential a credential on macwarden\'s own root key ID gets no revoke command macwarden would refuse', async () => {
  saveRegistry([]);
  const result = await verify([adminOwn], fake().lnd);
  expect(value(result)).toMatchObject({ status: 'accepted', ownCredential: true });
  expect(value(result).guidance.join('\n')).not.toContain(`macwarden revoke ${ownId}`);
  expect(render(result, 'text')).toContain("macwarden's own root key ID");
});

it('VERIFY/registry a different credential on a registered root key ID is matched by root key ID; a revoked record is reported', async () => {
  const alice = entry(oldId);
  saveRegistry([{ ...alice, fingerprint: 'fp:0000000000000000' }]);
  const target = alice.outPath!;
  const result = await verify([target], fake().lnd);
  expect(value(result).registry).toEqual({ label: 'Alice', status: 'active', match: 'root-key-id' });
  saveRegistry([{ ...alice, status: 'revoked', revokedAt: '2026-10-03T00:00:00Z', revokeEvidence: 'rejected' }]);
  const revoked = await verify([target], fake({ check: { valid: false, reason: 'root-key-missing', message: 'x' }, ids: [0n] }).lnd);
  expect(value(revoked).registry).toEqual({ label: 'Alice', status: 'revoked', match: 'fingerprint' });
  expect(exit(revoked)).toBe(0);
});

it('VERIFY/input stdin and literals follow inspect: a literal needs --unsafe-arg; no input or two inputs is a usage error', async () => {
  saveRegistry([]);
  const hex = readFileSync(vectorPath('default-readonly')).toString('hex');
  const refused = await verify([hex], fake().lnd);
  expect(refused.error).toMatchObject({ code: 2, step: null });
  expect(render(refused, 'json') + render(refused, 'text')).not.toContain(hex);
  const literal = await verify([hex, '--unsafe-arg'], fake().lnd);
  expect(literal.warnings).toContainEqual({ code: 'unsafe-arg', message: 'literal credentials can appear in shell history and process listings' });
  expect(value(literal).fingerprint).toBe(vector('default-readonly').fingerprint);
  const piped = await verify(['-'], fake().lnd, adminOwn, Object.assign(Readable.from([readFileSync(vectorPath('default-readonly'))]), { isTTY: false }));
  expect(value(piped).fingerprint).toBe(vector('default-readonly').fingerprint);
  expect((await verify([], fake().lnd)).error).toMatchObject({ code: 2, step: null });
  expect((await verify([vectorPath('default-readonly'), vectorPath('default-admin')], fake().lnd)).error).toMatchObject({ code: 2 });
  expect((await verify([vectorPath('default-readonly'), '--frobnicate'], fake().lnd)).error).toMatchObject({ code: 2 });
  const missing = await run([vectorPath('default-readonly')], { lnd: fake().lnd, fs: { ...fs }, env: {}, clock });
  expect(missing.error?.message).toContain('--lnd-rest (or MACWARDEN_LND_REST) is required');
});

it('VERIFY/empty-permissions a credential with no permissions is never sent to LND with an empty list', async () => {
  const target = register(responseBytes(4294967600n, []));
  const { calls, lnd } = fake();
  const result = await verify([target], lnd);
  expect(result.error).toMatchObject({ code: 3, step: 'C3' });
  expect(calls).toEqual([]);
});

it('VERIFY/leak the credential under test and the own credential never appear in text or JSON output', async () => {
  const bytes = responseBytes(oldId, vector('preset-invoice-only').permissions);
  const target = register(bytes);
  const own = readFileSync(adminOwn);
  for (const check of [{ valid: true } as Check, { valid: false, reason: 'root-key-missing', message: 'x' } as Check]) {
    const result = await verify([target], fake({ check }).lnd);
    const output = render(result, 'text') + render(result, 'json');
    for (const secret of [bytes, own]) {
      for (const encoded of [secret.toString('hex'), secret.toString('hex').toUpperCase(), secret.toString('base64'), secret.toString('base64url')])
        expect(output).not.toContain(encoded);
    }
  }
});

it('VERIFY/MW110-06 baking authority is macaroon:generate or the BakeMacaroon URI, not the ADMIN grade; an incomplete decode counts as able to bake', async () => {
  saveRegistry([]);
  const id = 4294967410n;
  const cases: [string, string[], string, boolean][] = [
    // macaroon:write deletes root key IDs (ADMIN) but LND refuses BakeMacaroon with it.
    ['macaroon:write only', ['info:read', 'macaroon:write'], 'ADMIN', false],
    ['macaroon:generate', ['info:read', 'macaroon:generate'], 'ADMIN', true],
    ['BakeMacaroon URI', ['info:read', 'uri:/lnrpc.Lightning/BakeMacaroon'], 'ADMIN', true],
    // An unknown permission is unassessed: it might grant anything.
    ['unassessed', ['info:read', 'future:bake'], 'UNASSESSED', true],
    // Past the decoder's bound the rest of the identifier is not kept: it may hold macaroon:generate.
    ['truncated', ['macaroon:write', ...Array.from({ length: 1100 }, (_, index) => `info:r${index}`)], 'ADMIN', true],
  ];
  for (const [name, permissions, grade, canBake] of cases) {
    // Piped on stdin, never written as a sentinel file: the 15 KB truncated credential would push the
    // shared leak checker's literal alternation past V8's regular expression size limit.
    const piped = Object.assign(Readable.from([responseBytes(id, permissions)]), { isTTY: false });
    const result = await verify(['-'], fake({ ids: [0n, ownId, id] }).lnd, adminOwn, piped);
    expect(exit(result), name).toBe(1);
    expect(value(result), name).toMatchObject({ status: 'accepted', grade, canBake });
    if (name === 'truncated') expect(value(result).warnings, name).toContain('identifier-exceeds-bounds');
    expect(value(result).guidance.includes(CAN_BAKE_ACCEPTED), name).toBe(canBake);
  }
});

it('VERIFY/RL-06 an inconclusive rejection never suggests revoking macwarden\'s own root key ID or root key ID 0, and says what to do instead', async () => {
  saveRegistry([]);
  // A copy on the own root key ID (an IP-locked session macaroon, say) that LND refuses for this caller.
  const target = register(responseBytes(ownId, ['info:read']));
  for (const reason of ['other', 'signature-mismatch'] as const) {
    const result = await verify([target], fake({ check: { valid: false, reason, message: 'x' } }).lnd);
    expect(exit(result), reason).toBe(1);
    expect(value(result), reason).toMatchObject({ ownCredential: true, conclusive: false });
    expect(value(result).guidance.join('\n'), reason).not.toContain(`macwarden revoke ${ownId}`);
    expect(value(result).guidance, reason).toContain(OWN_ROOT_KEY_INCONCLUSIVE);
  }
  // Root key ID 0: no revoke command, and the regeneration is named.
  const zero = await verify([vectorPath('ipaddr')], fake({ check: { valid: false, reason: 'other', message: 'x' } }).lnd);
  expect(exit(zero)).toBe(1);
  expect(value(zero).guidance.join('\n')).not.toMatch(/macwarden revoke 0\b/);
  expect(value(zero).guidance).toContain(ROOT_KEY_0_INCONCLUSIVE);
});

it('VERIFY/RT-01 regeneration a signature mismatch on the exact bytes the registry recorded is conclusive; altered or unregistered copies are not', async () => {
  const alice = entry(oldId);
  saveRegistry([alice]);
  const mismatch = () => fake({ check: { valid: false, reason: 'signature-mismatch', message: 'x' } }).lnd;
  // The file macwarden baked and recorded: its fingerprint equals the registry's, so only a changed root key explains the mismatch.
  const genuine = await verify([alice.outPath!], mismatch());
  expect(exit(genuine)).toBe(0);
  expect(value(genuine)).toMatchObject({ status: 'rejected', rejection: 'signature-mismatch', conclusive: true, rootKeyListed: true,
    registry: { label: 'Alice', status: 'active', match: 'fingerprint' } });
  expect(value(genuine).guidance[0]).toContain('its root key was regenerated');
  expect(value(genuine).guidance.join(' ')).toContain('It can no longer be used against this node');
  // One flipped byte: the same root key ID, a different fingerprint, so it stays inconclusive.
  const bytes = Buffer.from(readFileSync(alice.outPath!));
  bytes[bytes.length - 1] ^= 0x01;
  const altered = await verify([register(bytes)], mismatch());
  expect(exit(altered)).toBe(1);
  expect(value(altered)).toMatchObject({ conclusive: false, registry: { match: 'root-key-id' } });
  expect(value(altered).guidance).toContain(SIGNATURE_MISMATCH_HOW_TO_CONCLUDE);
  // Not in the registry at all: inconclusive, with the same advice.
  saveRegistry([]);
  const unregistered = await verify([alice.outPath!], mismatch());
  expect(exit(unregistered)).toBe(1);
  expect(value(unregistered)).toMatchObject({ conclusive: false, registry: null });
  expect(value(unregistered).guidance).toContain(SIGNATURE_MISMATCH_HOW_TO_CONCLUDE);
  // A recorded fingerprint from another node does not count.
  saveRegistry([{ ...alice, nodePubkey: '03' + 'cd'.repeat(32) }]);
  expect(exit(await verify([alice.outPath!], mismatch()))).toBe(1);
});

// Audit 1.3.2: revoke --unregistered --target-file records any file's fingerprint with verified:false,
// so only a verified row's fingerprint proves the bytes genuine.
it('VERIFY/audit-1.3.2 a signature mismatch on bytes a verified:false row recorded is not conclusive', async () => {
  const alice = entry(oldId);
  const mismatch = () => fake({ check: { valid: false, reason: 'signature-mismatch', message: 'x' } }).lnd;
  saveRegistry([{ ...alice, verified: false }]);
  const unverified = await verify([alice.outPath!], mismatch());
  expect(exit(unverified)).toBe(1);
  expect(value(unverified)).toMatchObject({ rejection: 'signature-mismatch', conclusive: false, rootKeyListed: true,
    registry: { label: 'Alice', match: 'root-key-id' } });
  expect(value(unverified).guidance).toContain(SIGNATURE_MISMATCH_HOW_TO_CONCLUDE);
  saveRegistry([alice]);
  const verified = await verify([alice.outPath!], mismatch());
  expect(exit(verified)).toBe(0);
  expect(value(verified)).toMatchObject({ conclusive: true, registry: { match: 'fingerprint' } });
});

// 1.2.1: LND's two answers must agree. A rejection that says the root key ID is gone while
// ListMacaroonIDs still lists it is a contradiction, not a verdict.
it('VERIFY/contradicted a root-key-missing rejection while the root key ID is still listed is not conclusive', async () => {
  saveRegistry([]);
  const target = register(responseBytes(oldId, vector('preset-invoice-only').permissions));
  const { lnd } = fake({ ids: [0n, oldId, ownId], check: { valid: false, reason: 'root-key-missing', message: 'x' } });
  const result = await verify([target], lnd);
  expect(exit(result)).toBe(1);
  expect(value(result)).toMatchObject({ status: 'rejected', rejection: 'other', conclusive: false, rootKeyListed: true });
  expect(value(result).guidance).toContain(ROOT_KEY_MISSING_CONTRADICTED);
  expect(value(result).guidance).toContain(`To make sure: macwarden revoke ${oldId} --unregistered.`);
  expect(render(result, 'text')).toContain('status       REJECTED BY THIS CHECK ONLY (other)');
  expect(render(result, 'text')).not.toContain('no longer exists. It can no longer be used');
});
