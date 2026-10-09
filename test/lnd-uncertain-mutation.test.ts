import { existsSync } from 'node:fs';
import { relative, resolve } from 'node:path';
import { expect, it } from 'vitest';
import { run as bake } from '../src/commands/bake/index.js';
import { run as rotate } from '../src/commands/rotate.js';
import { run as revoke } from '../src/commands/revoke.js';
import { LndError, LndUncertainError } from '../src/errors.js';
import { fixture, type Fixture, oldId } from './helpers/cp038-online.js';

// An incomplete response (timeout, reset) after the request may have reached LND,
// against a definite LND error response. Only the latter proves "nothing changed".
const uncertain = (stage: string) => new LndUncertainError(4, stage, 'LND transport timeout');
const definite = (stage: string) => new LndError(5, stage, 'LND request rejected');

function failBake(f: Fixture, error: Error) {
  f.lnd.bakeMacaroon = async () => { f.lnd.calls.push('BakeMacaroon'); throw error; };
}
function failDelete(f: Fixture, error: Error, applied = false) {
  f.lnd.deleteMacaroonId = async id => {
    f.lnd.calls.push('DeleteMacaroonID');
    if (applied) f.lnd.ids = f.lnd.ids.filter(item => item !== id);
    throw error;
  };
}
function tokens(command: string): string[] {
  return [...command.matchAll(/'((?:[^']|'')*)'|(\S+)/g)].map(match => match[1] !== undefined
    ? match[1].replaceAll("''", "'") : match[2]);
}
function printed(message: string, verb: 'revoke' | 'rotate'): string[] {
  const command = new RegExp(`macwarden ${verb} [^;\\u2014]+?(?= to confirm|;|$)`).exec(message)?.[0];
  expect(command, message).toBeDefined();
  return tokens(command!.trim()).slice(2);
}
const pending = (f: Fixture, id: bigint | string, label: string) => f.rows().find(row => row.rootKeyId === String(id)
  && row.label === label && row.status === 'active' && row.verified === false && row.outPath === null && row.fingerprint === null);

it('UNCERTAIN/bake-B11 an incomplete BakeMacaroon response keeps the pending entry and exits 7 with a working recovery', async () => {
  const f = fixture(); f.save([]); failBake(f, uncertain('bake-macaroon'));
  const result = await bake(['--label', 'Bob', '--preset', 'invoice-only', '--out', f.out, ...f.flags], f.deps);
  expect(result.error).toMatchObject({ code: 7, step: 'B11' });
  expect(result.error!.message).toMatch(/outcome unknown/i);
  expect(result.error!.message).not.toMatch(/nothing changed/i);
  const id = /create root key (\d+)/.exec(result.error!.message)![1];
  expect(pending(f, id, 'Bob')).toBeDefined();
  expect(existsSync(f.out)).toBe(false); expect(existsSync(f.registry + '.lock')).toBe(false);
  // LND applied the request after the client gave up: the printed command revokes it.
  f.lnd.ids.push(BigInt(id));
  const recovered = await revoke([...printed(result.error!.message, 'revoke'), '--yes'], f.deps);
  expect(recovered.error).toBeNull();
  expect(f.lnd.ids).not.toContain(BigInt(id));
  expect(f.rows().find(row => row.rootKeyId === id)).toMatchObject({ status: 'revoked' });
});

it('UNCERTAIN/bake-B11 if LND never applied the request the same recovery closes the pending entry without a delete', async () => {
  const f = fixture(); f.save([]); failBake(f, uncertain('bake-macaroon'));
  const result = await bake(['--label', 'Bob', '--preset', 'invoice-only', '--out', f.out, ...f.flags], f.deps);
  const id = /create root key (\d+)/.exec(result.error!.message)![1];
  const recovered = await revoke([...printed(result.error!.message, 'revoke'), '--yes'], f.deps);
  expect(recovered.error).toBeNull();
  expect(f.lnd.calls).not.toContain('DeleteMacaroonID');
  expect(f.rows().find(row => row.rootKeyId === id)).toMatchObject({ status: 'revoked', revokeEvidence: 'by-id-only' });
});

it('UNCERTAIN/bake-B11 a definite LND error response still proves nothing changed', async () => {
  const f = fixture(); f.save([]); failBake(f, definite('bake-macaroon'));
  const result = await bake(['--label', 'Bob', '--preset', 'invoice-only', '--out', f.out, ...f.flags], f.deps);
  expect(result.error).toMatchObject({ code: 5, step: 'B11' });
  expect(result.error!.message).toMatch(/nothing changed/i);
  expect(f.rows()).toEqual([]);
});

it('UNCERTAIN/stage-S10 an incomplete BakeMacaroon response keeps the pending replacement and the old credential', async () => {
  const f = fixture(); failBake(f, uncertain('bake-macaroon'));
  const result = await rotate(['Alice', '--out', f.out, ...f.flags], f.deps);
  expect(result.error).toMatchObject({ code: 7, step: 'S10' });
  expect(result.error!.message).toMatch(/outcome unknown/i);
  expect(result.error!.message).toMatch(/old credential unchanged/i);
  const id = /create root key (\d+)/.exec(result.error!.message)![1];
  expect(pending(f, id, 'Alice')).toMatchObject({ replaces: String(oldId) });
  expect(f.rows().find(row => row.rootKeyId === String(oldId))).toMatchObject({ status: 'active', verified: true });
  expect(f.lnd.ids).toContain(oldId); expect(existsSync(f.registry + '.lock')).toBe(false);
  expect(printed(result.error!.message, 'revoke')[0]).toBe(id);
});

it('UNCERTAIN/stage-S10 a definite LND error response still removes the pending replacement', async () => {
  const f = fixture(); failBake(f, definite('bake-macaroon'));
  const result = await rotate(['Alice', '--out', f.out, ...f.flags], f.deps);
  expect(result.error).toMatchObject({ code: 5, step: 'S10' });
  expect(f.rows()).toEqual([expect.objectContaining({ rootKeyId: String(oldId), status: 'active' })]);
});

it('UNCERTAIN/revoke-V11 an incomplete DeleteMacaroonID response with the ID still listed exits 7, not "still valid"', async () => {
  const f = fixture(); failDelete(f, uncertain('delete-macaroon-id'));
  const result = await revoke(['Alice', '--yes', ...f.flags], f.deps);
  expect(result.error).toMatchObject({ code: 7, step: 'V11' });
  expect(result.error!.message).toMatch(/outcome unknown/i);
  expect(result.error!.message).not.toMatch(/still valid/i);
  expect(f.rows()).toEqual([expect.objectContaining({ rootKeyId: String(oldId), status: 'active' })]);
  // The deletion landed later; the printed rerun repairs the record without another delete.
  f.lnd.ids = f.lnd.ids.filter(id => id !== oldId); f.lnd.calls.length = 0;
  f.lnd.deleteMacaroonId = async () => { throw new Error('no second delete expected'); };
  const rerun = await revoke([...printed(result.error!.message, 'revoke'), '--yes'], f.deps);
  expect(rerun.error).toBeNull();
  expect(f.rows()[0]).toMatchObject({ status: 'revoked' });
});

it('UNCERTAIN/revoke-V11 an incomplete response after the deletion applied completes the revocation', async () => {
  const f = fixture(); failDelete(f, uncertain('delete-macaroon-id'), true);
  const result = await revoke(['Alice', '--yes', ...f.flags], f.deps);
  expect(result.error).toBeNull();
  expect(f.rows()[0]).toMatchObject({ rootKeyId: String(oldId), status: 'revoked' });
});

it('UNCERTAIN/revoke-V11 a definite LND error response with the ID listed still reports the credential valid', async () => {
  const f = fixture(); failDelete(f, definite('delete-macaroon-id'));
  const result = await revoke(['Alice', '--yes', ...f.flags], f.deps);
  expect(result.error).toMatchObject({ code: 5, step: 'V11' });
  expect(result.error!.message).toMatch(/still valid/i);
});

it('UNCERTAIN/finish-F10 an incomplete DeleteMacaroonID response with the old ID listed exits 7 with an executable rerun', async () => {
  const f = fixture(); f.save([f.old, f.next]); failDelete(f, uncertain('delete-macaroon-id'));
  const result = await rotate(['Alice', '--finish', '--yes', ...f.flags], f.deps);
  expect(result.error).toMatchObject({ code: 7, step: 'F10' });
  expect(result.error!.message).toMatch(/outcome unknown/i);
  expect(result.error!.message).not.toMatch(/still valid/i);
  expect(f.rows().find(row => row.rootKeyId === String(oldId))).toMatchObject({ status: 'active' });
  const args = printed(result.error!.message, 'rotate');
  expect(args.slice(0, 2)).toEqual(['Alice', '--finish']);
  f.lnd.ids = f.lnd.ids.filter(id => id !== oldId);
  f.lnd.deleteMacaroonId = async () => { throw new Error('no second delete expected'); };
  const rerun = await rotate([...args, '--yes'], f.deps);
  expect(rerun.error).toBeNull();
  expect(f.rows().find(row => row.rootKeyId === String(oldId))).toMatchObject({ status: 'revoked' });
});

it('UNCERTAIN/finish-F10 a definite LND error response with the old ID listed still reports it valid', async () => {
  const f = fixture(); f.save([f.old, f.next]); failDelete(f, definite('delete-macaroon-id'));
  const result = await rotate(['Alice', '--finish', '--yes', ...f.flags], f.deps);
  expect(result.error).toMatchObject({ code: 5, step: 'F10' });
  expect(result.error!.message).toMatch(/still valid/i);
});

it('UNCERTAIN/recovery-paths printed recovery commands carry absolute registry, certificate and macaroon paths', async () => {
  const f = fixture(); f.save([]); failBake(f, uncertain('bake-macaroon'));
  const flags = [...f.flags];
  for (const flag of ['--registry', '--tls-cert', '--macaroon']) {
    const index = flags.indexOf(flag) + 1;
    flags[index] = relative(process.cwd(), flags[index]);
    expect(flags[index]).not.toBe(resolve(flags[index]));
  }
  const result = await bake(['--label', 'Bob', '--preset', 'invoice-only', '--out', f.out, ...flags], f.deps);
  const args = printed(result.error!.message, 'revoke');
  for (const flag of ['--registry', '--tls-cert', '--macaroon'])
    expect(args[args.indexOf(flag) + 1]).toBe(resolve(flags[flags.indexOf(flag) + 1]));
});
