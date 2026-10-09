// Synthetic macaroons and time-before strings judged by the LND v0.21.4 oracle
// (./oracle). Shared by generate.mjs, which records the oracle's verdicts, and by the
// tests, which rebuild the same bytes (checked against the recorded SHA-256) and compare
// macwarden's decoding with those verdicts. The root key is a throwaway test value.
import { createHmac } from 'node:crypto';

export const ROOT_KEY = 'macwarden-fuzz-root-key-0123456';
export const NOW = '2026-10-08T12:00:00Z';

function varint(n, pad = 0) {
  const out = [];
  let v = BigInt(n);
  do { let b = Number(v & 0x7fn); v >>= 7n; if (v || pad > 0) b |= 0x80; out.push(b); } while (v);
  if (pad > 0) { for (let i = 0; i < pad - 1; i++) out.push(0x80); out.push(0x00); }
  return Buffer.from(out);
}
const tag = (field, wire, pad = 0) => varint((BigInt(field) << 3n) | BigInt(wire), pad);
const bytesField = (field, value) => Buffer.concat([tag(field, 2), varint(value.length), Buffer.from(value)]);
const op = (entity, actions) => bytesField(3, Buffer.concat([bytesField(1, Buffer.from(entity)),
  ...actions.map(action => bytesField(2, Buffer.from(action)))]));
function identifier({ storageId = '0', ops = [['info', ['read']]], extra = [] } = {}) {
  return Buffer.concat([Buffer.from([3]), bytesField(1, Buffer.alloc(16, 7)), bytesField(2, Buffer.from(storageId)),
    ...ops.map(([entity, actions]) => op(entity, actions)), ...extra]);
}
const hmac = (key, data) => createHmac('sha256', key).update(data).digest();
function signature(id, caveats) {
  let sig = hmac(hmac('macaroons-key-generator', ROOT_KEY), id);
  for (const c of caveats) sig = c.vid?.length ? hmac(sig, Buffer.concat([hmac(sig, c.vid), hmac(sig, c.cid)])) : hmac(sig, c.cid);
  return sig;
}
const packet = (kind, value, enc) => Buffer.concat([varint(kind, enc.kindPad ?? 0), varint(value.length, enc.lenPad ?? 0), value]);
function serialize({ location = Buffer.from('lnd'), id, caveats = [], enc = {}, trailing = Buffer.alloc(0) }) {
  const eos = enc.eos ?? Buffer.from([0]);
  const parts = [Buffer.from([2])];
  if (location !== null) parts.push(packet(1, location, enc));
  parts.push(packet(2, id, enc), eos);
  for (const c of caveats) {
    if (c.loc != null) parts.push(packet(1, c.loc, enc));
    parts.push(packet(2, c.cid, enc));
    if (c.vid != null) parts.push(packet(4, c.vid, enc));
    parts.push(eos);
  }
  parts.push(eos, packet(6, signature(id, caveats), enc), trailing);
  return Buffer.concat(parts);
}

const ADMIN = [['macaroon', ['generate', 'read', 'write']], ['onchain', ['read', 'write']], ['offchain', ['read', 'write']], ['info', ['read']]];
const APP = { storageId: '1234', ops: [['onchain', ['read', 'write']], ['offchain', ['read', 'write']], ['macaroon', ['generate']]] };
const firstParty = [{ cid: Buffer.from('time-before 2030-01-01T00:00:00Z') }, { cid: Buffer.from('ipaddr 127.0.0.1') }];
const thirdParty = { cid: Buffer.from('third-party-caveat-id'), vid: Buffer.alloc(48, 9), loc: Buffer.from('https://discharge.example') };
const nest = (depth, field = 10) => Buffer.concat([...Array(depth).fill(tag(field, 3)), ...Array(depth).fill(tag(field, 4))]);
const ten = Buffer.from([0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00]);

export function m1() {
  const id = identifier(APP);
  const base = { id, caveats: firstParty };
  const withThirdParty = { id, caveats: [...firstParty, thirdParty] };
  const canonical = serialize(base);
  const idAt = canonical.indexOf(Buffer.from([0x02, id.length]), 4);
  return {
    canonical,
    'identifier length non-minimal': Buffer.concat([canonical.subarray(0, idAt + 1), Buffer.from([id.length | 0x80, 0x00]),
      canonical.subarray(idAt + 2)]),
    'all lengths non-minimal': serialize({ ...base, enc: { lenPad: 1 } }),
    'all lengths padded to 10 bytes': serialize({ ...base, enc: { lenPad: 9 } }),
    'all kinds non-minimal': serialize({ ...base, enc: { kindPad: 1 } }),
    'all kinds padded to 10 bytes': serialize({ ...base, enc: { kindPad: 9 } }),
    'end-of-section as 0x80 0x00': serialize({ ...base, enc: { eos: Buffer.from([0x80, 0x00]) } }),
    'end-of-section padded to 10 bytes': serialize({ ...base, enc: { eos: ten } }),
    'every varint non-minimal': serialize({ ...base, enc: { lenPad: 2, kindPad: 3, eos: Buffer.from([0x80, 0x80, 0x00]) } }),
    'every varint non-minimal, no location, trailing bytes': serialize({ ...base, location: null, trailing: Buffer.from('junk'),
      enc: { lenPad: 1, kindPad: 1, eos: Buffer.from([0x80, 0x00]) } }),
    'third-party caveat, canonical': serialize(withThirdParty),
    'third-party caveat, every varint non-minimal': serialize({ ...withThirdParty,
      enc: { lenPad: 1, kindPad: 2, eos: Buffer.from([0x80, 0x00]) } }),
    'empty location packet in header': serialize({ ...base, location: Buffer.alloc(0) }),
    'empty location and verification ID packets in a first-party caveat': serialize({ id,
      caveats: [{ cid: firstParty[0].cid, loc: Buffer.alloc(0), vid: Buffer.alloc(0) }] }),
    'kind 11 bytes (rejected)': serialize({ ...base, enc: { kindPad: 10 } }),
    'length tenth byte 2 (rejected)': Buffer.concat([Buffer.from([2, 1, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02])]),
    'length above 0x7fffffff (rejected)': Buffer.concat([Buffer.from([2, 1]), varint(0x80000000), Buffer.from('lnd')]),
    'end-of-section 11 bytes (rejected)': serialize({ ...base, enc: { eos: Buffer.concat([Buffer.from([0x80]), ten]) } }),
    'kind 0x80 0x01 is 128, not end-of-section (rejected)': serialize({ ...base, enc: { eos: Buffer.from([0x80, 0x01]) } }),
  };
}

export function m2() {
  const admin = (extra, options = {}) => serialize({ id: identifier({ ops: ADMIN, extra, ...options }) });
  return {
    'extra op with empty entity': admin([op('', ['read'])]),
    'extra op with no actions': admin([op('info', [])]),
    'extra empty op': admin([bytesField(3, Buffer.alloc(0))]),
    'first op with empty entity': serialize({ id: identifier({ ops: [['', ['read']], ...ADMIN] }) }),
    'first op with no actions (rejected)': serialize({ id: identifier({ ops: [['info', []], ...ADMIN] }) }),
    'first op empty (rejected)': serialize({ id: Buffer.concat([Buffer.from([3]), bytesField(2, Buffer.from('0')),
      bytesField(3, Buffer.alloc(0)), ...ADMIN.map(([e, a]) => op(e, a))]) }),
    'unknown group field': admin([nest(1)]),
    'unknown group field with members': admin([Buffer.concat([tag(10, 3), bytesField(3, Buffer.from('zz')), tag(1, 1),
      Buffer.alloc(8), tag(2 ** 30, 0), varint(1), tag(10, 4)])]),
    'ops field sent as a group': admin([Buffer.concat([tag(3, 3), bytesField(1, Buffer.from('macaroon')), tag(3, 4)])]),
    'group inside an op': admin([bytesField(3, Buffer.concat([bytesField(1, Buffer.from('onchain')), nest(2, 9),
      bytesField(2, Buffer.from('write'))]))]),
    'groups nested 10001 deep': admin([nest(10001)]),
    'groups nested 10002 deep (rejected)': admin([nest(10002)]),
    'unterminated group (rejected)': admin([tag(10, 3)]),
    'mismatched end group (rejected)': admin([Buffer.concat([tag(10, 3), tag(11, 4)])]),
    'lone end group (rejected)': admin([tag(10, 4)]),
    'group member field 2^31 (rejected)': admin([Buffer.concat([tag(10, 3), varint(2n ** 31n << 3n), varint(1), tag(10, 4)])]),
    'non-minimal protobuf tag': admin([Buffer.concat([tag(3, 2, 1), varint(0)])]),
    'protobuf tag padded to 10 bytes': admin([Buffer.concat([tag(3, 2, 9), varint(0)])]),
    'extra op with 17-byte entity': admin([op('x'.repeat(17), ['read'])]),
    'extra op with 300-byte action': admin([op('info', ['r'.repeat(300)])]),
    '257 ops': admin(Array.from({ length: 257 }, () => op('info', ['read']))),
    '600 actions in one op': admin([op('info', Array.from({ length: 600 }, () => 'read'))]),
    '2000 ops (exceeds 1,024 permissions)': admin(Array.from({ length: 2000 }, () => op('info', ['read']))),
    'admin after 1,024 permissions': serialize({ id: identifier({ ops: [['info', Array.from({ length: 1024 }, () => 'read')],
      ['macaroon', ['generate']]] }) }),
    'admin after 64 KiB of permission text': serialize({ id: identifier({ ops: [['info', ['r'.repeat(65_530)]],
      ['offchain', ['write']]] }) }),
    'invalid UTF-8 in an op beyond the bounds (rejected)': serialize({ id: identifier({
      ops: [['info', Array.from({ length: 1100 }, () => 'read')]],
      extra: [bytesField(3, Buffer.concat([bytesField(1, Buffer.from([0xc3, 0x28])), bytesField(2, Buffer.from('read'))]))] }) }),
    '4097 caveats': serialize({ id: identifier({ ops: ADMIN }),
      caveats: Array.from({ length: 4097 }, () => ({ cid: Buffer.from('time-before 2030-01-01T00:00:00Z') })) }),
  };
}

export const TIMES = [
  '2027-10-08T1:00:00Z', '2026-10-08T1:00:00Z', '2026-10-08T9:59:59.5Z', '2027-10-08T23:00:00+24:00',
  '2027-10-08T23:00:00-24:00', '2027-10-08T1:00:00+24:00', '2027-10-08T00:00:00+24:59', '2027-10-08T00:00:00+25:00',
  '2027-10-08T00:00:00Z', '2027-10-08T00:00:00.123456789Z', '2027-10-08T00:00:00,5+01:00', '2027-10-08T24:00:00Z',
  '2027-10-08T001:00:00Z', '2027-10-08T1:0:00Z', '2027-10-08T1:00:0Z', '2027-10-08T:00:00Z', '2027-10-08T01:00:00+1:00',
  '2027-10-08T01:00:00+01:0', '2027-10-08T01:00:00+0100', '2027-02-29T01:00:00Z', '2028-02-29T1:00:00Z',
  '2027-10-08T9:00:00-23:59', '2027-10-08T01:00:00+24:00', '2027-10-08T01:00:00-24:00', '0000-01-01T0:00:00+24:00',
  '9999-12-31T23:59:59-24:00', '2027-10-08T1:00:00.5+24:00', '2027-10-08T1:00:00z', '2027-10-08t1:00:00Z',
  '2027-10-08T01:00:00+23:60', '2027-10-08T01:00:00+00:60', '2027-10-08T01:00:00+00:61', '2027-10-08T01:00:00+24:60',
  '2027-10-08T01:00:00-24:59', '2027-10-08T01:60:00Z', '2027-10-08T01:00:60Z', '2027-10-08T1:00:00.Z', '2027-10-08T1:00:00.1234567891Z',
  '2027-10-08T1:00:00,5Z', '2027-10-08T 1:00:00Z', '2027-10-08T+1:00:00Z', '0000-01-01T00:00:00Z', '2027-10-08T9:5:00Z',
  '2027-10-08T09:00:00+24:00', '2026-10-08T9:00:00-03:00', '2026-10-08T11:59:59.999999999+00:00', '2027-10-08T1:00:00+00:00',
];
