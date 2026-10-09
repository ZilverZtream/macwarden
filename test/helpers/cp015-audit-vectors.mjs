import { readFileSync } from 'node:fs';
import { join } from 'node:path';

function uint(value) {
  let n = BigInt(value);
  const out = [];
  do { out.push(Number(n & 0x7fn) | (n > 127n ? 128 : 0)); n >>= 7n; } while (n);
  return Buffer.from(out);
}
function packet(type, data) { return Buffer.concat([uint(type), uint(data.length), data]); }
function readUint(bytes, start) {
  let value = 0n;
  for (let shift = 0n, pos = start; shift <= 63n && pos < bytes.length; shift += 7n) {
    const byte = bytes[pos++];
    value |= BigInt(byte & 127) << shift;
    if (!(byte & 128)) return { value, end: pos };
  }
  throw new Error('Audit source vector has invalid varint');
}
function packets(bytes) {
  if (bytes[0] !== 2) throw new Error('Audit source vector is not v2');
  const out = [];
  for (let pos = 1; pos < bytes.length;) {
    const start = pos;
    if (bytes[pos] === 0) { out.push({ type: 0, start, end: ++pos, data: Buffer.alloc(0) }); continue; }
    const type = readUint(bytes, pos); pos = type.end;
    const length = readUint(bytes, pos); pos = length.end;
    const end = pos + Number(length.value);
    if (end > bytes.length) throw new Error('Audit source vector packet overrun');
    out.push({ type: Number(type.value), start, end, data: bytes.subarray(pos, end) });
    pos = end;
  }
  return out;
}
function replace(bytes, entry, replacement) {
  return Buffer.concat([bytes.subarray(0, entry.start), replacement, bytes.subarray(entry.end)]);
}
const vector = (root, name) => readFileSync(join(root, 'test/vectors', `${name}.macaroon`));

// Structural protobuf probe only: the changed identifier has no LND-acceptance claim.
export function permissionTextVector(root, entity, action) {
  const base = vector(root, 'grade-signer-read');
  const identifier = packets(base).find(entry => entry.type === 2);
  if (!identifier || identifier.data[0] !== 3) throw new Error('Audit identifier is not bakery v3');
  const proto = identifier.data.subarray(1);
  const fields = [];
  for (let pos = 0; pos < proto.length;) {
    const start = pos;
    const key = readUint(proto, pos); pos = key.end;
    if ((key.value & 7n) !== 2n) throw new Error('Audit identifier has unexpected protobuf wire type');
    const length = readUint(proto, pos); pos = length.end + Number(length.value);
    if (pos > proto.length) throw new Error('Audit identifier protobuf overrun');
    if (key.value >> 3n !== 3n) fields.push(proto.subarray(start, pos));
  }
  const op = Buffer.concat([packet(10, Buffer.from(entity, 'utf8')),
    packet(18, Buffer.from(action, 'utf8'))]);
  return replace(base, identifier, packet(2,
    Buffer.concat([Buffer.from([3]), ...fields, packet(26, op)])));
}

export function auditVectors(root) {
  const time = vector(root, 'time-before');
  const timePackets = packets(time);
  const headerEnd = timePackets.findIndex(entry => entry.type === 0);
  const firstCaveat = timePackets[headerEnd + 1];
  if (firstCaveat?.type !== 2) throw new Error('Audit time vector lacks first-party caveat');
  const firstPartyLocation = Buffer.concat([time.subarray(0, firstCaveat.start),
    packet(1, Buffer.from('audit-location')), time.subarray(firstCaveat.start)]);

  const thirdParty = vector(root, 'third-party');
  const vid = packets(thirdParty).find(entry => entry.type === 4);
  if (!vid) throw new Error('Audit third-party vector lacks verification ID');
  const emptyVerificationId = replace(thirdParty, vid, packet(4, Buffer.alloc(0)));

  const signer = vector(root, 'grade-signer-read');
  const signerPackets = packets(signer);
  const location = signerPackets.find(entry => entry.type === 1);
  const identifier = signerPackets.find(entry => entry.type === 2);
  if (!location || !identifier) throw new Error('Audit signer vector lacks header fields');
  const malformedUtf8Location = replace(signer, location, packet(1, Buffer.from([0xff])));
  const entityBytes = Buffer.from(identifier.data);
  const entityOffset = entityBytes.indexOf(Buffer.from('signer'));
  if (entityOffset < 0) throw new Error('Audit signer vector lacks expected entity');
  entityBytes[entityOffset] = 0xff;
  const malformedUtf8Entity = replace(signer, identifier, packet(2, entityBytes));
  const withUnknownField = field => replace(signer, identifier,
    packet(2, Buffer.concat([identifier.data, uint((BigInt(field) << 3n) | 2n), Buffer.from([0])])));

  const ordered = vector(root, 'cp015-permission-order');
  const orderedId = packets(ordered).find(entry => entry.type === 2);
  if (!orderedId) throw new Error('Audit permission vector lacks identifier');
  const proto = orderedId.data.subarray(1);
  const fields = [];
  for (let pos = 0; pos < proto.length;) {
    const start = pos;
    const key = readUint(proto, pos); pos = key.end;
    if ((key.value & 7n) !== 2n) throw new Error('Audit permission vector has unexpected protobuf wire type');
    const length = readUint(proto, pos); pos = length.end + Number(length.value);
    if (pos > proto.length) throw new Error('Audit permission vector protobuf overrun');
    fields.push({ number: Number(key.value >> 3n), bytes: proto.subarray(start, pos) });
  }
  const ops = fields.filter(field => field.number === 3).map(field => field.bytes).reverse();
  if (ops.length < 2) throw new Error('Audit permission vector lacks distinct ops');
  const reversedProto = Buffer.concat(fields.map(field => field.number === 3 ? ops.shift() : field.bytes));
  const reversedPermissionOrder = replace(ordered, orderedId,
    packet(2, Buffer.concat([Buffer.from([3]), reversedProto])));

  return [
    { name: 'first-party-location', bytes: firstPartyLocation, audit: 'B1' },
    { name: 'empty-verification-id', bytes: emptyVerificationId, audit: 'B2' },
    { name: 'malformed-utf8-location', bytes: malformedUtf8Location, audit: 'B4' },
    { name: 'malformed-utf8-entity', bytes: malformedUtf8Entity, audit: 'B4' },
    { name: 'protobuf-max-field', bytes: withUnknownField(536870911), audit: 'B4' },
    { name: 'protobuf-over-max-field', bytes: withUnknownField(536870912), audit: 'B4' },
    { name: 'permission-order-reversed', bytes: reversedPermissionOrder, audit: 'B15' },
  ];
}
