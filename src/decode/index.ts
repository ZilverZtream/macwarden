import { revealSecret } from '../secret-capability.js';
import { createECDH, createHash, createHmac } from 'node:crypto';
import { Secret } from '../secret.js';
import { DecodeError, UsageError, type DecodeStage, type NwcStage } from '../errors.js';

export { DecodeError } from '../errors.js';
export type { DecodeStage } from '../errors.js';

export type Caveat = {
  type: 'time-before' | 'ipaddr' | 'iprange' | 'lnd-custom' | 'third-party' | 'unknown';
  value: string;
  expired?: boolean;
};
export type MacaroonFacts = {
  location: string | null;
  rootKeyId: bigint;
  permissions: string[];
  caveats: Caveat[];
  fingerprint: string;
  warnings: string[];
};

type Section = { location: Buffer | null; identifier: Buffer; vid: Buffer | null };
type Parsed = { header: Section; caveats: Section[]; signature: Buffer };
const canonicalSource = Symbol("canonical macaroon");
const MAX_UINT64 = (1n << 64n) - 1n;
const MAX_PROTO_FIELD = 536_870_911n;
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function fail(stage: DecodeStage): never {
  throw new DecodeError(stage);
}

function varint(data: Buffer, start: number, end: number, stage: DecodeStage): [bigint, number] {
  let value = 0n;
  for (let i = 0; i < 10; i++) {
    const offset = start + i;
    if (offset >= end) return fail(stage);
    const byte = data[offset];
    if (i === 9 && byte > 1) return fail(stage);
    value |= BigInt(byte & 0x7f) << BigInt(i * 7);
    if ((byte & 0x80) === 0) return [value, offset + 1];
  }
  return fail(stage);
}

export type PacketRange = { kind: number; start: number; end: number };
export type SectionRange = { location: PacketRange | null; identifier: PacketRange; vid: PacketRange | null; end: number };

// go-macaroon v2.0.0 (LND v0.21.4) reads packet kinds and lengths with
// binary.Uvarint: up to 10 bytes, non-minimal encodings accepted, values above
// 0x7fffffff refused. Anyone holding a macaroon can re-frame it this way without
// the root key (the signature covers the identifier and caveat bytes, not the
// framing), so the decoder accepts exactly what LND accepts.
const MAX_PACKET_VALUE = 0x7fffffff;

function packetVarint(data: Uint8Array, start: number): [number, number] | null {
  let value = 0;
  for (let i = 0; i < 10; i++) {
    const offset = start + i;
    if (offset >= data.length) return null;
    const byte = data[offset];
    if (i === 9 && byte > 1) return null;
    const bits = byte & 0x7f;
    if (bits !== 0) {
      if (i >= 5) return null;
      value += bits * 2 ** (7 * i);
      if (value > MAX_PACKET_VALUE) return null;
    }
    if ((byte & 0x80) === 0) return [value, offset + 1];
  }
  return null;
}

/** End offset of an end-of-section marker at `start` (any varint encoding of 0), else null. */
export function macaroonEosEnd(data: Uint8Array, start: number): number | null {
  const item = packetVarint(data, start);
  return item !== null && item[0] === 0 ? item[1] : null;
}

// Shared structural parser: decoder and bounded recognition use identical
// packet ordering, varint, end-of-section and caveat-location rules.
export function macaroonPacketRange(data: Buffer, start: number): PacketRange | null {
  const kindItem = packetVarint(data, start);
  if (kindItem === null || ![1, 2, 4, 6].includes(kindItem[0])) return null;
  const lengthItem = packetVarint(data, kindItem[1]);
  if (lengthItem === null) return null;
  const [length, afterLength] = lengthItem;
  if (length > data.length - afterLength) return null;
  return { kind: kindItem[0], start: afterLength, end: afterLength + length };
}

export function macaroonSectionRange(data: Buffer, start: number, header: boolean): SectionRange | null {
  let pos = start;
  let lastKind = 0;
  let location: PacketRange | null = null;
  let identifier: PacketRange | null = null;
  let vid: PacketRange | null = null;
  let end: number | null = null;
  while (pos < data.length && (end = macaroonEosEnd(data, pos)) === null) {
    const item = macaroonPacketRange(data, pos);
    if (!item || item.kind <= lastKind || ![1, 2, 4].includes(item.kind) || header && item.kind === 4) return null;
    if (item.kind === 1) location = item;
    if (item.kind === 2) identifier = item;
    if (item.kind === 4) vid = item;
    lastKind = item.kind;
    pos = item.end;
  }
  if (end === null || identifier === null || !header && location && location.end > location.start && vid === null) return null;
  return { location, identifier, vid, end };
}

function packet(data: Buffer, start: number): [number, Buffer, number] {
  const item = macaroonPacketRange(data, start);
  if (!item) return fail('packet');
  return [item.kind, data.subarray(item.start, item.end), item.end];
}

function section(data: Buffer, start: number, header: boolean): [Section, number] {
  const item = macaroonSectionRange(data, start, header);
  if (!item) return fail('packet');
  return [{ location: item.location ? data.subarray(item.location.start, item.location.end) : null,
    identifier: data.subarray(item.identifier.start, item.identifier.end),
    vid: item.vid ? data.subarray(item.vid.start, item.vid.end) : null }, item.end];
}

// Group nesting LND's protobuf decoder accepts (protowire's DefaultRecursionLimit of 10,000
// lets a group hold 10,000 nested groups). Deeper nesting is refused there and here.
const MAX_GROUP_DEPTH = 10_001;
const MAX_GROUP_FIELD = 0x7fffffffn;

function skipValue(data: Buffer, pos: number, wire: number): number {
  switch (wire) {
    case 0: return varint(data, pos, data.length, 'identifier-proto')[1];
    case 1: return data.length - pos < 8 ? fail('identifier-proto') : pos + 8;
    case 2: {
      const [length, afterLength] = varint(data, pos, data.length, 'identifier-proto');
      if (length > BigInt(data.length - afterLength)) return fail('identifier-proto');
      return afterLength + Number(length);
    }
    case 5: return data.length - pos < 4 ? fail('identifier-proto') : pos + 4;
    default: return fail('identifier-proto');
  }
}

// An unknown group (wire type 3) is skipped as protowire.ConsumeFieldValue skips it: every
// member is consumed, nested groups must close with their own field number, and members may
// use field numbers up to 2^31-1. Iterative, with only the open field numbers kept.
function skipGroup(data: Buffer, pos: number, field: bigint): number {
  const open: bigint[] = [field];
  while (open.length > 0) {
    const [tag, afterTag] = varint(data, pos, data.length, 'identifier-proto');
    const member = tag >> 3n;
    const wire = Number(tag & 7n);
    if (member === 0n || member > MAX_GROUP_FIELD) return fail('identifier-proto');
    pos = afterTag;
    if (wire === 3) {
      if (open.length >= MAX_GROUP_DEPTH) return fail('identifier-proto');
      open.push(member);
    } else if (wire === 4) {
      if (open.pop() !== member) return fail('identifier-proto');
    } else {
      pos = skipValue(data, pos, wire);
    }
  }
  return pos;
}

// The protobuf wire format as LND's decoder (golang/protobuf v1.5.4 over protobuf-go) reads it:
// varints up to 10 bytes (non-minimal accepted), field numbers 1 to 2^29-1, wire types 0, 1,
// 2, 5 and groups (3 ... 4); a lone end-group or wire types 6 and 7 are refused.
function protobuf(data: Buffer, visit: (field: number, wire: number, value: Buffer | null) => void): void {
  let pos = 0;
  while (pos < data.length) {
    const [tag, afterTag] = varint(data, pos, data.length, 'identifier-proto');
    const field = tag >> 3n;
    const wire = Number(tag & 7n);
    if (field === 0n || field > MAX_PROTO_FIELD) return fail('identifier-proto');
    let value: Buffer | null = null;
    if (wire === 2) {
      const [length, afterLength] = varint(data, afterTag, data.length, 'identifier-proto');
      if (length > BigInt(data.length - afterLength)) return fail('identifier-proto');
      pos = afterLength + Number(length);
      value = data.subarray(afterLength, pos);
    } else {
      pos = wire === 3 ? skipGroup(data, afterTag, field) : skipValue(data, afterTag, wire);
    }
    visit(Number(field), wire, value);
  }
}

/** A proto3 string field: LND refuses the whole identifier when one is not valid UTF-8. */
function checkedString(value: Buffer): void {
  try { utf8.decode(value); } catch { fail('identifier-proto'); }
}

// Bounds on what one identifier may expand to. Permissions are entity x action products, so a
// small identifier could otherwise decode to hundreds of megabytes. LND v0.21.4 has 164 RPC
// methods (longest URI 49 bytes) across 19 entities whose longest name is 8 bytes, so a real
// macaroon carries at most about 200 permissions. The entity is repeated in every permission it
// applies to; leaving out entities over 16 bytes (and actions over 256 bytes) bounds the
// expansion to about 6 bytes of permission text per identifier byte, and the totals bound it
// absolutely. Exceeding a bound never refuses the macaroon (LND honours it): what fits is
// decoded, the rest is left out, and the warning identifier-exceeds-bounds makes the grade fail
// closed.
const IDENTIFIER_BOUNDS = { permissions: 1024, permissionBytes: 65_536, entityBytes: 16, actionBytes: 256 } as const;
/** Caveats kept per macaroon; LND adds a handful. Further caveats are parsed and counted, not kept. */
const MAX_CAVEATS = 4096;

type IdentifierFacts = { rootKeyId: bigint; permissions: string[]; exceedsBounds: boolean };

function identifier(data: Buffer): IdentifierFacts {
  if (data[0] !== 3) return fail('identifier-version');
  let storageId: Buffer | null = null;
  const permissions: string[] = [];
  let operations = 0;
  let permissionBytes = 0;
  let exceedsBounds = false;
  protobuf(data.subarray(1), (field, wire, value) => {
    if (wire !== 2 || value === null) return;
    if (field === 2) storageId = value;
    if (field !== 3) return;
    // Bakery expands every op's actions in order (an empty entity included) and requires only
    // that the first op has an action. The entity is a proto3 string: the last one wins.
    const first = operations++ === 0;
    let entity: Buffer = Buffer.alloc(0);
    let actions = 0;
    protobuf(value, (opField, opWire, opValue) => {
      if (opWire !== 2 || opValue === null || (opField !== 1 && opField !== 2)) return;
      checkedString(opValue);
      if (opField === 1) entity = opValue;
      else actions++;
    });
    if (first && actions === 0) return fail('identifier-proto');
    if (actions === 0 || exceedsBounds) return;
    if (entity.length > IDENTIFIER_BOUNDS.entityBytes) { exceedsBounds = true; return; }
    const entityText = entity.toString('utf8');
    protobuf(value, (opField, opWire, action) => {
      if (opField !== 2 || opWire !== 2 || action === null || exceedsBounds) return;
      const size = entity.length + 1 + action.length;
      // Checked before building any string, so the expansion itself is bounded.
      if (action.length > IDENTIFIER_BOUNDS.actionBytes || permissions.length >= IDENTIFIER_BOUNDS.permissions
        || permissionBytes + size > IDENTIFIER_BOUNDS.permissionBytes) { exceedsBounds = true; return; }
      permissionBytes += size;
      permissions.push(`${entityText}:${action.toString('utf8')}`);
    });
  });
  if (storageId === null) return fail('identifier-root-key-id');
  const storageBytes = storageId as Buffer;
  if (storageBytes.length === 0 || storageBytes.length > 20 || storageBytes.some(byte => byte < 0x30 || byte > 0x39)) {
    return fail('identifier-root-key-id');
  }
  const decimal = storageBytes.toString('ascii');
  if (!/^(0|[1-9][0-9]*)$/.test(decimal)) return fail('identifier-root-key-id');
  const rootKeyId = BigInt(decimal);
  if (rootKeyId > MAX_UINT64) return fail('identifier-root-key-id');
  return { rootKeyId, permissions, exceedsBounds };
}

function caveat(sectionValue: Section, warnings: string[]): Caveat {
  if (sectionValue.vid !== null && sectionValue.vid.length > 0) {
    return { type: 'third-party', value: sectionValue.location?.toString('utf8') ?? '' };
  }
  const condition = sectionValue.identifier.toString('utf8');
  for (const type of ['time-before', 'ipaddr', 'iprange', 'lnd-custom'] as const) {
    if (!condition.startsWith(`${type} `)) continue;
    const value = condition.slice(type.length + 1);
    if (type === 'time-before' && parseTimeBefore(value) === undefined) warnings.push('bad-time-before');
    return { type, value };
  }
  return { type: 'unknown', value: condition };
}

/** Days from 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's days_from_civil). */
function daysFromCivil(year: number, month: number, day: number): number {
  const y = month <= 2 ? year - 1 : year;
  const era = Math.floor(y / 400);
  const yearOfEra = y - era * 400;
  const dayOfYear = Math.floor((153 * (month + (month > 2 ? -3 : 9)) + 2) / 5) + day - 1;
  return era * 146_097 + yearOfEra * 365 + Math.floor(yearOfEra / 4) - Math.floor(yearOfEra / 100) + dayOfYear - 719_468;
}

/**
 * The instant (Unix nanoseconds) LND enforces for a time-before value. Bakery checks it with Go's
 * time.Parse(time.RFC3339Nano), whose general parser (the fallback after the strict RFC 3339
 * path) accepts a one- or two-digit hour, a comma or a period before any number of fraction
 * digits (nanoseconds kept), and a zone offset of up to 24 hours and 60 minutes.
 */
export function parseTimeBefore(value: string): bigint | undefined {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{1,2}):(\d{2}):(\d{2})(?:[.,](\d+))?(Z|([+-])(\d{2}):(\d{2}))$/.exec(value);
  if (!match) return undefined;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fraction, zone, sign, offsetHourText, offsetMinuteText] = match;
  const year = Number(yearText), month = Number(monthText), day = Number(dayText);
  const hour = Number(hourText), minute = Number(minuteText), second = Number(secondText);
  const offsetHour = zone === 'Z' ? 0 : Number(offsetHourText), offsetMinute = zone === 'Z' ? 0 : Number(offsetMinuteText);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth[month - 1]
    || hour > 23 || minute > 59 || second > 59 || offsetHour > 24 || offsetMinute > 60) return undefined;
  const offset = (sign === '-' ? -1 : 1) * (offsetHour * 3600 + offsetMinute * 60);
  const seconds = daysFromCivil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset;
  return BigInt(seconds) * 1_000_000_000n + BigInt((fraction ?? '').slice(0, 9).padEnd(9, '0'));
}

function varintSize(value: number): number {
  let size = 1;
  while (value >= 128) { value = Math.floor(value / 128); size++; }
  return size;
}

const packetSize = (kind: number, value: Buffer): number => varintSize(kind) + varintSize(value.length) + value.length;

/** Size of a section as go-macaroon's MarshalBinary writes it: empty location and verification ID packets are omitted. */
function canonicalSectionSize(value: Section): number {
  return (value.location?.length ? packetSize(1, value.location) : 0) + packetSize(2, value.identifier)
    + (value.vid?.length ? packetSize(4, value.vid) : 0) + 1;
}

function parsedMacaroon(data: Buffer, onCaveat?: (value: Section) => void):
  { parsed: Parsed; end: number; canonicalLength: number; omittedCaveats: number } {
  if (data[0] !== 2) {
    if (data.subarray(0, 3).toString('ascii') === '001') {
      throw new DecodeError('v2-header', 'macaroon v1 format is not supported');
    }
    return fail('v2-header');
  }
  const [header, afterHeader] = section(data, 1, true);
  let canonicalLength = 1 + canonicalSectionSize(header);
  const caveats: Section[] = [];
  let omittedCaveats = 0;
  let pos = afterHeader;
  for (;;) {
    if (pos >= data.length) return fail('packet');
    const eos = macaroonEosEnd(data, pos);
    if (eos !== null) { pos = eos; break; }
    const [next, after] = section(data, pos, false);
    if (caveats.length < MAX_CAVEATS) caveats.push(next); else omittedCaveats++;
    onCaveat?.(next);
    canonicalLength += canonicalSectionSize(next);
    pos = after;
  }
  if (pos >= data.length) return fail('packet');
  const [kind, signature, end] = packet(data, pos);
  if (kind !== 6 || signature.length !== 32) return fail('packet');
  canonicalLength += 1 + packetSize(6, signature);
  return { parsed: { header, caveats, signature }, end, canonicalLength, omittedCaveats };
}

/**
 * The canonical public identity of a fully valid offline macaroon: the bytes go-macaroon's
 * MarshalBinary writes for it (minimal varints, one-byte end-of-section markers, no empty
 * location or verification ID packets). Every macaroon LND or macwarden writes is already in
 * this form: `length` is then the length of that prefix and `reencoded` is null. A re-framed
 * copy of the same credential (which LND accepts) is re-encoded, so both share one fingerprint.
 * Trailing bytes are never part of it. Generic Secret containers holding anything else get null
 * and keep hashing their own bytes.
 */
export function canonicalMacaroonForm(data: Buffer, checkIdentifier: (value: Buffer) => unknown = identifier):
  { length: number; reencoded: Buffer | null } | null {
  try {
    const { parsed, end, canonicalLength } = parsedMacaroon(data);
    checkIdentifier(parsed.header.identifier);
    if (canonicalLength === end) return { length: end, reencoded: null };
    // Any non-canonical framing only adds bytes, so equal lengths mean equal bytes.
    const marshalled = (value: Section): Buffer[] => encodeSection({ identifier: value.identifier,
      location: value.location?.length ? value.location : null, vid: value.vid?.length ? value.vid : null });
    const pieces: Buffer[] = [Buffer.from([2]), ...marshalled(parsed.header)];
    parsedMacaroon(data, value => pieces.push(...marshalled(value)));
    pieces.push(Buffer.from([0]), encodePacket(6, parsed.signature));
    const reencoded = Buffer.concat(pieces);
    return { length: reencoded.length, reencoded };
  } catch { return null; }
}

export function decodeMacaroon(mac: Secret): MacaroonFacts {
  const data = revealSecret(mac);
  const { parsed: { header, caveats }, end, omittedCaveats } = parsedMacaroon(data);
  const { rootKeyId, permissions, exceedsBounds } = identifier(header.identifier);
  const warnings: string[] = [];
  // Fail closed: what could not be kept is named, and the grade treats it as unassessed.
  if (exceedsBounds) warnings.push('identifier-exceeds-bounds');
  if (omittedCaveats > 0) warnings.push('caveats-exceed-bounds');
  const decodedCaveats = caveats.map(value => caveat(value, warnings));
  if (end < data.length) warnings.push('trailing-bytes');
  // One fingerprint definition: the canonical container (go-macaroon's MarshalBinary form,
  // which is the input up to its signature for every macaroon LND writes) hashes its own bytes.
  const form = canonicalMacaroonForm(data);
  const canonical = new Secret(form?.reencoded ?? data.subarray(0, end));
  const fingerprint = canonical.fingerprint;
  const facts: MacaroonFacts = {
    location: header.location?.toString('utf8') ?? null,
    rootKeyId, permissions, caveats: decodedCaveats, fingerprint,
    warnings: [...new Set(warnings)],
  };
  Object.defineProperty(facts, canonicalSource, { value: canonical, enumerable: true });
  return facts;
}

/**
 * Stable public identity of a baked macaroon: SHA-256 of its identifier packet (version,
 * nonce, root key ID, operations). Client-side caveats such as lncli's per-call timeout
 * change the fingerprint but never the identifier, so usage is attributed per baked
 * credential. The identifier holds no secret: the signature is the credential.
 */
export function macaroonId(mac: Secret): { rootKeyId: bigint; id: string } {
  const { parsed: { header } } = parsedMacaroon(revealSecret(mac));
  const { rootKeyId } = identifier(header.identifier);
  return { rootKeyId, id: `id:${createHash('sha256').update(header.identifier).digest('hex').slice(0, 16)}` };
}

function encodeVarint(value: number): Buffer {
  const bytes: number[] = [];
  do {
    let digit = value % 128;
    value = Math.floor(value / 128);
    if (value) digit |= 0x80;
    bytes.push(digit);
  } while (value);
  return Buffer.from(bytes);
}

function encodePacket(kind: number, value: Buffer): Buffer {
  return Buffer.concat([encodeVarint(kind), encodeVarint(value.length), value]);
}

function encodeSection(value: Section): Buffer[] {
  const result: Buffer[] = [];
  if (value.location !== null) result.push(encodePacket(1, value.location));
  result.push(encodePacket(2, value.identifier));
  if (value.vid !== null) result.push(encodePacket(4, value.vid));
  result.push(Buffer.from([0]));
  return result;
}

export function encodeMacaroon(facts: MacaroonFacts): Secret {
  const source = (facts as MacaroonFacts & { [canonicalSource]?: Secret })[canonicalSource];
  if (!source) throw new Error('macaroon facts have no decoded binary source');
  return new Secret(revealSecret(source));
}

export function addFirstPartyCaveat(mac: Secret, condition: string): Secret {
  const { parsed } = parsedMacaroon(revealSecret(mac));
  identifier(parsed.header.identifier);
  const conditionId = Buffer.from(condition, 'utf8');
  const signature = createHmac('sha256', parsed.signature).update(conditionId).digest();
  return new Secret(Buffer.concat([
    Buffer.from([2]), ...encodeSection(parsed.header),
    ...parsed.caveats.flatMap(encodeSection),
    ...encodeSection({ location: null, identifier: conditionId, vid: null }),
    Buffer.from([0]), encodePacket(6, signature),
  ]));
}

export function timeBeforeCondition(expires: string, clock: () => Date): string {
  const match = /^([1-9][0-9]{0,4})([mhd])$/.exec(expires);
  if (!match) throw new UsageError('invalid expiry duration');
  const amount = Number(match[1]);
  const milliseconds = { m: 60_000, h: 3_600_000, d: 86_400_000 }[match[2] as 'm' | 'h' | 'd'];
  const instant = new Date(clock().getTime() + amount * milliseconds);
  if (!Number.isFinite(instant.getTime())) throw new UsageError('invalid expiry duration');
  return `time-before ${instant.toISOString().replace(/\.\d{3}Z$/, 'Z')}`;
}

export function validMacaroonIdentifier(data: Buffer): boolean {
  try { identifier(data); return true; } catch { return false; }
}

// NIP-47 Nostr Wallet Connect URIs. The URI is held verbatim in a Secret
// container; only this module reveals it. Crypto entry points and their methods
// are captured at load, as in secret-capability.ts.
const nwcHash = createHash;
const nwcEcdh = createECDH;
const nwcHashProbe = nwcHash('sha256');
const nwcHashUpdate = nwcHashProbe.update.call.bind(nwcHashProbe.update) as (hash: unknown, data: Uint8Array) => unknown;
const nwcHashDigest = nwcHashProbe.digest.call.bind(nwcHashProbe.digest) as (hash: unknown, encoding: 'hex') => string;
const nwcEcdhProbe = nwcEcdh('secp256k1');
const nwcSetPrivateKey = nwcEcdhProbe.setPrivateKey.call.bind(nwcEcdhProbe.setPrivateKey) as
  (ecdh: unknown, key: Uint8Array) => void;
const nwcGetPublicKey = nwcEcdhProbe.getPublicKey.call.bind(nwcEcdhProbe.getPublicKey) as
  (ecdh: unknown, encoding: 'hex', format: 'compressed') => string;
// NIP-47's canonical scheme plus the legacy forms wallets still emit (accepted
// by the reference Alby js-sdk parser): with or without "//", with or without "+".
const NWC_PREFIXES = ['nostr+walletconnect://', 'nostrwalletconnect://', 'nostr+walletconnect:', 'nostrwalletconnect:'];
const NWC_MAX_RELAYS = 64;
// Fail-closed windows: 8 secret bytes as hex (16 characters, 64 bits) or 11
// characters of its case-folded, separator-free base64 (about 56 bits). A
// legitimate relay or lud16 value matches one of the few hundred windows of a
// random secret with probability below 1e-12.
const NWC_HEX_WINDOW = 16;
const NWC_BASE64_WINDOW = 11;

export type NwcFacts = {
  fingerprint: string;
  walletPubkey: string;
  clientPubkey: string;
  relays: string[];
  lud16: string | null;
  relayDetailsRemoved: boolean;
};

function nwcFail(stage: NwcStage): never {
  throw new DecodeError(stage, `invalid NWC URI ${stage}`);
}

function nwcPrefixLength(bytes: Uint8Array): number {
  const head = Buffer.from(bytes.subarray(0, 24)).toString('latin1').toLowerCase();
  return NWC_PREFIXES.find(prefix => head.startsWith(prefix))?.length ?? 0;
}

function nwcText(secret: Secret): { text: string; prefix: number } | null {
  const bytes = revealSecret(secret);
  const prefix = nwcPrefixLength(bytes);
  if (!prefix) return null;
  try { return { text: new TextDecoder('utf-8', { fatal: true }).decode(bytes), prefix }; }
  catch { return nwcFail('nwc-uri'); }
}

/** True when the container holds an NWC URI rather than macaroon bytes. */
export function isNwcContainer(secret: Secret): boolean {
  return nwcPrefixLength(revealSecret(secret)) > 0;
}

// Percent-decode until stable, case-fold and keep only [0-9a-z], so separators,
// hostname labels and URL escaping cannot hide an encoding of the secret.
function folded(text: string): string {
  let current = text;
  for (let round = 0; round < 16; round++) {
    const next = current.replace(/%([0-9a-f]{2})/gi, (_match, digits: string) => String.fromCharCode(parseInt(digits, 16)));
    if (next === current) break;
    current = next;
  }
  return current.toLowerCase().replace(/[^0-9a-z]/g, '');
}

function secretWindows(secretBytes: Buffer): string[] {
  const windows = new Set<string>();
  const hex = secretBytes.toString('hex');
  for (let at = 0; at + NWC_HEX_WINDOW <= hex.length; at++) windows.add(hex.slice(at, at + NWC_HEX_WINDOW));
  for (let shift = 0; shift < 3; shift++) {
    // base64 and base64url differ only in +/ versus -_, which folding removes.
    const encoded = folded(secretBytes.subarray(shift).toString('base64'));
    for (let at = 0; at + NWC_BASE64_WINDOW <= encoded.length; at++) windows.add(encoded.slice(at, at + NWC_BASE64_WINDOW));
  }
  return [...windows];
}

// Each reported field is checked on its own after folding. Folding joins
// hostname labels, path segments and percent-escapes inside one field, so
// splitting the secret there does not hide it. Deliberate obfuscation across
// fields (or by transformation) is out of scope: its author already holds the
// secret, and docs/spec.md states the limit.
function refuseSecret(fields: string[], windows: string[], stage: NwcStage): void {
  for (const field of fields) {
    const text = folded(field);
    if (windows.some(window => text.includes(window))) nwcFail(stage);
  }
}

export function decodeNwc(secret: Secret): NwcFacts {
  const container = nwcText(secret);
  if (container === null) return nwcFail('nwc-uri');
  const { text, prefix } = container;
  if (/[\s#]/.test(text)) nwcFail('nwc-uri');
  const rest = text.slice(prefix);
  const query = rest.indexOf('?');
  if (query < 0) nwcFail('nwc-uri');
  // One trailing "/" after the wallet public key is accepted, as URL parsers do.
  const wallet = rest.slice(0, query).replace(/\/$/, '');
  if (!/^[0-9a-f]{64}$/i.test(wallet)) nwcFail('nwc-wallet-pubkey');
  let params: URLSearchParams;
  try { params = new URLSearchParams(rest.slice(query + 1)); }
  catch { return nwcFail('nwc-uri'); }

  const secrets = params.getAll('secret');
  if (secrets.length !== 1 || !/^[0-9a-f]{64}$/i.test(secrets[0])) nwcFail('nwc-secret');
  const secretBytes = Buffer.from(secrets[0], 'hex');
  const ecdh = nwcEcdh('secp256k1');
  try { nwcSetPrivateKey(ecdh, secretBytes); }
  catch { return nwcFail('nwc-secret'); }
  const clientPubkey = nwcGetPublicKey(ecdh, 'hex', 'compressed').slice(2);
  const hash = nwcHash('sha256');
  nwcHashUpdate(hash, secretBytes);
  const fingerprint = `fp:${nwcHashDigest(hash, 'hex').slice(0, 16)}`;
  const windows = secretWindows(secretBytes);
  refuseSecret([wallet], windows, 'nwc-wallet-pubkey');

  const rawRelays = params.getAll('relay');
  if (rawRelays.length === 0 || rawRelays.length > NWC_MAX_RELAYS) nwcFail('nwc-relay');
  let relayDetailsRemoved = false;
  const relays = rawRelays.map(raw => {
    let url: URL;
    try { url = new URL(raw); }
    catch { return nwcFail('nwc-relay'); }
    if ((url.protocol !== 'wss:' && url.protocol !== 'ws:') || !url.hostname) nwcFail('nwc-relay');
    // Userinfo, query and fragment can carry credentials; report only the endpoint.
    if (url.username || url.password || url.search || url.hash) relayDetailsRemoved = true;
    return `${url.protocol}//${url.host}${url.pathname === '/' ? '' : url.pathname}`;
  });
  refuseSecret(relays, windows, 'nwc-relay');

  const lud16s = params.getAll('lud16');
  if (lud16s.length > 1) nwcFail('nwc-lud16');
  if (lud16s.length === 1 && (lud16s[0].length > 320 || !/^[^@\s]+@[^@\s]+$/.test(lud16s[0]))) nwcFail('nwc-lud16');
  const lud16 = lud16s.length === 1 ? lud16s[0] : null;
  if (lud16 !== null) refuseSecret([lud16], windows, 'nwc-lud16');

  return { fingerprint, walletPubkey: wallet.toLowerCase(), clientPubkey, relays, lud16, relayDetailsRemoved };
}

// L402 (formerly LSAT) credentials: a macaroon minted by an L402 server such as Aperture plus
// the preimage of the Lightning invoice it commits to. The macaroon identifier is Aperture's
// l402.Identifier: a big-endian uint16 version (0), the 32-byte payment hash and a 32-byte
// token ID (lightninglabs/aperture l402/identifier.go). Caveats are "condition=value" strings
// (l402/caveat.go, l402/service.go). Only this module reveals the credential; callers get facts
// without the preimage or macaroon bytes.
const L402_IDENTIFIER_LENGTH = 66;
const L402_PREIMAGE_LENGTH = 32;
// Aperture's token store (l402/token.go serializeToken): uint32 macaroon length, macaroon,
// payment hash, preimage (zero while pending), amount paid, routing fee and creation time.
const L402_TOKEN_TAIL = 32 + 32 + 8 + 8 + 8;
/** Largest macaroon a token file may hold, as for *.macaroon files. */
const L402_TOKEN_MACAROON_LIMIT = 65_536;
/** Macaroons one Authorization value may carry; the L402 grammar sets no limit, Aperture accepts one. */
export const L402_MAX_MACAROONS = 16;
const l402Preimage = Symbol('l402 preimage');

export type L402Form = 'authorization' | 'challenge' | 'pair' | 'macaroon' | 'token-file';
export type L402CaveatType = 'services' | 'capabilities' | 'valid-until' | 'preimage' | 'constraint' | 'third-party'
  | 'unknown' | 'withheld';
export type L402Caveat = { type: L402CaveatType; condition: string | null; value: string | null; service?: string };
export type L402Facts = {
  form: L402Form;
  scheme: 'L402' | 'LSAT' | null;
  fingerprint: string;
  macaroonFingerprint: string;
  /** How many macaroons the credential carries; the facts describe the primary one. */
  macaroons: number;
  location: string | null;
  identifier: { version: number; paymentHash: string; tokenId: string } | null;
  caveats: L402Caveat[];
  preimage: 'absent' | 'matches' | 'mismatch' | 'unverifiable';
  preimageSource: 'credential' | 'caveat' | null;
  warnings: string[];
};
/** An L402 form that carries an LND macaroon instead: it is inspected as that macaroon. */
export type L402Decoded = { l402: L402Facts } | { lnd: Secret };

function l402Fail(stage: 'l402-form' | 'l402-preimage', message?: string): never {
  throw new DecodeError(stage, message ?? `invalid L402 credential ${stage}`);
}

/** An Aperture version 0 identifier: exactly 66 bytes starting with version 0. */
export function isL402Identifier(data: Uint8Array): boolean {
  return data.length === L402_IDENTIFIER_LENGTH && data[0] === 0 && data[1] === 0;
}

function sha256Hex(...parts: Uint8Array[]): string {
  const hash = nwcHash('sha256');
  for (const part of parts) nwcHashUpdate(hash, part);
  return nwcHashDigest(hash, 'hex');
}

// Canonical base64 or base64url, padded or not, as readCredential accepts it.
function strictBase64(value: string): Buffer | null {
  const standard = /^[A-Za-z0-9+/]+={0,2}$/.test(value);
  const url = /^[A-Za-z0-9_-]+={0,2}$/.test(value);
  if ((!standard && !url) || value.length % 4 === 1) return null;
  const padding = value.length - value.replace(/=+$/, '').length;
  if (padding > 0 && value.length % 4 !== 0) return null;
  const bytes = Buffer.from(value, standard ? 'base64' : 'base64url');
  if (!bytes.length || bytes.toString(standard ? 'base64' : 'base64url').replace(/=+$/, '') !== value.replace(/=+$/, '')) return null;
  return bytes;
}

// The text forms an inspect input may hold: an Authorization value or a WWW-Authenticate
// challenge (each optionally with its header name), or a bare "<base64 macaroon>:<hex
// preimage>" pair.
const L402_SCHEME = /^(?:(?:authorization|www-authenticate)[ \t]*:[ \t]*)?(?:l402|lsat)[ \t]/i;
const L402_AUTHORIZATION = /^(?:authorization[ \t]*:[ \t]*)?(l402|lsat)[ \t]+(\S*)$/i;
// A challenge's parameters (L402 section 5.1): macaroon="<base64>" and invoice="<bolt11>";
// some servers name the macaroon "token" (getAlby/js-lightning-tools parseL402).
const L402_CHALLENGE = /^(?:(?:www-authenticate|authorization)[ \t]*:[ \t]*)?(l402|lsat)[ \t]+(.*)$/i;
const L402_CHALLENGE_PARAMETER = /(?:^|,)[ \t]*(?:macaroon|token|invoice)[ \t]*=/i;
const L402_CHALLENGE_MACAROON = /(?:^|,)[ \t]*(?:macaroon|token)[ \t]*=[ \t]*("?)([A-Za-z0-9+/_=-]*)\1[ \t]*(?=,|$)/i;
const L402_PAIR = /^([A-Za-z0-9+/_=-]{16,}):([0-9a-f]*)$/i;

function l402Text(bytes: Buffer): string | null {
  if (bytes.length === 0 || bytes[0] === 0 || bytes[0] === 2) return null;
  const text = bytes.toString('latin1');
  return L402_SCHEME.test(text) || L402_PAIR.test(text) ? text : null;
}

function tokenFileLayout(data: Buffer): { macaroonEnd: number; end: number } | null {
  if (data.length < 4 || data[0] !== 0) return null;
  const length = data.readUInt32BE(0);
  if (length === 0 || length > L402_TOKEN_MACAROON_LIMIT || data.length < 4 + length + L402_TOKEN_TAIL || data[4] !== 2) return null;
  return { macaroonEnd: 4 + length, end: 4 + length + L402_TOKEN_TAIL };
}

/** True when the container holds an L402 header value, a challenge, a pair or a token store file. */
export function isL402Container(secret: Secret): boolean {
  const bytes = revealSecret(secret);
  return l402Text(bytes) !== null || tokenFileLayout(bytes) !== null;
}

/** True when the container holds a bare macaroon whose identifier is an L402 identifier. */
export function isL402Macaroon(secret: Secret): boolean {
  try {
    return isL402Identifier(parsedMacaroon(revealSecret(secret)).parsed.header.identifier);
  } catch { return false; }
}

/** Hex of the preimage these facts were decoded with, for redaction only; never rendered. */
export function l402RedactionSecret(facts: L402Facts): string | null {
  return (facts as L402Facts & { [l402Preimage]?: string })[l402Preimage] ?? null;
}

function containsSecret(text: string, preimage: Buffer): boolean {
  if (text.toLowerCase().includes(preimage.toString('hex'))) return true;
  return [preimage.toString('base64'), preimage.toString('base64url')]
    .some(encoded => text.includes(encoded.replace(/=+$/, '')));
}

function l402Caveat(value: Section): L402Caveat {
  if (value.vid !== null && value.vid.length > 0) {
    return { type: 'third-party', condition: null, value: value.location?.toString('utf8') ?? '' };
  }
  // Aperture's DecodeCaveat splits at the first "=" and ignores caveats without one.
  const text = value.identifier.toString('utf8');
  const at = text.indexOf('=');
  if (at < 0) return { type: 'unknown', condition: null, value: text };
  const condition = text.slice(0, at);
  const conditionValue = text.slice(at + 1);
  if (condition === 'services') return { type: 'services', condition, value: conditionValue };
  if (condition === 'preimage') return { type: 'preimage', condition, value: null };
  if (condition.endsWith('_capabilities'))
    return { type: 'capabilities', condition, value: conditionValue, service: condition.slice(0, -'_capabilities'.length) };
  if (condition.endsWith('_valid_until'))
    return { type: 'valid-until', condition, value: conditionValue, service: condition.slice(0, -'_valid_until'.length) };
  return { type: 'constraint', condition, value: conditionValue };
}

type ParsedL402Macaroon = { data: Buffer; header: Section; caveats: Section[]; end: number; omitted: number; canonical: Buffer };

function parsedL402(mac: Secret): ParsedL402Macaroon {
  const data = revealSecret(mac);
  const caveats: Section[] = [];
  const { parsed: { header }, end, omittedCaveats } = parsedMacaroon(data, value => {
    if (caveats.length < MAX_CAVEATS) caveats.push(value);
  });
  const canonical = canonicalMacaroonForm(data, () => undefined);
  return { data, header, caveats, end, omitted: omittedCaveats, canonical: canonical?.reencoded ?? data.subarray(0, end) };
}

/**
 * The facts of an L402 credential: one or more macaroons (in order) and the preimage presented
 * with them. Throws DecodeError for a macaroon that does not parse. `presented` is the
 * separately presented preimage (Authorization value, pair or token file), null when there is
 * none. With several macaroons, the primary one is the first with an L402 identifier (else the
 * first); its facts are reported and the preimage is checked against its payment hash.
 */
export function decodeL402Macaroons(macs: Secret[], presented: Secret | null, form: L402Form,
  scheme: 'L402' | 'LSAT' | null = null): L402Decoded {
  if (macs.length === 0 || macs.length > L402_MAX_MACAROONS) return l402Fail('l402-form');
  const parsed = macs.map(parsedL402);
  // A credential that carries exactly one LND macaroon carries that LND macaroon.
  if (parsed.length === 1 && validMacaroonIdentifier(parsed[0].header.identifier)) return { lnd: new Secret(parsed[0].data) };
  const primary = parsed.find(item => isL402Identifier(item.header.identifier)) ?? parsed[0];
  const warnings: string[] = [];
  if (parsed.length > 1) warnings.push('l402-several-macaroons');
  if (primary.omitted > 0) warnings.push('caveats-exceed-bounds');
  if (parsed.some(item => item.end < item.data.length)) warnings.push('trailing-bytes');
  const id = primary.header.identifier;
  const identifierFacts = isL402Identifier(id)
    ? { version: 0, paymentHash: id.subarray(2, 34).toString('hex'), tokenId: id.subarray(34, 66).toString('hex') } : null;
  if (identifierFacts === null) warnings.push('l402-identifier-unrecognized');
  let caveats = primary.caveats.map(l402Caveat);

  // Aperture reads the Authorization preimage; without one, the last preimage caveat (l402/header.go).
  const presentedBytes = presented === null ? null : revealSecret(presented);
  let preimage: Buffer | null = presentedBytes;
  let preimageSource: L402Facts['preimageSource'] = presentedBytes === null ? null : 'credential';
  if (preimage === null) {
    let last: string | undefined;
    for (const value of primary.caveats) {
      if (value.vid !== null && value.vid.length > 0) continue;
      const text = value.identifier.toString('utf8');
      if (text.startsWith('preimage=')) last = text.slice('preimage='.length);
    }
    if (last !== undefined) {
      if (/^[0-9a-f]{64}$/i.test(last)) { preimage = Buffer.from(last, 'hex'); preimageSource = 'caveat'; }
      else warnings.push('l402-bad-preimage-caveat');
    }
  }
  let location = primary.header.location?.toString('utf8') ?? null;
  if (preimage !== null) {
    // Nothing reported may carry the preimage: such a caveat or location is withheld.
    const secret = preimage;
    let withheld = false;
    caveats = caveats.map(caveat => {
      if (caveat.type === 'preimage') return caveat;
      if (![caveat.condition, caveat.value].some(text => text !== null && containsSecret(text, secret))) return caveat;
      withheld = true;
      return { type: 'withheld', condition: null, value: null };
    });
    if (location !== null && containsSecret(location, secret)) { location = null; withheld = true; }
    if (withheld) warnings.push('l402-caveat-withheld');
  }
  const macaroonFingerprint = `fp:${sha256Hex(primary.canonical).slice(0, 16)}`;
  const fingerprint = presentedBytes === null && parsed.length === 1 ? macaroonFingerprint
    : `fp:${sha256Hex(...parsed.map(item => item.canonical), ...(presentedBytes === null ? [] : [presentedBytes])).slice(0, 16)}`;
  const status: L402Facts['preimage'] = preimage === null ? 'absent' : identifierFacts === null ? 'unverifiable'
    : sha256Hex(preimage) === identifierFacts.paymentHash ? 'matches' : 'mismatch';
  const facts: L402Facts = { form, scheme, fingerprint, macaroonFingerprint, macaroons: parsed.length, location,
    identifier: identifierFacts, caveats, preimage: status, preimageSource, warnings: [...new Set(warnings)] };
  if (preimage !== null) Object.defineProperty(facts, l402Preimage, { value: preimage.toString('hex'), enumerable: false });
  return { l402: facts };
}

/** One macaroon and its presented preimage; see decodeL402Macaroons. */
export function decodeL402Macaroon(mac: Secret, presented: Secret | null, form: L402Form,
  scheme: 'L402' | 'LSAT' | null = null): L402Decoded {
  return decodeL402Macaroons([mac], presented, form, scheme);
}

/** The macaroon a WWW-Authenticate challenge carries, from its first macaroon (or token) parameter. */
export function l402ChallengeMacaroon(text: string): string | null {
  const challenge = L402_CHALLENGE.exec(text);
  if (!challenge || !L402_CHALLENGE_PARAMETER.test(challenge[2])) return null;
  const match = L402_CHALLENGE_MACAROON.exec(challenge[2]);
  return match ? match[2] : null;
}

function decodeL402Text(text: string): L402Decoded {
  const challenge = L402_CHALLENGE.exec(text);
  if (challenge && L402_CHALLENGE_PARAMETER.test(challenge[2])) {
    const value = l402ChallengeMacaroon(text);
    const macaroon = value === null ? null : strictBase64(value);
    if (macaroon === null) return l402Fail('l402-form');
    return decodeL402Macaroon(new Secret(macaroon), null, 'challenge', challenge[1].toUpperCase() as 'L402' | 'LSAT');
  }
  const authorization = L402_AUTHORIZATION.exec(text);
  if (authorization === null && L402_SCHEME.test(text)) return l402Fail('l402-form');
  const scheme = authorization ? (authorization[1].toUpperCase() as 'L402' | 'LSAT') : null;
  const body = authorization ? authorization[2] : text;
  const colon = body.lastIndexOf(':');
  if (colon < 0) return l402Fail('l402-form');
  const parts = body.slice(0, colon).split(',');
  if (parts.length > L402_MAX_MACAROONS) return l402Fail('l402-form', `an L402 credential with more than ${L402_MAX_MACAROONS} macaroons is not read`);
  const preimage = body.slice(colon + 1);
  const macaroons = parts.map(strictBase64);
  if (macaroons.some(macaroon => macaroon === null)) return l402Fail('l402-form');
  // Aperture requires exactly 64 hex digits (l402/header.go authRegex).
  if (!/^[0-9a-f]{64}$/i.test(preimage)) return l402Fail('l402-preimage');
  return decodeL402Macaroons(macaroons.map(macaroon => new Secret(macaroon!)), new Secret(Buffer.from(preimage, 'hex')),
    authorization ? 'authorization' : 'pair', scheme);
}

/**
 * Decodes an L402 container: an Authorization value, challenge or macaroon:preimage pair
 * (text), an Aperture token store file, or a bare macaroon with an L402 identifier.
 */
export function decodeL402(secret: Secret): L402Decoded {
  const bytes = revealSecret(secret);
  const text = l402Text(bytes);
  if (text !== null) return decodeL402Text(text);
  if (bytes.length > 0 && bytes[0] === 0) {
    const layout = tokenFileLayout(bytes);
    // Neither a macaroon (first byte 2) nor a token store file.
    if (layout === null) return fail('v2-header');
    const macaroon = bytes.subarray(4, layout.macaroonEnd);
    const tokenHash = bytes.subarray(layout.macaroonEnd, layout.macaroonEnd + 32);
    const preimage = bytes.subarray(layout.macaroonEnd + 32, layout.macaroonEnd + 32 + L402_PREIMAGE_LENGTH);
    // A pending token holds the zero preimage until its invoice is paid (l402/token.go).
    const paid = preimage.some(byte => byte !== 0);
    const decodedToken = decodeL402Macaroon(new Secret(macaroon), paid ? new Secret(preimage) : null, 'token-file');
    if ('lnd' in decodedToken) return decodedToken;
    const facts = decodedToken.l402;
    const extra: string[] = [];
    if (facts.identifier !== null && facts.identifier.paymentHash !== tokenHash.toString('hex')) extra.push('l402-token-hash-differs');
    if (layout.end < bytes.length) extra.push('trailing-bytes');
    facts.warnings = [...new Set([...facts.warnings, ...extra])];
    return decodedToken;
  }
  return decodeL402Macaroon(secret, null, 'macaroon');
}
