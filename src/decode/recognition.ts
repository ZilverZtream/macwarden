import { isL402Identifier, validMacaroonIdentifier, macaroonEosEnd, macaroonPacketRange, macaroonSectionRange } from './index.js';

// Identifier parsing one macaroonEnds call may do, in bytes read by the protobuf parser per byte
// of its input (audit 1.4.0). Nested candidate headers can share one long identifier tail, so
// parsing each in full costs the input length times the number of candidates. Only the bytes a
// check actually reads are charged: a candidate refused at its first field costs a few bytes,
// whatever its length. Past the budget a structurally complete candidate is taken as a
// credential without finishing its identifier check: recognition then redacts more, never less.
const IDENTIFIER_PARSE_BUDGET_PER_BYTE = 4;
// Floor for short inputs, so a few real credentials in a small value are always parsed.
const IDENTIFIER_PARSE_BUDGET_MIN = 65_536;

// Packet and caveat endings depend only on their byte offset. Compute them
// backwards once per decoded run so candidate headers can share a long tail.
export function macaroonEnds(bytes: Buffer): (start: number) => number | null {
  if (!bytes.includes(2)) return () => null;
  const tails = new Int32Array(bytes.length + 1).fill(-1);
  const identifiers = new Map<number, boolean>();
  const meter = { remaining: Math.max(IDENTIFIER_PARSE_BUDGET_MIN, IDENTIFIER_PARSE_BUDGET_PER_BYTE * bytes.length) };
  function packet(start: number): [bigint, bigint, number, number] | null {
    const item = macaroonPacketRange(bytes, start);
    return item ? [BigInt(item.kind), BigInt(item.end - item.start), item.start, item.end] : null;
  }
  function section(start: number, header: boolean): [number, number, number] | null {
    const item = macaroonSectionRange(bytes, start, header);
    return item ? [item.end, item.identifier.start, item.identifier.end] : null;
  }
  function validIdentifier(start: number, end: number): boolean {
    const cached = identifiers.get(start);
    if (cached !== undefined) return cached;
    // LND macaroons, and L402 macaroons (Aperture identifiers), are redacted alike.
    const identifier = bytes.subarray(start, end);
    const valid = isL402Identifier(identifier) || validMacaroonIdentifier(identifier, meter);
    identifiers.set(start, valid);
    return valid;
  }
  for (let pos = bytes.length - 1; pos >= 0; pos--) {
    // Any varint encoding of 0 ends a section, as in go-macaroon.
    const eos = macaroonEosEnd(bytes, pos);
    if (eos !== null) {
      const signature = packet(eos);
      if (signature?.[0] === 6n && signature[1] === 32n) tails[pos] = signature[3];
      continue;
    }
    const caveat = section(pos, false);
    if (caveat) tails[pos] = tails[caveat[0]];
  }
  return start => {
    if (bytes[start] !== 2) return null;
    const header = section(start + 1, true);
    if (!header || tails[header[0]] < 0 ||
        !validIdentifier(header[1], header[2])) return null;
    const end = tails[header[0]];
    // The shared packet, section and identifier parsers prove the same
    // structural validity as decodeMacaroon, without another buffer copy or
    // a second interpretation of the format.
    return end - start;
  };
}

