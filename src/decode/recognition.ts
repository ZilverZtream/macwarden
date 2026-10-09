import { validMacaroonIdentifier, macaroonEosEnd, macaroonPacketRange, macaroonSectionRange } from './index.js';

// Packet and caveat endings depend only on their byte offset. Compute them
// backwards once per decoded run so candidate headers can share a long tail.
export function macaroonEnds(bytes: Buffer): (start: number) => number | null {
  if (!bytes.includes(2)) return () => null;
  const tails = new Int32Array(bytes.length + 1).fill(-1);
  const identifiers = new Map<number, boolean>();
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
    const valid = validMacaroonIdentifier(bytes.subarray(start, end));
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

