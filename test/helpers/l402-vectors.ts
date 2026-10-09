import { createHash, createHmac } from 'node:crypto';

// Synthetic L402 credentials for tests, built independently of src/: go-macaroon v2 binary
// framing and signature chain, Aperture's version 0 identifier, caveats and token store file
// (lightninglabs/aperture l402/identifier.go, l402/caveat.go, l402/token.go, mint/mint.go).
// A fixed throwaway root key; nothing here was ever issued by a real service.
export const ROOT_KEY = Buffer.alloc(32, 0x5a);

function varint(value: number): Buffer {
  const bytes: number[] = [];
  do {
    let byte = value % 128;
    value = Math.floor(value / 128);
    if (value) byte |= 0x80;
    bytes.push(byte);
  } while (value);
  return Buffer.from(bytes);
}

const packet = (kind: number, data: Buffer) => Buffer.concat([varint(kind), varint(data.length), data]);
const hmac = (key: Buffer, data: Buffer) => createHmac('sha256', key).update(data).digest();
export const sha256 = (...parts: Buffer[]) => parts.reduce((hash, part) => hash.update(part), createHash('sha256')).digest();
export const fp = (...parts: Buffer[]) => `fp:${sha256(...parts).toString('hex').slice(0, 16)}`;

export type Caveat = string | { thirdParty: string };

/** A go-macaroon v2 binary macaroon with first-party (string) and third-party caveats. */
export function macaroon(identifier: Buffer, caveats: Caveat[] = [], location = 'lsat', rootKey = ROOT_KEY): Buffer {
  // go-macaroon derives the signing key: HMAC-SHA256 keyed with "macaroons-key-generator".
  let signature = hmac(hmac(Buffer.from('macaroons-key-generator'), rootKey), identifier);
  const parts: Buffer[] = [Buffer.from([2])];
  if (location) parts.push(packet(1, Buffer.from(location)));
  parts.push(packet(2, identifier), Buffer.from([0]));
  for (const caveat of caveats) {
    if (typeof caveat === 'string') {
      const id = Buffer.from(caveat, 'utf8');
      parts.push(packet(2, id), Buffer.from([0]));
      signature = hmac(signature, id);
    } else {
      const vid = Buffer.alloc(48, 7);
      parts.push(packet(1, Buffer.from(caveat.thirdParty)), packet(2, Buffer.from('third-party-id')), packet(4, vid), Buffer.from([0]));
      signature = hmac(signature, Buffer.concat([vid, Buffer.from('third-party-id')]));
    }
  }
  parts.push(Buffer.from([0]), packet(6, signature));
  return Buffer.concat(parts);
}

/** Aperture's version 0 identifier: uint16 version, payment hash, token ID. */
export function identifier(paymentHash: Buffer, tokenId: Buffer, version = 0): Buffer {
  const head = Buffer.alloc(2);
  head.writeUInt16BE(version);
  return Buffer.concat([head, paymentHash, tokenId]);
}

export type Token = {
  preimage: Buffer; paymentHash: Buffer; tokenId: Buffer; macaroon: Buffer; base64: string;
  header: string; pair: string; fingerprint: string; macaroonFingerprint: string;
};

/** A paid L402 token: macaroon committing to sha256(preimage), with the given caveats. */
export function token(seed: number, caveats: Caveat[] = ['services=weather:0', 'weather_capabilities=forecast,history',
  'weather_valid_until=1893456000'], location = 'lsat'): Token {
  const preimage = sha256(Buffer.from(`synthetic preimage ${seed}`));
  const paymentHash = sha256(preimage);
  const tokenId = sha256(Buffer.from(`synthetic token id ${seed}`));
  const mac = macaroon(identifier(paymentHash, tokenId), caveats, location);
  const base64 = mac.toString('base64');
  return { preimage, paymentHash, tokenId, macaroon: mac, base64,
    header: `L402 ${base64}:${preimage.toString('hex')}`, pair: `${base64}:${preimage.toString('hex')}`,
    fingerprint: fp(mac, preimage), macaroonFingerprint: fp(mac) };
}

/** Aperture's FileStore token file (l402/token.go serializeToken). A pending token has the zero preimage. */
export function tokenFile(value: Token, pending = false, created = 1_700_000_000_000_000_000n): Buffer {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(value.macaroon.length);
  const tail = Buffer.alloc(24);
  tail.writeBigUInt64BE(21_000n, 0);
  tail.writeBigUInt64BE(1_000n, 8);
  tail.writeBigInt64BE(created, 16);
  return Buffer.concat([length, value.macaroon, value.paymentHash, pending ? Buffer.alloc(32) : value.preimage, tail]);
}

/** Every common encoding of a byte string, for leak assertions. */
export function encodings(bytes: Buffer): string[] {
  return [bytes.toString('hex'), bytes.toString('hex').toUpperCase(), bytes.toString('base64'),
    bytes.toString('base64').replace(/=+$/, ''), bytes.toString('base64url')];
}
