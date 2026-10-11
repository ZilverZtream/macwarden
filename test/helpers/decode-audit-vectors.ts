// Synthetic inputs for the 1.4.0 decode audit tests, built independently of src/.

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

function readVarint(data: Buffer, at: number): [number, number] {
  let value = 0;
  for (let shift = 0; ; shift += 7) {
    const byte = data[at++];
    value += (byte & 0x7f) * 2 ** shift;
    if ((byte & 0x80) === 0) return [value, at];
  }
}

type V2Section = { location: Buffer | null; identifier: Buffer; vid: Buffer | null };

/** A canonical go-macaroon v2 binary macaroon read into its sections and signature. */
export function readV2(data: Buffer): { header: V2Section; caveats: V2Section[]; signature: Buffer } {
  if (data[0] !== 2) throw new Error('not a v2 macaroon');
  let at = 1;
  const section = (): V2Section | null => {
    const result: V2Section = { location: null, identifier: Buffer.alloc(0), vid: null };
    if (data[at] === 0) { at++; return null; }
    for (;;) {
      const kind = data[at++];
      if (kind === 0) return result;
      const [length, after] = readVarint(data, at);
      const value = data.subarray(after, after + length);
      at = after + length;
      if (kind === 1) result.location = value;
      else if (kind === 2) result.identifier = value;
      else if (kind === 4) result.vid = value;
      else throw new Error(`unexpected packet kind ${kind}`);
    }
  };
  const header = section()!;
  const caveats: V2Section[] = [];
  for (let next = section(); next !== null; next = section()) caveats.push(next);
  if (data[at++] !== 6) throw new Error('no signature');
  const [length, after] = readVarint(data, at);
  return { header, caveats, signature: data.subarray(after, after + length) };
}

/** One go-macaroon v1 binary packet: 4 lowercase hex digits of the whole length, field, space, value, newline. */
function packetV1(field: string, value: Buffer): Buffer {
  const size = 4 + field.length + 1 + value.length + 1;
  if (size > 0xffff) throw new Error('v1 packet too long');
  return Buffer.concat([Buffer.from(size.toString(16).padStart(4, '0'), 'latin1'), Buffer.from(`${field} `, 'latin1'), value, Buffer.from('\n')]);
}

/**
 * The same credential in go-macaroon's v1 binary format (marshal-v1.go appendBinaryV1): the
 * identifier, caveats and signature are unchanged, so LND (UnmarshalBinary) accepts it alike.
 */
export function toV1(v2: Buffer): Buffer {
  const { header, caveats, signature } = readV2(v2);
  const parts = [packetV1('location', header.location ?? Buffer.alloc(0)), packetV1('identifier', header.identifier)];
  for (const caveat of caveats) {
    parts.push(packetV1('cid', caveat.identifier));
    if (caveat.vid !== null) parts.push(packetV1('vid', caveat.vid), packetV1('cl', caveat.location ?? Buffer.alloc(0)));
  }
  parts.push(packetV1('signature', signature));
  return Buffer.concat(parts);
}

const packetV2 = (kind: number, value: Buffer) => Buffer.concat([varint(kind), varint(value.length), value]);

/**
 * A v2 binary macaroon with caveats given by ID, third-party ones with a verification ID and
 * location. The signature is a fixed placeholder: decoding never checks it.
 */
export function v2Macaroon(location: string, identifier: Buffer, caveats: { id: string; vid?: Buffer; location?: string }[]): Buffer {
  const parts = [Buffer.from([2]), packetV2(1, Buffer.from(location)), packetV2(2, identifier), Buffer.from([0])];
  for (const caveat of caveats) {
    if (caveat.vid) parts.push(packetV2(1, Buffer.from(caveat.location ?? '')));
    parts.push(packetV2(2, Buffer.from(caveat.id)));
    if (caveat.vid) parts.push(packetV2(4, caveat.vid));
    parts.push(Buffer.from([0]));
  }
  parts.push(Buffer.from([0]), packetV2(6, Buffer.alloc(32, 0x33)));
  return Buffer.concat(parts);
}

/**
 * n nested candidate macaroon headers (02 02 <len> 03 0a <len> [next header]) sharing one
 * identifier tail of m small protobuf fields, followed by a signature. Every candidate's
 * identifier spans the whole tail: the shape that made recognition cost n * m.
 */
export function nestedCandidates(n: number, m: number): Buffer {
  const tail = Buffer.concat([Buffer.alloc(2 * m).map((_, i) => i % 2 ? 0 : 0x20),
    Buffer.from([0x12, 1, 0x30, 0x1a, 0x08, 0x0a, 1, 0x61, 0x12, 1, 0x62, 0x12, 1, 0x63])]);
  let nested = Buffer.alloc(0);
  for (let k = 1; k <= n; k++) {
    const inner = Buffer.concat([Buffer.from([3, 0x0a]), varint(nested.length), nested]);
    nested = Buffer.concat([Buffer.from([2, 2]), varint(inner.length + tail.length), inner]);
  }
  return Buffer.concat([nested, tail, Buffer.from([0, 0, 6, 32]), Buffer.alloc(32, 7)]);
}
