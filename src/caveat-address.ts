// Offline address parsing for `ipaddr` and `iprange` caveats. The output is the
// canonical text LND writes (Go net.IP.String and net.IPNet.String), so a caveat
// appended here is byte-identical to `lncli constrainmacaroon --ip_address` (lncli 0.21.4 has no IP-range flag).

function ipv4(text: string): number[] | undefined {
  const parts = text.split('.');
  if (parts.length !== 4) return undefined;
  const bytes: number[] = [];
  for (const part of parts) {
    // Go rejects leading zeros (ambiguous octal) and anything that is not a decimal octet.
    if (!/^(?:0|[1-9][0-9]{0,2})$/.test(part)) return undefined;
    const value = Number(part);
    if (value > 255) return undefined;
    bytes.push(value);
  }
  return bytes;
}

function ipv6(text: string): number[] | undefined {
  if (!/^[0-9A-Fa-f:.]+$/.test(text)) return undefined;
  const halves = text.split('::');
  if (halves.length > 2) return undefined;
  // Go accepts an embedded IPv4 address only as the final 32 bits of the whole text,
  // so a dotted quad is allowed only as the last item of the part that ends the string.
  const groups = (part: string, endsText: boolean): number[] | undefined => {
    if (part === '') return [];
    const items = part.split(':');
    const out: number[] = [];
    for (let index = 0; index < items.length; index++) {
      const item = items[index];
      if (endsText && index === items.length - 1 && item.includes('.')) {
        const tail = ipv4(item);
        if (!tail) return undefined;
        out.push((tail[0] << 8) | tail[1], (tail[2] << 8) | tail[3]);
      } else if (/^[0-9A-Fa-f]{1,4}$/.test(item)) out.push(parseInt(item, 16));
      else return undefined;
    }
    return out;
  };
  const head = groups(halves[0], halves.length === 1);
  const tail = halves.length === 2 ? groups(halves[1], true) : [];
  if (!head || !tail) return undefined;
  if (halves.length === 1 && head.length !== 8) return undefined;
  // "::" must stand for at least one zero group.
  if (halves.length === 2 && head.length + tail.length > 7) return undefined;
  const words = [...head, ...new Array(8 - head.length - tail.length).fill(0), ...tail];
  return words.flatMap(word => [word >> 8, word & 255]);
}

function mapped(bytes: number[]): boolean {
  return bytes.length === 16 && bytes.slice(0, 10).every(byte => byte === 0) && bytes[10] === 255 && bytes[11] === 255;
}

function format(bytes: number[]): string {
  if (bytes.length === 4) return bytes.join('.');
  const words = Array.from({ length: 8 }, (_, index) => (bytes[2 * index] << 8) | bytes[2 * index + 1]);
  // RFC 5952 as Go's netip: compress the first longest run of two or more zero groups.
  let start = -1, length = 0;
  for (let index = 0; index < 8; index++) {
    let end = index;
    while (end < 8 && words[end] === 0) end++;
    if (end - index >= 2 && end - index > length) { start = index; length = end - index; }
  }
  const hex = (from: number, to: number) => words.slice(from, to).map(word => word.toString(16)).join(':');
  return start < 0 ? hex(0, 8) : `${hex(0, start)}::${hex(start + length, 8)}`;
}

function address(text: string): number[] | undefined {
  const bytes = ipv4(text) ?? ipv6(text);
  // IPv4-mapped IPv6 prints as IPv4 in Go, which would silently change the operator's input.
  return bytes && !mapped(bytes) ? bytes : undefined;
}

/** Canonical `ipaddr` caveat value, or undefined for anything Go's net.ParseIP would refuse or rewrite. */
export function canonicalIp(text: string): string | undefined {
  const bytes = address(text);
  return bytes ? format(bytes) : undefined;
}

/** Canonical `iprange` caveat value (host bits cleared), or undefined for an invalid CIDR. */
export function canonicalCidr(text: string): string | undefined {
  const slash = text.indexOf('/');
  if (slash < 0 || text.indexOf('/', slash + 1) >= 0) return undefined;
  const bytes = address(text.slice(0, slash));
  const prefix = text.slice(slash + 1);
  if (!bytes || !/^(?:0|[1-9][0-9]{0,2})$/.test(prefix)) return undefined;
  const bits = Number(prefix);
  if (bits > bytes.length * 8) return undefined;
  const masked = bytes.map((byte, index) => {
    const keep = Math.max(0, Math.min(8, bits - index * 8));
    return byte & ((0xff << (8 - keep)) & 0xff);
  });
  return `${format(masked)}/${bits}`;
}
