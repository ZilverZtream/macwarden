// Parse the raw query value so URLSearchParams cannot turn a literal plus into
// a space or silently repair malformed percent escapes.
/**
 * `standardBase64`: also accept the macaroon in the standard base64 alphabet (`+`, `/`), as
 * some generators write it. Scan detection uses it; credential input keeps base64url only.
 */
export function parseLndconnect(value: string, { standardBase64 = false } = {}): Buffer | null {
  try {
    const fragmentStart = value.indexOf('#');
    const queryStart = value.indexOf('?');
    if (queryStart < 0 || (fragmentStart >= 0 && fragmentStart < queryStart)) return null;
    const query = value.slice(queryStart + 1, fragmentStart < 0 ? undefined : fragmentStart);
    // A key is compared percent-decoded (`%6Dacaroon` names the macaroon parameter too, as every
    // URL parser reads it), so exactly one parameter can carry the macaroon. A key that does not
    // decode cannot read as `macaroon` under any decoder: a malformed escape stays literal.
    const named = (key: string): boolean => {
      try { return decodeURIComponent(key) === 'macaroon'; } catch { return false; }
    };
    const raw = query.split('&').filter(part => named(part.split('=', 1)[0]));
    if (raw.length !== 1) return null;
    const separator = raw[0].indexOf('=');
    if (separator < 0) return null;
    const encoded = raw[0].slice(separator + 1);
    if (/\s/u.test(encoded)) return null;
    const uri = new URL(value);
    if (uri.protocol.toLowerCase() !== 'lndconnect:' || !uri.hostname) return null;
    let form = decodeURIComponent(encoded);
    if (standardBase64 && /^[A-Za-z0-9+/]+={0,2}$/.test(form)) form = form.replace(/\+/g, '-').replace(/\//g, '_');
    if (!/^[A-Za-z0-9_-]+={0,2}$/.test(form) || form.length % 4 === 1) return null;
    const bare = form.replace(/=+$/, '');
    const requiredPadding = (4 - bare.length % 4) % 4;
    if (form !== bare && form !== bare + '='.repeat(requiredPadding)) return null;
    const bytes = Buffer.from(bare, 'base64url');
    return bytes.length && bytes.toString('base64url') === bare ? bytes : null;
  } catch {
    return null;
  }
}
