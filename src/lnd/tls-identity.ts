// Server identity check for an LND endpoint given as an IPv6 literal. Host names and IPv4
// addresses keep Node's default check (no option is passed). Some supported Node releases
// (22.x) pass the host through domainToASCII before matching, which turns "::1" into "" and
// refuses every IPv6 certificate, even one whose IP address SAN matches. This replacement
// is as strict as Node's own IP rule: only IP address SANs count (never the common name),
// compared in canonical form, and quoted SAN lists (which need an escaping-aware parser)
// are refused rather than parsed.

/** Canonical (WHATWG: compressed, lower case) form of an IPv6 address, or null. */
function canonicalIPv6(address: string): string | null {
  const bare = address.replace(/^\[(.*)\]$/, '$1');
  if (!bare.includes(':') || /[[\]/?#@]/.test(bare)) return null;
  try { return new URL(`https://[${bare}]/`).hostname; } catch { return null; }
}

type Certificate = { subjectaltname?: string };

/** TLS options for `host`: a strict IP SAN check for an IPv6 literal, nothing otherwise. */
export function identityCheck(host: string): { checkServerIdentity?: (name: string, cert: Certificate) => Error | undefined } {
  const wanted = canonicalIPv6(host);
  if (wanted === null) return {};
  return {
    checkServerIdentity(_name, cert) {
      const altnames = cert.subjectaltname ?? '';
      const names = altnames.includes('"') ? [] : altnames.split(', ');
      if (names.some(name => name.startsWith('IP Address:') && canonicalIPv6(name.slice(11)) === wanted)) return undefined;
      const reason = `IP: ${host} is not in the cert's list`;
      return Object.assign(new Error(`Hostname/IP does not match certificate's altnames: ${reason}`),
        { code: 'ERR_TLS_CERT_ALTNAME_INVALID', reason, host });
    },
  };
}
