export const macaroonHex = /0201036c6e6402[0-9a-f]{40,}/i;
// docs/spec.md fixes this regex's source, including the escaped slash in its character class.
// eslint-disable-next-line no-useless-escape
export const macaroonBase64 = /AgEDbG5kA[A-Za-z0-9+\/_-]{40,}={0,2}/;
export const lndconnect = /lndconnect:\/\/[^\s"'<>]+/i;
// L402 (formerly LSAT): an Authorization credential "L402 <base64 macaroons>:<64 hex preimage>"
// (lightninglabs/L402 protocol-specification.md section 5.2; Aperture l402/header.go), and a
// macaroon with Aperture's location "lsat" and version 0 identifier in hex or base64.
export const l402Header = /\b(?:l402|lsat)[ \t]+[A-Za-z0-9+/_=-]{40,}(?:,[A-Za-z0-9+/_=-]{40,})*:[0-9a-f]{64}\b/i;
// Scan only (not in the rule packs; a challenge carries no preimage): a WWW-Authenticate
// challenge "L402 macaroon=\"<base64>\", invoice=\"<bolt11>\"" (L402 section 5.1), the macaroon
// parameter first or after the invoice, named "token" by some servers, quoted, JSON-escaped or bare.
export const l402Challenge = /\b(?:l402|lsat)[ \t]+(?:invoice[ \t]*=[ \t]*\\?"?[A-Za-z0-9]*\\?"?[ \t]*,[ \t]*)?(?:macaroon|token)[ \t]*=[ \t]*\\?"?[A-Za-z0-9+/_-]{40,}={0,2}/i;
export const l402MacaroonHex = /0201046c73617402420000[0-9a-f]{40,}/i;
// eslint-disable-next-line no-useless-escape
export const l402MacaroonBase64 = /AgEEbHNhdAJCAA[A-Za-z0-9+\/_-]{40,}={0,2}/;
export const nwc = /(?:nostr\+walletconnect|nostrwalletconnect):(?:\/\/)?[0-9a-f]{64}\/?\?[^\s"'<>]*?secret=[0-9a-f]{64}(?:[^0-9a-f]|$)/i;
