export const macaroonHex = /0201036c6e6402[0-9a-f]{40,}/i;
// docs/spec.md fixes this regex's source, including the escaped slash in its character class.
// eslint-disable-next-line no-useless-escape
export const macaroonBase64 = /AgEDbG5kA[A-Za-z0-9+\/_-]{40,}={0,2}/;
export const lndconnect = /lndconnect:\/\/[^\s"'<>]+/i;
export const nwc = /(?:nostr\+walletconnect|nostrwalletconnect):(?:\/\/)?[0-9a-f]{64}\/?\?[^\s"'<>]*?secret=[0-9a-f]{64}(?:[^0-9a-f]|$)/i;
