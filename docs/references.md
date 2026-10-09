# References

The external sources macwarden's documentation and design rely on, with their status. A status of "verified 2026-10-02" means the page was opened and read on that date. "Reported, not verified" means the claim came from someone else and was not checked here.

## Incident

- [BTCPay Server 2.4.2 security advisory](https://blog.btcpayserver.org/security-advisory-btcpay-server-2-4-2/) (2026-08-07). An unauthenticated remote attacker could obtain LND `.macaroon` files. The flaw was exploited and funds were stolen, and the advisory tells LND users to treat their credentials as exposed. This is the main reason macwarden exists. *Verified 2026-10-02.*
- [btcpayserver v2.4.2 release](https://github.com/btcpayserver/btcpayserver/releases/tag/v2.4.2) (published 2026-08-07). The fix release. *Verified 2026-10-02.*

## Rotation failures

- [btcpayserver-docker#1112](https://github.com/btcpayserver/btcpayserver-docker/issues/1112) (2026-09-13, closed by PR #1150). Rotation deleted `macaroons.db`, and a later `changepassword` migration left the wallet permanently locked. This is the reason for SAFE-02 and the `rotate` ordering. *Verified 2026-10-02.*
- [lnd#11049](https://github.com/lightningnetwork/lnd/issues/11049) (2026-08-08, closed). An operator renamed `admin.macaroon` and `macaroons.db` to rotate them, and LND got stuck in `WAITING_TO_START`. It shows that do-it-yourself rotation breaks nodes. *Verified 2026-10-02.*

## LND issues

- [lnd#10594](https://github.com/lightningnetwork/lnd/issues/10594) (2026-02-18, open). LND forgets the macaroons it issues, and operators track them by hand. This is the reason for the registry. The only comment is a follow-up from the issue's own author. *Verified 2026-10-02.*
- [lnd#10595](https://github.com/lightningnetwork/lnd/issues/10595) (2026-02-18, open). Proposes a new root key per baked macaroon so each one can be revoked. This is the basis for `bake` and `revoke`. The thread has several comments, including a June 2026 offer from a contributor to implement it. If it lands, it overlaps only with part of `bake` (a fresh root key per macaroon), not with inventory, rotation or scanning; `bake` would then use it. *Verified 2026-10-02.*
- [lnd PR #11117](https://github.com/lightningnetwork/lnd/pull/11117) (2026-08-24, open). Adds "protector caveats" to restrict RPC request fields. A future caveat type that `inspect` may need to show. *Verified 2026-10-02 (title and state only).*

## Existing tools

- [lightning-agent-tools](https://github.com/lightninglabs/lightning-agent-tools), `skills/macaroon-bakery/scripts/bake.sh`. The closest existing tool: role presets, `--inspect` and `--list-permissions`, but no inventory, revocation, rotation or scanning. Its `lnd` skill also pays invoices with a pay-only macaroon. *Verified 2026-10-02.*
- [gitleaks default config](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml). More than 200 rules. It has a rule for Fly.io access tokens, which are macaroons, but no dedicated rule for LND macaroons, `lndconnect://` URIs, Nostr Wallet Connect strings, LNbits keys or runes. This is the reason for `scan` and `rules/gitleaks.toml`. *Verified 2026-10-02.*
- [trufflehog detectors](https://github.com/trufflesecurity/trufflehog/tree/main/pkg/detectors). None of the detectors is dedicated to LND macaroons, lndconnect, NWC, LNbits or runes; the only Bitcoin-related one is `bitcoinaverage`, a price API. *Verified 2026-10-02 (previously reported, not verified).*

## LND docs and API

- [LND docs/macaroons.md](https://github.com/lightningnetwork/lnd/blob/master/docs/macaroons.md). Confirms that the three default macaroons share one ID, describes invalidating them with `changepassword --new_mac_root_key` or by deleting `macaroons.db`, and that `macaroon:generate` is required to bake. *Verified 2026-10-02.*
- [LND macaroons/README.md](https://github.com/lightningnetwork/lnd/blob/master/macaroons/README.md). Covers `bakemacaroon` with entity:action and `uri:` permissions, `listmacaroonids` and `deletemacaroonid` (deleting an ID invalidates every macaroon derived from it). *Verified 2026-10-02.*
- [LND macaroons/store.go](https://github.com/lightningnetwork/lnd/blob/master/macaroons/store.go). `DefaultRootKeyID = "0"`, and `DeleteMacaroonID` returns `ErrDeletionForbidden` for it. `GenerateNewRootKey` (behind `changepassword --new_mac_root_key`) regenerates the default root key and every other root key ID ("Now iterate over all the other root keys that may exist and re-generate each of them"). *Verified 2026-10-02.*
- [LND rpcperms/interceptor.go](https://github.com/lightningnetwork/lnd/blob/master/rpcperms/interceptor.go). `MacaroonStreamServerInterceptor` checks the macaroon once, when a stream opens, so streams survive a revoke. *Verified 2026-10-02.*
- [LND lnrpc/routerrpc/router_server.go](https://github.com/lightningnetwork/lnd/blob/master/lnrpc/routerrpc/router_server.go) `macPermissions` and `MainRPCServerPermissions` in [rpcserver.go](https://github.com/lightningnetwork/lnd/blob/master/rpcserver.go). `/routerrpc.Router/SendPaymentV2` needs `offchain:write`, `/routerrpc.Router/TrackPaymentV2` `offchain:read`, `/lnrpc.Lightning/DecodePayReq` `offchain:read` (the `pay-only` preset); `HtlcInterceptor`, `UpdateChanStatus` and `UpdateChannelPolicy` need `offchain:write`; `ListInvoices` and `SubscribeInvoices` need `invoices:read`. *Verified 2026-10-02 (permission maps only).*
- LND REST proxy: it dials the gRPC listener, so `ipaddr`/`iprange` caveats see the proxy's (loopback) address for REST clients. *Reported, not verified* ([architecture.md](architecture.md#assumptions-to-confirm) assumption 5).
- [macaroon-bakery `bakery/checker.go`](https://github.com/go-macaroon-bakery/macaroon-bakery/blob/v3/bakery/checker.go) as used by LND's CheckMacaroonPermissions: with an empty permission list it may accept a macaroon whose caveats fail or whose signature is wrong; readings disagree. *Reported, not verified* (assumption 9).
- ListInvoices / SubscribeInvoices return payment preimages under `invoices:read` (lightning.proto `Invoice.r_preimage`). *Reported, not verified* (assumption 10).
- `getinfo` `version` has the form `0.21.4-beta commit=v0.21.4-beta`. *Reported, not verified* (assumption 11).
- [Lightning Terminal](https://github.com/lightninglabs/lightning-terminal) stores "super macaroon" root keys in LND's store with root key ID prefix `0xFFEEDDCC`. *Reported, not verified* (assumption 12; not found in `session/macaroon.go` or `litrpc/lit-sessions.proto` on 2026-10-02).
- [LND API reference](https://lightning.engineering/api-docs/api/lnd/). REST and gRPC reference for `BakeMacaroon`, `ListMacaroonIDs`, `DeleteMacaroonID`, `ListPermissions` and `CheckMacaroonPermissions`. *Page reachable 2026-10-02; individual endpoints not yet checked.*

- LND and macaroon source files checked for [architecture.md](architecture.md): [lnrpc/lightning.yaml](https://github.com/lightningnetwork/lnd/blob/master/lnrpc/lightning.yaml), [lnrpc/lightning.proto](https://github.com/lightningnetwork/lnd/blob/master/lnrpc/lightning.proto), [rpcserver.go](https://github.com/lightningnetwork/lnd/blob/master/rpcserver.go), [macaroons/constraints.go](https://github.com/lightningnetwork/lnd/blob/master/macaroons/constraints.go), [cmd_macaroon.go](https://github.com/lightningnetwork/lnd/blob/master/cmd/commands/cmd_macaroon.go), [go-macaroon v2](https://github.com/go-macaroon/macaroon/blob/v2/marshal-v2.go), [lndconnect spec](https://github.com/LN-Zap/lndconnect/blob/master/lnd_connect_uri.md). *Verified 2026-10-02.*

LND behaviour not yet confirmed against a running node is listed in [architecture.md](architecture.md#assumptions-to-confirm) under "Assumptions to confirm" (1–12).

## Release and tooling

- Pinned images, confirmed against the registry on 2026-10-02: `lightninglabs/lnd:v0.21.4-beta@sha256:04d06edcc0f6e99a5e797ea34959f330add222226f840cd86afbc31f8f29627d`, `lightninglabs/bitcoin-core:31.1@sha256:86e15e4348869a86343aacbbd1aff38e96cffddd87b61644694b1e1358d737cd`. *Verified 2026-10-02.*
- [gitleaks v8.30.1](https://github.com/gitleaks/gitleaks/releases) (latest release on 2026-10-02), image `zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f`. *Release and digest verified 2026-10-02.* That `--redact` keeps matched secrets out of its output and report is *reported, not verified* by reading its source; the gitleaks test suite (`npm run test:gitleaks`) checks it for the rule pack.
- GitHub Actions: [actions/checkout](https://github.com/actions/checkout) and [actions/setup-node](https://github.com/actions/setup-node) are pinned by commit SHA in `.github/workflows/`.
- [npm provenance and trusted publishing](https://docs.npmjs.com/generating-provenance-statements) and `npm audit signatures`. *Reported, not verified.* Current releases do not carry npm provenance; it applies once releases are published through trusted publishing from CI.

## BTCPay Server preset

The `btcpay` preset is pinned to **BTCPay Server v2.4.4**, server revision `2d5a0d8077bb33af080e949031da33d84b80638d`. Its [project dependency declaration](https://github.com/btcpayserver/btcpayserver/blob/2d5a0d8077bb33af080e949031da33d84b80638d/BTCPayServer/BTCPayServer.csproj) pins `BTCPayServer.Lightning.All` 1.7.8, whose LND dependency is `BTCPayServer.Lightning.LND` 1.7.2, client revision `62164e9394295bb27ebd06b769c6038f9277fb37`.

The independently captured inventory in `test/oracle/btcpay/manifest.json` attributes all LndClient ILightningClient operations, including payments, invoice cancellation, channels, balances, deposit addresses and peer helpers. The primary client sources are [LndClient.cs](https://github.com/btcpayserver/BTCPayServer.Lightning/blob/62164e9394295bb27ebd06b769c6038f9277fb37/src/BTCPayServer.Lightning.LND/LndClient.cs) (`client` below), [LndSwaggerClient.cs](https://github.com/btcpayserver/BTCPayServer.Lightning/blob/62164e9394295bb27ebd06b769c6038f9277fb37/src/BTCPayServer.Lightning.LND/LndSwaggerClient.cs), and [LndSwaggerClient.partial2.cs](https://github.com/btcpayserver/BTCPayServer.Lightning/blob/62164e9394295bb27ebd06b769c6038f9277fb37/src/BTCPayServer.Lightning.LND/LndSwaggerClient.partial2.cs). Uncalled generated endpoints, other backends, other versions and features outside this inventory are not claimed as supported.

Each method below is sent as its exact `uri:<method>` permission. The set grades **SPEND**, because OpenChannelSync and SendPaymentV2 can move funds. Permission mappings are pinned to LND `0.21.4-beta`, revision `390b2d2b7bdcc335c183962e483f5daeceb8f0e7`: [rpcserver.go](https://github.com/lightningnetwork/lnd/blob/390b2d2b7bdcc335c183962e483f5daeceb8f0e7/rpcserver.go) (`rpc`), [router_server.go](https://github.com/lightningnetwork/lnd/blob/390b2d2b7bdcc335c183962e483f5daeceb8f0e7/lnrpc/routerrpc/router_server.go) (`router`), and [invoices_server.go](https://github.com/lightningnetwork/lnd/blob/390b2d2b7bdcc335c183962e483f5daeceb8f0e7/lnrpc/invoicesrpc/invoices_server.go) (`invoices`). Source attribution is checked independently; live authorization is tested against the pinned regtest node and is not implied by this source inventory.

| Required method | Client source line | LND required permissions | Permission source line |
|---|---|---|---|
| `/invoicesrpc.Invoices/CancelInvoice` | client:413 | `invoices:write` | invoices:59 |
| `/lnrpc.Lightning/AddInvoice` | client:394 | `invoices:write` | rpc:399 |
| `/lnrpc.Lightning/ChannelBalance` | client:479 | `offchain:read` | rpc:379 |
| `/lnrpc.Lightning/ConnectPeer` | client:933 | `peers:write` | rpc:306 |
| `/lnrpc.Lightning/GetInfo` | client:443 | `info:read` | rpc:346 |
| `/lnrpc.Lightning/ListChannels` | client:421 | `offchain:read` | rpc:387 |
| `/lnrpc.Lightning/ListInvoices` | client:559 | `invoices:read` | rpc:407 |
| `/lnrpc.Lightning/ListPayments` | client:595 | `offchain:read` | rpc:459 |
| `/lnrpc.Lightning/LookupInvoice` | client:512 | `invoices:read` | rpc:403 |
| `/lnrpc.Lightning/NewAddress` | client:928 | `address:write` | rpc:294 |
| `/lnrpc.Lightning/OpenChannelSync` | client:871 | `onchain:write`, `offchain:write` | rpc:328 |
| `/lnrpc.Lightning/PendingChannels` | client:480, client:891 | `offchain:read` | rpc:383 |
| `/lnrpc.Lightning/SubscribeInvoices` | client:46 | `invoices:read` | rpc:411 |
| `/lnrpc.Lightning/WalletBalance` | client:478 | `onchain:read` | rpc:371 |
| `/routerrpc.Router/SendPaymentV2` | client:202, client:211, client:775 | `offchain:write` | router:91 |
| `/routerrpc.Router/TrackPaymentV2` | client:196 | `offchain:read` | router:99 |
