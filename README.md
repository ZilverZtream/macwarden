# MacWarden

[![npm version](https://img.shields.io/npm/v/macwarden.svg)](https://www.npmjs.com/package/macwarden)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

MacWarden helps LND operators track issued credentials, detect exposures, and manage revocation and rotation with verification at each step. It brings established LND capabilities into one operational workflow.

It is a single command-line tool, `macwarden`, for teams that run LND behind BTCPay Server, LNbits, RTL, ThunderHub, their own backend or an AI agent. It talks only to your own LND node, sends no telemetry and has no runtime dependencies. It never prints a credential: a credential appears only as a short SHA-256 fingerprint.

## What it adds

Most of what MacWarden does online can also be done by hand with `lncli`. It adds a registry of what was issued to whom, verification after every change, and five capabilities that are not part of LND's own tooling:

- **Canaries.** Create decoy macaroons that LND rejects, with use alerts while `macwarden watch` runs. Place one where an attacker would look. Without `watch` running there is no alert, and requests that LND rejects before its RPC middleware runs are not seen. Alerts are grouped and rate-limited.
- **Usage-based narrowing.** Recommend narrower macaroon permissions from observed RPC usage, with observation coverage and warnings about rarely used methods. The recommendation covers the methods observed during the observation period; with less than 7 days of coverage it withholds the narrowing command unless you accept the short observation explicitly.
- **Lightning-aware scanning.** Detect LND macaroons, `lndconnect://` URIs and NWC connection strings in repositories, git history and supported agent configurations, with CI and SARIF output. No dedicated detector for LND macaroons, lndconnect or NWC was found in gitleaks, TruffleHog or GitHub's catalog (gitleaks has a rule for Fly.io macaroons). Rule packs for gitleaks and TruffleHog are included.
- **Core Lightning runes, offline.** `lightning-cli decode` already decodes a rune. MacWarden adds finding runes in files, git history and agent configurations without printing them, and a conservative assessment of what their restrictions may allow, graded on the same ladder from a method table pinned to Core Lightning v26.06.8. It never contacts a node about a rune, so whether the node accepts it (authenticity, blacklist, rate limits) is reported as unchecked.
- **Verified recovery.** After rotation, verify that the old root key is absent and the replacement is accepted, reporting direct credential rejection when it can be checked. The verification covers the selected credential on the node it was issued on, at the time of the check.

## Why it exists

In August 2026 an unauthenticated flaw in BTCPay Server let attackers download LND `.macaroon` files, and funds were stolen ([BTCPay Server 2.4.2 security advisory](https://blog.btcpayserver.org/security-advisory-btcpay-server-2-4-2/)). The fix closed the hole, but it could not invalidate the files already taken. Operators had to work out by hand which credentials existed, which apps used them, and how to replace them without breaking payments.

That is hard with LND alone:

- **LND keeps no record of what it issued.** `listmacaroonids` returns bare numbers; who holds which macaroon is up to you ([lnd#10594](https://github.com/lightningnetwork/lnd/issues/10594)).
- **Most macaroons cannot be revoked one at a time.** Anything baked without `--root_key_id`, including `admin.macaroon`, shares root key 0, which LND will not delete.
- **Rotation is easy to get wrong.** Operators have locked themselves out by deleting `macaroons.db` or renaming files ([btcpayserver-docker#1112](https://github.com/btcpayserver/btcpayserver-docker/issues/1112), [lnd#11049](https://github.com/lightningnetwork/lnd/issues/11049)).

## Install

MacWarden needs Node.js 22.23.2 or later on the 22 line, 24.18.1 or later on the 24 line, or 26.5.1 or later.

```sh
npm i -g macwarden
```

On production hosts, install an exact version and check the registry signatures of what you installed with `npm audit signatures` in a project that depends on MacWarden:

```sh
npm i -g macwarden@1.2.0
```

After installing on a new host or upgrading, the [field check](docs/field-check.md) confirms a release against your own node in about 15 minutes.

## Quick start

### Check a repository (offline)

No node and no credentials are needed:

```sh
macwarden scan . --git-history --fail-on READ
```

It exits 1 if it finds a credential at or above the grade you set, and 0 if it finds none. To accept a known test fixture, add its fingerprint to `.macwardenignore`.

In GitHub Actions:

```yaml
- uses: actions/checkout@v5
  with:
    fetch-depth: 0
- run: npx --yes macwarden@1.2.0 scan . --git-history --fail-on READ --format github
```

[CI integration](docs/ci-integration.md) covers SARIF upload for GitHub code scanning, the pre-commit hook and the gitleaks and TruffleHog rule packs.

To see what a single macaroon can do, offline:

```sh
macwarden inspect ./btcpay.macaroon
```

### L402 tokens (offline)

L402 (formerly LSAT) tokens pay for access to an API: a macaroon issued by the service, such as one behind [Aperture](https://github.com/lightninglabs/aperture), plus the preimage of the Lightning invoice that paid for it. `inspect` reads an `Authorization: L402 …` or legacy `LSAT` value, a `WWW-Authenticate` challenge, a `macaroon:preimage` pair, a bare L402 macaroon or a client token store file such as lnget's `~/.lnget/tokens/<domain>/l402.token`. It reports the payment hash and token ID, the services, capabilities and expiry from the caveats, and whether the preimage hashes to the payment hash, without printing the preimage or the macaroon. An L402 token gives access to a service, not control of a node: it is reported as `service-access`, never on the ADMIN to READ ladder. `scan` finds these forms in files, HTTP logs, HAR files and git history; `--fail-on READ` counts a token whose preimage is present, and a challenge or pending token, which grants nothing alone, is reported but not counted. Only the issuing service can revoke a token.

```sh
macwarden inspect ./lnget/tokens/api.example.com/l402.token
macwarden scan . --fail-on READ
```

### Core Lightning runes (offline)

A Core Lightning rune is URL-safe base64 with no fixed prefix, so `scan` looks for runes only in rune context: a rune key in env files, shell, JSON, YAML, TOML, code and agent configurations (`RUNE=…`, `CLN_RUNE=…`, `"rune": …`), clnrest's `Rune:` header, the base64 of a rune in a Kubernetes Secret, and checkable runes passed to `lightning-cli commando`, `checkrune` or `showrunes`. A value in rune key context that does not parse is reported as `rune-invalid` (`UNASSESSED`) rather than dropped. `inspect` reads a rune from a file or stdin and reports its unique ID, restrictions, the methods they may allow and the resulting grade on the same ladder as macaroons, from a method table pinned to Core Lightning v26.06.8; a capability is excluded only when the restrictions prove it cannot be used. Nothing is sent to a node: whether it would accept the rune is reported as unchecked, and a rune is revoked with `lightning-cli blacklistrune`. The rune, its authenticator and the decoded string never appear in any output.

```sh
macwarden inspect ./cln.rune
macwarden scan . --fail-on OPERATE
```

### Manage a node (online)

MacWarden runs with a macaroon of its own. Because that macaroon can bake other macaroons, it is admin-equivalent: make it short-lived and keep it out of application configs.

```sh
lncli bakemacaroon --root_key_id 123456789 --timeout 3600 \
  --save_to ./macwarden-session.macaroon \
  macaroon:generate macaroon:read macaroon:write info:read

export MACWARDEN_LND_REST=127.0.0.1:8080
export MACWARDEN_TLS_CERT=~/.lnd/tls.cert
export MACWARDEN_MACAROON=./macwarden-session.macaroon

macwarden inventory --verify
macwarden bake --label btcpay --preset btcpay --out ./btcpay.macaroon
macwarden rotate btcpay --out ./btcpay-next.macaroon
# switch BTCPay to btcpay-next.macaroon, then:
macwarden rotate btcpay --finish
```

Pick an unused root key ID (check `lncli listmacaroonids`) and run `lncli deletemacaroonid 123456789` when the session is over. The node address, certificate and credential come from one place: all from the `MACWARDEN_*` variables, or all from `--lnd-rest`, `--tls-cert` and `--macaroon`. Mixing the two is refused (exit 2), so a credential exported for one node is never sent to a node named on the command line.

`inventory` shows every root key ID on the node against the registry:

```text
$ macwarden inventory --verify
node 03f2a1c97b5e4d0e8a6b9f31c2d47e5a0b8c6d2e9f1a3b5c7d9e0f2a4b6c8d0e1f (shop-node) mainnet
ROOT KEY ID  LABEL      GRADE    AGE  EXPIRES     STATUS
0            —          —        —    —           default root key: cannot be individually revoked
4294967341   btcpay     RECEIVE  41d  —           active; accepted; last used 2026-10-08T09:12:44Z (18324 calls)
4294967342   lnbits     SPEND    12d  2026-10-26  active; accepted; expires in 17d; rotate with: macwarden rotate lnbits --out /home/op/lnbits-2026-10-09.macaroon
4294967355   ci-reader  READ     3d   2026-10-07  active; expired; revoke with: macwarden revoke ci-reader
9187201950   —          —        —    —           unknown — not in this registry (another tool or operator may own it)
```

To move existing apps off `admin.macaroon` and root key 0, follow [Replacing the default macaroons](docs/replacing-default-macaroons.md). It covers the maintenance window, the one step only the operator can do, and how to confirm nothing is left behind.

### After a suspected leak

Patching the hole does not invalidate copied files: LND keeps accepting a copied macaroon until its root key ID is deleted or every root key is regenerated. Check each file that may have been exposed:

```sh
macwarden verify /path/to/old/btcpay.macaroon
# exit 1: LND still accepts it, or rejects it for a reason that may not hold for every caller or copy.
# exit 0: LND rejects it conclusively. The output says what to run next in either case.
```

To know which credential spent what, run `watch` with a payment journal and reconcile it against the node later:

```sh
macwarden watch --payment-journal ./payments.journal      # as a supervised service
macwarden reconcile --payment-journal ./payments.journal --since 7d
```

The journal records, for each SendPaymentV2 and SendToRouteV2 call, the caller's credential ID and root key ID, the payment hash, the requested amount and the fee limit, and it records every period in which `watch` was not registered. It never stores the invoice text, preimages or macaroons. `reconcile` then asks LND (read-only, `info:read` and `offchain:read`) how each journaled payment ended: settled amount, routing fees over all attempts, failure reason, or still in flight. It keeps the two kinds of evidence apart: a journaled request is not a payment, and a payment LND lists in a period the journal does not cover is reported as unattributed with that gap, never assigned to anyone. Exit 0 means the window was fully covered and everything matched; exit 1 lists what did not.

The [incident playbook](docs/incident-playbook.md) walks through the whole response: what patching fixes, replacing and revoking credentials with `respond`, `rotate` and `revoke`, what to do about root key 0, re-pairing apps and checking for unauthorized activity.

## Commands

`macwarden --help` lists every command and `macwarden <command> --help` shows its options. Every command accepts `--json` and prints one document whose shape is published as a JSON Schema in `schemas/output/<command>.schema.json`.

Offline:

- `inspect` decodes a macaroon, `lndconnect://` URI, Nostr Wallet Connect string or Core Lightning rune and grades what it can do: `ADMIN`, `SPEND`, `OPERATE`, `RECEIVE` or `READ`. It also decodes L402 (LSAT) tokens, which it reports as service access.
- `scan` finds macaroons, `lndconnect://` URIs, NWC strings, L402 tokens and Core Lightning runes (in rune context: `RUNE=…`, `"rune": …`, clnrest's `Rune:` header, `lightning-cli commando …`) in files and directories; `--git-history` also reads every blob ever committed on any branch, and `--agent-configs` checks the files where AI agents and MCP clients keep credentials. `--fail-on <grade>` fails a build; `--format sarif|github` reports for CI.
- `attenuate` adds an expiry or IP lock to a copy of a macaroon.

Online (against your LND node):

- `inventory` lists every root key ID on the node against the registry: owner label, grade, age, expiry, last use, and flags for anything unknown, expired or on root key 0. `--verify` asks LND whether each recorded macaroon is still accepted; `--report markdown|csv|json` writes an access-review record for internal reviews or audits.
- `bake` issues one macaroon per app, each on its own fresh root key ID so it can be revoked alone, from presets (`read-only`, `invoice-only`, `pay-only`, `btcpay`) or explicit permissions, with an optional expiry. LND verifies it before it is written. `--canary` creates a decoy.
- `revoke` deletes a credential's root key ID and confirms that LND now rejects it.
- `rotate` replaces a credential in two steps: stage a verified replacement, switch the app, then `--finish` to revoke the old one.
- `watch` registers a read-only LND RPC middleware that attributes each call to the credential that made it, records last use without storing macaroon bytes, and guards canaries. With `--payment-journal <file>` it also journals each payment request with the credential that made it.
- `reconcile` compares that payment journal with LND's payment records: per credential, what was requested, settled and paid in fees, and which payments LND made that no journal entry explains.
- `recommend` suggests a narrower permission set from what `watch` observed, with the commands to apply it.
- `verify` asks the node whether one credential file is still accepted.
- `respond` stages a replacement for every registered credential in one confirmed batch; `respond --finish` revokes the old root key IDs and reports, per credential, that the old one is rejected and the new one accepted.

Every command that changes the node has `--dry-run`. `revoke`, `rotate --finish` and `respond` ask for a typed confirmation. An interrupted run prints the exact command that completes or undoes it.

## Safety guarantees

These rules are enforced in code and covered by tests; [docs/security-model.md](docs/security-model.md) defines them as SAFE-01 to SAFE-11 and describes the threat model.

- It never prints, logs or stores credential bytes. The only file that holds a credential is one you asked for with `--out`. It is never overwritten and is owner-only before its first byte: the `0600` mode or the Windows owner-only ACL is read back and verified, and the command fails without writing when the file system cannot keep it (for example WSL's `/mnt/c`). A Windows FAT or exFAT volume, which stores no permissions, is written with a warning.
- It never calls `changepassword`, never deletes root key ID 0, and never reads or writes `macaroons.db`, wallet passwords, seeds or TLS keys.
- Rotation has two steps. The stage step bakes the replacement and verifies that LND accepts it, and changes nothing else. The old credential keeps working until you run `--finish`, which revokes it and then checks that LND rejects it and still accepts the replacement. A failure at any point before the revoke leaves the old credential valid.
- When the outcome of a change is uncertain (a timeout or a dropped connection), it says so, exits 7 and prints the command to reconcile. It reports "nothing changed" only when it has checked.
- `inspect` and `scan` are offline and read-only. The only network peer is your LND node, with TLS verification against its certificate. There is no telemetry.

## Compatibility

| | |
| --- | --- |
| LND | 0.21.x. Every online command is tested against a pinned LND v0.21.4-beta regtest node. |
| Platforms | Linux and Windows, tested before each release. macOS should work but is not tested. |
| Node.js | 22.23.2+, 24.18.1+ or 26.5.1+ (the July 2026 security releases, which fix HTTP/2 flaws CVE-2026-56846 and CVE-2026-56848 in the module `watch` uses). No runtime dependencies. |
| Transport | REST over HTTPS; `watch` uses gRPC. For a Tor-only node, tunnel to localhost over SSH. |

The online commands are for LND only. Core Lightning runes are decoded by `inspect` and found by `scan`, offline; creating, listing and blacklisting runes stays with `lightning-cli` (`createrune`, `showrunes`, `blacklistrune`). LNbits keys, Eclair and LDK are not supported. Nostr Wallet Connect strings are decoded and found by `scan`, but NWC connections are revoked in the wallet service. L402 tokens are decoded and found by `scan`; they are revoked by the service that issued them.

## How it compares

| Tool | What it covers | Relation to MacWarden |
| --- | --- | --- |
| `lncli` | `printmacaroon`, `bakemacaroon`, `listmacaroonids`, `deletemacaroonid`, `constrainmacaroon`: every primitive MacWarden uses | MacWarden calls the same LND APIs and adds the registry, verification after each change and the stage-then-finish order |
| Lightning Labs macaroon-bakery (lightning-agent-tools) | Role presets for baking, `--inspect`, `--list-permissions` | A good fit for one agent that needs one scoped macaroon; no inventory, revocation workflow or scanning |
| [ln-service](https://github.com/alexbosworth/ln-service) | Node.js library for LND with `grantAccess`, `getAccessIds`, `revokeAccess`, `verifyAccess` and RPC request subscriptions | Building blocks for your own tooling; MacWarden is a finished CLI workflow with a registry |
| [Amboss lnd-macaroon](https://github.com/AmbossTech/lnd-macaroon) | npm library and small CLI that decodes a hex macaroon into its entity/action permissions and helps check them | Comparable to `macwarden inspect`; MacWarden adds risk grading, caveat decoding and the online workflow |
| [`macaroon`](https://www.npmjs.com/package/macaroon) npm library | Generic macaroon creation, caveats, verification and serialization | Not LND-aware; MacWarden implements LND's format and grading itself, without runtime dependencies |
| [Lightning Terminal](https://github.com/lightninglabs/lightning-terminal) | Accounts with per-app spending limits; Lightning Node Connect sessions with their own permissions, expiry and revocation | Use accounts for spending limits. MacWarden manages plain LND macaroons and does not replace accounts or LNC |

## Limits

- A clean `scan` is not proof that nothing leaked. Encrypted, archived or unusually encoded credentials can be missed, and git history covers only what is present in your local clone.
- Revoking a credential blocks new requests. Streams opened before the revoke, such as an invoice subscription, stay open until they disconnect; restart LND if a compromised credential may hold one.
- While `watch` is registered, LND waits for it on every RPC. Run it as a supervised service and never enable `rpcmiddleware.addmandatory`. Its own work is bounded whatever callers do: canary alerts are rate-limited, at most one alert command runs (stopped after 12 s), and usage data keeps at most 20,000 records.
- On nodes run with `--no-macaroons`, stateless init or a remote signer, MacWarden sees only part of the picture.
- A rune is found only in rune context (a rune key, the `Rune` header, or a `lightning-cli commando`/`checkrune` argument); a bare rune in prose is not. Its grade is an upper bound from its encoded restrictions: macwarden does not know whether the node issued it, blacklisted it or would accept it now.
- Root key 0 (`admin.macaroon` and the other default macaroons) cannot be revoked on its own; only regenerating every root key invalidates it, and MacWarden leaves that step to the operator.

## Documentation

- [Incident playbook](docs/incident-playbook.md): what to do when macaroon files may have been copied
- [Replacing the default macaroons](docs/replacing-default-macaroons.md): moving every app onto its own macaroon
- [CI integration](docs/ci-integration.md): GitHub Actions, SARIF, pre-commit, gitleaks and TruffleHog
- [Field check](docs/field-check.md): a short, safe procedure to confirm a release against your own node
- [Safe agent payments example](examples/agent-payments/README.md): a regtest stack where an agent pays an L402 API with a scoped, expiring macaroon, and is then cut off with proof
- [Payment lab](examples/payment-lab/README.md): a three-node regtest lab that recovers a payment after a dropped connection, processes settlements once, diagnoses directional liquidity and reconciles fees across attempts
- [Specification](docs/spec.md): every command, flag, grade, exit code and output format
- [Security model](docs/security-model.md): the SAFE rules and the threat model
- [Architecture](docs/architecture.md): how it is built and the LND facts it relies on
- [References](docs/references.md): the external sources behind the design
- [Audit reports](docs/reviews/README.md): independent audits and the releases that fixed their findings
- [CHANGELOG](CHANGELOG.md): release notes

## Contributing and security

Source and issues: https://github.com/ZilverZtream/macwarden. [CONTRIBUTING.md](CONTRIBUTING.md) explains how to build and test MacWarden locally and how changes are made. Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), never in a public issue.

## License

MIT. See [LICENSE](LICENSE).
