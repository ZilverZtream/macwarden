# Security policy

macwarden handles LND macaroons, which are bearer credentials that can move funds. Security reports are welcome and are handled with priority.

## Supported versions

| Version | Supported |
| --- | --- |
| Latest 1.x release | Yes |
| Older 1.x releases | No; upgrade to the latest 1.x release |
| 0.x and release candidates | No |

Fixes are released as a new 1.x version. The [CHANGELOG](CHANGELOG.md) lists what each release fixes.

## Report a vulnerability

Report vulnerabilities privately through GitHub security advisories: open the [Security tab of ZilverZtream/macwarden](https://github.com/ZilverZtream/macwarden/security) and choose **Report a vulnerability**, or go directly to <https://github.com/ZilverZtream/macwarden/security/advisories/new>. Do not open a public issue, pull request or discussion for a vulnerability.

Please include:

- the macwarden version (`macwarden --version`), Node.js version and operating system;
- the command and flags used, and whether it ran offline or against a node;
- what you observed and what you expected;
- a reproduction, preferably against a disposable regtest node.

Never send real credentials. Do not include a real macaroon, `lndconnect://` URI, Nostr Wallet Connect string, TLS key or seed in a report, in any encoding. A fingerprint printed by macwarden, a redacted excerpt or a regtest reproduction is enough. If a real credential was exposed while you investigated, treat it as compromised and revoke it on your node.

## What to expect

- An acknowledgement of your report, normally within 7 days.
- An assessment of severity and affected versions, shared with you in the advisory.
- A fix in a new release, followed by a published GitHub security advisory. We will agree a disclosure date with you and credit you in the advisory unless you prefer otherwise.

## Security guarantees

macwarden is built around a set of safety rules, SAFE-01 to SAFE-11, which are enforced in code and covered by tests. In summary:

- It never prints, logs or stores credential bytes; a credential appears only as a short SHA-256 fingerprint. The only file that holds a credential is one you asked it to write with `--out`, created owner-only and verified before the first byte is written.
- It never calls `changepassword`, never deletes root key ID 0, and never reads or writes `macaroons.db`, wallet passwords, seeds or TLS keys.
- Rotation is two steps: the replacement is created and verified first, and the old credential is revoked only after you confirm the switch.
- `inspect` and `scan` are offline and read-only. The only network peer is your own LND node, with TLS verification on. There is no telemetry.

The full rules, the threat model and what macwarden does not protect against are in [docs/security-model.md](docs/security-model.md).

## Verifying a release

Install a pinned version (`npm i -g macwarden@<exact version>`) and check registry signatures with `npm audit signatures` in a project that depends on macwarden. Current releases do not carry npm provenance; when releases are published through npm trusted publishing in the future, they will carry provenance that `npm audit signatures` verifies.

## Past audits

Independent audit reports, with every finding and the release that fixed it, are in [docs/reviews/](docs/reviews/README.md).
