# Contributing to MacWarden

Thank you for helping. MacWarden handles credentials that can move funds, so changes are held to a strict standard: every behaviour is specified, every fix is tested, and no real credential ever enters the repository, an issue or a pull request.

Before you start on a larger change, open an issue to discuss it. The [specification](docs/spec.md) is the contract for every command; a change in behaviour starts with a change to the specification.

## Prerequisites

- **Node.js** in one of the ranges in `package.json` `engines`: 22.23.2 or later on the 22 line, 24.18.1 or later on the 24 line, or 26.5.1 or later.
- **Git.**
- **Docker**, for the regtest oracle tests and the gitleaks tests. They start a pinned `lightninglabs/lnd:v0.21.4-beta` node with `bitcoind` on regtest, and the pinned gitleaks image. Unit and harness tests do not need Docker.
- **Linux or Windows.** Both are tested before each release. macOS should work for development but is not part of release validation.

### WSL notes

- Clone into the Linux file system (for example `~/src/macwarden`), not under `/mnt/c`. Files on `/mnt/c` cannot keep `0600` permissions, so the owner-only file tests fail there, as MacWarden itself does.
- Run the tests as an ordinary user. Full validation refuses to run as root on Linux, because root bypasses the permission checks the tests rely on.
- For Docker, enable Docker Desktop's WSL integration for your distribution, or install Docker Engine inside it, so that `docker` works from the WSL shell.

## Setup

```sh
git clone https://github.com/ZilverZtream/macwarden.git
cd macwarden
npm ci
npm run build
```

`npm run build` compiles `src/` to `dist/` and type-checks the tests. Run the CLI you built with `node dist/bin.js --help`.

## Tests

| Command | What it runs | Needs |
| --- | --- | --- |
| `npm test` | The product unit tests (builds first) | Node.js |
| `npm run test:harness` | Tests of the test tooling, documentation consistency and repository configuration | Node.js |
| `npm run test:related -- <files>` | The tests related to the files you changed, while you work | Node.js |
| `npm run fixture:up`, `npm run test:oracle`, `npm run fixture:down` | The oracle tests against a pinned regtest LND node; the fixture refuses any other network or LND version | Docker |
| `npm run fixture:cln:up`, `npm run test:cln-oracle`, `npm run fixture:cln:down` | The Core Lightning rune comparison tests against a pinned regtest Core Lightning v26.06.8 node (native `decode`, `help`, `checkrune`); the fixture publishes no port | Docker |
| `npm run fuzz:runes` | Long property fuzz of rune decoding, assessment and scan context (the properties of `test/rune-fuzz.test.ts`, which runs a short seeded profile with every `npm test`): `RUNE_FUZZ_CASES` (default 200,000) and `RUNE_FUZZ_SEED` (printed; random by default); a failure names its seed and case index, and `RUNE_FUZZ_START` reruns from that index | Node.js |
| `node scripts/cln-rune-campaign.mjs --runes <n>` | The differential rune campaign against the Core Lightning fixture at any size (after `npm run build` and `npm run fixture:cln:up`): created runes against native `decode`, mutated copies against `checkrune`'s parser, random requests against `checkrune` | Docker |
| `npm run test:gitleaks` | Runs the pinned gitleaks image (always with `--redact`) with `rules/gitleaks.toml` over the scan fixtures | Docker |
| `npm run test:full` | Everything on the current platform: build, lint, unit and harness tests, both oracle shards on their own regtest nodes, the Core Lightning rune comparison on its own regtest node (fixture up, `test:cln-oracle`, fixture down, recorded as `oracle-cln`), gitleaks, leak checks over all output, a check that no test is skipped, and a check that the inputs did not change during the run | Docker; Windows or Linux as an ordinary user; a clean, committed working tree |
| `npm run lint` | ESLint, including the credential-boundary rules | Node.js |

Always run `npm run fixture:down` after the oracle tests, and `npm run fixture:cln:down` after the rune comparison tests, also when they fail. `node scripts/rune-false-positives.mjs` (after `npm run build`) measures how often rune scanning reports values that are not runes, and how often it misses runes in the supported contexts. `npm run test:full` starts and stops its own fixtures and writes its evidence to `.ratchet/evidence/full/` (ignored by git). It takes a while: on Windows the unit phase alone needs several minutes. `MACWARDEN_VALIDATION_TIMEOUT_MS` (up to 600000) and `MACWARDEN_ORACLE_TIMEOUT_MS` (up to 2400000) bound each command.

Pull requests need `npm run lint`, `npm run build`, `npm test` and `npm run test:harness` to pass. Changes to online commands also need the oracle tests, changes to the scan patterns or rule packs need `npm run test:gitleaks`, and changes to rune parsing, assessment or the method table need the rune comparison tests.

### Leak tests

The test suite registers sentinel credentials (`test/sentinels.json`) and checks that none of them appears, in any common encoding, in command output, temporary files or test reports. A test that writes a credential on purpose must declare that output file. If a leak check fails, treat it as a real leak until you have shown otherwise.

### Platform variants

A few tests only make sense on one platform (POSIX permissions, Windows ACLs, shell quoting). They are selected by name in [scripts/platform-variants.mjs](scripts/platform-variants.mjs), which both `vitest.config.ts` and full validation read. Each excluded file names a counterpart that runs instead and a case it must pass. Never skip a test at runtime: no `.skip`, `.only`, `.todo`, `skipIf` or `runIf`. Full validation fails if a test file contains `.skip`, `.only` or `.todo`, or if any test is reported as skipped, and reviewers reject runtime conditions.

### Test names

Test titles start with an identifier such as `CP-031/FI-7`, `RR-111/walk-windows` or `MW110-03`, and some files are named after one (`cp031-*.test.ts`). These are historical identifiers from the development plan, the review rounds and the audits; the changelog and the [audit reports](docs/reviews/README.md) refer to them. Keep existing identifiers unchanged. For new tests, use a descriptive title, and the audit finding ID when a test covers a finding.

## Rules for changes

- **Test first.** Every fix comes with a test that fails on the code before the fix and passes after it. Every new behaviour comes with tests for its specification, including the failure paths.
- **Never weaken a test to make code pass.** Do not delete, skip, loosen or retitle a test because the code fails it, and do not raise a timeout or limit to hide a slow or hanging test. If you believe a test is wrong, explain why in the pull request and change it in its own commit.
- **Keep the specification and the code in step.** A change in behaviour updates [docs/spec.md](docs/spec.md), the `--help` text and the README together; a documentation test checks that they agree.
- **Keep the safety rules.** The SAFE rules in [docs/security-model.md](docs/security-model.md) are not changed to make code pass. A pull request that touches one needs a clear security argument.
- **No runtime dependencies.** MacWarden uses Node.js built-ins only. Development dependencies are pinned exactly.
- **Regenerate the output schemas** with `node scripts/output-schemas.mjs` when a `--json` shape changes, and check them with `node scripts/output-schemas.mjs --check`.

## Credential safety

- Never put a real credential in an issue, pull request, commit, test, fixture, log or screenshot: no macaroon, `lndconnect://` URI, Nostr Wallet Connect string, TLS key or seed, in any encoding. Never paste one into an AI assistant or any other third-party service.
- Tests use synthetic vectors and throwaway credentials from a disposable regtest node only (`test/vectors/`, generated by `scripts/make-vectors.mjs`). Read vectors by path, and refer to credentials by their fingerprint.
- When you report a problem, a fingerprint printed by MacWarden, a redacted excerpt or a regtest reproduction is enough.
- Run gitleaks only with `--redact`; without it gitleaks prints and stores the matched credential.
- A real credential that was ever exposed is compromised. Revoke it on the node; deleting the text is not enough.

## Commits and pull requests

- Write commit messages that describe the resulting behaviour, for example "rotate refuses a replacement whose root key ID was already revoked", not the steps you took. Use the body to explain why.
- Keep each commit to one logical change, with its tests.
- Keep commit messages to the change itself: no tool-generated trailers or notices.
- Fill in the pull request template, including how you tested the change.

## Security reports

Do not report a vulnerability in a public issue or pull request. Use GitHub's private vulnerability reporting as described in [SECURITY.md](SECURITY.md). Reports are handled privately until a fix is released and an advisory is published.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
