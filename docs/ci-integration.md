# CI integration

No mainstream secret scanner (gitleaks, TruffleHog, GitHub secret scanning, GitGuardian) has a detector for LND macaroons, `lndconnect://` URIs or Nostr Wallet Connect strings. macwarden finds them, decodes macaroons offline and grades what they can do. This page shows how to run it in CI. The examples are not enabled in this repository.

Every format reports only location, kind, grade, fingerprint and root key ID. No format contains the matched credential.

## GitHub code scanning (SARIF)

Code scanning on a private repository needs GitHub Code Security. On public repositories it is free.

```yaml
# .github/workflows/macwarden.yml
name: macwarden
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      # The action tags here are illustrative: pin each action to a commit SHA in a real workflow.
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0            # full history for --git-history
      - uses: actions/setup-node@v5
        with:
          node-version: 22
      - run: npx --yes macwarden@1.3.0 scan . --git-history --format sarif > macwarden.sarif
        continue-on-error: true     # upload the results even when credentials were found
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: macwarden.sarif
          category: macwarden
```

Each result carries `partialFingerprints.macwardenFingerprint/v1`, so an alert keeps its identity when lines move. Accepted fingerprints go in `.macwardenignore`, as for any scan.

## GitHub annotations (free on private repositories)

```yaml
      - run: npx --yes macwarden@1.3.0 scan . --git-history --fail-on READ --format github
```

Each finding becomes an inline `::error`, `::warning` or `::notice` annotation on the file and line. `--fail-on READ` makes the job fail when any credential is found.

## Other CI systems

`--json` (or `--format json`) prints one JSON document described by `schemas/output/scan.schema.json`. `--fail-on <grade>` exits 1 when a finding is at or above the grade, so any CI system can gate on the exit code.

## Pre-commit

As a [pre-commit](https://pre-commit.com) hook, so a credential never reaches a commit. The hook runs an installed `macwarden` (`npm install -g macwarden@1.3.0`). Create an empty `.macwardenignore` at the repository root first.

```yaml
repos:
  - repo: https://github.com/ZilverZtream/macwarden
    rev: v1.3.0
    hooks:
      - id: macwarden-scan
```

The hook runs `macwarden scan --fail-on READ --ignore-file .macwardenignore` on the staged files. To accept a known test fixture, add its fingerprint (and optionally a path glob) to `.macwardenignore`. Parent directories are never searched for ignore files, so a file you did not name can never hide a finding.

## gitleaks and TruffleHog

If you already run one of these, add macwarden's detectors to it:

- gitleaks: `gitleaks dir . --config rules/gitleaks.toml --redact` (or `gitleaks git` for history). The pack extends gitleaks' default rules rather than replacing them. With the gitleaks GitHub Action, set `GITLEAKS_CONFIG` to the file. Always pass `--redact`: without it gitleaks prints and stores the credential it found.
- TruffleHog: `trufflehog filesystem . --config rules/trufflehog.yaml --no-verification`. TruffleHog prints matched secrets, so treat its output as sensitive.

These rule packs only find candidates. They cannot decode a macaroon or say what it can do; `macwarden scan` does both.

The packs are regular expressions over the literal credential prefixes, so they miss forms `scan` finds: hex split by separators (`02:01:03…`, `0x02, 0x01, …`), base64 that starts at a byte offset other than zero or is base64-encoded twice (a Kubernetes Secret holding a `.env`), UTF-16 text, a percent-encoded `nostr%2Bwalletconnect://` scheme, a bare NWC secret without its URI, and Core Lightning runes. Run `macwarden scan` as well where those can occur.

## Agent configurations

`macwarden scan --agent-configs` checks where AI agents and MCP clients keep their server credentials on the machine that runs it: Claude Desktop and Claude Code, Cursor, VS Code, Windsurf, Continue, Gemini CLI, Codex, Zed, lnget, and a project `.env`. A credential inside an MCP server entry is reported with `context: "mcp-config"` (text: `(MCP server config)`). Run it on developer machines and agent hosts, not only in CI.
