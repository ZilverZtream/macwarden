# Deep audit, fixes and additions, 2026-10-08

Scope: the whole codebase at `5f2c3ee` (not a diff), plus market research into what Lightning operators need. Every finding below was verified by code reading and a probe or test before it was fixed. Every fix has a test that fails on the code before the fix.

## 1. Reported issues

| Report | Verdict | Fix |
|---|---|---|
| Output rendered as one string (V8 string limit, memory) | Real. `render()` copied the whole result and stringified it once. The "blows the call stack" part was wrong: recursion depth follows nesting, not finding count. | Output streams in 64 KiB chunks, byte-identical to before, and the CLI waits for stdout `drain`. |
| PowerShell without TEMP/TMP | Not reproducible here: the query still worked with both removed. | Kept a defensive fallback to `<SystemRoot>\Temp`; tested by the environment passed. |

## 2. Audit findings fixed

Security:
- Windows `--out`: a handle opened before the ACL restriction could read the written macaroon. The file is now written only through an exclusive handle opened after `icacls`.
- `scan --git-history`: a `.git` gitfile, `commondir`, alternates or config include could point git at a network share (SMB, NTLM). Locations are validated before git starts, and git runs with `GIT_DIR`/`GIT_WORK_TREE` pinned.
- Grouped base64 redaction was quadratic (a 200 KB caveat took 52 s); now linear (0.15 s).

State correctness:
- A timed-out or reset BakeMacaroon/DeleteMacaroonID could still complete in LND after macwarden reported "nothing changed". Unknown outcomes now exit 7 with an executable recovery command.
- A failed claim-file cleanup leaked the registry lock; the registry rename was not durable on POSIX; registry validation was O(n²). All fixed.

Scale (measured before → after):
- 200,000-file tree: 384 s → 15 s. 999,800-entry history at 1 GiB heap: out-of-memory crash → 10 s.
- Hostile `.macwardenignore`: over 10 minutes → 0.6 s. Known-NWC-secret redaction: 28.8 s → 0.03 s.
- Scan now honours SIGINT/SIGTERM, keeps the exit status on a closed pipe (`| head`), and refuses shallow clones unless `--allow-shallow`.

Tests: mutation testing ran 97 deliberate bugs; 24 survived real gaps (lock recovery, protected-path symlinks, root key ID 0 refusals, registry save safeguards, git-history isolation, NWC alignments). Each now has a test that catches it. `--help` printed a literal `\x0a`; fixed, with per-command help.

## 3. Additions from research

Research report: industry needs, incidents (the August 2026 BTCPay macaroon theft), existing tools and gaps. Built:
- `watch`: read-only LND RPC middleware over gRPC; attributes every call to a credential without storing macaroon bytes; last-used data in `inventory`.
- Canary macaroons (`bake --canary`): denied and alerted on first permitted use while `watch` runs.
- `recommend`: least permissions from observed usage.
- `respond`: after a suspected leak, stage replacements for every credential, then `--finish` with proof old ones are rejected.
- `inventory --report markdown|csv|json`: access-review evidence; expiry columns and `--expiring-within`.
- `scan --format sarif|github`, `--agent-configs` (MCP and agent config files), TruffleHog rules; gitleaks pack no longer disables gitleaks' default rules.
- Actionable error messages, JSON schemas for every command, release metadata for npm trusted publishing, pre-commit hook.

Not built, by decision: spend caps and rate limits (Lightning Terminal accounts), NWC budgets (Alby Hub), CLN rune management, automatic root key 0 rotation (SAFE-02), NWC rotation (needs its own checkpoint and docs/security-model.md review).

A second independent review of the new features found 14 issues (no critical); all fixed, including a stalled stdout that could make `watch` hold every LND RPC. A source check of LND v0.21.4 (`macaroons/store.go`, `GenerateNewRootKey`) also showed that `changepassword --new_mac_root_key` regenerates every root key, not only ID 0; `respond` now says so and orders the regeneration before staging replacements.

## 4. Validation

Final candidate on Windows and Linux (`npm run test:full`), including every real-LND oracle:

| Platform | Unit + harness | Real-LND oracle | gitleaks |
|---|---|---|---|
| Windows | 2,000 / 2,001 | 249 / 249 | 2 / 2 |
| Linux (WSL, unprivileged) | 1,987 / 1,990 | 247 / 249 | 2 / 2 on native Docker |

The four unit failures were test defects exposed by the merge or by Linux, not product defects, and are fixed:
- an error-message test pinned the old inventory flag list;
- a Windows file-swap test let ext4 reuse the deleted file's inode;
- two process-domain tests used a Windows path that is not absolute on Linux.
Their files then pass on both platforms. The two Linux oracle failures are the gitleaks Docker cases, which need native WSL bind mounts; the oracle shards run through the Windows docker.exe interop, and the same cases pass on native Docker.

## 5. Red-team rounds before the 1.0.0 release

After a canary flood (an attacker holding a canary could make `watch` start one alert process per request) was found outside the audit, every later review used one threat model: attackers control the rate, volume, size, content and timing of every input they can reach, and every bound must be proven with a probe. Four red teams (network and `watch`, files and repositories, host and environment, abuse of features), a hostile-LND harness, a regression verifier that reran every probe before and after, a fresh adversarial audit and a final gate found and fixed:

- High: canary alert flood; Linux non-blocking stdout silencing `watch`; decoder permission expansion (61 KB file, 2 minutes, 1.3 GB); git-history fan-out (244 KB repository, 4.6 GB); `respond` turning canaries into ordinary credentials and hiding revoked-but-present IDs.
- Medium: alert commands ignoring SIGTERM or leaving children; usage store growth, flush stalls and eviction; `recommend` suggesting too-narrow or broader credentials; registry replacement cycles; stale and racing watch locks; workflow-command and bidi forging; regressions introduced by fixes (canary alerts dropped in bursts, header pre-allocation, unread-output hang, history locations lost).
- The final gate reran all 34 earlier probes against the release candidate (all fixed) and fuzzed frame splitting, the protobuf decoder (400,000 mutations), usage files, registries (20,000 tampered registries) and decode bounds with no findings.

Known limits, documented in SPEC: above about 160,000 RPCs per second per node, `watch` sheds attribution and its feedback latency approaches LND's 2 s intercept timeout; on Windows, children of an alert command that has already exited cannot be killed.
