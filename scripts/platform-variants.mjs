// Platform test variants, selected by contract and never by a capability probe.
// vitest.config.ts excludes these files and scripts/full-validation.mjs proves
// that each excluded file's counterpart ran its required case. A selected
// filesystem test fails if its required capability is unavailable.
//
// Every entry names the excluded file, why it does not run on this platform, the
// counterpart file that runs instead, and the case ID that counterpart must pass.
// Unknown platform suffixes stay required, so a new suffix alone cannot hide a test.

/**
 * @param {NodeJS.Platform} [platform]
 * @returns {{ file: string, reason: string, counterpart: string, requiredCase: string }[]}
 */
export function platformVariants(platform = process.platform) {
  const linux = platform === 'linux';
  if (platform === 'win32') return [
    { file: 'test/input.real-fs.test.ts', reason: 'POSIX unprivileged permission variant',
      counterpart: 'test/input.test.ts', requiredCase: 'CP-006/B7' },
    { file: 'test/cp040-modes.linux-fs.test.ts', reason: 'Linux unprivileged 0600/0700 filesystem variant',
      counterpart: 'test/cp040-acl.windows-fs.test.ts', requiredCase: 'CP-040/B10-strict-platform' },
    { file: 'test/shell-quote.posix.test.ts', reason: 'POSIX shell quoting variant',
      counterpart: 'test/shell-quote.windows.test.ts', requiredCase: 'RECOVERY/shell-quote' },
    { file: 'test/watch-alert-process.posix.test.ts', reason: 'POSIX process-group alert variant',
      counterpart: 'test/watch-alert-tree.windows.test.ts', requiredCase: 'WATCH/alert-tree-windows' },
    { file: 'test/rr111-walk.linux-fs.test.ts', reason: 'Linux file names (backslash, case-sensitive) and FIFO variant',
      counterpart: 'test/rr111-walk.windows-fs.test.ts', requiredCase: 'RR-111/walk-windows' },
    { file: 'test/redteam-file-names.posix.test.ts', reason: 'POSIX file names with a colon and bidi controls, which Windows refuses',
      counterpart: 'test/redteam-files.test.ts', requiredCase: 'RED-TEAM/forging' },
  ];
  return [
    { file: 'test/cp023-acl.windows-fs.test.ts', reason: 'Windows ACL variant',
      counterpart: 'test/registry.test.ts', requiredCase: 'CP-017/B5' },
    { file: 'test/cp036-protected-streams.windows-fs.test.ts', reason: 'Windows stream variant',
      counterpart: 'test/cp036-protected-paths.test.ts', requiredCase: 'CP-036/A8-protected-input-scan' },
    { file: 'test/sidecar-private.windows-fs.test.ts', reason: 'Windows owner-only sidecar (registry, usage, canary, journal) variant',
      counterpart: 'test/payment-journal.test.ts', requiredCase: 'PAYJ/open refusals' },
    { file: 'test/private-file-leftover.windows-fs.test.ts', reason: 'Windows helper leftover-file removal variant',
      counterpart: 'test/private-file-outcome.test.ts', requiredCase: 'PRIVATE-FILE/helper-exit' },
    { file: 'test/cp038-acl.windows-fs.test.ts', reason: 'Windows ACL failure-path variant',
      counterpart: 'test/cp038-online.test.ts', requiredCase: 'CP-038/B7-spec-output' },
    { file: 'test/cp039-acl.windows-fs.test.ts', reason: 'Windows absolute-icacls variant',
      counterpart: 'test/cp039-scan.test.ts', requiredCase: 'CP-039/B9-protected-limits' },
    { file: 'test/cp040-acl.windows-fs.test.ts', reason: 'Windows System32 icacls owner-only ACL variant',
      counterpart: linux ? 'test/cp040-modes.linux-fs.test.ts' : 'test/harness/cp040-readiness.test.ts',
      requiredCase: 'CP-040/B10-strict-platform' },
    ...(linux ? [] : [{ file: 'test/cp040-modes.linux-fs.test.ts',
      reason: 'Linux-only unprivileged 0600/0700 proof; other platforms establish portable strict configuration only',
      counterpart: 'test/harness/cp040-readiness.test.ts', requiredCase: 'CP-040/B10-strict-platform' }]),
    { file: 'test/shell-quote.windows.test.ts', reason: 'PowerShell quoting variant',
      counterpart: 'test/shell-quote.posix.test.ts', requiredCase: 'RECOVERY/shell-quote' },
    { file: 'test/watch-alert-tree.windows.test.ts', reason: 'Windows taskkill alert-tree variant',
      counterpart: 'test/watch-alert-process.posix.test.ts', requiredCase: 'WATCH/alert-kill' },
    { file: 'test/rr111-walk.windows-fs.test.ts', reason: 'Windows separator and case-insensitive name variant',
      counterpart: linux ? 'test/rr111-walk.linux-fs.test.ts' : 'test/rr111-walk.test.ts',
      requiredCase: linux ? 'RR-111/walk-linux' : 'RR-111/walk-portable' },
    ...(linux ? [] : [{ file: 'test/rr111-walk.linux-fs.test.ts',
      reason: 'Linux-only file name and FIFO proof; other platforms run the portable walk cases',
      counterpart: 'test/rr111-walk.test.ts', requiredCase: 'RR-111/walk-portable' }]),
    { file: 'test/out-private.windows-fs.test.ts', reason: 'Windows owner-only creation and output-name variant',
      counterpart: 'test/cp023-acl-principal.test.ts', requiredCase: 'RO-1/acl-verified' },
    { file: 'test/out-registry-case.windows-fs.test.ts', reason: 'Windows case-folding file system variant (a real bake)',
      counterpart: 'test/out-registry-collision.test.ts', requiredCase: 'OUT-REGISTRY/case-rule' },
    { file: 'test/lnd-audit-env-case.windows-fs.test.ts', reason: 'Windows case-insensitive environment names (the built CLI)',
      counterpart: 'test/cli-runtime.test.ts', requiredCase: 'ENV-CASE/portable' },
    { file: 'test/githist-audit-alias.windows-fs.test.ts', reason: 'Windows 8.3 short-name alias of a protected file (git history location check)',
      counterpart: 'test/githist-audit-location.test.ts', requiredCase: 'githist-audit/alias' },
  ];
}

/**
 * Platform-specific files that must run on this platform. Every platform-suffixed test file
 * is either here or excluded by platformVariants (test/harness/tooling-audit-platform.test.ts),
 * and full validation fails when a file here did not run and pass (validation-support.mjs).
 * @param {NodeJS.Platform} [platform]
 * @returns {string[]}
 */
export function requiredPlatformFiles(platform = process.platform) {
  return ['test/scan-walk.permission.real-fs.test.ts', 'test/scan-walk.symlink.real-fs.test.ts',
    ...(platform === 'win32'
      ? ['test/cp023-acl.windows-fs.test.ts', 'test/cp036-protected-streams.windows-fs.test.ts',
        'test/cp038-acl.windows-fs.test.ts', 'test/cp039-acl.windows-fs.test.ts',
        'test/cp040-acl.windows-fs.test.ts', 'test/shell-quote.windows.test.ts', 'test/watch-alert-tree.windows.test.ts',
        'test/rr111-walk.windows-fs.test.ts', 'test/out-private.windows-fs.test.ts',
        'test/sidecar-private.windows-fs.test.ts', 'test/private-file-leftover.windows-fs.test.ts',
        'test/out-registry-case.windows-fs.test.ts', 'test/lnd-audit-env-case.windows-fs.test.ts',
        'test/githist-audit-alias.windows-fs.test.ts']
      : ['test/input.real-fs.test.ts', 'test/shell-quote.posix.test.ts', 'test/watch-alert-process.posix.test.ts',
        'test/redteam-file-names.posix.test.ts',
        ...(platform === 'linux' ? ['test/cp040-modes.linux-fs.test.ts', 'test/rr111-walk.linux-fs.test.ts'] : [])])];
}
