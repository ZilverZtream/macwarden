/** The Node versions package.json's engines field allows: ^22.23.2 || ^24.18.1 || >=26.5.1 (July 2026 security releases). */
export const SUPPORTED_NODE = '22.23.2 or later 22.x, 24.18.1 or later 24.x, or 26.5.1 or later';
/** The warning watch raises on a Node release outside the supported ranges, or null. */
export function nodeVersionWarning(version: string): { code: 'unsupported-node'; message: string } | null {
  if (supportedNode(version)) return null;
  return { code: 'unsupported-node', message: `Node ${version} is outside the supported releases (${SUPPORTED_NODE}); watch's HTTP/2 client depends on their fixes` };
}
export function supportedNode(version: string): boolean {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (!match) return false;
  const [major, minor, patch] = match.slice(1).map(Number);
  const atLeast = (a: number, b: number) => minor > a || (minor === a && patch >= b);
  if (major === 22) return atLeast(23, 2);
  if (major === 24) return atLeast(18, 1);
  if (major === 26) return atLeast(5, 1);
  return major > 26;
}

/**
 * Diagnostic Node flags given on the command line (process.execArgv) are the counterpart of
 * NODE_DEBUG and NODE_OPTIONS (audit 1.2.1): an inspector, a CPU or heap profile, a heap
 * snapshot, a diagnostic report, tracing or a TLS key log would hold or expose what macwarden
 * handles. Flags that only size the runtime (--max-old-space-size) or select a syntax are allowed.
 */
const DIAGNOSTIC_FLAG = /^--?(?:inspect|debug|cpu-prof|heap-prof|heapsnapshot|report|diagnostic|trace|prof\b|track-heap|tls-keylog|logfile|log-|perf-)/i;
export function unsafeNodeFlags(execArgv: readonly string[]): boolean { return execArgv.some(flag => DIAGNOSTIC_FLAG.test(flag)); }

export function unsafeNodeDiagnostics(env: Record<string, string | undefined>): boolean {
  const debug = (env.NODE_DEBUG ?? '').split(/[\s,]+/).some(pattern => {
    // Node's debug categories support '*' wildcards; other metacharacters are literal.
    const expression = pattern.replace(/[|\\{}()[\]^$+?.]/g, '\\$&').replace(/\*/g, '.*');
    const enabled = new RegExp(`^${expression}$`, 'i');
    return ['http', 'https', 'tls', 'net'].some(category => enabled.test(category));
  });
  return debug || (env.NODE_OPTIONS ?? '').length > 0;
}
