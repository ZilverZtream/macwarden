// Machine formats for `scan` in CI: SARIF 2.1.0 for code scanning, and GitHub Actions
// workflow commands for free inline annotations. Both carry only what text output
// carries (location, kind, grade, fingerprint, root key ID); never matched text,
// snippets or line content (SAFE-01). Both are generators of small pieces so a large
// result streams through renderChunks in bounded chunks.
import { isAbsolute, relative, resolve, sep } from 'node:path';
import type { ScanFinding, ScanResult } from '../scan/index.js';

type Replacer = (key: string, value: unknown) => unknown;

const KINDS: { id: ScanFinding['kind']; name: string; text: string }[] = [
  { id: 'macaroon-file', name: 'MacaroonFile', text: 'LND macaroon file' },
  { id: 'macaroon-hex', name: 'MacaroonHex', text: 'Hex-encoded LND macaroon' },
  { id: 'macaroon-base64', name: 'MacaroonBase64', text: 'Base64-encoded LND macaroon' },
  { id: 'lndconnect', name: 'Lndconnect', text: 'lndconnect:// URI carrying a macaroon' },
  { id: 'nwc', name: 'NostrWalletConnect', text: 'Nostr Wallet Connect URI carrying a spending secret' },
  { id: 'undecodable', name: 'UndecodableMacaroonFile', text: 'Macaroon file that does not decode (treated as ADMIN)' },
  { id: 'undecodable-candidate', name: 'UndecodableCandidate', text: 'Macaroon-like text that does not decode (treated as ADMIN)' },
  { id: 'l402', name: 'L402Credential', text: 'L402 (LSAT) paid API access token' },
  { id: 'l402-file', name: 'L402TokenFile', text: 'L402 (LSAT) token store file' },
];
const L402_KINDS = new Set<string>(['l402', 'l402-file']);

const HELP = 'https://github.com/ZilverZtream/macwarden#scan';

/** GitHub code scanning accepts at most 25,000 results per run; the rest are summarised. */
export const SARIF_MAX_RESULTS = 25_000;

const GRADES = ['ADMIN', 'SPEND', 'UNASSESSED', 'OPERATE', 'RECEIVE', 'READ'] as const;
const GRADED = new Set<string>(['macaroon-file', 'macaroon-hex', 'macaroon-base64', 'lndconnect']);
const titleCase = (grade: string) => grade.charAt(0) + grade.slice(1).toLowerCase();

/**
 * One rule per kind, and per grade for decoded macaroons: GitHub reads security-severity
 * only from the rule, so a READ macaroon must not inherit an ADMIN rule's severity.
 */
type Rule = { id: string; name: string; text: string; level: 'error' | 'warning' | 'note'; score: string };
// L402 tokens: one rule with a usable preimage (paid: counted as READ) and one without (unpaid:
// a challenge, a pending token or a wrong preimage, which grant nothing alone).
const L402_STATES = [{ id: 'paid', name: 'Paid', text: 'with a usable preimage (live service-access secret, counted as READ)' },
  { id: 'unpaid', name: 'Unpaid', text: 'without a usable preimage (not counted)' }] as const;
const RULES: Rule[] = KINDS.flatMap(kind => L402_KINDS.has(kind.id)
  ? L402_STATES.map(state => ({ id: `macwarden/${kind.id}/${state.id}`, name: `${kind.name}${state.name}`, text: `${kind.text} ${state.text}`,
    ...findingSeverity({ kind: kind.id, grade: null, l402: state.id === 'paid' ? { countedAs: 'READ' } : { countedAs: null } }) }))
  : GRADED.has(kind.id)
  ? GRADES.map(grade => {
    const { level, score } = findingSeverity({ kind: kind.id, grade });
    return { id: `macwarden/${kind.id}/${grade.toLowerCase()}`, name: `${kind.name}${titleCase(grade)}`,
      text: `${kind.text}, ${grade} grade`, level, score };
  })
  : [{ id: `macwarden/${kind.id}`, name: kind.name, text: kind.text, ...findingSeverity({ kind: kind.id, grade: null }) }]);

export function ruleIdFor(finding: Pick<ScanFinding, 'kind' | 'grade' | 'l402'>): string {
  if (L402_KINDS.has(finding.kind)) return `macwarden/${finding.kind}/${finding.l402?.countedAs ? 'paid' : 'unpaid'}`;
  return GRADED.has(finding.kind) ? `macwarden/${finding.kind}/${(finding.grade ?? 'UNASSESSED').toLowerCase()}` : `macwarden/${finding.kind}`;
}

/** SARIF result level and GitHub security-severity for one finding. */
export function findingSeverity(finding: { kind: ScanFinding['kind']; grade: ScanFinding['grade'] | null;
  l402?: { countedAs: 'READ' | null } }): { level: 'error' | 'warning' | 'note'; score: string } {
  if (finding.kind === 'nwc') return { level: 'error', score: '9.0' };
  // An L402 token pays for access to a service; it gives no control of a node. With a usable
  // preimage it is scored like a READ credential, without one lower still.
  if (L402_KINDS.has(finding.kind)) return finding.l402?.countedAs ? { level: 'note', score: '3.0' } : { level: 'note', score: '1.0' };
  if (finding.kind === 'undecodable' || finding.kind === 'undecodable-candidate') return { level: 'error', score: '8.0' };
  switch (finding.grade) {
    case 'ADMIN': return { level: 'error', score: '9.5' };
    case 'SPEND': return { level: 'error', score: '9.0' };
    case 'UNASSESSED': return { level: 'error', score: '8.0' };
    case 'OPERATE': return { level: 'warning', score: '6.5' };
    case 'RECEIVE': return { level: 'warning', score: '4.0' };
    default: return { level: 'note', score: '3.0' };
  }
}

// alsoAt on a history finding: other paths that added the content; on a work-tree finding:
// the file's other hard-link names.
const alsoText = (finding: ScanFinding) => finding.commit === undefined ? 'same file also at' : 'same content also added at';

const gradeLabel = (finding: ScanFinding) => finding.l402
  ? (finding.l402.countedAs ? `${finding.l402.countedAs} (L402 ${finding.l402.status})` : `not counted (L402 ${finding.l402.status})`)
  : finding.kind === 'nwc' ? 'SPEND (NWC)'
  : finding.kind === 'undecodable' || finding.kind === 'undecodable-candidate' ? 'ADMIN (undecodable)'
    : finding.grade ?? 'UNASSESSED';

/**
 * A finding's path as SARIF/GitHub expect it: relative to the scan root with forward slashes
 * when inside it, otherwise absolute. A relative path (scan paths are relative to the working
 * directory, the scan root) is resolved first, so '../x' is outside the root.
 */
export function locationOf(path: string, root: string): { relative: string } | { absolute: string } {
  const absolute = resolve(root, path);
  const rel = relative(root, absolute);
  if (rel === '' || isAbsolute(rel) || rel === '..' || rel.startsWith(`..${sep}`)) return { absolute };
  return { relative: rel.split(sep).join('/') };
}

const encodeSegments = (parts: string[]) => parts.map(encodeURIComponent).join('/');

/**
 * An absolute path as a file URI (RFC 8089), each segment percent-encoded as UTF-8. A Windows
 * path (drive letter, UNC, or the \\?\ and \\.\ forms) takes '\' and '/' as separators; in a
 * POSIX path '\' is part of a name and is encoded.
 */
export function fileUri(path: string): string {
  let local = path;
  let windows = /^[A-Za-z]:[\\/]/.test(local) || /^[\\/]{2}[^\\/]/.test(local);
  if (/^[\\/]{2}[?.][\\/]/.test(local)) {
    local = local.slice(4);
    if (/^UNC[\\/]/i.test(local)) local = `\\\\${local.slice(4)}`;
    windows = true;
  }
  if (!windows) return `file://${encodeSegments(local.split('/'))}`;
  const parts = local.split(/[\\/]/);
  // UNC \\server\share\x is file://server/share/x; a drive path keeps its colon.
  if (parts[0] === '' && parts[1] === '') return `file://${encodeURIComponent(parts[2] ?? '')}/${encodeSegments(parts.slice(3))}`;
  return `file:///${parts[0]}/${encodeSegments(parts.slice(1))}`;
}

function artifactLocation(path: string, root: string): { uri: string; uriBaseId?: string } {
  const where = locationOf(path, root);
  if ('relative' in where) return { uri: where.relative.split('/').map(encodeURIComponent).join('/'), uriBaseId: '%SRCROOT%' };
  return { uri: fileUri(where.absolute) };
}

/** SARIF 2.1.0 log for a scan result, as JSON pieces. */
export function* sarifPieces(result: ScanResult, root: string, version: string, replacer: Replacer): Generator<string> {
  const rules = RULES.map(rule => ({
    id: rule.id, name: rule.name,
    shortDescription: { text: rule.text },
    ...(rule.id.startsWith('macwarden/l402') ? {
      fullDescription: { text: `${rule.text}. Anyone holding the macaroon and its preimage can use the paid service until the token expires or the service revokes it; it gives no control of a Lightning node.` },
      helpUri: HELP,
      help: { text: 'Remove the token from the file and its history. Only the service that issued it can revoke it; a token with a usable preimage should be treated as spent and replaced.' },
    } : {
      fullDescription: { text: `${rule.text}. Anyone holding it can call the node with its permissions until its root key ID is deleted.` },
      helpUri: HELP,
      help: { text: 'Remove the credential from the file and its history, then revoke or rotate it with macwarden revoke / rotate.' },
    }),
    defaultConfiguration: { level: rule.level },
    properties: { tags: ['security', 'secret', 'lightning'], 'security-severity': rule.score, precision: 'very-high' },
  }));
  const head = { $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0' };
  const driver = { name: 'macwarden', version, semanticVersion: version, informationUri: HELP, rules };
  const headJson = JSON.stringify(head, replacer);
  // Columns are Unicode code points from the line start (SPEC, scan); SARIF defaults to UTF-16 units.
  // %SRCROOT% is declared as the scan root, so every relative result URI resolves to its file.
  const rootUri = fileUri(resolve(root));
  const baseIds = { '%SRCROOT%': { uri: rootUri.endsWith('/') ? rootUri : `${rootUri}/` } };
  yield `${headJson.slice(0, -1)},"runs":[{"tool":${JSON.stringify({ driver }, replacer)},`
    + `"originalUriBaseIds":${JSON.stringify(baseIds, replacer)},"columnKind":"unicodeCodePoints","results":[`;
  let first = true;
  let emitted = 0;
  for (const finding of result.findings) {
    if (emitted === SARIF_MAX_RESULTS) break;
    emitted += 1;
    const ruleId = ruleIdFor(finding);
    const ruleIndex = RULES.findIndex(rule => rule.id === ruleId);
    const { level, score } = findingSeverity(finding);
    const physicalLocation: Record<string, unknown> = { artifactLocation: artifactLocation(finding.path, root) };
    if (finding.line !== null) physicalLocation.region = { startLine: finding.line, ...(finding.column !== null ? { startColumn: finding.column } : {}) };
    const location: Record<string, unknown> = { physicalLocation };
    if (finding.commit !== undefined) location.logicalLocations = [{ name: finding.commit, kind: 'commit' }];
    const related = finding.alsoAt?.paths.map((path, index) => ({ id: index + 1,
      physicalLocation: { artifactLocation: artifactLocation(path, root) },
      message: { text: finding.commit === undefined ? 'same file (hard link) also here' : 'same content also added here' } }));
    const sarifResult = {
      ruleId, ruleIndex, level,
      message: { text: `${finding.kind} credential, grade ${gradeLabel(finding)}, ${finding.fingerprint}`
        + (finding.rootKeyId === null ? '' : `, root key ${finding.rootKeyId}`)
        + (finding.commit === undefined ? '' : `, added in commit ${finding.commit}`)
        + (finding.context === 'mcp-config' ? ', configured for an AI agent (MCP server)' : '')
        + (finding.alsoAt ? `, ${alsoText(finding)} ${finding.alsoAt.count} other path(s)` : '') },
      locations: [location],
      ...(related?.length ? { relatedLocations: related } : {}),
      partialFingerprints: { 'macwardenFingerprint/v1': finding.fingerprint },
      properties: { grade: finding.grade, kind: finding.kind, fingerprint: finding.fingerprint, rootKeyId: finding.rootKeyId,
        'security-severity': score, ...(finding.commit !== undefined ? { commit: finding.commit } : {}),
        ...(finding.context !== undefined ? { context: finding.context } : {}),
        ...(finding.alsoAt ? { alsoAt: finding.alsoAt.count } : {}) },
    };
    yield `${first ? '' : ','}${JSON.stringify(sarifResult, replacer)}`;
    first = false;
  }
  const { summary } = result;
  const omitted = result.findings.length - emitted;
  const notifications = omitted > 0 ? [{ level: 'warning', message: { text: `${omitted} further findings are not in this SARIF log: `
    + `GitHub code scanning accepts at most ${SARIF_MAX_RESULTS} results per run. Use --format json for the complete list.` } }] : [];
  const invocation = { executionSuccessful: true, ...(notifications.length ? { toolExecutionNotifications: notifications } : {}),
    properties: { ...(omitted > 0 ? { omittedResults: omitted } : {}), summary: { findings: summary.findings, distinct: summary.distinct,
    filesScanned: summary.filesScanned, filesSkipped: summary.filesSkipped, ignored: summary.ignored,
    ...(summary.blobsScanned !== undefined ? { blobsScanned: summary.blobsScanned } : {}) },
  ...(result.failOn ? { failOn: result.failOn } : {}) } };
  yield `],"invocations":[${JSON.stringify(invocation, replacer)}]}]}\n`;
}

/** GitHub workflow-command escaping for the message part. */
export function escapeData(value: string): string {
  return value.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

/** GitHub workflow-command escaping for a property value (also ':' and ','). */
export function escapeProperty(value: string): string {
  return escapeData(value).replace(/:/g, '%3A').replace(/,/g, '%2C');
}

/**
 * GitHub Actions annotations, one per finding, then the text summary line. `clean` escapes
 * the message for display; the file property carries the real path (credentials redacted by
 * `redact`) with GitHub's own property escaping, so the annotation names the actual file.
 */
export function* githubLines(result: ScanResult, root: string, clean: (text: string) => string, summary: string,
  redact: (text: string) => string = text => text): Generator<string> {
  for (const finding of result.findings) {
    const { level } = findingSeverity(finding);
    const command = level === 'error' ? 'error' : level === 'warning' ? 'warning' : 'notice';
    const where = locationOf(finding.path, root);
    const file = 'relative' in where ? where.relative : where.absolute;
    const properties = [`file=${escapeProperty(redact(file))}`];
    if (finding.line !== null) properties.push(`line=${finding.line}`);
    if (finding.column !== null) properties.push(`col=${finding.column}`);
    properties.push(`title=${escapeProperty(`macwarden ${finding.kind}`)}`);
    const message = `${gradeLabel(finding)} ${finding.fingerprint}`
      + (finding.rootKeyId === null ? '' : ` root key ${finding.rootKeyId}`)
      + (finding.commit === undefined ? '' : ` in commit ${finding.commit.slice(0, 12)}`)
      + (finding.context === 'mcp-config' ? ' (MCP server config)' : '')
      + (finding.alsoAt ? ` (${alsoText(finding)} ${finding.alsoAt.count} other path(s))` : '');
    yield `::${command} ${properties.join(',')}::${escapeData(clean(message))}\n`;
  }
  yield summary;
}
