// Access-review evidence for `inventory --report`. Built only from registry entries and
// LND's root key ID list, which never hold credential bytes; every text field still passes
// credential recognition before it is written.
import { redactEncodedCredentials } from '../credential-recognition.js';
import { parseTimeBefore } from '../decode/index.js';
import type { RegistryEntry } from '../registry/index.js';

export type ReportFormat = 'markdown' | 'csv' | 'json';
export const REPORT_FORMATS: readonly ReportFormat[] = ['markdown', 'csv', 'json'];

export type ReviewFlag = 'default-root-key' | 'own-credential' | 'unknown' | 'missing-in-lnd' | 'revoked-but-present'
  | 'admin-grade' | 'no-expiry' | 'expired' | 'unlabelled' | 'canary-triggered';

export type ReviewedCredential = {
  rootKeyId: string; inLnd: boolean; label: string | null; status: 'active' | 'revoked' | 'not-in-registry';
  grade: string | null; permissions: string[]; caveats: string[]; expiresAt: string | null;
  createdAt: string | null; revokedAt: string | null; revokeEvidence: string | null;
  replaces: string | null; replacedBy: string | null;
  /** From `macwarden watch` usage records for this root key ID; null when none were observed. */
  lastUsed: string | null; calls: number | null;
  /** Denied uses watch's canary guard recorded for this root key ID; null when none were. */
  canary: { uses: number; firstUse: string; lastUse: string } | null; flags: ReviewFlag[];
};

/** The scope statement every format carries. */
export const LIMITATIONS = 'This report is evidence for a reviewer. It does not by itself establish compliance with any framework.';

export type AccessReview = {
  schema: 1; kind: 'macwarden-access-review'; generatedAt: string; macwardenVersion: string;
  node: { pubkey: string; alias: string; network: string; version: string };
  credentials: ReviewedCredential[];
  totals: { inLnd: number; active: number; revoked: number; unknown: number; flagged: Record<ReviewFlag, number> };
  controls: { control: string; observation: string; rootKeyIds: string[] }[];
  signOff: { reviewer: null; date: null; decision: null; notes: null };
  limitations: string;
};

const FLAGS: ReviewFlag[] = ['default-root-key', 'own-credential', 'unknown', 'missing-in-lnd', 'revoked-but-present',
  'admin-grade', 'no-expiry', 'expired', 'unlabelled', 'canary-triggered'];

const byId = (left: string, right: string) => { const a = BigInt(left), b = BigInt(right); return a < b ? -1 : a > b ? 1 : 0; };

function expiry(entry: RegistryEntry, now: Date): { at: string | null; expired: boolean } {
  let earliest: bigint | undefined;
  let text: string | null = null;
  for (const caveat of entry.caveats) {
    if (caveat.type !== 'time-before') continue;
    const at = parseTimeBefore(caveat.value);
    if (at !== undefined && (earliest === undefined || at < earliest)) { earliest = at; text = caveat.value; }
  }
  return { at: text, expired: earliest !== undefined && BigInt(now.getTime()) * 1_000_000n >= earliest };
}

/** Joins LND's root key IDs with every registry entry for this node, revoked ones included. */
export function buildAccessReview(input: { node: AccessReview['node']; ids: string[]; entries: RegistryEntry[];
  ownRootKeyId: string; now: Date; version: string;
  usage?: (rootKeyId: string) => { lastUsed: string; calls: number } | null;
  /** Denied canary uses recorded by watch's guard, when any. */
  canary?: (rootKeyId: string) => { uses: number; firstUse: string; lastUse: string } | null }): AccessReview {
  const pubkey = input.node.pubkey.toLowerCase();
  const entries = input.entries.filter(entry => entry.nodePubkey.toLowerCase() === pubkey);
  const inLnd = new Set(input.ids);
  const observed = (rootKeyId: string) => {
    const seen = input.usage?.(rootKeyId) ?? null;
    return { lastUsed: seen?.lastUsed ?? null, calls: seen?.calls ?? null };
  };
  const credentials: ReviewedCredential[] = [];
  const seen = new Set<string>();
  for (const entry of [...entries].sort((a, b) => byId(a.rootKeyId, b.rootKeyId) || a.createdAt.localeCompare(b.createdAt))) {
    seen.add(entry.rootKeyId);
    const present = inLnd.has(entry.rootKeyId);
    const { at, expired } = expiry(entry, input.now);
    const flags: ReviewFlag[] = [];
    if (entry.rootKeyId === '0') flags.push('default-root-key');
    if (entry.rootKeyId === input.ownRootKeyId) flags.push('own-credential');
    if (entry.status === 'active' && !present) flags.push('missing-in-lnd');
    if (entry.status === 'revoked' && present) flags.push('revoked-but-present');
    if (entry.status === 'active' && entry.grade === 'ADMIN') flags.push('admin-grade');
    if (entry.status === 'active' && at === null) flags.push('no-expiry');
    if (entry.status === 'active' && expired) flags.push('expired');
    if (entry.label === null) flags.push('unlabelled');
    const triggered = input.canary?.(entry.rootKeyId) ?? null;
    if (triggered) flags.push('canary-triggered');
    credentials.push({ rootKeyId: entry.rootKeyId, inLnd: present, label: entry.label, status: entry.status,
      grade: entry.grade, permissions: [...entry.permissions].sort(), caveats: entry.caveats.map(caveat => `${caveat.type} ${caveat.value}`),
      expiresAt: at, createdAt: entry.createdAt, revokedAt: entry.revokedAt, revokeEvidence: entry.revokeEvidence,
      replaces: entry.replaces, replacedBy: entry.replacedBy, ...observed(entry.rootKeyId),
      canary: triggered ? { uses: triggered.uses, firstUse: triggered.firstUse, lastUse: triggered.lastUse } : null, flags });
  }
  for (const id of [...inLnd].filter(id => !seen.has(id)).sort(byId)) {
    const flags: ReviewFlag[] = id === '0' ? ['default-root-key'] : id === input.ownRootKeyId ? [] : ['unknown'];
    if (id === input.ownRootKeyId) flags.push('own-credential');
    credentials.push({ rootKeyId: id, inLnd: true, label: null, status: 'not-in-registry', grade: null, permissions: [],
      caveats: [], expiresAt: null, createdAt: null, revokedAt: null, revokeEvidence: null, replaces: null,
      replacedBy: null, ...observed(id), canary: null, flags });
  }
  credentials.sort((a, b) => byId(a.rootKeyId, b.rootKeyId));
  const flagged = Object.fromEntries(FLAGS.map(flag => [flag, credentials.filter(item => item.flags.includes(flag)).length])) as Record<ReviewFlag, number>;
  const ids = (predicate: (item: ReviewedCredential) => boolean) => credentials.filter(predicate).map(item => item.rootKeyId);
  return {
    schema: 1, kind: 'macwarden-access-review', generatedAt: input.now.toISOString(), macwardenVersion: input.version,
    node: { ...input.node }, credentials,
    totals: { inLnd: inLnd.size, active: credentials.filter(item => item.status === 'active').length,
      revoked: credentials.filter(item => item.status === 'revoked').length,
      unknown: credentials.filter(item => item.flags.includes('unknown')).length, flagged },
    controls: [
      // Listed first when present: a used canary is an incident, not a review item.
      ...(credentials.some(item => item.flags.includes('canary-triggered')) ? [{ control: 'Incident response',
        rootKeyIds: ids(item => item.flags.includes('canary-triggered')),
        observation: 'Canary credentials were used, so someone has read where each was stored. Treat those places as compromised: rotate every credential kept there and find how they were read.' }] : []),
      { control: 'Least privilege', rootKeyIds: ids(item => item.flags.includes('admin-grade') || item.flags.includes('default-root-key')),
        observation: 'Active ADMIN-grade credentials and root key ID 0 (shared by LND\'s default macaroons) grant the widest access; each needs a documented reason or a narrower replacement.' },
      { control: 'Periodic access review', rootKeyIds: ids(item => item.flags.includes('unknown') || item.flags.includes('own-credential') || item.flags.includes('no-expiry') || item.flags.includes('missing-in-lnd')),
        observation: 'Root key IDs without a registry owner, the admin-equivalent credential macwarden itself uses, active credentials without an expiry, and registry entries LND no longer has need a reviewer decision.' },
      { control: 'Prompt removal', rootKeyIds: ids(item => item.flags.includes('expired') || item.flags.includes('revoked-but-present')),
        observation: 'Expired credentials still active and revoked entries whose root key ID is still in LND should be removed with macwarden revoke.' },
    ],
    signOff: { reviewer: null, date: null, decision: null, notes: null },
    limitations: LIMITATIONS,
  };
}

/** Credential recognition plus removal of control characters; reports are plain text. */
function clean(value: string): string {
  // eslint-disable-next-line no-control-regex
  return redactEncodedCredentials(value).replace(/[\x00-\x1f\x7f-\x9f]/g, ' ');
}

function cleanReview(review: AccessReview): AccessReview {
  const walk = (value: unknown): unknown => typeof value === 'string' ? clean(value)
    : Array.isArray(value) ? value.map(walk)
      : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, walk(item)])) : value;
  return walk(review) as AccessReview;
}

const COLUMNS: [string, (item: ReviewedCredential) => string][] = [
  ['root_key_id', item => item.rootKeyId], ['in_lnd', item => String(item.inLnd)], ['label', item => item.label ?? ''],
  ['status', item => item.status], ['grade', item => item.grade ?? ''], ['permissions', item => item.permissions.join(' ')],
  ['expires_at', item => item.expiresAt ?? ''], ['created_at', item => item.createdAt ?? ''], ['revoked_at', item => item.revokedAt ?? ''],
  ['revoke_evidence', item => item.revokeEvidence ?? ''], ['replaces', item => item.replaces ?? ''], ['replaced_by', item => item.replacedBy ?? ''],
  ['last_used', item => item.lastUsed ?? ''], ['calls', item => item.calls === null ? '' : String(item.calls)],
  ['flags', item => item.flags.join(' ')],
  ['caveats', item => item.caveats.join('; ')], ['canary_uses', item => item.canary ? String(item.canary.uses) : ''],
  ['canary_first_use', item => item.canary?.firstUse ?? ''], ['canary_last_use', item => item.canary?.lastUse ?? ''],
];

/**
 * Columns after the credential columns: the controls that name this row, then report-level
 * fields repeated on every row, so the CSV stays one table with one header row.
 */
const REPORT_COLUMNS: [string, (review: AccessReview, item: ReviewedCredential) => string][] = [
  ['controls', (review, item) => naming(review, item).map(control => control.control).join('; ')],
  ['control_observations', (review, item) => naming(review, item).map(control => `${control.control}: ${control.observation}`).join(' | ')],
  ['generated_at', review => review.generatedAt], ['macwarden_version', review => review.macwardenVersion],
  ['node_pubkey', review => review.node.pubkey], ['node_alias', review => review.node.alias],
  ['node_network', review => review.node.network], ['node_version', review => review.node.version],
  ['reviewer', () => ''], ['review_date', () => ''], ['review_decision', () => ''], ['review_notes', () => ''],
  ['limitations', review => review.limitations],
];

function naming(review: AccessReview, item: ReviewedCredential): AccessReview['controls'] {
  return review.controls.filter(control => control.rootKeyIds.includes(item.rootKeyId));
}

/** RFC 4180 field; a leading formula character is neutralised so spreadsheets never evaluate it. */
export function csvField(value: string): string {
  const safe = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

function markdownCell(value: string): string {
  // Backslash-escape every Markdown metacharacter so registry text renders literally;
  // < and > become entities so no HTML reaches a Markdown viewer.
  return value.replace(/[\\|[\]()!*_`#~]/g, character => `\\${character}`)
    .replace(/[<>]/g, character => character === '<' ? '&lt;' : '&gt;') || '—';
}

export function formatAccessReview(review: AccessReview, format: ReportFormat): string {
  const safe = cleanReview(review);
  if (format === 'json') return `${JSON.stringify(safe, null, 2)}\n`;
  if (format === 'csv') return [[...COLUMNS, ...REPORT_COLUMNS].map(([name]) => name).join(','),
    ...safe.credentials.map(item => [...COLUMNS.map(([, value]) => value(item)), ...REPORT_COLUMNS.map(([, value]) => value(safe, item))]
      .map(csvField).join(','))].join('\r\n') + '\r\n';
  const node = safe.node;
  const lines = [
    `# Lightning credential access review`, '',
    `- Generated: ${markdownCell(safe.generatedAt)}`,
    `- Node: ${markdownCell(node.pubkey)} (${markdownCell(node.alias)}), ${markdownCell(node.network)}, LND ${markdownCell(node.version)}`,
    `- Tool: macwarden ${markdownCell(safe.macwardenVersion)}`,
    `- Root key IDs in LND: ${safe.totals.inLnd}; active registry entries: ${safe.totals.active}; revoked: ${safe.totals.revoked}; unknown: ${safe.totals.unknown}`,
    `- Flag counts: ${Object.entries(safe.totals.flagged).map(([flag, count]) => `${markdownCell(flag)} ${count}`).join(', ')}`,
    '', safe.limitations, '',
    '## Credentials', '',
    '| Root key ID | In LND | Label | Status | Grade | Expires | Created | Revoked | Evidence | Replaces | Replaced by | Last used | Calls | Canary uses | Flags |',
    '|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|',
    ...safe.credentials.map(item => `| ${[item.rootKeyId, item.inLnd ? 'yes' : 'no', item.label ?? '', item.status, item.grade ?? '',
      item.expiresAt ?? '', item.createdAt ?? '', item.revokedAt ?? '', item.revokeEvidence ?? '', item.replaces ?? '', item.replacedBy ?? '',
      item.lastUsed ?? 'not observed', item.calls === null ? '' : String(item.calls),
      item.canary ? `${item.canary.uses} denied (first ${item.canary.firstUse}, last ${item.canary.lastUse})` : '',
      item.flags.join(', ')].map(markdownCell).join(' | ')} |`),
    '', '## Permissions', '',
    ...safe.credentials.filter(item => item.permissions.length).map(item =>
      `- ${markdownCell(item.rootKeyId)} ${markdownCell(item.label ?? '')}: ${item.permissions.map(markdownCell).join(', ')}`),
    '', '## Caveats', '',
    ...safe.credentials.filter(item => item.caveats.length).map(item =>
      `- ${markdownCell(item.rootKeyId)} ${markdownCell(item.label ?? '')}: ${item.caveats.map(markdownCell).join('; ')}`),
    '', '## Control observations', '',
    ...safe.controls.flatMap(control => [`### ${control.control}`, '', control.observation, '',
      control.rootKeyIds.length ? `Root key IDs: ${control.rootKeyIds.map(markdownCell).join(', ')}` : 'Root key IDs: none', '']),
    '## Reviewer sign-off', '',
    '| Field | Value |', '|---|---|', '| Reviewer | |', '| Date | |', '| Decision (approved / changes required) | |', '| Notes | |', '',
  ];
  return lines.join('\n');
}
