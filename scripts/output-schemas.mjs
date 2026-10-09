// Generates schemas/output/{inventory,bake,revoke,rotate,attenuate,watch,recommend,respond,verify,macwarden}.schema.json
// and watch-event.schema.json (the NDJSON lines watch --json prints before its final document)
// from the hand-written inspect and registry-entry schemas, so shared definitions have one source.
// Run: node scripts/output-schemas.mjs [--check]. --check exits 1 when a file is stale.
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const dir = join(import.meta.dirname, '..', 'schemas', 'output');
const read = name => JSON.parse(readFileSync(join(dir, `${name}.schema.json`), 'utf8'));
const inspect = read('inspect');
const entrySource = read('registry-entry');
const base = 'https://github.com/ZilverZtream/macwarden/blob/main/schemas/output/';

// A registry entry, embedded without its own $schema and title.
const registryEntry = { ...entrySource };
delete registryEntry.$schema;
delete registryEntry.title;
const pick = (keys) => ({
  type: 'object', additionalProperties: false, required: keys,
  properties: Object.fromEntries(keys.map(key => [key, registryEntry.properties[key]])),
});
const defs = {
  // Exit codes 1-8 (docs/spec.md Exit codes); step is the SPEC step name (B1, V7, S10, F3, A1, N2, ...),
  // a decode stage, cancelled, cleanup or internal, or null for a usage error.
  error: { type: 'object', additionalProperties: false, required: ['code', 'step', 'message'],
    properties: { code: { type: 'integer', minimum: 1, maximum: 8 },
      step: { type: ['string', 'null'], minLength: 1 }, message: { type: 'string', minLength: 1 } } },
  warning: { oneOf: [{ type: 'string', minLength: 1 },
    { type: 'object', additionalProperties: false, required: ['code', 'message'],
      properties: { code: { type: 'string', minLength: 1 }, message: { type: 'string' } } }] },
  rootKeyId: inspect.$defs.rootKeyId,
  grade: { enum: ['ADMIN', 'SPEND', 'OPERATE', 'RECEIVE', 'READ', 'UNASSESSED'] },
  registryEntry,
};

// `macwarden <command> --help --json`: the command's synopsis lines (docs/spec.md, Output > Help).
// The hand-written inspect and scan schemas carry the same definition.
function help(command) {
  return { type: 'object', additionalProperties: false, required: ['usage'],
    properties: { usage: { type: 'array', minItems: 1, items: { type: 'string', pattern: `^macwarden ${command} ` } } } };
}

function envelope(command, title, description, result, extraDefs = {}) {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: `${base}${command}.schema.json`,
    title, description,
    type: 'object', additionalProperties: false,
    required: ['schema', 'command', 'ok', 'warnings', 'result', 'error'],
    properties: {
      schema: { const: 1 }, command: { const: command }, ok: { type: 'boolean' },
      warnings: { type: 'array', items: { $ref: '#/$defs/warning' } },
      result: { oneOf: [{ type: 'null' }, { $ref: '#/$defs/result' }, { $ref: '#/$defs/help' }] },
      error: { oneOf: [{ type: 'null' }, { $ref: '#/$defs/error' }] },
    },
    allOf: [{
      if: { properties: { ok: { const: true } }, required: ['ok'] },
      then: { properties: { result: { oneOf: [{ $ref: '#/$defs/result' }, { $ref: '#/$defs/help' }] }, error: { type: 'null' } } },
      else: { properties: { result: { type: 'null' }, error: { $ref: '#/$defs/error' } } },
    }],
    $defs: { ...defs, ...extraDefs, help: help(command), result },
  };
}

const instant = { type: 'string', pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$' };
// Date.prototype.toISOString(): what watch writes for its own clock readings.
const isoTime = { type: 'string', pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$' };
const count = { type: 'integer', minimum: 0 };
const credentialId = { type: 'string', pattern: '^id:[0-9a-f]{16}$' };
const watchCounts = ['calls', 'errors', 'credentials', 'canaryAlerts', 'canaryUses', 'alertFailures', 'reconnects', 'canaries',
  'droppedUsageRecords', 'evictedUsageRecords', 'droppedAttributions', 'droppedEvents'];

// One watch --json event line. A call without a decodable macaroon has credential id:none or
// id:undecodable and root key ID "none"; it is shown but never recorded.
const eventWho = {
  method: { type: 'string' },
  rootKeyId: { oneOf: [{ $ref: '#/$defs/rootKeyId' }, { const: 'none' }] },
  credential: { type: 'string', pattern: '^id:([0-9a-f]{16}|none|undecodable)$' },
  label: { type: ['string', 'null'] },
};
const event = (required, properties) => ({ type: 'object', additionalProperties: false,
  required: ['schema', 'event', 'time', ...required], properties: { schema: { const: 1 }, time: isoTime, ...properties } });
const watchEvent = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: `${base}watch-event.schema.json`,
  title: 'macwarden watch --json event line',
  description: 'Normative source: docs/spec.md, Output and Commands > 8. watch. With --json, watch prints one of these objects per line while it runs, '
    + 'then its final document (watch.schema.json, the only line with a "command" field) as the last line.',
  oneOf: [
    event(['method', 'rootKeyId', 'credential', 'label'], { event: { enum: ['call', 'error'] }, ...eventWho }),
    event(['method', 'rootKeyId', 'credential', 'label', 'denied'], { event: { const: 'canary' }, ...eventWho, denied: { const: true },
      // Further denied uses folded into this alert since the previous one for the same canary.
      repeats: { type: 'integer', minimum: 1 } }),
    event(['status', 'canaries', 'readOnly'], { event: { const: 'status' }, status: { enum: ['registered', 'reconnecting'] },
      canaries: count, readOnly: { const: true } }),
    event(['status', 'dropped'], { event: { const: 'status' }, status: { const: 'output-dropped' }, dropped: { type: 'integer', minimum: 1 } }),
    event(['status', 'rootKeyId', 'label'], { event: { const: 'status' }, status: { const: 'alert-failed' },
      rootKeyId: eventWho.rootKeyId, label: eventWho.label }),
  ],
  $defs: { rootKeyId: defs.rootKeyId },
};
const schemas = {
  inventory: envelope('inventory', 'macwarden inventory --json output',
    'Normative source: docs/spec.md, Commands > 3. inventory. Exit 1 with --expiring-within still has ok: true.', {
      type: 'object', additionalProperties: false, required: ['node', 'rootKeys'],
      properties: {
        node: { type: 'object', additionalProperties: false, required: ['pubkey', 'alias', 'network', 'version'],
          properties: { pubkey: registryEntry.properties.nodePubkey, alias: { type: 'string' },
            network: { type: 'string' }, version: { type: 'string' } } },
        rootKeys: { type: 'array', items: {
          type: 'object', additionalProperties: false,
          required: ['rootKeyId', 'inLnd', 'flags', 'verify', 'expires', 'entry'],
          properties: {
            rootKeyId: { $ref: '#/$defs/rootKeyId' }, inLnd: { type: 'boolean' },
            flags: { type: 'array', uniqueItems: true, items: { enum: ['default-root-key', 'own-credential', 'unknown',
              'missing-in-lnd', 'revoked-but-present', 'pending-replacement', 'replacement', 'invalid-replacement', 'rejected', 'expired', 'expiring', 'canary-triggered'] } },
            verify: { enum: ['accepted', 'rejected', 'error', 'canary', 'not-checked'] },
            expires: { oneOf: [{ type: 'null' }, instant] },
            entry: { oneOf: [{ type: 'null' }, pick(['label', 'grade', 'permissions', 'caveats', 'createdAt', 'status',
              'fingerprint', 'outPath', 'replaces', 'replacedBy'])] },
            // Present only when a watch usage file has records for this root key ID.
            usage: { type: 'object', additionalProperties: false, required: ['calls', 'errors', 'lastUsed', 'methods'],
              properties: { calls: { type: 'integer', minimum: 0 }, errors: { type: 'integer', minimum: 0 },
                lastUsed: { type: 'string' }, methods: { type: 'array', items: { type: 'string' } } } },
            // Present only when watch's canary guard denied uses of this root key ID.
            canary: { type: 'object', additionalProperties: false, required: ['uses', 'firstUse', 'lastUse'],
              properties: { uses: { type: 'integer', minimum: 1 }, firstUse: { type: 'string' }, lastUse: { type: 'string' } } },
          } } },
        // Present only with --report: the access-review evidence (docs/spec.md, 3. inventory).
        report: { type: 'object', additionalProperties: false, required: ['format', 'path', 'review'],
          properties: {
            format: { enum: ['markdown', 'csv', 'json'] }, path: { type: ['string', 'null'] },
            review: { type: 'object', additionalProperties: false,
              required: ['schema', 'kind', 'generatedAt', 'macwardenVersion', 'node', 'credentials', 'totals', 'controls', 'signOff', 'limitations'],
              properties: {
                schema: { const: 1 }, kind: { const: 'macwarden-access-review' }, generatedAt: { type: 'string' },
                macwardenVersion: { type: 'string' },
                node: { type: 'object', additionalProperties: false, required: ['pubkey', 'alias', 'network', 'version'],
                  properties: { pubkey: registryEntry.properties.nodePubkey, alias: { type: 'string' },
                    network: { type: 'string' }, version: { type: 'string' } } },
                credentials: { type: 'array', items: { type: 'object', additionalProperties: false,
                  required: ['rootKeyId', 'inLnd', 'label', 'status', 'grade', 'permissions', 'caveats', 'expiresAt', 'createdAt',
                    'revokedAt', 'revokeEvidence', 'replaces', 'replacedBy', 'lastUsed', 'calls', 'canary', 'flags'],
                  properties: {
                    rootKeyId: { $ref: '#/$defs/rootKeyId' }, inLnd: { type: 'boolean' }, label: { type: ['string', 'null'] },
                    status: { enum: ['active', 'revoked', 'not-in-registry'] },
                    grade: { oneOf: [{ type: 'null' }, { $ref: '#/$defs/grade' }] },
                    permissions: { type: 'array', items: { type: 'string' } }, caveats: { type: 'array', items: { type: 'string' } },
                    expiresAt: { type: ['string', 'null'] }, createdAt: { type: ['string', 'null'] }, revokedAt: { type: ['string', 'null'] },
                    revokeEvidence: { type: ['string', 'null'] }, replaces: { type: ['string', 'null'] }, replacedBy: { type: ['string', 'null'] },
                    lastUsed: { type: ['string', 'null'] }, calls: { type: ['integer', 'null'], minimum: 0 },
                    // Denied uses watch's canary guard recorded; null when none were.
                    canary: { oneOf: [{ type: 'null' }, { type: 'object', additionalProperties: false, required: ['uses', 'firstUse', 'lastUse'],
                      properties: { uses: { type: 'integer', minimum: 1 }, firstUse: { type: 'string' }, lastUse: { type: 'string' } } }] },
                    flags: { type: 'array', uniqueItems: true, items: { enum: ['default-root-key', 'own-credential', 'unknown', 'missing-in-lnd', 'revoked-but-present', 'admin-grade', 'no-expiry', 'expired', 'unlabelled', 'canary-triggered'] } },
                  } } },
                totals: { type: 'object', additionalProperties: false, required: ['inLnd', 'active', 'revoked', 'unknown', 'flagged'],
                  properties: { inLnd: { type: 'integer', minimum: 0 }, active: { type: 'integer', minimum: 0 },
                    revoked: { type: 'integer', minimum: 0 }, unknown: { type: 'integer', minimum: 0 },
                    flagged: { type: 'object', additionalProperties: false, required: ['default-root-key', 'own-credential', 'unknown', 'missing-in-lnd', 'revoked-but-present', 'admin-grade', 'no-expiry', 'expired', 'unlabelled', 'canary-triggered'],
                      properties: Object.fromEntries(['default-root-key', 'own-credential', 'unknown', 'missing-in-lnd', 'revoked-but-present', 'admin-grade', 'no-expiry', 'expired', 'unlabelled', 'canary-triggered'].map(flag => [flag, { type: 'integer', minimum: 0 }])) } } },
                controls: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['control', 'observation', 'rootKeyIds'],
                  properties: { control: { type: 'string' }, observation: { type: 'string' },
                    rootKeyIds: { type: 'array', items: { $ref: '#/$defs/rootKeyId' } } } } },
                signOff: { type: 'object', additionalProperties: false, required: ['reviewer', 'date', 'decision', 'notes'],
                  properties: { reviewer: { type: 'null' }, date: { type: 'null' }, decision: { type: 'null' }, notes: { type: 'null' } } },
                limitations: { type: 'string', minLength: 1 },
              } },
          } },
        expiring: { type: 'object', additionalProperties: false, required: ['within', 'count'],
          properties: { within: { type: 'string', pattern: '^[1-9][0-9]{0,4}[mhd]$' }, count: { type: 'integer', minimum: 0 } } },
      } }),
  bake: envelope('bake', 'macwarden bake --json output',
    'Normative source: docs/spec.md, Commands > 4. bake. A dry run returns the plan; a bake returns the new registry entry.', {
      oneOf: [
        { type: 'object', additionalProperties: false, required: ['dryRun', 'label', 'permissions', 'grade', 'caveats'],
          properties: { dryRun: { const: true }, label: registryEntry.properties.label, grade: { $ref: '#/$defs/grade' },
            permissions: { type: 'array', items: { type: 'string' } },
            caveats: { type: 'array', items: { type: 'object', required: ['type', 'value'] } } } },
        { $ref: '#/$defs/registryEntry' },
      ] }),
  revoke: envelope('revoke', 'macwarden revoke --json output',
    'Normative source: docs/spec.md, Commands > 5. revoke. A dry run returns the plan; a revocation returns the evidence and the updated entry.', {
      oneOf: [
        { type: 'object', additionalProperties: false, required: ['dryRun', 'rootKeyId', 'label', 'grade', 'proof'],
          properties: { dryRun: { type: 'boolean' }, rootKeyId: { $ref: '#/$defs/rootKeyId' },
            label: { type: ['string', 'null'] }, grade: { oneOf: [{ type: 'null' }, { $ref: '#/$defs/grade' }] },
            proof: { enum: ['rejected', 'by-id-only'] } } },
        { type: 'object', additionalProperties: false, required: ['rootKeyId', 'label', 'evidence', 'repaired', 'entry'],
          properties: { rootKeyId: { $ref: '#/$defs/rootKeyId' }, label: { type: ['string', 'null'] },
            evidence: { enum: ['rejected', 'by-id-only'] }, repaired: { type: 'boolean' },
            entry: { $ref: '#/$defs/registryEntry' } } },
      ] }),
  rotate: envelope('rotate', 'macwarden rotate --json output',
    'Normative source: docs/spec.md, Commands > 6. rotate. Stage and finish each return a plan (dry run) or their result.', {
      oneOf: [
        { type: 'object', additionalProperties: false, required: ['dryRun', 'old', 'permissions', 'grade', 'stage'],
          properties: { dryRun: { const: true }, old: { $ref: '#/$defs/registryEntry' },
            permissions: { type: 'array', items: { type: 'string' } }, grade: { $ref: '#/$defs/grade' },
            stage: { enum: ['stage', 'finish'] }, permissionsProven: { type: 'boolean' } } },
        { type: 'object', additionalProperties: false, required: ['stage', 'old', 'new'],
          properties: { stage: { const: 'staged' }, old: { $ref: '#/$defs/registryEntry' }, new: { $ref: '#/$defs/registryEntry' } } },
        { type: 'object', additionalProperties: false, required: ['stage', 'old', 'new', 'evidence', 'repaired'],
          properties: { stage: { const: 'finished' }, old: { $ref: '#/$defs/registryEntry' }, new: { $ref: '#/$defs/registryEntry' },
            evidence: { enum: ['rejected', 'by-id-only'] }, repaired: { type: 'boolean' } } },
      ] }),
  attenuate: envelope('attenuate', 'macwarden attenuate --json output',
    'Normative source: docs/spec.md, Commands > 7. attenuate. The facts of the attenuated copy, as inspect reports them, plus the caveats added.', {
      type: 'object', additionalProperties: false,
      required: [...inspect.$defs.result.required, 'dryRun', 'out', 'parentFingerprint', 'added'],
      properties: {
        ...inspect.$defs.result.properties,
        dryRun: { type: 'boolean' }, out: { type: ['string', 'null'] },
        parentFingerprint: inspect.$defs.fingerprint,
        added: { type: 'array', minItems: 1, items: { type: 'string' } },
      } }, {
      fingerprint: inspect.$defs.fingerprint, caveat: inspect.$defs.caveat, macaroonWarning: inspect.$defs.macaroonWarning,
    }),
  watch: envelope('watch', 'macwarden watch --json final document',
    'Normative source: docs/spec.md, Commands > 8. watch. The last line of watch --json; the event lines before it follow watch-event.schema.json.', {
      type: 'object', additionalProperties: false,
      required: ['node', 'startedAt', 'endedAt', ...watchCounts, 'usageFile'],
      properties: {
        node: registryEntry.properties.nodePubkey, startedAt: isoTime, endedAt: isoTime,
        ...Object.fromEntries(watchCounts.map(name => [name, count])),
        usageFile: { type: 'string', minLength: 1 },
      } }),
  recommend: envelope('recommend', 'macwarden recommend --json output',
    'Normative source: docs/spec.md, Commands > 9. recommend. A recommendation only; commands is empty whenever the evidence does not support narrowing.', {
      type: 'object', additionalProperties: false,
      required: ['node', 'selector', 'label', 'rootKeyId', 'credentials', 'observed', 'unmapped', 'recommended', 'recommendedUris',
        'current', 'unneeded', 'observation', 'commands'],
      properties: {
        node: registryEntry.properties.nodePubkey,
        // The label, root key ID or credential ID given, or the credential ID of --target-file.
        selector: { type: 'string', minLength: 1 },
        label: { type: ['string', 'null'] },
        rootKeyId: { oneOf: [{ type: 'null' }, { $ref: '#/$defs/rootKeyId' }] },
        credentials: { type: 'array', uniqueItems: true, items: credentialId },
        observed: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['method', 'calls', 'lastUsed', 'permissions'],
          properties: { method: { type: 'string' }, calls: count, lastUsed: { type: 'string' },
            permissions: { type: 'array', uniqueItems: true, items: { type: 'string' } } } } },
        unmapped: { type: 'array', uniqueItems: true, items: { type: 'string' } },
        recommended: { type: 'array', uniqueItems: true, items: { type: 'string' } },
        recommendedUris: { type: 'array', uniqueItems: true, items: { type: 'string', pattern: '^uri:' } },
        current: { oneOf: [{ type: 'null' }, { type: 'array', uniqueItems: true, items: { type: 'string' } }] },
        unneeded: { type: 'array', uniqueItems: true, items: { type: 'string' } },
        observation: { type: 'object', additionalProperties: false, required: ['seconds', 'since', 'until', 'sessions', 'short', 'accepted'],
          properties: { seconds: { oneOf: [{ type: 'null' }, count] }, since: { type: ['string', 'null'] }, until: { type: ['string', 'null'] },
            sessions: count, short: { type: 'boolean' }, accepted: { type: 'boolean' } } },
        commands: { type: 'array', items: { type: 'string', minLength: 1 } },
      } }),
  respond: envelope('respond', 'macwarden respond --json output',
    'Normative source: docs/spec.md, Commands > 10. respond. A batch with failed items still has ok: true; its exit code is the batch code.', {
      type: 'object', additionalProperties: false,
      required: ['mode', 'dryRun', 'node', 'rootKey0', 'own', 'unknown', 'revokedButPresent', 'bakingRisk', 'outDir', 'items', 'unproven'],
      properties: {
        mode: { enum: ['stage', 'finish'] }, dryRun: { type: 'boolean' },
        node: { type: 'object', additionalProperties: false, required: ['pubkey', 'alias', 'network'],
          properties: { pubkey: registryEntry.properties.nodePubkey, alias: { type: 'string' }, network: { type: 'string' } } },
        rootKey0: { type: 'object', additionalProperties: false, required: ['present', 'ownOnRootKey0', 'guidance'],
          properties: { present: { type: 'boolean' }, ownOnRootKey0: { type: 'boolean' },
            guidance: { type: 'array', items: { type: 'string', minLength: 1 } } } },
        own: { type: 'object', additionalProperties: false, required: ['rootKeyId'],
          properties: { rootKeyId: { $ref: '#/$defs/rootKeyId' } } },
        unknown: { type: 'object', additionalProperties: false, required: ['rootKeyIds', 'guidance'],
          properties: { rootKeyIds: { type: 'array', items: { $ref: '#/$defs/rootKeyId' } }, guidance: { type: 'string' } } },
        revokedButPresent: { type: 'object', additionalProperties: false, required: ['rootKeyIds', 'guidance'],
          properties: { rootKeyIds: { type: 'array', items: { $ref: '#/$defs/rootKeyId' } }, guidance: { type: 'string' } } },
        bakingRisk: { type: 'object', additionalProperties: false, required: ['rootKeyIds', 'guidance'],
          properties: { rootKeyIds: { type: 'array', items: { $ref: '#/$defs/rootKeyId' } },
            guidance: { type: 'array', items: { type: 'string', minLength: 1 } } } },
        outDir: { type: ['string', 'null'] },
        items: { type: 'array', items: { $ref: '#/$defs/respondItem' } },
        unproven: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['label', 'rootKeyId', 'reason'],
          properties: { label: { type: ['string', 'null'] }, rootKeyId: { $ref: '#/$defs/rootKeyId' }, reason: { type: 'string', minLength: 1 } } } },
      } }, {
      respondItem: { type: 'object', additionalProperties: false,
        required: ['label', 'rootKeyId', 'grade', 'action', 'status', 'replacementRootKeyId', 'outPath', 'note', 'error', 'proof'],
        properties: {
          label: { type: ['string', 'null'] }, rootKeyId: { $ref: '#/$defs/rootKeyId' }, grade: { $ref: '#/$defs/grade' },
          action: { enum: ['stage', 'finish', 'repair', 'manual'] },
          status: { enum: ['planned', 'staged', 'finished', 'failed', 'staged-earlier', 'not-staged', 'finished-earlier', 'not-run', 'manual'] },
          replacementRootKeyId: { oneOf: [{ type: 'null' }, { $ref: '#/$defs/rootKeyId' }] },
          replacementFingerprint: registryEntry.properties.fingerprint,
          outPath: { type: ['string', 'null'] }, note: { type: ['string', 'null'] },
          error: { oneOf: [{ type: 'null' }, { $ref: '#/$defs/error' }] },
          proof: { oneOf: [{ type: 'null' }, { type: 'object', additionalProperties: false, required: ['evidence'],
            properties: {
              evidence: { enum: ['rejected', 'by-id-only'] },
              oldRootKeyIdAbsent: { type: ['boolean', 'null'] },
              oldCredential: { enum: ['accepted', 'rejected', 'error', 'not-tested'] },
              newCredential: { enum: ['accepted', 'rejected', 'error', 'not-tested'] },
              proven: { type: 'boolean' },
              strength: { enum: ['credential-rejected', 'root-key-id-absent'] },
              scope: { const: 'this-credential' },
            } }] },
        } },
    }),
  verify: envelope('verify', 'macwarden verify --json output',
    'Normative source: docs/spec.md, Commands > 11. verify. The facts of the credential, as inspect reports them, plus LND\'s answer. '
      + 'Exit 1 (ok: true) when the credential is accepted or the rejection is not conclusive; exit 0 when LND conclusively rejects it.', {
      type: 'object', additionalProperties: false,
      required: [...inspect.$defs.result.required, 'node', 'status', 'rejection', 'conclusive', 'rootKeyListed',
        'ownCredential', 'canBake', 'registry', 'guidance'],
      properties: {
        ...inspect.$defs.result.properties,
        node: { type: 'object', additionalProperties: false, required: ['pubkey', 'alias', 'network'],
          properties: { pubkey: registryEntry.properties.nodePubkey, alias: { type: 'string' }, network: { type: 'string' } } },
        status: { enum: ['accepted', 'rejected'] },
        rejection: { enum: ['root-key-missing', 'signature-mismatch', 'expired', 'other', null] },
        conclusive: { type: 'boolean' },
        rootKeyListed: { type: ['boolean', 'null'] },
        ownCredential: { type: 'boolean' },
        canBake: { type: 'boolean' },
        registry: { oneOf: [{ type: 'null' }, { type: 'object', additionalProperties: false, required: ['label', 'status', 'match'],
          properties: { label: { type: ['string', 'null'] }, status: { enum: ['active', 'revoked'] },
            match: { enum: ['fingerprint', 'root-key-id'] } } }] },
        guidance: { type: 'array', minItems: 1, items: { type: 'string', minLength: 1 } },
      },
      allOf: [
        { if: { properties: { status: { const: 'accepted' } } },
          then: { properties: { rejection: { const: null }, conclusive: { const: true } } },
          else: { properties: { rejection: { enum: ['root-key-missing', 'signature-mismatch', 'expired', 'other'] } } } },
      ] }, {
      fingerprint: inspect.$defs.fingerprint, caveat: inspect.$defs.caveat, macaroonWarning: inspect.$defs.macaroonWarning,
    }),
};
// attenuate's and verify's results reuse inspect's grade definition name.
schemas.attenuate.$defs.grade = inspect.$defs.grade;
schemas.verify.$defs.grade = inspect.$defs.grade;
schemas['watch-event'] = watchEvent;
// Documents with command: null: `macwarden --help --json`, and a usage error before any command is
// known (missing or unknown command, unknown leading flag).
const topLevel = envelope('macwarden', 'macwarden --json output without a command',
  'Normative source: docs/spec.md, Output > Help and --json. `macwarden --help --json` (ok: true, the general usage lines and every '
    + 'command with its summary), or a usage error before any command is known (ok: false, exit 2, step null).', {
    type: 'object', additionalProperties: false, required: ['usage', 'commands'],
    properties: {
      usage: { type: 'array', minItems: 1, items: { type: 'string', pattern: '^macwarden ' } },
      commands: { type: 'array', minItems: 1, items: { type: 'object', additionalProperties: false, required: ['name', 'summary'],
        properties: { name: { type: 'string', pattern: '^[a-z]+$' }, summary: { type: 'string', minLength: 1 } } } },
    } });
topLevel.properties.command = { const: null };
topLevel.properties.result = { oneOf: [{ type: 'null' }, { $ref: '#/$defs/result' }] };
topLevel.allOf[0].then.properties.result = { $ref: '#/$defs/result' };
delete topLevel.$defs.help;
schemas.macwarden = topLevel;

const check = process.argv.includes('--check');
let stale = false;
for (const [name, schema] of Object.entries(schemas)) {
  const path = join(dir, `${name}.schema.json`);
  const text = `${JSON.stringify(schema, null, 2)}\n`;
  let current = '';
  try { current = readFileSync(path, 'utf8'); } catch { /* new file */ }
  if (current === text) continue;
  if (check) { console.error(`stale: schemas/output/${name}.schema.json`); stale = true; }
  else writeFileSync(path, text);
}
if (stale) process.exit(1);
