import { copyFileSync, mkdirSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { FixtureInvalidError } from './fixture-invalid.mjs';

export function requirePinnedFixture(info, ids) {
  if (info?.chains?.[0]?.network !== 'regtest' ||
      typeof info?.version !== 'string' || !info.version.startsWith('0.21.4-beta')) {
    throw new FixtureInvalidError('Fixture must be LND 0.21.4-beta on regtest');
  }
  requireBaselineRootKeyIds(ids);
}

export function requireBaselineRootKeyIds(response) {
  const ids = response?.root_key_ids;
  if (!Array.isArray(ids) || ids.length !== 1 || String(ids[0]) !== '0') {
    throw new FixtureInvalidError('Fixture has leftover root key IDs');
  }
}

export function classifyAcceptance(result) {
  if (result?.status === 0) return 'accepted';
  if (typeof result?.stderr === 'string' &&
      /root key with id [0-9]+ doesn't exist/i.test(result.stderr)) return 'rejected';
  return 'error';
}

export function registerFixtureSentinel(source, name, directory = process.env.MACWARDEN_SENTINEL_DIR) {
  if (!directory) throw new FixtureInvalidError('MACWARDEN_SENTINEL_DIR is required');
  if (!/^[a-z0-9][a-z0-9-]*\.macaroon$/.test(name)) throw new Error('Invalid sentinel name');
  const target = join(resolve(directory), basename(name));
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  copyFileSync(source, target);
  return target;
}

export function compareReference({ reference, statement, observed, expected }) {
  if (observed === expected) return { settled: true, conflict: null };
  return { settled: false,
    conflict: `REFERENCE_CONFLICT: ${statement} says ${expected}; ${reference} shows ${observed}` };
}

export class ReferenceConflictError extends Error {
  constructor(message) { super(message); this.name = 'ReferenceConflictError'; }
}

// Only record numeric/status facts here; raw REST and lncli responses can contain secrets.
/** @param {string} kind
 * @param {Record<string, unknown>} fact
 * @param {(comparison: {settled: boolean, conflict: string|null}) => void} [report]
 */
export function checkLiveReference(kind, fact, report = () => {}) {
  const number = value => Number.isInteger(value) ? String(value) : 'unavailable';
  let comparison;
  if (kind === 'bake-rest-error') {
    const rejected = Number.isInteger(fact.invalidStatus) && fact.invalidStatus >= 400;
    comparison = compareReference({
      statement: 'docs/architecture.md#verified-lnd-behaviour-the-commands-rely-on: BakeMacaroon errors are Unknown, not InvalidArgument',
      reference: 'pinned LND 0.21.4-beta BakeMacaroon REST /v1/macaroon',
      expected: 'HTTP error; code 2 (Unknown)',
      observed: rejected && fact.invalidCode === 2 ? 'HTTP error; code 2 (Unknown)' :
        `HTTP ${number(fact.invalidStatus)}; code ${number(fact.invalidCode)}`,
    });
  } else if (kind === 'rest-caveat-address') {
    const accepted = Number.isInteger(fact.hostRestStatus) &&
      fact.hostRestStatus >= 200 && fact.hostRestStatus < 300 && fact.containerRestExit === 0;
    comparison = compareReference({
      statement: 'docs/spec.md#output REST proxy annotation; docs/architecture.md#assumptions-to-confirm assumption 5: REST caveats see proxy loopback',
      reference: 'pinned LND 0.21.4-beta host and container REST /v1/getinfo with ipaddr 127.0.0.1',
      expected: 'host HTTP 2xx; container exit 0',
      observed: accepted ? 'host HTTP 2xx; container exit 0' :
        `host HTTP ${number(fact.hostRestStatus)}; container exit ${number(fact.containerRestExit)}`,
    });
  } else {
    throw new Error('Unknown live reference check');
  }
  report(comparison);
  if (!comparison.settled) throw new ReferenceConflictError(comparison.conflict);
  return comparison;
}
