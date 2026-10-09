import type { MacaroonFacts } from '../decode/index.js';
import snapshot from './lnd-permissions.json' with { type: 'json' };

export type Grade = 'ADMIN' | 'SPEND' | 'OPERATE' | 'RECEIVE' | 'READ' | 'UNASSESSED';
export type GradeResult = {
  grade: Grade;
  reasons: string[];
  warnings: string[];
  unassessed: string[];
};

type AssessedGrade = Exclude<Grade, 'UNASSESSED'>;

const classes: readonly AssessedGrade[] = ['READ', 'RECEIVE', 'OPERATE', 'SPEND', 'ADMIN'];
const knownEntities = new Set([
  'onchain', 'offchain', 'address', 'message', 'peers', 'info', 'invoices', 'signer', 'macaroon',
]);
const exactClasses: Record<string, AssessedGrade> = {
  'macaroon:generate': 'ADMIN',
  'macaroon:write': 'ADMIN',
  'onchain:write': 'SPEND',
  'offchain:write': 'SPEND',
  'signer:generate': 'SPEND',
  'peers:write': 'OPERATE',
  'info:write': 'OPERATE',
  'message:write': 'OPERATE',
  'invoices:write': 'RECEIVE',
  'address:write': 'RECEIVE',
};
const uriShape = /^uri:\/[A-Za-z_][A-Za-z0-9_.]*\/[A-Za-z_][A-Za-z0-9_]*$/;

function byteSort(values: Iterable<string>): string[] {
  // Encode each value once instead of on every comparison.
  return [...values].map(value => [Buffer.from(value), value] as const)
    .sort((left, right) => Buffer.compare(left[0], right[0])).map(([, value]) => value);
}

function classOfPair(permission: string): AssessedGrade | undefined {
  if (Object.hasOwn(exactClasses, permission)) return exactClasses[permission];
  const match = /^([^:]+):(read|write|generate)$/.exec(permission);
  if (!match || !knownEntities.has(match[1])) return undefined;
  return match[2] === 'read' ? 'READ' : 'SPEND';
}

function classOfUri(permission: string): AssessedGrade | undefined {
  const required = snapshot.methods[permission.slice(4) as keyof typeof snapshot.methods];
  if (!required) return undefined;
  let highest: AssessedGrade = 'READ';
  for (const pair of required) {
    const assessed = classOfPair(pair);
    if (!assessed) return undefined;
    if (classes.indexOf(assessed) > classes.indexOf(highest)) highest = assessed;
  }
  return highest;
}

/**
 * `incomplete` is true when the decoder could not keep every permission of the identifier
 * (warning identifier-exceeds-bounds): the permissions left out count as unassessed, so the
 * grade fails closed to UNASSESSED unless the kept ones already give ADMIN.
 */
export function grade(permissions: string[], incomplete = false): GradeResult {
  const assessed = new Map<string, AssessedGrade>();
  const unassessed = new Set<string>();
  const warnings = new Set<string>();
  const unique = new Set(permissions);

  if (incomplete) warnings.add('identifier-exceeds-bounds');
  else if (unique.size === 0) warnings.add('no-permissions');
  for (const permission of unique) {
    const isUri = uriShape.test(permission);
    const permissionClass = isUri ? classOfUri(permission) : classOfPair(permission);
    if (permissionClass) {
      assessed.set(permission, permissionClass);
    } else {
      unassessed.add(permission);
      warnings.add(isUri ? 'unassessed-uri' : 'unassessed-permission');
    }
  }

  let highest: AssessedGrade | undefined;
  for (const permissionClass of assessed.values()) {
    if (!highest || classes.indexOf(permissionClass) > classes.indexOf(highest)) highest = permissionClass;
  }
  const resultGrade: Grade = (unassessed.size > 0 || incomplete) && highest !== 'ADMIN'
    ? 'UNASSESSED' : highest ?? 'UNASSESSED';
  const reasons = resultGrade === 'UNASSESSED' ? [] : byteSort(
    [...assessed].filter(([, permissionClass]) => permissionClass === resultGrade)
      .map(([permission]) => permission),
  );
  return { grade: resultGrade, reasons, warnings: byteSort(warnings), unassessed: byteSort(unassessed) };
}

/** The grade of decoded facts, failing closed when the identifier exceeded the decoder's bounds. */
export function gradeFacts(facts: Pick<MacaroonFacts, 'permissions' | 'warnings'>): GradeResult {
  return grade(facts.permissions, facts.warnings.includes('identifier-exceeds-bounds'));
}

export function describe(facts: MacaroonFacts): string[] {
  const warnings = new Set(facts.warnings);
  if (facts.rootKeyId === 0n) warnings.add('root-key-0');
  return byteSort(warnings);
}

/** The exact URI permission LND accepts for BakeMacaroon, besides macaroon:generate. */
export const BAKE_MACAROON_URI = 'uri:/lnrpc.Lightning/BakeMacaroon';
const INCOMPLETE = ['identifier-exceeds-bounds', 'caveats-exceed-bounds', 'unassessed-permission', 'unassessed-uri'];

/**
 * Whether a credential can, or may, bake macaroons (MW110-06). Baking needs macaroon:generate or
 * the BakeMacaroon URI; the ADMIN grade alone does not imply it (macaroon:write is ADMIN, and
 * LND refuses BakeMacaroon with it). A decode or assessment that is incomplete (truncated
 * identifier or caveats, unassessed permissions, grade UNASSESSED) fails closed: it may bake.
 */
export function canBake(permissions: readonly string[], assessedGrade: Grade | string, warnings: readonly string[] = []): boolean {
  return permissions.includes('macaroon:generate') || permissions.includes(BAKE_MACAROON_URI)
    || assessedGrade === 'UNASSESSED' || warnings.some(warning => INCOMPLETE.includes(warning));
}
