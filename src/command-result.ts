import type { RegistryEntry } from './registry/index.js';

export type RevokePlan = {
  dryRun: boolean;
  rootKeyId: string;
  label: string | null;
  grade: string | null;
  proof: 'rejected' | 'by-id-only';
};

export type RevokeResult = {
  rootKeyId: string;
  label: string | null;
  evidence: RevokePlan['proof'];
  repaired: boolean;
  entry: RegistryEntry;
};

export type RotatePlan = {
  dryRun: true;
  old: RegistryEntry;
  permissions: string[];
  grade: string;
} & ({ stage: 'stage'; permissionsProven?: boolean } | { stage: 'finish' });

export type RotateStagedResult = {
  stage: 'staged';
  old: RegistryEntry;
  new: RegistryEntry;
};

export type RotateFinishedResult = {
  stage: 'finished';
  old: RegistryEntry;
  new: RegistryEntry;
  evidence: 'rejected' | 'by-id-only';
  repaired: boolean;
};


export type RespondProof = {
  evidence: 'rejected' | 'by-id-only';
  oldRootKeyIdAbsent?: boolean | null;
  oldCredential?: 'accepted' | 'rejected' | 'error' | 'not-tested';
  newCredential?: 'accepted' | 'rejected' | 'error' | 'not-tested';
  proven?: boolean;
  strength?: 'credential-rejected' | 'root-key-id-absent';
  /** A proof covers this credential only; it says nothing about other credentials a leak could have created. */
  scope?: 'this-credential';
};

export type RespondItem = {
  label: string | null;
  rootKeyId: string;
  grade: string;
  action: 'stage' | 'finish' | 'repair' | 'manual';
  status: 'planned' | 'staged' | 'finished' | 'failed' | 'staged-earlier' | 'not-staged' | 'finished-earlier' | 'not-run' | 'manual';
  replacementRootKeyId: string | null;
  /** Fingerprint of the staged replacement, for the operator to compare with the file the app uses. */
  replacementFingerprint?: string | null;
  outPath: string | null;
  note: string | null;
  error: { code: number; step: string | null; message: string } | null;
  proof: RespondProof | null;
};

export type RespondResult = {
  mode: 'stage' | 'finish';
  dryRun: boolean;
  node: { pubkey: string; alias: string; network: string };
  rootKey0: { present: boolean; ownOnRootKey0: boolean; guidance: string[] };
  own: { rootKeyId: string };
  unknown: { rootKeyIds: string[]; guidance: string };
  /** Root key IDs LND still holds although the registry records them revoked. */
  revokedButPresent: { rootKeyIds: string[]; guidance: string };
  /** Credentials in scope that can bake (macaroon:generate or ADMIN): proofs are per credential only. */
  bakingRisk: { rootKeyIds: string[]; guidance: string[] };
  outDir: string | null;
  items: RespondItem[];
  unproven: { label: string | null; rootKeyId: string; reason: string }[];
};
