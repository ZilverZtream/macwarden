import { readFileSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { InvoiceApi, PayerApi, ReadApi } from './lnd/api.ts';
import { LndRestClient, loadConnection } from './lnd/rest.ts';

/**
 * The lab manifest written by setup: where each node listens, which TLS
 * certificate it presents, and which credential file (baked by macwarden)
 * each role uses. Paths inside a lab run are relative to its directory.
 * Credentials are always read by path; their bytes never pass through
 * arguments, environment variables or output.
 */

export const LAB_ROOT = fileURLToPath(new URL('..', import.meta.url));
export const RUNTIME_DIR = join(LAB_ROOT, 'runtime');

export type NodeName = 'customer' | 'router' | 'merchant';
export const NODE_NAMES: readonly NodeName[] = ['customer', 'router', 'merchant'];

export interface CredentialEntry {
  node: NodeName;
  preset: 'pay-only' | 'invoice-only' | 'read-only';
  label: string;
  path: string;
  rootKeyId: string;
  fingerprint: string;
}

export interface LabManifest {
  schema: 1;
  createdAt: string;
  composeProject: string;
  nodes: Record<NodeName, { rest: string; tlsCert: string; pubkey: string }>;
  channels: { customerRouterA: string; customerRouterB: string; routerCustomer: string; routerMerchant: string };
  routerPolicy: { baseFeeMsat: string; feeRatePpm: string };
  credentials: Record<string, CredentialEntry>;
}

export const PAYER_PROFILES = {
  'customer-payer': { credential: 'customer-payer', database: 'customer-payer.db' },
  'merchant-refunds': { credential: 'merchant-refunds', database: 'merchant-refunds.db' },
} as const;
export type PayerProfile = keyof typeof PAYER_PROFILES;

export const RECEIVER_PROFILES = {
  merchant: { credential: 'merchant-invoices', database: 'merchant-orders.db' },
  customer: { credential: 'customer-invoices', database: 'customer-refunds.db' },
} as const;
export type ReceiverProfile = keyof typeof RECEIVER_PROFILES;

export interface Lab {
  dir: string;
  manifest: LabManifest;
}

/** The current lab run: `runtime/current.json` names its directory unless one is given. */
export function loadLab(explicitDir?: string): Lab {
  let dir = explicitDir;
  if (dir === undefined) {
    let pointer: unknown;
    try { pointer = JSON.parse(readFileSync(join(RUNTIME_DIR, 'current.json'), 'utf8')); } catch {
      throw new Error('no lab is set up: run setup.sh or setup.ps1 first');
    }
    const name = (pointer as { dir?: unknown }).dir;
    if (typeof name !== 'string' || !/^lab-[0-9TZ]+$/.test(name)) throw new Error('runtime/current.json is invalid');
    dir = join(RUNTIME_DIR, name);
  }
  dir = resolve(dir);
  const manifest = JSON.parse(readFileSync(join(dir, 'lab.json'), 'utf8')) as LabManifest;
  if (manifest.schema !== 1) throw new Error('lab.json has an unknown schema');
  return { dir, manifest };
}

export function labPath(lab: Lab, relative: string): string {
  return isAbsolute(relative) ? relative : join(lab.dir, relative);
}

export function client(lab: Lab, credentialName: string): LndRestClient {
  const credential = lab.manifest.credentials[credentialName];
  if (credential === undefined) throw new Error(`unknown credential ${credentialName}`);
  const node = lab.manifest.nodes[credential.node];
  return new LndRestClient(loadConnection(`${credential.node} (${credential.preset})`, node.rest, labPath(lab, node.tlsCert),
    labPath(lab, credential.path)));
}

export function payerApi(lab: Lab, profile: PayerProfile): PayerApi {
  return new PayerApi(client(lab, PAYER_PROFILES[profile].credential));
}

export function invoiceApi(lab: Lab, profile: ReceiverProfile): InvoiceApi {
  return new InvoiceApi(client(lab, RECEIVER_PROFILES[profile].credential));
}

export function readApi(lab: Lab, node: NodeName): ReadApi {
  return new ReadApi(client(lab, `${node}-analysis`));
}

export function databasePath(lab: Lab, file: string): string {
  return join(lab.dir, 'data', file);
}

/** The lab's effect directory per component: receipts (receiver) and confirmations (payer); outbox/effects.ts EFFECT_DIRS names the same. */
export const EFFECT_DIR = { receiver: 'receipts', payer: 'confirmations' } as const;

/**
 * Where a profile's outbox worker writes its effects: `<lab>/receipts/<profile>` or `<lab>/confirmations/<profile>`. One
 * directory per profile, as one database per profile: the same order or operation ID in two profiles (the two receivers,
 * the two payers) names two files, not one. The profile is one of the fixed names above, so it is a safe directory name.
 */
export function effectDir(lab: Lab, component: 'payer' | 'receiver', profile: string): string {
  if (!Object.hasOwn(component === 'payer' ? PAYER_PROFILES : RECEIVER_PROFILES, profile)) throw new Error(`unknown ${component} profile ${profile}`);
  return join(lab.dir, EFFECT_DIR[component], profile);
}
