/**
 * Loads the payment lab's state-machine harness (examples/payment-lab/test/harness/harness.ts) for
 * test/payment-lab-harness.test.ts. Like payment-lab-modules.ts, it imports at run time from a computed
 * specifier: the harness is written for Node's type stripping (its imports end in `.ts`), which
 * `tsc -p tsconfig.test.json` would reject with TS5097 in a static import. The shapes the test uses are
 * declared here structurally; the harness itself is type-checked with the lab's compiler settings.
 */

export type PredicateName = string;

export interface StepViolation { predicate: PredicateName; message: string; step: number; states: Record<string, unknown> }

export interface CampaignResult {
  seed: number;
  cases: number;
  events: number;
  seconds: number;
  violations: { case: number; predicate: PredicateName; message: string; step: number; replay?: string; shrunkSteps?: number; replayMessage?: string }[];
  coverage: Record<string, number>;
  configs: Record<string, number>;
}

export interface ReplayOutcome { file: string; predicate: PredicateName; violations: StepViolation[]; ms: number; mutant?: string; invalid?: string }

export interface Replay { schema: number; kind: string; predicate: PredicateName; rule: string; events: unknown[]; config: unknown; failingStep: number; mutant?: string }

export interface Mutant { predicate: PredicateName; description: string; edits: [string, string, string][] }

export interface Harness {
  PREDICATES: Record<PredicateName, string>;
  MUTANTS: string;
  campaign(options: { seed: number; cases: number; steps?: number; labSrc?: string; replayOut?: string; shrink?: boolean; collect?: boolean }):
    Promise<CampaignResult>;
  replay(options: { path: string; labSrc?: string; scratch?: string }): Promise<ReplayOutcome[]>;
  replayFiles(path: string): string[];
  readReplay(path: string): Replay;
  readMutant(path: string): Mutant;
  buildMutant(path: string, dest: string, labSrc?: string): string;
  ReplayError: new (file: string, step: number | undefined, problem: string) => Error & { file: string; step: number | undefined };
}

/** One case of the harness (harness.ts Run), driven event by event, with the scripted LND's payments in view. */
export interface HarnessRun {
  step(event: Record<string, unknown>): Promise<boolean>;
  dispose(): Promise<void>;
  lnd: { payments: Map<string, { status: string; valueMsat: bigint; feeMsat: bigint; htlcs: { status: string; principalMsat: bigint;
    route: { totalAmtMsat: bigint; totalFeesMsat: bigint; hops: { amtToForwardMsat: bigint }[] } }[] }> };
  oracle: { violations: { predicate: string; message: string }[] };
}

export interface HarnessCase {
  Run: new (lab: unknown, config: { scale: 'small' | 'huge'; budget: boolean; limit: string }, scratch: string) => HarnessRun;
  loadLab(): Promise<unknown>;
}

const HARNESS = '../../examples/payment-lab/test/harness/';

export async function loadHarness(): Promise<Harness> {
  return await import(/* @vite-ignore */ `${HARNESS}harness.ts`) as Harness;
}

/** The Run class and the lab loader, to drive one case by hand. */
export async function loadHarnessCase(): Promise<HarnessCase> {
  const { Run } = await import(/* @vite-ignore */ `${HARNESS}harness.ts`) as Pick<HarnessCase, 'Run'>;
  const { loadLab } = await import(/* @vite-ignore */ `${HARNESS}lab.ts`) as { loadLab(): Promise<unknown> };
  return { Run, loadLab };
}

/** The replay corpus directory, relative to the repository root. */
export const CORPUS = 'examples/payment-lab/test/harness/replays';

/** The command-line runner, relative to the repository root. */
export const RUNNER = 'examples/payment-lab/test/harness/run.mjs';
