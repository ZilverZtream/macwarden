export type LeakOptions = {
  sentinels: string; sentinelDir?: string; paths?: string[]; commandOutput?: string;
  testTmp?: string; root?: string; evidenceDir?: string;
};
// Public tool inputs are independently declared here; TypeScript inference of
// unannotated JavaScript defaults (notably []) is not the CLI contract.
type LeakTool = { findLeaks(options: LeakOptions): { path: string; encoding: string; fingerprint?: string } | null };
const tool = await import('../../scripts/leak-check.mjs') as LeakTool;
export const findLeaks = tool.findLeaks;
