import { readFileSync } from 'node:fs';

/** The installed macwarden version; this module sits at the top of src/ and dist/ beside package.json's parent. */
export function macwardenVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version?: unknown };
    return typeof pkg.version === 'string' ? pkg.version : 'unknown';
  } catch { return 'unknown'; }
}
