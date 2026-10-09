import { childEnvironment } from './helpers/environment.js';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';

describe('CP-001 process errors', () => {
  it('CP-001/B8 handles uncaught exceptions and unhandled rejections without leaks', () => {
    const marker = 'face'.repeat(16);
    for (const preload of ['uncaught.mjs', 'unhandled.mjs']) {
      for (const delayed of [false, true]) {
        const url = pathToFileURL(resolve('test', 'preloads', preload)).href;
        const delayUrl = pathToFileURL(resolve('test', 'preloads', 'startup-delay.mjs')).href;
        const child = spawnSync(process.execPath, [resolve('dist', 'bin.js'), '--help'], {
          encoding: 'utf8',
          timeout: 5_000,
          env: childEnvironment({NODE_OPTIONS: `--import=${url}${delayed ? ` --import=${delayUrl}` : ''}`, MACWARDEN_CRASH_MARKER: marker}),
        });
        expect(child.error).toBeUndefined();
        expect(child.status, `${preload} delayed=${delayed}`).toBe(8);
        expect(child.stderr).toContain('error: internal');
        expect(child.stdout + child.stderr).not.toContain(marker);
        expect(child.stdout + child.stderr).not.toMatch(/^\s{4}at /m);
      }
    }
  });

  it('CP-001/B8 redacts emitted process warnings without turning success into failure', () => {
    const marker = 'bead'.repeat(16);
    const url = pathToFileURL(resolve('test', 'preloads', 'warning.mjs')).href;
    const delayUrl = pathToFileURL(resolve('test', 'preloads', 'startup-delay.mjs')).href;
    for (const delayed of [false, true]) {
      const child = spawnSync(process.execPath, [resolve('dist', 'bin.js'), '--help'], {
        encoding: 'utf8',
        timeout: 5_000,
        env: childEnvironment({NODE_OPTIONS: `--import=${url}${delayed ? ` --import=${delayUrl}` : ''}`, MACWARDEN_CRASH_MARKER: marker}),
      });
      expect(child.error).toBeUndefined();
      expect(child.status, `warning delayed=${delayed}`).toBe(0);
      expect(child.stdout).toContain('Usage: macwarden');
      expect(child.stderr).toBe('');
      const output = child.stdout + child.stderr;
      expect(output.includes(marker)).toBe(false);
      expect(/^\s{4}at /m.test(output)).toBe(false);
    }
  });
});
