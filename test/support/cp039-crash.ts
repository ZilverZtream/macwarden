import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect } from 'vitest';
import { findLeaks } from '../../scripts/leak-check.mjs';
import { noCredential, pubkey, register, repo, root, scratch, sentinelList } from './cp039-audit.js';
import { localPeer } from './cp039-peer.js';

export async function crashLeakControl() {
  await scratch(async dir => {
    const peer = await localPeer();
    try {
      peer.state.body = JSON.stringify({ identity_pubkey: pubkey, alias: 'fixture', version: '0.21.4-beta', chains: [{ network: 'regtest' }] });
      const trace = join(dir, 'request-trace.txt'), env: NodeJS.ProcessEnv = { ...process.env, MACWARDEN_CP039_TRACE: trace };
      delete env.NODE_OPTIONS; delete env.NODE_DEBUG;
      const own = register(readFileSync(join(repo, 'test/vectors/default-admin.macaroon')));
      const child = spawn(process.execPath, ['--import', pathToFileURL(join(repo, 'test/preloads/cp039-midrequest.mjs')).href,
        join(repo, 'dist/bin.js'), 'inventory', '--registry', join(dir, 'absent.json'), '--lnd-rest', peer.restUrl.replace('https://', ''),
        '--tls-cert', peer.cert, '--macaroon', own, '--json'], { cwd: repo, env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
      let stdout = '', stderr = '';
      child.stdout.on('data', chunk => { stdout += chunk.toString(); }); child.stderr.on('data', chunk => { stderr += chunk.toString(); });
      const timeout = setTimeout(() => child.kill(), 15_000);
      let status: number | null;
      try { status = await new Promise<number | null>((done, fail) => { child.once('error', fail); child.once('close', done); }); }
      finally { clearTimeout(timeout); }
      expect(status).toBe(8); expect(readFileSync(trace, 'utf8')).toBe('request-entered');
      expect(stderr).toBe('');
      expect(JSON.parse(stdout)).toMatchObject({ schema: 1, command: 'inventory', ok: false, result: null, error: { code: 8, step: 'internal' } });
      noCredential(stdout + stderr);
      expect(findLeaks({ sentinels: sentinelList, sentinelDir: root('MACWARDEN_SENTINEL_DIR'), root: repo,
        commandOutput: stdout + stderr, paths: [dir] }) === null, 'crash output and evidence contain no credential').toBe(true);
    } finally { await peer.close(); }
  });
}
