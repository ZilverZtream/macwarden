import { spawn, spawnSync } from 'node:child_process';

/**
 * Asynchronous twin of validation-support's run() for long Node commands (direct Vitest).
 * Full validation runs them beside the oracle shards; a spawnSync would block the event loop,
 * so the shards' next steps could not start and their output pipes would go undrained.
 * Same contract as run(): 32 MB of output, the deadline, and exit 1 on a timeout or overflow;
 * the whole process tree is killed, since Vitest runs its tests in child processes.
 */
export function runNode(args, root, env, timeout) {
  return new Promise(resolveResult => {
    const output = [];
    let outputSize = 0;
    let outputLimitExceeded = false;
    let timedOut = false;
    let settled = false;
    let child;
    let timer;
    const killTree = () => {
      if (!child?.pid) return;
      if (process.platform === 'win32') {
        const killed = spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'],
          { windowsHide: true, encoding: 'utf8', timeout: 5_000 });
        if (killed.status !== 0) child.kill('SIGKILL');
      } else {
        try { process.kill(-child.pid, 'SIGKILL'); }
        catch (error) { if (error.code !== 'ESRCH') child.kill('SIGKILL'); }
      }
    };
    const append = data => {
      if (outputLimitExceeded) return;
      const chunk = Buffer.isBuffer(data) ? data : Buffer.from(data);
      const kept = chunk.subarray(0, 32_000_000 - outputSize);
      output.push(kept);
      outputSize += kept.length;
      if (kept.length < chunk.length) {
        outputLimitExceeded = true;
        killTree();
      }
    };
    const finish = code => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolveResult({ exitCode: timedOut || outputLimitExceeded ? 1 : Number.isInteger(code) ? code : 1,
        output: Buffer.concat(output).toString('utf8'), timedOut });
    };
    try {
      child = spawn(process.execPath, args, {
        cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'], detached: process.platform !== 'win32', windowsHide: true,
      });
    } catch {
      return resolveResult({ exitCode: 1, output: '', timedOut: false });
    }
    child.stdout.on('data', append);
    child.stderr.on('data', append);
    child.on('error', () => finish(1));
    child.on('close', finish);
    timer = setTimeout(() => {
      if (settled) return;
      timedOut = true;
      killTree();
    }, timeout);
  });
}
