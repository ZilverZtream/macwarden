// inventory --verify never probes a protected path a registry entry names as its outPath (SAFE-02, 1.2.1).
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it, vi } from 'vitest';
import { run as inventory } from '../src/commands/inventory.js';
import { save, scratch } from './helpers/cp029-rotate-support.js';

vi.setConfig({ testTimeout: 60_000 });

for (const name of ['macaroons.db', 'wallet.db', 'tls.key']) {
  it(`inventory --verify leaves an entry whose outPath is ${name} unverified without touching the file`, async () => scratch(async f => {
    const protectedPath = join(f.dir, name);
    writeFileSync(protectedPath, 'not for macwarden', { mode: 0o600 });
    f.old.outPath = protectedPath; save(f);
    const stat = vi.spyOn(f.deps.fs, 'stat'), open = vi.mocked(f.deps.fs.open);
    const result = await inventory([...f.args.slice(2), '--verify'], f.deps);
    expect(result.error).toBeNull();
    const row = (result.result as { rootKeys: Array<{ rootKeyId: string; verify: string }> }).rootKeys
      .find(item => item.rootKeyId === f.old.rootKeyId)!;
    expect(row.verify).toBe('not-checked');
    for (const call of [...stat.mock.calls, ...open.mock.calls]) expect(String(call[0])).not.toContain(name);
  }));
}
