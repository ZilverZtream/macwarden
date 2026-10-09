import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, vi } from 'vitest';
import { run as inspect } from '../../src/commands/inspect.js';
import { run as scan } from '../../src/commands/scan.js';
import { run as inventory } from '../../src/commands/inventory.js';
import { run as bake } from '../../src/commands/bake/index.js';
import { run as revoke } from '../../src/commands/revoke.js';
import { run as rotate } from '../../src/commands/rotate.js';
import { run as attenuate } from '../../src/commands/attenuate.js';
import { render } from '../../src/output/index.js';
import { Secret } from '../../src/secret.js';
import { findLeaks } from '../../scripts/leak-check.mjs';
import { context, entry, noCredential, register, repo, root, scratch, sentinel, sentinelList, wireMacaroon } from './cp039-audit.js';

export const commandNames = ['inspect', 'scan', 'inventory', 'bake', 'revoke', 'rotate', 'attenuate'] as const;
export async function commandLeakControl(command: typeof commandNames[number]): Promise<void> {
  await scratch(async dir => {
    const f = context(dir, [entry()]);
    f.online[f.online.length - 1] = register(readFileSync(join(repo, 'test/vectors/default-admin.macaroon')));
    const input = join(dir, 'input.macaroon');
    // Input is registered, and excluded solely as a pre-existing credential input, not as output evidence.
    writeFileSync(input, sentinel());
    const beforeFiles = new Set(readdirSync(dir));
    f.lnd.bakeMacaroon = async (permissions, id) => {
      f.lnd.calls.push('BakeMacaroon');
      const bytes = wireMacaroon(permissions, id); register(bytes); f.lnd.ids.push(id); return new Secret(bytes);
    };
    f.lnd.deleteMacaroonId = async id => {
      f.lnd.calls.push('DeleteMacaroonID'); f.lnd.ids = f.lnd.ids.filter(value => value !== id); return { deleted: true };
    };
    const deps = command === 'rotate' ? { ...f.deps,
      stdin: Object.assign(f.deps.stdin, { isTTY: true }),
      prompt: Object.assign(async (question: string) => {
        expect(question).toContain(entry().grade);
        for (const permission of entry().permissions) expect(question).toContain(permission);
        expect(question).toMatch(/unproven|cannot|unable|not.*prov/i);
        capture += question;
        expect(readdirSync(dir)).not.toContain('registry.json.lock');
        expect(readdirSync(dir)).not.toContain('issued.macaroon');
        return 'Alice';
      }, { isTTY: true }) } : f.deps;
    const leading = command === 'bake' ? ['--label', 'New', '--preset', 'invoice-only', '--out', f.out] :
      command === 'rotate' ? ['Alice', '--out', f.out] : command === 'revoke' ? ['Alice', '--yes'] : [];
    let capture = '';
    const out = vi.spyOn(process.stdout, 'write').mockImplementation(((value: unknown) => { capture += String(value); return true; }) as typeof process.stdout.write);
    const err = vi.spyOn(process.stderr, 'write').mockImplementation(((value: unknown) => { capture += String(value); return true; }) as typeof process.stderr.write);
    let result: Parameters<typeof render>[0];
    try {
      const run = { inspect, scan, inventory, bake, revoke, rotate, attenuate }[command];
      result = await run(command === 'inspect' || command === 'scan' ? [input]
        : command === 'attenuate' ? [input, '--out', f.out, '--expires', '1h', '--ip', '127.0.0.1'] : [...leading, ...f.online], deps);
    } finally { out.mockRestore(); err.mockRestore(); }
    expect(result.error?.code ?? 0, `${command} completes`).toBe(0);
    // The attenuated copy is itself a credential: register it so the leak oracle also looks for it.
    if (command === 'attenuate') register(readFileSync(f.out));
    const json = render(result, 'json'), text = render(result, 'text');
    expect(JSON.parse(json)).toMatchObject({ schema: 1, command, ok: true, error: null });
    noCredential(capture + json + text);
    const output = join(dir, 'command-output.txt'); writeFileSync(output, capture + json + text);
    const written = readdirSync(dir).filter(file => !beforeFiles.has(file) && join(dir, file) !== f.out).map(file => join(dir, file));
    expect(findLeaks({ sentinels: sentinelList, sentinelDir: root('MACWARDEN_SENTINEL_DIR'), root: repo,
      commandOutput: capture + json + text, paths: [...written, f.registry], testTmp: root() }) === null,
      `${command} output registry and other written files are leak-free`).toBe(true);
    if (['bake', 'rotate', 'attenuate'].includes(command)) expect(readFileSync(f.out).length > 0, 'declared credential output was written').toBe(true);
    if (command === 'inspect' || command === 'scan' || command === 'attenuate') expect(f.lnd.calls).toEqual([]);
  });
}
