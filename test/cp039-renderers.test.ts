import { expect, it, vi } from 'vitest';
import { run as inventory } from '../src/commands/inventory.js';
import { run as revoke } from '../src/commands/revoke.js';
import { run as rotate } from '../src/commands/rotate.js';
import type { OutputResult } from '../src/output/index.js';
import { render } from '../src/output/index.js';
import { context, entry, noCredential, now, scratch, sentinel } from './support/cp039-audit.js';

// Secret bytes are computed in memory and never appear in assertion diffs.
const nwcSecret = sentinel().subarray(0, 32).toString('hex');
const nwc = `nostr+walletconnect://${'ab'.repeat(32)}?relay=wss://relay.invalid&secret=${nwcSecret}`;
for (const command of ['revoke', 'rotate'] as const) {
  it(`CP-039/B2-renderers ${command} retains dry-run plans after NWC redaction and copying`, async () => scratch(async dir => {
    const old = entry({ caveats: [{ type: 'unknown', value: `operator-note ${nwc}` }] });
    const f = context(dir, [old]);
    if (command === 'revoke') f.lnd.ids = [0n]; // V7's already-absent repair plan.
    const run = command === 'revoke' ? revoke : rotate;
    const result = await run(['Alice', ...f.online, '--dry-run', ...(command === 'rotate' ? ['--out', f.out] : [])], f.deps);
    expect(result.error).toBeNull();
    result.warnings.push({ code: 'snapshot-drift', message: `peer-note ${nwc}` });
    const text = render(result, 'text');
    expect(text.includes(nwcSecret), 'NWC secret absent').toBe(false);
    if (command === 'revoke') expect(text.toLowerCase()).toContain('already absent');
    else {
      expect(text.toLowerCase()).toContain('stage'); expect(text.toLowerCase()).toContain('finish');
      expect(text).toContain('macwarden rotate Alice --finish');
    }
    for (const value of ['9001', 'Alice', old.grade]) expect(text).toContain(value);
    if (!result.ok) throw new Error('Expected successful dry-run result');
    let copy: OutputResult;
    if (result.command === 'revoke') copy = { ...result, result: { ...result.result }, warnings: [...result.warnings] };
    else if (result.command === 'rotate') copy = { ...result, result: { ...result.result }, warnings: [...result.warnings] };
    else throw new Error('Unexpected dry-run command');
    expect(render(copy, 'text')).toBe(text);
    const doc = JSON.parse(render(result, 'json'));
    expect(doc).toMatchObject({ schema: 1, command, ok: true, error: null, result: { dryRun: true } });
    expect(JSON.stringify(doc).includes(nwcSecret), 'JSON excludes NWC secret').toBe(false);
    noCredential(text);
  }));
}
it('CP-039/B2-renderers inventory age uses the injected clock across copied results', async () => scratch(async dir => {
  const f = context(dir, [entry()]);
  const liveClock = vi.spyOn(Date, 'now').mockReturnValue(Date.parse('2040-01-01T00:00:00Z'));
  try {
    const result = await inventory(f.online, f.deps);
    expect(result.error).toBeNull();
    const text = render(result, 'text');
    expect(text, `age as of ${now}`).toMatch(/\b3d\b/);
    expect(text).not.toMatch(/\b\d{4,}d\b/);
    if (!result.ok || result.command !== 'inventory') throw new Error('Expected successful inventory result');
    const copy: OutputResult = { ...result, result: { ...result.result } };
    expect(render(copy, 'text')).toBe(text);
    expect(JSON.parse(render(copy, 'json'))).toEqual(JSON.parse(render(result, 'json')));
  } finally { liveClock.mockRestore(); }
}));
