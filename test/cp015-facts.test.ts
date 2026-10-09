import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { FixtureInvalidError } from './helpers/fixture-invalid.mjs';
import { classifyAcceptance, compareReference, registerFixtureSentinel,
  requireBaselineRootKeyIds, requirePinnedFixture } from './helpers/lnd-facts.mjs';

const testTmp = process.env.MACWARDEN_TEST_TMP || join(process.cwd(), 'test/.tmp');
process.env.MACWARDEN_TEST_TMP = testTmp;

it('CP-015/B1 wrong network or version aborts before a fact probe', () => {
  for (const [network, version] of [['signet', '0.21.4-beta'], ['regtest', '0.21.5-beta']]) {
    let probed = false;
    const start = () => { requirePinnedFixture({ chains: [{ network }], version }, { root_key_ids: ['0'] });
      probed = true; };
    expect(start).toThrow(FixtureInvalidError);
    expect(probed).toBe(false);
  }
});

it('CP-015/B2 leftover root key ID aborts before a fact probe', () => {
  let probed = false;
  const start = () => { requireBaselineRootKeyIds({ root_key_ids: ['0', '7'] }); probed = true; };
  expect(start).toThrow(FixtureInvalidError);
  expect(probed).toBe(false);
});

it('CP-015/B3 lncli acceptance has three distinct outcomes and redacts response text', () => {
  const marker = 'private-test-marker';
  const results = [
    { status: 0, stderr: marker },
    { status: 1, stderr: `rpc error: root key with id 7 doesn't exist ${marker}` },
    { status: 1, stderr: `rpc error: unavailable ${marker}` },
  ];
  expect(results.map(classifyAcceptance)).toEqual(['accepted', 'rejected', 'error']);
  expect(JSON.stringify(results.map(classifyAcceptance))).not.toContain(marker);
});

it('CP-015/B4 fixture macaroon is registered by path without outputting contents', () => {
  mkdirSync(testTmp, { recursive: true });
  const dir = mkdtempSync(join(testTmp, 'cp015-sentinel-'));
  try {
    const source = join(dir, 'source.macaroon');
    const marker = Buffer.from('disposable fixture-only sentinel');
    writeFileSync(source, marker);
    const target = registerFixtureSentinel(source, 'cp015-baked.macaroon', join(dir, 'sentinels'));
    expect(readFileSync(target)).toEqual(marker);
    expect(target).not.toContain(marker.toString());
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

it('CP-015/B13 a contradictory pinned fact emits both references and remains unsettled', () => {
  const result = compareReference({ statement: 'docs/architecture.md assumption 2',
    reference: 'pinned ListMacaroonIDs', expected: 'strings', observed: 'numbers' });
  expect(result.settled).toBe(false);
  expect(result.conflict).toContain('REFERENCE_CONFLICT');
  expect(result.conflict).toContain('docs/architecture.md assumption 2');
  expect(result.conflict).toContain('pinned ListMacaroonIDs');
});

it('CP-015/B12 Lightning Terminal prefix is tied to an exact source revision', () => {
  const citation = JSON.parse(readFileSync(join(process.cwd(), 'test/oracle/facts/assumption-12.json'), 'utf8')) as {
    revision: string; source: string; location: string; observation: string; localLndObservation: boolean;
  };
  expect(citation.revision).toMatch(/^[0-9a-f]{40}$/);
  expect(citation.source).toContain(`/blob/${citation.revision}/macaroons/super_mac.go#L19-L35`);
  expect(citation.location).toContain('macaroons/super_mac.go');
  expect(citation.observation).toContain('FF EE DD CC');
  expect(citation.localLndObservation).toBe(false);
});

it('CP-015/B11 a nonempty pinned GetInfo requirement controls URI grade', async () => {
  const snapshot = JSON.parse(readFileSync(join(process.cwd(), 'src/grade/lnd-permissions.json'), 'utf8')) as {
    methods: Record<string, string[]>;
  };
  expect(snapshot.methods['/lnrpc.Lightning/GetInfo']).toEqual(['info:read']);

  const { grade } = await import('../src/grade/index.js') as {
    grade: (permissions: string[]) => { grade: string; reasons: string[] };
  };
  expect(grade(['uri:/lnrpc.Lightning/GetInfo']).grade).toBe('READ');
  expect(grade(['uri:/lnrpc.Lightning/GetInfo']).reasons).toEqual(['uri:/lnrpc.Lightning/GetInfo']);
});
