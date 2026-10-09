import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, expect, it } from 'vitest';
import { findLeaks } from "../helpers/leak-check.js";
import { artifact, files, repo, retainArtifactBytes } from '../release/artifact.js';

it('CP-014/tarball-leak extracted actual package contains no committed credential sentinel', () => {
  const a = artifact();
  const sentinelDir = join(a.root, 'tarball-sentinels');
  mkdirSync(sentinelDir);
  try {
    const vectors = join(repo, 'test/vectors');
    const manifest = JSON.parse(readFileSync(join(vectors, 'manifest.json'), 'utf8')) as {
      vectors: Array<{ file: string }> };
    const credentialFiles = manifest.vectors.map(entry => entry.file);
    expect(credentialFiles.length).toBeGreaterThan(0);
    for (const [index, path] of credentialFiles.entries())
      copyFileSync(join(vectors, path), join(sentinelDir, `vector-${index}.macaroon`));

    const scanFixtures = join(repo, 'test/scan-fixtures');
    const nwc = new Set<string>();
    for (const path of files(scanFixtures)) {
      if (!/\.(?:env|json|ya?ml|txt)$/.test(path)) continue;
      const contents = readFileSync(join(scanFixtures, path), 'utf8');
      if (!contents.includes('nostr+walletconnect://')) continue;
      for (const match of contents.matchAll(/\bsecret=([a-fA-F0-9]{64})\b/g)) nwc.add(match[1]);
    }
    expect(nwc.size).toBeGreaterThan(0);
    for (const [index, hex] of [...nwc].entries())
      writeFileSync(join(sentinelDir, `nwc-${index}.bin`), Buffer.from(hex, 'hex'));
    expect(files(sentinelDir).length).toBe(credentialFiles.length + nwc.size);
    expect(files(sentinelDir).every(path => readFileSync(join(sentinelDir, path)).length >= 32))
      .toBe(true);

    const leak = findLeaks({
      sentinels: join(repo, 'test/sentinels.json'), sentinelDir,
      paths: [a.extracted, a.tarball], testTmp: a.root, root: repo,
    });
    expect(leak, leak ? `${leak.path}: ${leak.encoding}` : 'no tarball credential leak').toBeNull();
  } finally { rmSync(sentinelDir, { recursive: true, force: true }); }
}, 120_000);

afterAll(retainArtifactBytes);
