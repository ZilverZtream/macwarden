## What changes

<!-- The resulting behaviour, in a sentence or two. Link the issue if there is one. -->

## Why

## How it was tested

<!-- Which tests were added or changed, and which commands you ran. A fix needs a test that fails before it. -->

- [ ] `npm run lint`
- [ ] `npm run build`
- [ ] `npm test`
- [ ] `npm run test:harness`
- [ ] Oracle tests (`npm run fixture:up`, `npm run test:oracle`, `npm run fixture:down`), for changes to online commands
- [ ] `npm run test:gitleaks`, for changes to scan patterns or rule packs

## Checklist

- [ ] No real credentials anywhere in this change, its tests or this description (test vectors and fingerprints only)
- [ ] No test was removed, skipped or loosened to make the change pass
- [ ] docs/spec.md, `--help` and the README agree with the new behaviour
- [ ] The SAFE rules in docs/security-model.md still hold
- [ ] CHANGELOG.md has an entry for user-visible changes
