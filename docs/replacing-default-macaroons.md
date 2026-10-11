# Replacing the default macaroons

Replace shared default LND macaroons with one individually revocable macaroon per app. The order is: maintenance window → operator root-key rotation → fresh macwarden session macaroon → bake once per app → distribute → `inventory --verify` → scan app configs for root-key-0 credentials.

Root-key rotation invalidates **every previously baked macaroon**, including all macwarden-baked app credentials and macwarden's own credential. Do not move apps to new macaroons before rotating: that rotation would invalidate their replacements too. Each app must finish with its own distinct, non-zero root key ID; credentials sharing an ID are revoked together.

This guide uses the online commands (`bake`, `inventory --verify`) and `scan`; any macwarden 1.x release has them (see the [README](../README.md)). Rehearse the whole procedure on a disposable regtest node before running it on a node that holds funds.

## 1. Plan a maintenance window

List every app, its credential/config paths, required LND calls and restart procedure. Include apps using `admin.macaroon`, `readonly.macaroon`, `invoice.macaroon` or other credentials on root key ID 0, and apps already using non-zero IDs: all are affected. Pause the apps and disconnect their existing streams during the window. Revocation blocks new requests; existing streams can stay open until disconnected. If a credential may be compromised, restart LND.

Arrange secure operator access, recovery procedures and a version-appropriate LND password-change workflow before starting. Keep wallet passwords, seeds, TLS keys and credential stores away from macwarden. Do not delete, rename, read or write `macaroons.db` as part of this guide, and never delete root key ID 0. macwarden does not rotate the node's root keys or call `changepassword` (SAFE-02/03).

Use an operator machine or locked-down admin host, with a private working directory outside app repositories. Do not store macwarden's credential in an app repository or CI variable. Install an appropriate pinned build; see [Installing](security-model.md#installing). Protect all macaroon files and distribute them through your existing secure secret delivery mechanism. Reports and maintenance records contain paths, labels, root key IDs and fingerprints only, never credential bytes, hex or base64.

The following examples use Bash and assume `lncli` is configured for the intended node and its current operator credential. Set macwarden's connection parameters to that same node, using paths to its TLS certificate and macaroon files, never literal credential text:

```sh
export MACWARDEN_LND_REST='localhost:8080'
export MACWARDEN_TLS_CERT='/operator/path/to/tls.cert'
```

Replace the endpoint and certificate path for your setup. TLS verification remains enabled. Unset `NODE_OPTIONS` and keep `NODE_DEBUG` HTTP/HTTPS/TLS/net tracing disabled, because they can expose credentials: macwarden refuses to run with any non-empty `NODE_OPTIONS` or such a `NODE_DEBUG`. All development rehearsals and integration validation must contact only the disposable pinned regtest fixture (SAFE-10).

## 2. Rotate the root keys yourself

With apps paused, the **operator**, outside macwarden, uses LND's password-change workflow with new root keys. Check the installed version's help and recovery instructions first:

```sh
lncli changepassword --help
lncli changepassword --new_mac_root_key
```

Perform the interactive password workflow privately; never put passwords in command arguments, transcripts or notes. Follow LND's version-specific restart/unlock instructions and obtain its freshly generated admin credential for the next step. Do not resume apps yet. Old credentials, including the old macwarden session, are invalid and cannot serve as a rollback. LND regenerates every root key, not just ID 0; see [verified LND behaviour](architecture.md#verified-lnd-behaviour-the-commands-rely-on).

## 3. Bake a fresh macwarden session macaroon

Use `lncli` authenticated with the **new** operator/admin credential. Holding `macaroon:generate` is **admin-equivalent**: it can issue spending permissions regardless of the caller's own permissions. Protect the session macaroon exactly like `admin.macaroon` (SAFE-09).

Check flag names with `lncli bakemacaroon --help` on your LND version. Follow the [session recipe](security-model.md#the-credential-macwarden-runs-with), using an explicit non-zero ID and a one-hour timeout:

```sh
lncli bakemacaroon --help
ID=$(( (RANDOM << 30) | (RANDOM << 15) | RANDOM ))    # check it is not in `lncli listmacaroonids`
lncli listmacaroonids
```

Before continuing, check that `$ID` is non-zero and absent from the listed IDs. If it is zero or collides, draw again and repeat the check. Baking with an existing ID reuses its root key; it does not create an independent credential.

```sh
lncli bakemacaroon --root_key_id "$ID" --timeout 3600 \
  --save_to ./macwarden-session.macaroon \
  macaroon:generate macaroon:read macaroon:write info:read
export MACWARDEN_MACAROON='./macwarden-session.macaroon'    # … this session's commands
macwarden inventory
```

The inventory call checks the connection with the fresh session; it does not replace the later app verification. Keep this session file and its ID until cleanup. If it expires before the work is complete, use the operator credential to bake another fresh session on a new, checked non-zero ID. Never substitute an expired pre-rotation session.

## 4. Bake one macaroon per app

Choose the smallest permission set that supports each app's required calls. Use a unique label and a new output file for every app, and the same node/registry throughout the procedure. macwarden allocates a fresh non-zero root key ID at bake time, verifies the final bytes and records the file's fingerprint and path. The output path must not already exist.

This preserves the specification's **invoice-only example**:

```sh
macwarden bake --label btcpay --preset invoice-only --expires 90d --out ./btcpay.macaroon
```

Here `btcpay` is a label, not a preset. `invoice-only` grants `info:read invoices:read invoices:write`. This example does not establish all permissions needed by BTCPay Server; the app-specific BTCPay Server preset is outside this guide's scope.

For a three-app rehearsal, use that invoice app plus two simulated apps whose needs match these existing presets:

```sh
macwarden bake --label dashboard --preset read-only --expires 90d --out ./dashboard.macaroon
macwarden bake --label invoice-service --preset invoice-only --expires 90d --out ./invoice-service.macaroon
```

Record the three labels, distinct non-zero root key IDs, output paths and fingerprints. For actual apps, select permissions from their documented calls rather than copying a preset on faith. Do not issue one shared credential to several apps. If an old active registry entry already uses a label, select a new migration label; retain the old entry for reconciliation rather than overwriting it.

Stop on any bake failure. In particular, exit 7 can mean LND changed even though the operation did not finish: follow the reported inventory/revoke instructions before another bake. Do not retry blindly or distribute an unverified file. On Windows, resolve an `acl-best-effort` warning by restricting folder/file access before distribution.

## 5. Distribute and switch the apps

Deliver each app only its own newly baked file. Replace old file references and embedded credentials in its active configuration, including duplicate config entries. Retain macwarden's recorded `--out` files securely at their registry paths so `inventory --verify` can verify matching fingerprints; distributing a copy is not a reason to remove those originals.

Restart or reconnect each app with its replacement credential. Exercise its required LND calls and check that it can do its intended job. If an app cannot authenticate or lacks a required permission, keep its migration unresolved and correct it before completion. A pre-rotation credential will not restore service.

## 6. Verify every replacement

```sh
macwarden inventory --verify
```

Check the node identity and each replacement's row: it must be active and **accepted**, on its own distinct non-zero root key ID, with the intended label, permissions, path and fingerprint. A zero command exit is not enough: inventory may exit 0 with flagged rows. `rejected`, `error`, `not-checked` or a missing row does not prove the app migrated. Restore missing registry-path files with matching fingerprints, resolve authentication/permission failures and repeat the affected verification before completion. Reconcile old invalid registry entries separately; their presence must not be mistaken for accepted replacements.

Inventory verifies the registered files, not what an app actually loaded. Confirm the app-side functional checks from step 5 as well. Unknown IDs may belong to other tools/operators; investigate ownership rather than deleting them indiscriminately. Root key ID 0 still exists in LND for operator use and is never deleted by this procedure.

## 7. Scan the app configs and decide whether migration is complete

Use the independently prepared list of app config paths from step 1, including each app's installed credential file. For example, after replacing these paths with the actual three app locations:

```sh
macwarden scan /apps/btcpay/config /apps/dashboard/config /apps/invoice-service/config --json
```

Check findings against your labels, root key IDs and fingerprints: **no root-key-0 credential may remain in those app configs**. A scan exit 0 alone does not establish this; it can return findings successfully. Non-zero app credentials are expected findings. Review ignored findings, skipped files and undecodable candidates; do not hide an old credential with `.macwardenignore` or a grade threshold. A root-key-0 read-only credential is still a migration failure. Remove or replace remaining old app-config credentials, resolve incomplete coverage, and rescan the affected paths before declaring completion.

A clean scan is not proof that no credential exists elsewhere or in an unrecognized encoding. Scan is pattern-based: text detectors require location `lnd`; split, line-wrapped, encrypted, archived or oddly encoded credentials may be missed. UTF-16 without a BOM is treated as binary, files over 5 MiB are skipped, and git history is scanned only with `scan --git-history`. Files whose names look like wallet secrets (`*.key`, names containing `seed`, `password` or `passwd` as a word, `macaroons.db`, `wallet.db`) are never opened (SAFE-02): they are reported as skipped (`never-open`) and named in text, JSON, SARIF and GitHub output, not scanned, so check any app config with such a name by hand. Inventory likewise cannot establish complete coverage of stateless/offline baking or a remote signer's separate store; verification is meaningless with `--no-macaroons`. See the [threat model](security-model.md#threat-model).

Declare this replacement complete only when every listed app works with its distinct non-zero-root-key credential, every replacement verifies accepted, and the final covered app configs contain no root-key-0 credentials. Failed verification or a remaining old config credential leaves the replacement incomplete; resolve it while maintaining the window. This procedure never delegates root-key rotation to macwarden.

For the disposable-regtest rehearsal, prepare a list of the simulated apps independently of scan output. Record the ordered steps, command exits, the final app/root-key/fingerprint mapping, `lncli` acceptance of each replacement and rejection of earlier credentials (including the old macwarden session), and agreement between your list, `inventory` and the config scan. Do not record credential encodings or passwords.

## 8. Revoke and remove the session credential

After completing the session's commands, use `lncli` with the current operator/admin credential, not the session being revoked:

```sh
lncli deletemacaroonid "$ID"
rm ./macwarden-session.macaroon
```

Confirm successful deletion before local cleanup; never use ID 0. If multiple fresh sessions were needed, revoke and remove each. This is the local cleanup from the session recipe in [security-model.md](security-model.md). Each app's different root key ID remains available for individual future revocation, without another global root-key rotation.
