# Field check

A short procedure to confirm a macwarden release against your own LND node. It takes about 15 minutes. It only reads from the node, except for one throwaway macaroon that it bakes, rotates and revokes. Nothing it does touches your existing apps or credentials.

Record only versions, exit codes and fingerprints. Never paste a macaroon, an `lndconnect://` URI or a connection string into the report or anywhere else.

## Before you start

- LND 0.21.x, unlocked, with `lncli` working on the node.
- Node.js 22.23.2 or later on the 22 line, 24.18.1 or later on the 24 line, or 26.5.1 or later, on the machine running macwarden.
- A working directory you can delete afterwards, for example `~/macwarden-field-check`.

```sh
npm install -g macwarden@1.1.1
macwarden --version            # expect 1.1.1
lncli getinfo | grep version   # record the LND version
```

## 1. Offline checks

```sh
macwarden inspect ~/.lnd/data/chain/bitcoin/mainnet/readonly.macaroon
macwarden scan ~/.lnd --fail-on READ
```

Expect: `inspect` grades `readonly.macaroon` as `READ` on root key ID 0. `scan` finds the default macaroons (`admin.macaroon` as `ADMIN`) and exits 1. It never opens `macaroons.db`, `wallet.db` or the TLS key; check that they appear as skipped `never-open`, not as findings. Adjust `mainnet` for your network.

## 2. A session credential for macwarden

```sh
lncli listmacaroonids              # pick an ID that is not listed, e.g. 777000111
lncli bakemacaroon --root_key_id 777000111 --timeout 3600 \
  --save_to ./session.macaroon \
  macaroon:generate macaroon:read macaroon:write info:read

export MACWARDEN_LND_REST=127.0.0.1:8080
export MACWARDEN_TLS_CERT=~/.lnd/tls.cert
export MACWARDEN_MACAROON=./session.macaroon
```

Use your node's REST address if it is not on `127.0.0.1:8080`. macwarden keeps its registry at `~/.config/macwarden/registry.json` (Windows: `%APPDATA%\macwarden\registry.json`); the field-check entries stay there afterwards as revoked records, which is harmless.

## 3. Inventory

```sh
macwarden inventory --verify
```

Expect: exit 0. Root key ID 0 is flagged as the default root key, your session ID (777000111) as macwarden's own credential, and any other IDs as unknown. macwarden never changes unknown IDs; they may belong to Lightning Terminal, Loop, Pool or another tool.

## 4. Bake, rotate and revoke a throwaway macaroon

```sh
macwarden bake --label field-check --preset read-only --expires 1h --out ./fc.macaroon --dry-run
macwarden bake --label field-check --preset read-only --expires 1h --out ./fc.macaroon
lncli --macaroonpath ./fc.macaroon getinfo            # expect success
lncli --macaroonpath ./fc.macaroon addinvoice 1       # expect permission denied

macwarden rotate field-check --out ./fc-next.macaroon
macwarden rotate field-check --finish                 # type the label to confirm
lncli --macaroonpath ./fc.macaroon getinfo            # expect failure: old credential rejected
lncli --macaroonpath ./fc-next.macaroon getinfo       # expect success

macwarden revoke field-check --target-file ./fc-next.macaroon
lncli --macaroonpath ./fc-next.macaroon getinfo       # expect failure
macwarden inventory --verify                          # field-check no longer appears: its root key IDs are gone from LND
```

Expect: every macwarden command exits 0, and `rotate --finish` and `revoke` end with the revocation-scope sentence. Neither `admin.macaroon` nor any app is affected.

## 5. Evidence report

```sh
macwarden inventory --report markdown --out ./access-review.md
```

Expect: a Markdown access review listing every root key ID with the same flags as step 3. Read it: it must contain no credential bytes, only IDs, labels, grades and fingerprints.

## 6. Optional: watch

Only if you can restart LND with `rpcmiddleware.enable=true`. Never enable `rpcmiddleware.addmandatory`.

```sh
macwarden watch --until 2m
```

While it runs, make a few calls with `lncli`. Expect one event per call, attributed to a root key ID, and a summary at the end. LND keeps working normally after `watch` exits.

## 7. Clean up

```sh
lncli deletemacaroonid 777000111
cd .. && rm -rf ~/macwarden-field-check
```

## Report

Record this and keep it with the release notes:

```text
macwarden version:
LND version and network:
OS and Node.js version:
Step 1 inspect / scan exit codes:
Step 3 inventory exit code and flags seen:
Step 4 bake / rotate / finish / revoke exit codes, and lncli results:
Step 5 report reviewed (yes/no):
Step 6 watch (run / skipped):
Surprises (anything unexpected, however small):
```

A surprise is anything that did not match an "Expect" line. Report it as a GitHub issue without credentials (see [CONTRIBUTING.md](../CONTRIBUTING.md)); it is fixed in a 1.x release.
