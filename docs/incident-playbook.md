# Incident playbook: credentials exposed (BTCPay Server < 2.4.2 and similar)

Use this when LND macaroon files, or connection strings that contain them, may have been copied by someone else. The case that prompted it is the [BTCPay Server 2.4.2 security advisory](https://blog.btcpayserver.org/security-advisory-btcpay-server-2-4-2/) (2026-08-07): an unauthenticated attacker could download `.macaroon` files for LND from affected BTCPay Server instances, the flaw was exploited, and funds were stolen. The advisory says: "If you use LND, treat its credentials as potentially exposed." The same steps apply to any leak of macaroon files: a backup, a repository, a support bundle or a compromised app server.

Work through the sections in order. Commands that change the node are marked; everything else only reads.

## 1. What patching fixes, and what it does not

Updating BTCPay Server to 2.4.2 or later closes the hole, so no new copies can be taken that way. It does nothing about copies already taken.

- A macaroon is a bearer credential. LND accepts a copy for as long as its root key exists and its caveats (such as an expiry) are satisfied. Upgrading or restarting BTCPay Server or LND does not change that.
- When `admin.macaroon` is missing at startup, LND writes a new one from the same root key, so replacing or regenerating the file leaves a stolen copy valid.
- `admin.macaroon`, `readonly.macaroon`, `invoice.macaroon` and every macaroon baked without `--root_key_id` share **root key ID 0**. LND refuses to delete root key ID 0, so these cannot be revoked one at a time. Only regenerating every root key invalidates them (section 5).
- A credential that can bake (`admin.macaroon`, or anything holding `macaroon:generate`) lets its holder create further credentials on any root key ID. Revoking the original does not remove those.

So after patching, assume every credential the vulnerable service could read is in someone else's hands until LND rejects it.

## 2. Contain

1. Update BTCPay Server (or whichever service leaked) before anything else. If you cannot update now, take it offline.
2. Make a list of every credential that may be exposed: each `.macaroon` file the service could read, and every `lndconnect://` URI or connection string in its configuration or database. If you are unsure, include it.
3. Find copies you do not know about. `scan` is offline and prints only fingerprints:

   ```sh
   macwarden scan /path/to/btcpay/data /path/to/backups --json
   macwarden scan /path/to/app-repo --git-history --fail-on READ
   ```

4. If an admin-capable credential was exposed, treat the node's funds as at risk and move straight to section 5 for it; do not wait for the rest of this list.

## 3. Check each old file with `macwarden verify`

`verify` asks your node whether one credential is still accepted. It decodes the file offline (fingerprint, root key ID, grade, permissions, caveats), then calls LND's CheckMacaroonPermissions with that credential and its own permissions. It never prints the credential, only its fingerprint, and it changes nothing.

Run it from an operator machine with a dedicated macwarden credential of its own, never with one of the exposed files. `info:read` and `macaroon:read` are enough for `verify` (and `inventory`); see [the credential macwarden runs with](security-model.md#the-credential-macwarden-runs-with).

```sh
export MACWARDEN_LND_REST=127.0.0.1:8080
export MACWARDEN_TLS_CERT=/path/to/tls.cert
export MACWARDEN_MACAROON=/path/to/macwarden-session.macaroon

macwarden verify /path/to/old/admin.macaroon
```

Check every file on your list. Pass files by path (or `-` for stdin); do not paste credentials on the command line.

```sh
for f in /path/to/old/*.macaroon; do
  macwarden verify "$f" --json > "$(basename "$f").verify.json"
  echo "$f: exit $?"
done
```

| Exit | Meaning | What to do |
| --- | --- | --- |
| 1, `status: accepted` | LND accepts it now. Whoever holds a copy can use it. | Section 4 (own root key ID) or section 5 (root key ID 0, or it can bake). The `next` lines name the command. |
| 1, `status: rejected`, `conclusive: false` | LND refused this check, but for a reason that can depend on the caller, such as an IP lock or a custom caveat. This includes a file whose expiry has passed by your machine's clock when LND did not report the expiry, and a `signature-mismatch` while the root key ID is still listed for a file that is not the exact credential the registry recorded: that is what LND answers after a root key regeneration, but also for an altered copy (a flipped byte, a mangled paste, a decoy) of a credential that still works. Section 5, step 7 explains how to get a conclusive answer. | Treat it as live and revoke its root key ID. On root key ID 0, regenerate every root key unless you already did. |
| 0 | LND rejects it: its root key ID is gone (`root-key-missing`), its signature does not match and the root key ID is no longer listed or the file is the exact credential the registry recorded (`signature-mismatch`) or LND itself reported it expired (`expired`; your machine's clock is never enough). | Nothing for this file. For an expired one, other macaroons on the same root key ID still work until it is revoked. |
| 2, 3 | Usage or input problem (a Nostr Wallet Connect string is refused: it is revoked in the wallet service, not in LND). | Fix the input and rerun. |
| 4, 5 | macwarden could not ask LND (connection, TLS, its own credential, or an LND error). | Fix the connection; the file is unchecked. |

The text output also says whether the root key ID is still listed in LND and which registry label it belongs to, if any. To see every root key ID on the node, including ones no file on your list uses, run `macwarden inventory`. Unknown IDs may belong to Lightning Terminal, Loop, Pool or another operator; find the owner before revoking one.

## 4. Replace and revoke credentials on their own root key ID

These are the credentials macwarden (or `lncli bakemacaroon --root_key_id`) issued per app. Each can be revoked alone. Revoking a root key ID invalidates every macaroon baked on it.

- **Registered with macwarden, several apps:** stage a replacement for every registered credential, switch the apps, then finish. `--finish` revokes the old root key IDs and proves each old credential rejected and each replacement accepted. *(Changes the node.)*

  ```sh
  macwarden respond --out-dir ./replacements
  # give each app its new file from ./replacements, restart it, check it works, then:
  macwarden respond --finish
  ```

- **One registered credential:** `macwarden rotate <label> --out <file>`, switch the app, then `macwarden rotate <label> --finish`. If no app needs it any more, `macwarden revoke <label>`. *(Changes the node.)*
- **Not in the registry** (baked by hand or by another tool): bake a replacement first if an app needs one (`macwarden bake --label <name> --preset <preset> --out <file>`), switch the app, then `macwarden revoke <id> --unregistered`. *(Changes the node.)*

Run `macwarden verify` on each old file again afterwards: it should exit 0.

If any exposed credential can bake (`canBake: true` in `verify --json`: it holds `macaroon:generate` or the BakeMacaroon URI, or macwarden could not assess all of its permissions), revoking it is not enough: anything its holder baked on other root key IDs survives. Go to section 5.

## 5. Root key ID 0 and credentials that can bake

`admin.macaroon`, `readonly.macaroon`, `invoice.macaroon` and anything else on root key ID 0 cannot be revoked one at a time. The only way to invalidate them is to regenerate every root key on the node:

```sh
lncli changepassword --new_mac_root_key
```

It needs the wallet password and a locked wallet; check `lncli changepassword --help` and your LND version's instructions first, and have the new password and your seed backup safe before you start (LND changes the wallet password before it regenerates the root keys). LND's documentation also describes stopping LND and deleting `macaroons.db`; that route has left nodes unable to start ([lnd#11049](https://github.com/lightningnetwork/lnd/issues/11049)), so prefer `changepassword`. macwarden never does either step for you.

This invalidates **every** macaroon on the node at once: every app's credential, macwarden's own, and any replacement already staged with `respond` or `rotate`. It is also the only step that removes credentials a leaked baking credential may have created. So the order is:

1. Plan a maintenance window. Run `macwarden inventory` and write down every app, its credential file and where it is configured.
2. Pause the apps.
3. Regenerate the root keys (above). Consider running LND with `--stateless_init` from now on, so `admin.macaroon` is not stored on disk again.
4. Bake a fresh macwarden session macaroon with the new admin credential, on its own root key ID.
5. Bake one least-privilege macaroon per app with `macwarden bake`, each on its own root key ID.
6. Re-pair each app (section 6), then run `macwarden inventory --verify`: every new credential should be accepted.
7. Run `macwarden verify` on the old files: each should now be rejected with `signature-mismatch`. A regeneration keeps every root key ID listed, and LND gives the same answer for an altered copy (a flipped byte, a mangled paste, a decoy), so the answer is conclusive (exit 0, "its root key was regenerated") only for a file whose bytes are known genuine: the exact file macwarden recorded in its registry (same fingerprint, `registry.match: "fingerprint"`). For any other file `verify` exits 1 (`conclusive: false`). To settle it, compare the file's fingerprint with one recorded before the incident (an `inventory --report` export or a backup of the registry or the file): equal fingerprints mean the bytes are unaltered, so the mismatch comes from the regeneration and that credential is dead. Files on root key ID 0 (`admin.macaroon`, `readonly.macaroon`, `invoice.macaroon`) are never in the registry, so for them the fingerprint comparison is the way to a conclusive answer.

Do not stage replacements before step 3; the regeneration would invalidate them too. [Replacing the default macaroons](replacing-default-macaroons.md) walks through steps 1 to 7 in detail.

## 6. Re-pair apps

Every app that used a replaced or invalidated credential needs its new one:

- BTCPay Server: update the store's Lightning connection with the new macaroon.
- RTL, ThunderHub, LNbits and similar: update the macaroon path or connection string in their configuration.
- Mobile and remote wallets paired with an `lndconnect://` QR code (Zeus and others): pair again with a new code built from the new macaroon.

Give each app only its own credential and only the permissions it uses; `macwarden watch` and `macwarden recommend` show what an app actually calls. After switching, exercise each app (create an invoice, make a test payment where it pays) and remove the old credential from its configuration, from backups you keep, and from password managers. Rescan with `macwarden scan` to confirm no old copies remain.

## 7. Check for unauthorized activity

LND does not record by default which credential made a call, so check outcomes rather than access:

- **Funds:** `lncli walletbalance`, `lncli channelbalance`, `lncli listchaintxns` (on-chain sends), `lncli listpayments` (Lightning payments), `lncli listunspent`.
- **Channels and peers:** `lncli listchannels`, `lncli pendingchannels`, `lncli closedchannels` (unexpected closes, especially force closes), `lncli listpeers` (peers you do not recognise).
- **Invoices and forwarding:** `lncli listinvoices`, `lncli fwdinghistory`.
- **Credentials:** `macwarden inventory` (root key IDs that are not in your registry may have been baked by the attacker), and `macwarden verify` on any credential you find that you did not issue.

Compare against the period since the vulnerable version was first exposed, not just since the advisory. If you find unauthorized activity, preserve the evidence (command output, BTCPay Server and LND logs) before changing more, and report it to the project concerned.

To notice future use of a leaked location, put a canary where the old files were (`macwarden bake --canary --label <name> --out <file>`) and keep `macwarden watch` running: every use LND lets through to its middleware is denied and alerted (rate-limited).

To be able to say which credential spent what next time, run `watch` with `--payment-journal <file>` from now on and check it with `macwarden reconcile --payment-journal <file> --since <time>`. It lists, per credential, the payments it asked LND to make and how LND settled them, and the payments LND made that the journal cannot attribute, with the periods `watch` was not watching. It cannot attribute payments made before the journal existed: for the period of this incident, `lncli listpayments` remains the evidence.

## 8. Afterwards

- Record what was done: `macwarden inventory --report markdown --out incident-review.md` lists every credential, its owner, permissions, expiry and last use.
- Give app credentials an expiry (`macwarden bake --expires 90d`) and check them on a schedule (`macwarden inventory --verify --expiring-within 14d`).
- Keep root key ID 0 out of apps entirely, so the next leak can be handled with `revoke` instead of a full regeneration.
