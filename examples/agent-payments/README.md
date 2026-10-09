# Example: safe agent payments

A runnable regtest walk-through of giving a software agent the power to pay, and taking it away again. An agent buys data from an L402 paid API with an LND macaroon that can only pay. The operator watches its calls live, finds the credential after it leaks into a log, revokes it, and proves the agent is cut off. A decoy credential raises an alert when an intruder tries it.

Everything runs locally in Docker on regtest. Every credential is created by the run and removed by the teardown.

## What it demonstrates

| Step | What happens | macwarden command |
| --- | --- | --- |
| 1 | `bitcoind` (regtest), the operator's node **alice**, the merchant's node **bob**, a channel alice → bob, a small paid HTTP API, and [Aperture](https://github.com/lightninglabs/aperture) (Lightning Labs' L402 reverse proxy) in front of it, creating invoices on bob | |
| 2 | The operator issues the agent a scoped credential that expires after one hour (`pay-only`: SendPaymentV2, TrackPaymentV2, DecodePayReq and `info:read`), plus a decoy | `bake --preset pay-only --expires 1h`, `bake --canary`, `inspect`, `inventory` |
| 3 | The operator watches the agent's calls live; on Linux and macOS each canary alert also runs an alert command | `watch --alert-command` |
| 4 | The agent requests the API and gets `402 Payment Required` with an L402 challenge. It decodes and checks the invoice, pays it over LND REST with its own macaroon, retries with `Authorization: L402 <macaroon>:<preimage>` and gets the data. The same credential is refused for the wallet balance, the channel list, new addresses, opening a channel and baking macaroons | |
| 5 | Leak drill: a careless debug log writes the agent's request headers (with its macaroon) and its L402 token to `agent.log` and `.env` | `scan --fail-on READ` |
| 6 | Incident: the agent's credential is revoked and proven dead; its next payment fails. An intruder tries the decoy: LND denies the call, `watch` raises a canary alert and the alert command records it | `revoke`, `verify`, `inventory` |
| 7 | Teardown | |

## Prerequisites

- **Docker** with Compose v2.17 or later (for `up --wait`): Docker Desktop on Windows or macOS, or Docker Engine on Linux. The images take about 800 MB on disk. Aperture publishes `linux/amd64` images only; on an ARM machine Docker runs it under emulation, which is slower and not tested.
- **Node.js** in the range macwarden supports (`package.json` `engines`): 22.23.2 or later on the 22 line, 24.18.1 or later on the 24 line, or 26.5.1 or later. The run checks this first.
- **macwarden built from this repository.** From the repository root:

  ```sh
  npm ci
  npm run build
  ```

  To use another build instead, set `MACWARDEN_BIN` to the path of its `dist/bin.js`.
- **On WSL**, clone into the Linux file system (for example `~/src/macwarden`), not under `/mnt/c`: macwarden refuses to write credential files where it cannot keep them owner-only (`0600`).
- Free loopback ports **19380**, **19309** and **19381** (see [Ports and layout](#ports-and-layout)). The run checks them before it starts any container.
- `NODE_OPTIONS` and `NODE_DEBUG` are removed from the environment of the commands the run starts, because macwarden refuses to run with them (they can write request headers, including macaroons, to the console).

## Run it

Linux, macOS or WSL:

```sh
examples/agent-payments/run.sh
```

Windows (PowerShell):

```powershell
examples\agent-payments\run.ps1
```

Each run starts from an empty stack: it first removes the containers, volumes and `runtime/` directory of any earlier run, so it can be repeated. Startup waits for each container's health check and then for each condition it needs (chain sync, peer connection, active channel, a real L402 challenge), each with a deadline and a message naming what it waited for.

The stack stays up afterwards, so you can look around:

```sh
docker compose -f examples/agent-payments/docker-compose.yml ps
docker compose -f examples/agent-payments/docker-compose.yml logs aperture
```

Remove containers, volumes and `runtime/` with:

```sh
examples/agent-payments/teardown.sh      # Windows: examples\agent-payments\teardown.ps1
```

`run.sh --teardown` (or `run.ps1 --teardown`) removes everything at the end of the run instead.

### Automated check

```sh
examples/agent-payments/verify.sh
```

`verify.sh` runs the whole story from a clean start, checks the outcome of every step, tears everything down and exits 0 only when every check passed. The checks: the stack starts; `bake` issues a `SPEND` credential with exactly the `pay-only` permissions; the canary is baked; `inventory` lists both; `watch` registers and guards the canary; the agent pays and gets the data, and `watch` attributes the payment to it; every non-payment call is refused; the leak drill writes its files and `scan` exits 1 with the macaroon found in `agent.log`; `revoke` exits 0 with the rejection proven; `verify` exits 0 with `root-key-missing`; the agent's next payment fails; the already-paid L402 token still works; the canary alert fires; on Linux and macOS the alert command receives the event and `watch` stops cleanly; `inventory` shows the agent's root key gone and the canary triggered. A normal run prints the same checks as it goes. On Windows, run `run.ps1 --teardown` and check its exit code.

## Ports and layout

| Port (127.0.0.1 only) | Service |
| --- | --- |
| 19380 | alice LND REST: the agent and macwarden |
| 19309 | alice LND gRPC: `macwarden watch` |
| 19381 | Aperture, plain HTTP: the paid API at `/api/forecast` |

bob, `bitcoind` and the API are reachable only inside the Compose network. The ports are chosen apart from the repository's test fixture (18009, 18080 and the shard ports 18109 to 18480), so the example and the oracle tests can run side by side. The Compose project is `macwarden-agent-demo`.

alice runs with `--rpcmiddleware.enable`, which `macwarden watch` needs. `rpcmiddleware.addmandatory` is deliberately not set: it would block every RPC while no watcher is connected.

The run creates `runtime/` (git-ignored; directories `0700` and credential files `0600` on Linux and macOS, owner-only ACLs on Windows for the files macwarden writes):

```text
runtime/operator/macwarden-session.macaroon   macwarden's own credential (root key ID 7001, 2-hour timeout)
runtime/operator/tls.cert                     alice's TLS certificate
runtime/operator/registry.json                macwarden's registry, with .usage.json and .canary.json beside it
runtime/agent/tls.cert                        alice's TLS certificate, for the agent
runtime/agent/agent.macaroon                  the agent's pay-only credential
runtime/agent/backup/readonly.macaroon        the decoy (canary)
runtime/agent/agent.log, runtime/agent/.env   written by the leak drill
runtime/alerts.jsonl                          canary alerts recorded by alert.sh (Linux and macOS)
```

macwarden's own credential is baked with `lncli bakemacaroon --root_key_id 7001` inside the alice container and copied out; the admin macaroon never leaves the container. Because it holds `macaroon:generate`, it is admin-equivalent, so it expires after two hours and stays with the operator.

### Files

| File | Purpose |
| --- | --- |
| [docker-compose.yml](docker-compose.yml) | The stack, with health checks and pinned images |
| [aperture.yaml](aperture.yaml) | Aperture: one service, 250 sat per token, tokens valid for one hour |
| [api/server.mjs](api/server.mjs) | The paid API. It knows nothing about Lightning; Aperture forwards only paid requests |
| [agent.mjs](agent.mjs) | The agent, an L402 client (below) |
| [alert.sh](alert.sh) | The `watch --alert-command` used on Linux and macOS |
| [demo.mjs](demo.mjs) | Runs the story and its checks |
| `run.sh`, `run.ps1`, `teardown.sh`, `teardown.ps1`, `verify.sh` | Entry points |

## The agent

[agent.mjs](agent.mjs) uses only Node.js built-ins and only its own macaroon, read from `AGENT_MACAROON`. It is written to be read and adapted:

- **TLS** to LND is verified against LND's certificate (`AGENT_TLS_CERT`); there is no option to skip verification.
- **Invoice checks before paying.** It decodes the invoice with DecodePayReq and refuses one without an amount, one above `AGENT_MAX_PRICE_SAT` (default 500 sat) or one that has expired. The routing fee is capped with `AGENT_MAX_FEE_SAT` (default 10 sat). These are the agent's own rules: see [Limits](#limits).
- **Payments are sent once.** SendPaymentV2 is never retried. If its stream ends without a final state (a timeout or a dropped connection), the agent asks TrackPaymentV2 for the payment's state by payment hash instead of paying again; LND also refuses a second payment of the same hash.
- **Timeouts and bounded retries.** Every request has a deadline (15 s; the payment 45 s). Idempotent requests (the API request, DecodePayReq, TrackPaymentV2) are retried at most three times, with backoff, on transport errors and HTTP 502, 503 or 504 only. A refusal from LND is never retried.
- **No secrets in its output.** It names credentials and tokens by what they are, shows invoices and hashes shortened, and never prints the payment preimage. Only `buy --simulate-leak`, the leak drill, writes secrets to disk, to give `scan` something real to find.

## Pinned versions

| Image | Version | Digest |
| --- | --- | --- |
| `lightninglabs/lnd` | v0.21.4-beta (as the test fixture) | `sha256:04d06edcc0f6e99a5e797ea34959f330add222226f840cd86afbc31f8f29627d` |
| `lightninglabs/bitcoin-core` | 31.1 (as the test fixture) | `sha256:86e15e4348869a86343aacbbd1aff38e96cffddd87b61644694b1e1358d737cd` |
| `lightninglabs/aperture` | v0.5.0 | `sha256:29e03e2c38dca0314f748cc07f483f03615dbf9876620c8e15b94b904fa16114` |
| `node` (paid API) | 22.23.2-alpine3.24 | `sha256:b6f26b36c8ff49624cfdac716b8ea1138d606df02586a77d364bb5536a634f85` |

Aperture reads only bob's TLS certificate and `invoice.macaroon` (it loads that file by name from `macdir`), from bob's data volume mounted read-only.

## Expected output

Steps 4 to 6 of a real run of `verify.sh` on the 1.2.0 release candidate (WSL Ubuntu, Node.js 22.23.3, Docker), 2026-10-09. Invoices and node keys are from the disposable regtest stack; no credential is printed.

```text
== Step 4/7: The agent buys data from the paid API with its pay-only credential
 $ node agent.mjs buy
    agent> GET http://127.0.0.1:19381/api/forecast
    agent> 402 Payment Required: L402 challenge, invoice lnbcrt2500n1…ntg4pe
   watch | 2026-10-09T19:00:40.353Z  /lnrpc.Lightning/DecodePayReq  root key 7025894489540552293  id:8cf0699196d857de  agent
    agent> DecodePayReq: 250 sat to 02478dceabc2…4bb314, "L402", hash 9efe6a25d0c3…1bd8bf
   watch | 2026-10-09T19:00:40.357Z  /routerrpc.Router/SendPaymentV2  root key 7025894489540552293  id:8cf0699196d857de  agent
    agent> SendPaymentV2: SUCCEEDED, 250 sat + 0 sat fee
    agent> GET with Authorization: L402 <token> → 200
    agent> data: {"location":"Regtest Harbour","hours":[{"hour":"06:00","windKnots":12,"direction":"SW"},{"hour":"09:00","windKnots":15,"direction":"SW"},{"hour":"12:00","windKnots":18,"direction":"W"}]}
   [ok] agent paid the L402 invoice and got the data
   [ok] watch attributed the payment to the agent
   # The same credential is refused for everything that is not a payment:
 $ node agent.mjs probe
   watch | 2026-10-09T19:00:40.529Z  /lnrpc.Lightning/GetInfo  root key 7025894489540552293  id:8cf0699196d857de  agent
    agent> GetInfo (info:read, granted)                             allowed
    agent> WalletBalance (needs onchain:read)                       refused (HTTP 500: permission denied)
    agent> ListChannels (needs offchain:read)                       refused (HTTP 500: permission denied)
    agent> NewAddress (needs address:write)                         refused (HTTP 500: permission denied)
    agent> OpenChannelSync (needs onchain:write, offchain:write)    refused (HTTP 500: permission denied)
    agent> BakeMacaroon (needs macaroon:generate)                   refused (HTTP 500: permission denied)
   [ok] non-payment calls are refused
   # LND checks permissions before RPC middleware runs, so watch lists only the calls LND accepted.
== Step 5/7: Leak drill: a careless debug log writes the agent's secrets to disk
 $ node agent.mjs buy --simulate-leak
    agent> GET http://127.0.0.1:19381/api/forecast
    agent> 402 Payment Required: L402 challenge, invoice lnbcrt2500n1…nwvkcy
   watch | 2026-10-09T19:00:40.601Z  /lnrpc.Lightning/DecodePayReq  root key 7025894489540552293  id:8cf0699196d857de  agent
    agent> DecodePayReq: 250 sat to 02478dceabc2…4bb314, "L402", hash 486c31e311ec…9f6d0c
   watch | 2026-10-09T19:00:40.605Z  /routerrpc.Router/SendPaymentV2  root key 7025894489540552293  id:8cf0699196d857de  agent
    agent> SendPaymentV2: SUCCEEDED, 250 sat + 0 sat fee
    agent> GET with Authorization: L402 <token> → 200
    agent> data: {"location":"Regtest Harbour","hours":[{"hour":"06:00","windKnots":12,"direction":"SW"},{"hour":"09:00","windKnots":15,"direction":"SW"},{"hour":"12:00","windKnots":18,"direction":"W"}]}
    agent> leak drill: wrote runtime/agent/agent.log (request headers with the macaroon, the L402 Authorization header)
    agent> leak drill: wrote runtime/agent/.env (LND_REST, LND_MACAROON_PATH, L402_TOKEN)
   [ok] leak drill wrote agent.log and .env
 $ macwarden scan runtime/agent --fail-on READ
  runtime/agent/.env:3:12  l402  fp:7cf2eedba77764a1 live (counted as READ)
  runtime/agent/agent.log:1:365  macaroon-hex  fp:3464daa548a32d9b SPEND root key 7025894489540552293
  runtime/agent/agent.log:2:100  macaroon-hex  fp:3464daa548a32d9b SPEND root key 7025894489540552293
  runtime/agent/agent.log:3:60  l402  fp:7cf2eedba77764a1 live (counted as READ)
  runtime/agent/agent.macaroon  macaroon-file  fp:3464daa548a32d9b SPEND root key 7025894489540552293
  runtime/agent/backup/readonly.macaroon  macaroon-file  fp:c55ae8498cdeed4e READ root key 3398524538690212698
  6 findings (3 distinct) in 5 files; 0 skipped; 0 ignored; 6 at or above READ
   (exit 1)
   [ok] scan finds the leaked agent macaroon in agent.log (exit 1)
   # The decoy is a macaroon file too, so scan lists it; it grants only reads and every use is denied and alerted.
   [ok] scan also reports the leaked L402 token (2 finding(s))
== Step 6/7: Incident response: revoke the agent, prove it is cut off
 $ macwarden revoke agent --yes --registry runtime/operator/registry.json
   watch | 2026-10-09T19:00:40.877Z  /lnrpc.Lightning/GetInfo  root key 7001  id:91205099efac68cc  unregistered
   watch | 2026-10-09T19:00:40.889Z  /lnrpc.Lightning/ListPermissions  root key 7001  id:91205099efac68cc  unregistered
   watch | 2026-10-09T19:00:40.899Z  /lnrpc.Lightning/ListMacaroonIDs  root key 7001  id:91205099efac68cc  unregistered
   watch | 2026-10-09T19:00:40.905Z  /lnrpc.Lightning/CheckMacaroonPermissions  root key 7001  id:91205099efac68cc  unregistered
   watch | 2026-10-09T19:00:40.917Z  /lnrpc.Lightning/DeleteMacaroonID  root key 7001  id:91205099efac68cc  unregistered
   watch | 2026-10-09T19:00:40.923Z  /lnrpc.Lightning/ListMacaroonIDs  root key 7001  id:91205099efac68cc  unregistered
   watch | 2026-10-09T19:00:40.927Z  /lnrpc.Lightning/CheckMacaroonPermissions  root key 7001  id:91205099efac68cc  unregistered
   watch | 2026-10-09T19:00:40.928Z  error /lnrpc.Lightning/CheckMacaroonPermissions  root key 7001  id:91205099efac68cc  unregistered
  revoked  agent  root key ID 7025894489540552293  fp:3464daa548a32d9b
  proof    ID absent from LND; macaroon rejected
  New requests with this macaroon are now rejected. Streams opened before the revoke stay open until they disconnect; if the credential may be compromised, restart LND.
   (exit 0)
   [ok] revoke agent
   # watch also lists macwarden's own calls: its session credential (root key 7001) is not in the registry, so it shows as unregistered.
 $ macwarden verify runtime/agent/agent.macaroon --registry runtime/operator/registry.json
   watch | 2026-10-09T19:00:41.011Z  /lnrpc.Lightning/GetInfo  root key 7001  id:91205099efac68cc  unregistered
   watch | 2026-10-09T19:00:41.024Z  /lnrpc.Lightning/ListPermissions  root key 7001  id:91205099efac68cc  unregistered
   watch | 2026-10-09T19:00:41.030Z  /lnrpc.Lightning/ListMacaroonIDs  root key 7001  id:91205099efac68cc  unregistered
   watch | 2026-10-09T19:00:41.035Z  /lnrpc.Lightning/CheckMacaroonPermissions  root key 7001  id:91205099efac68cc  unregistered
   watch | 2026-10-09T19:00:41.036Z  error /lnrpc.Lightning/CheckMacaroonPermissions  root key 7001  id:91205099efac68cc  unregistered
  fingerprint  fp:3464daa548a32d9b
  location     lnd
  root key ID  7025894489540552293
  grade        SPEND   (uri:/routerrpc.Router/SendPaymentV2)
  permissions  info:read uri:/lnrpc.Lightning/DecodePayReq uri:/routerrpc.Router/SendPaymentV2 uri:/routerrpc.Router/TrackPaymentV2
  caveats      time-before 2026-10-09T20:00:38Z (valid)
  snapshot     LND 0.21.4-beta
  node         0300882a3c825b7d0cacb46ad354ad2859c9a2f159673379108d8615a5959b8912 (alice) regtest
  status       rejected by LND (root-key-missing)
  root key     not listed in LND
  registry     agent (revoked, same credential)
  next         LND rejects this credential now: its root key ID no longer exists. It can no longer be used against this node.
   (exit 0)
   [ok] verify: conclusively rejected (exit 0)
 $ node agent.mjs buy
    agent> GET http://127.0.0.1:19381/api/forecast
    agent> 402 Payment Required: L402 challenge, invoice lnbcrt2500n1…q3dnmf
    agent> error: GET /v1/payreq/<invoice> failed with HTTP 500: cannot retrieve macaroon: cannot get macaroon: root key with id 7025894489540552293 doesn't exist
   [ok] the agent can no longer pay
   # Limit: the L402 token the agent already paid for is a separate bearer credential. Aperture honours it
   # until it expires (timeout: 3600 in aperture.yaml); revoking the macaroon does not end it.
 $ node agent.mjs reuse
    agent> GET with the L402 token from .env, no payment → 200
    agent> data: {"location":"Regtest Harbour","hours":[{"hour":"06:00","windKnots":12,"direction":"SW"},{"hour":"09:00","windKnots":15,"direction":"SW"},{"hour":"12:00","windKnots":18,"direction":"W"}]}
   [ok] the already-paid L402 token still works until it expires
   # An intruder who found the leaked files tries the decoy next to them:
 $ node agent.mjs intruder runtime/agent/backup/readonly.macaroon
   watch | 2026-10-09T19:00:41.687Z  /lnrpc.Lightning/GetInfo  root key 3398524538690212698  id:3bdf293602e60c3d  decoy
   watch | 2026-10-09T19:00:41.688Z  ALERT canary decoy used: /lnrpc.Lightning/GetInfo  root key 3398524538690212698  id:3bdf293602e60c3d  decoy  request denied
    agent> intruder GetInfo        → refused (HTTP 500: permission denied)
   watch | 2026-10-09T19:00:41.695Z  /lnrpc.Lightning/WalletBalance  root key 3398524538690212698  id:3bdf293602e60c3d  decoy
    agent> intruder WalletBalance  → refused (HTTP 500: permission denied)
   [ok] watch raised a canary alert, LND denied the call
 $ cat runtime/alerts.jsonl
  {"schema":1,"event":"canary","time":"2026-10-09T19:00:41.688Z","method":"/lnrpc.Lightning/GetInfo","rootKeyId":"3398524538690212698","credential":"id:3bdf293602e60c3d","label":"decoy","denied":true}
   [ok] the alert command received the canary event
   watch | 2026-10-09T19:00:42.264Z  /lnrpc.State/SubscribeState  root key none  id:none  unregistered
   watch | 2026-10-09T19:00:44.337Z  /lnrpc.State/SubscribeState  root key none  id:none  unregistered
 $ macwarden inventory --registry runtime/operator/registry.json
   watch | 2026-10-09T19:00:45.815Z  /lnrpc.Lightning/GetInfo  root key 7001  id:91205099efac68cc  unregistered
   watch | 2026-10-09T19:00:45.828Z  /lnrpc.Lightning/ListPermissions  root key 7001  id:91205099efac68cc  unregistered
   watch | 2026-10-09T19:00:45.835Z  /lnrpc.Lightning/ListMacaroonIDs  root key 7001  id:91205099efac68cc  unregistered
  node 0300882a3c825b7d0cacb46ad354ad2859c9a2f159673379108d8615a5959b8912 (alice) regtest
  ROOT KEY ID          LABEL  GRADE  AGE  EXPIRES  STATUS
  0                    —      —      —    —        default root key: cannot be individually revoked
  7001                 —      —      —    —        macwarden's own credential; last used 2026-10-09T19:00:41.036Z (11 calls, 2 errors)
  3398524538690212698  decoy  READ   0d   —        CANARY TRIGGERED 2 times, last 2026-10-09T19:00:41.695Z: assume this credential's location is compromised; active; last used 2026-10-09T19:00:41.695Z (2 calls)
  CANARY TRIGGERED: decoy; someone has read where each was stored: treat that place as compromised and rotate every credential kept there
   (exit 0)
   [ok] inventory: agent root key gone, canary triggered
 $ (stop watch: Ctrl+C)
   watch | 2026-10-09T19:00:41.695Z  ALERT canary decoy used: /lnrpc.Lightning/WalletBalance  root key 3398524538690212698  id:3bdf293602e60c3d  decoy  request denied (+1 more denied uses since the last alert)
   watch | watched 24 calls (2 errors) from 4 credentials; 2 canary alerts; 0 reconnects; usage saved to /home/dennis/mw-120/examples/agent-payments/runtime/operator/registry.json.usage.json
   [ok] watch stopped cleanly (exit 0)
...
20/20 checks passed
verify: all checks passed
```

### What `watch` shows, and what it does not

LND checks a macaroon's permissions before RPC middleware runs, so the agent's refused calls in step 4 never reach `watch`; it lists the calls LND accepted, including macwarden's own (its session credential is not in the registry, so `watch` shows it as unregistered). The decoy's calls do reach it: LND accepts a macaroon with a custom caveat only while a middleware for that caveat is registered, and the guard `watch` registers denies every such call and raises the alert. Without `watch` running, LND refuses the decoy and nobody is alerted.

On Linux and macOS each alert also runs [alert.sh](alert.sh), with the alert as one JSON line on stdin. On Windows `--alert-command` must be an `.exe` or `.com` file, because a script cannot run without a shell, so the Windows run uses no alert command and relies on the alert lines `watch` prints. Node.js cannot send a console Ctrl+C to a child process on Windows, so at the end of a Windows run `watch` is terminated and prints no summary line; the usage file it saves periodically is already written.

`scan` lists the decoy too, because it is a macaroon file. It grants only reads, and every use is denied and reported.

### L402 tokens and `scan`

The leak drill also writes the agent's L402 token (Aperture's macaroon and the payment preimage) to `agent.log` and `.env`. Step 5 reports what the macwarden build in use finds: the LND macaroon in every case, and the L402 token when that build detects L402 tokens. A build without L402 detection prints a note saying the token was not detected.

## Limits

- **A macaroon restricts what the agent may call, not how much it may spend.** The `pay-only` credential can pay any invoice, to anyone, up to the node's outbound liquidity, until it expires or is revoked. The agent's price and fee checks are the agent's own rules, not a security boundary: a compromised agent, or a thief with its macaroon, ignores them. Put spending limits where they are enforced: [Lightning Terminal accounts](https://docs.lightning.engineering/lightning-network-tools/lightning-terminal/accounts) give an app its own balance on your node, or give the agent a separate wallet or node funded with only what it may spend.
- **An L402 token grants service access until it expires.** It is a bearer credential separate from the LND macaroon: revoking the macaroon stops new payments, but a token already paid for keeps working with the service until its expiry, as step 6 shows. Keep L402 tokens out of logs and keep their lifetime short (`timeout` in [aperture.yaml](aperture.yaml)).
- **`watch` sees only what LND passes to its middleware, and only while it runs.** Run it as a supervised service, with an alert command that reaches a person.
- **Revocation blocks new requests.** Streams opened before the revoke stay open until they disconnect; if a compromised credential may hold one, restart LND.
- **Regtest only.** Never use mainnet credentials, or a node that holds real funds, with this example. Its teardown deletes every volume, Aperture serves plain HTTP, and the leak drill writes credentials to disk on purpose.

## Further reading

- [macwarden specification](../../docs/spec.md): `bake` presets and `--canary`, `watch` and `--alert-command`, `scan`, `revoke`, `verify`
- [Incident playbook](../../docs/incident-playbook.md): the full response when credentials may have been copied
- [LND macaroons](https://docs.lightning.engineering/lightning-network-tools/lnd/macaroons) and [RPC middleware](https://docs.lightning.engineering/lightning-network-tools/lnd/rpc-middleware-interceptor)
- [L402](https://docs.lightning.engineering/the-lightning-network/l402) and [Aperture's sample configuration](https://github.com/lightninglabs/aperture/blob/v0.5.0/sample-conf.yaml)
