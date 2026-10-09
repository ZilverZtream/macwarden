# Payment lab (regtest)

A Lightning payment service run against three real LND nodes on regtest, with five scenarios that break it in the ways production payment systems break: a connection lost mid-payment, a settlement delivered twice, a channel that has capacity but not in the needed direction, a payment split over several attempts, and two payouts racing for one budget. Each scenario drives the nodes, narrates what happens and ends with a verdict computed from node state and the service's durable records.

The service runs with three credentials baked by `macwarden bake`, one per role, each with the least privilege its role needs. Everything runs on regtest; no real funds and no real credentials are involved.

## Four identities the code keeps apart

| Identity | What it is | Where it lives |
| --- | --- | --- |
| **Business operation** (order ID, refund ID, payout ID) | What the business wants done, exactly once | `operations` (payer) and `orders` (receiver) |
| **Payment hash** | The one Lightning payment LND tracks for that operation | `payments.payment_hash`, `invoices.payment_hash` |
| **RPC call** | One interaction with a node (SendPaymentV2, TrackPaymentV2, SettleInvoice, …); it can be lost without the payment being lost | `payments.submissions`, `payment_events`, `deliveries` |
| **HTLC attempt** | How LND executed the payment: routes, shards, retries | `htlc_attempts` |

One operation has at most one live payment. One payment can take any number of RPC calls to learn its outcome and any number of HTLC attempts to execute. A lost RPC call says nothing about the payment; a failed HTLC attempt says nothing about the payment either, until LND reports the payment itself terminal.

## Architecture

```text
 HOST: payment service (node src/cli.ts)                    DOCKER: Compose project macwarden-payment-lab
 one SQLite file per profile under runtime/

 payer     customer-payer    [pay-only]     --REST-->  +----------------+
 receiver  customer          [invoice-only] --REST-->  |  customer LND  |  127.0.0.1:19501
 analysis  customer          [read-only]    --REST-->  +----------------+
                                                         A |   B |   ^ D
                                                           v     v   |
 analysis  router            [read-only]    --REST-->  +----------------+
                                                       |   router LND   |  127.0.0.1:19502
                                                       +----------------+
                                                                 | C
                                                                 v
 receiver  merchant          [invoice-only] --REST-->  +----------------+
 payer     merchant-refunds  [pay-only]     --REST-->  |  merchant LND  |  127.0.0.1:19503
 analysis  merchant          [read-only]    --REST-->  +----------------+
                                                       all three on one bitcoind (regtest)

 scenarios/<n>-<name>.ts: start, kill and restart service processes; operator actions with
 lncli and bitcoin-cli inside the containers; verdict from node state and the databases
```

Setup opens four channels with known balances:

```text
customer ==A (500,000 sat, customer side)==> router ==C (2,000,000 sat, router side)==> merchant
customer ==B (500,000 sat, customer side)==> router
customer <==D (1,000,000 sat, router side)== router
```

The router charges 1,000 msat + 2,000 ppm per forwarded HTLC. The merchant opens no channel, so all of its channel balance starts on the router's side: it can receive and cannot send. Scenario 3 depends on that.

## Requirements

- Docker with Compose v2 (`docker compose`).
- Node.js 22.23.2 or later on 22, 24.18.1 or later on 24, or 26.5.1 or later (the versions macwarden supports). The lab's TypeScript runs directly through Node's type stripping; there is no build step and no runtime dependency.
- macwarden built from this repository: `npm ci && npm run build` at the repository root. To use an installed macwarden instead, set `MACWARDEN_JS` to its `dist/bin.js`.
- Free loopback ports 19501, 19502 and 19503. They differ from the test fixture's (18009, 18080, 18109 to 18480) and the agent payments example's (19309, 19380, 19381).

`npm ci` inside `examples/payment-lab` is needed only for `npm run typecheck` (TypeScript and Node type definitions).

## Run it

```sh
cd examples/payment-lab
./setup.sh                              # nodes, funding, channels, credentials
./scenarios/1-dropped-connection.sh     # add --cut drop to drop the HTTP connection instead of killing the process
./scenarios/2-settlement-replay.sh
./scenarios/3-directional-liquidity.sh
./scenarios/4-multi-attempt.sh
./scenarios/5-concurrent-budget.sh
./teardown.sh
```

On Windows PowerShell use the `.ps1` files with the same names (`.\setup.ps1`, `.\scenarios\1-dropped-connection.ps1`, …).

Each scenario exits 0 when its verdict is PASS and 1 otherwise. The scenarios are independent and can run in any order against one lab; each uses fresh business IDs. They consume channel liquidity, and scenarios 3 and 4 size their payments from the current balances; when a lab no longer has the liquidity a scenario needs, the scenario says so before it starts, and `teardown` followed by `setup` gives a fresh lab.

`teardown` runs `docker compose down --volumes --remove-orphans` for this Compose project only: its containers, its network and its named volumes. It does not touch anything else. The regtest files of each run (`runtime/lab-<time>/`: TLS certificates, credentials, databases, the macwarden registry) stay on disk; they stop working with the volumes, and you can delete them when you no longer need them.

## Credentials

Setup bakes a short-lived session credential for macwarden on each node with `lncli`, uses it to bake one credential per role with `macwarden bake`, and then deletes the session's root key, so the session credential stops working. Each role credential has its own root key ID, is recorded in the run's macwarden registry, and expires after 7 days.

```sh
# on each node, as its operator
lncli bakemacaroon --root_key_id 9001 --timeout 3600 macaroon:generate macaroon:read macaroon:write info:read

# then, from the host (setup prints each command with the run's paths)
macwarden bake --label lab-customer-payer    --preset pay-only     --expires 7d --out runtime/lab-<time>/credentials/customer-payer.macaroon    --lnd-rest 127.0.0.1:19501 --tls-cert runtime/lab-<time>/tls/customer.cert --macaroon runtime/lab-<time>/sessions/customer.macaroon --registry runtime/lab-<time>/registry.json
macwarden bake --label lab-customer-invoices --preset invoice-only --expires 7d --out …/customer-invoices.macaroon …
macwarden bake --label lab-customer-analysis --preset read-only    --expires 7d --out …/customer-analysis.macaroon …
macwarden bake --label lab-router-analysis   --preset read-only    --expires 7d --out …/router-analysis.macaroon   --lnd-rest 127.0.0.1:19502 …
macwarden bake --label lab-merchant-invoices --preset invoice-only --expires 7d --out …/merchant-invoices.macaroon --lnd-rest 127.0.0.1:19503 …
macwarden bake --label lab-merchant-refunds  --preset pay-only     --expires 7d --out …/merchant-refunds.macaroon  …
macwarden bake --label lab-merchant-analysis --preset read-only    --expires 7d --out …/merchant-analysis.macaroon …

# on each node
lncli deletemacaroonid 9001
```

| Role | Preset | Permissions | Used for |
| --- | --- | --- | --- |
| payer worker | `pay-only` | `info:read`, `uri:/routerrpc.Router/SendPaymentV2`, `uri:/routerrpc.Router/TrackPaymentV2`, `uri:/lnrpc.Lightning/DecodePayReq` | paying and reconciling payments |
| invoice worker | `invoice-only` | `info:read invoices:read invoices:write` | invoices, hold invoices (AddHoldInvoice, SettleInvoice, CancelInvoice), settlement subscription and lookups |
| analysis | `read-only` | `info:read onchain:read offchain:read address:read invoices:read peers:read` | evidence: ListPayments, channels, wallet, QueryRoutes, ForwardingHistory |

The payer cannot list payments or read balances; the evidence that no second payment was sent comes from the separate read-only credential. Funding, channels, fee policy and mining are operator actions done with `lncli` and `bitcoin-cli` inside the containers; no role credential can do them. The service reads every credential by path; credential bytes never appear in arguments, environment variables or output.

## Scenarios

### 1. Dropped connection after submission

`scenarios/1-dropped-connection.sh [--cut kill|drop]`

The merchant creates a hold invoice, so LND holds the HTLC and the payment stays in flight. The customer's worker records the operation and the payment hash, then calls SendPaymentV2. Once the merchant node reports the HTLC accepted, the worker is killed (`--cut kill`, the default: SIGKILL, or TerminateProcess on Windows) or destroys its own HTTP connection (`--cut drop`). The merchant then tries to issue a replacement invoice for the same order. A new process reconciles with TrackPaymentV2, the merchant settles the hold invoice, and a client repeats the original request.

It proves: after the cut the record is unresolved, not failed, and the operation stays open with nothing posted; LND still holds the payment; no replacement invoice can be issued while the first is unresolved; recovery uses TrackPaymentV2 only; there is one payment for the hash in ListPayments and one SendPaymentV2 call in total; the record's principal and routing fee equal LND's; the operation completes and the ledger is posted once; the repeated request is answered from the record; the merchant fulfills the order once.

```text
[placeholder: output of scenarios/1-dropped-connection.sh from the release run]
```

### 2. Settlement notification repeats after a restart

`scenarios/2-settlement-replay.sh`

The merchant's listener (SubscribeInvoices from its stored cursor) runs while two orders are paid. It is stopped and restarted from the cursor as it was after the first order, so LND replays the second order's settlement. A reconciliation pass then looks the invoice up as well.

The listener commits each effect and its cursor in one transaction, so a crash alone does not repeat a delivery. Repeats still happen in production whenever a listener starts from a cursor older than its effects: a cursor kept in another store, a second instance, a restored cursor, a replay after an incident. LND replays only for a non-zero settle index, so the scenario uses two orders and replays from the first one's index.

It proves, from the merchant's durable records: the settlement was delivered at least twice, including once by LND after the restart; the order was fulfilled once and the sale posted once (both keyed on payment hash and order ID), for the amount LND reports paid; the cursor caught up.

```text
[placeholder: output of scenarios/2-settlement-replay.sh from the release run]
```

### 3. Directional liquidity

`scenarios/3-directional-liquidity.sh`

The merchant owes the customer a refund. The amount is set from the merchant's current channel balances (what it can send, plus 25,000 sat), so it cannot be sent whatever earlier scenarios did. The merchant has 4 BTC on-chain and channel C has 2,000,000 sat capacity. The refund fails. The lab then diagnoses the failure from the merchant's own read-only view: wallet balance, each channel's capacity, local and remote balance, both reserves, commitment fee and pending HTLCs, a QueryRoutes check, and the payment's failure reason and HTLC attempts. The operator opens a new channel from the merchant's on-chain funds, and the same refund (same invoice, same payment hash) is retried.

The diagnosis explains: on-chain funds are not Lightning liquidity until they are in a channel; capacity counts both sides, and only the local side can send; reserves and the commitment fee are not spendable; sending needs outbound balance at every hop while receiving needs inbound balance toward the receiver; and a failure names the first node that refused one attempt, so it does not always locate all of the missing liquidity, and the sender cannot see other nodes' balances.

It proves: the refund failed as LND reports it; on-chain funds and capacity each exceed the amount while the sendable balance does not; the record and operation are failed with nothing posted; after the new channel the retry succeeds, the customer receives the amount once, and the record shows two submissions of one payment with the actual fee.

```text
[placeholder: output of scenarios/3-directional-liquidity.sh from the release run]
```

### 4. Multi-attempt settlement

`scenarios/4-multi-attempt.sh`

The amount is set above the local balance of each of the customer's two channels to the router (largest balance plus 20,000 sat), so LND must split the payment into parts and may retry some of them. The merchant creates the invoice, the customer pays with up to 16 parts.

It proves: the payment succeeded with at least two successful HTLC attempts and is one payment in ListPayments; the successful shards add up to the invoice amount; LND's total fee equals the sum of the successful attempts' route fees; the books hold one principal entry and one fee entry equal to LND's values; the stored attempts match LND's; the fee equals the router's policy (1,000 msat + 2,000 ppm) applied to each shard; the router's ForwardingHistory shows the same shards and the same total fee; the merchant received the amount once, in several HTLCs.

```text
[placeholder: output of scenarios/4-multi-attempt.sh from the release run]
```

### 5. Concurrent budget enforcement

`scenarios/5-concurrent-budget.sh`

A payout budget of 100,000 sat. Two worker processes each pay a 60,000 sat hold invoice with a 1,000 sat fee allowance; they decode their invoices, wait at a barrier, and reserve at the same instant. The admitted worker is killed while its HTLC is held. A small payout is admitted and then canceled by the payee. A 38,500 sat payout is tried while the first is still unresolved, and again after it settles.

It proves: exactly one of the two concurrent payouts is admitted and the refusal follows from the arithmetic; the reservation (principal plus fee allowance) stays held while the payment is unresolved; a payment LND reports failed releases its reservation; a payment that does not fit while a reservation is held is refused, and is admitted once the settled payment's reservation shrinks to principal plus actual fee if it then fits; LND shows one payment for each admitted payout and none for refused ones; the budget's consumed amount equals what LND paid, fees included, within the limit.

The budget is enforced by this service. It does not limit anyone who holds the `pay-only` macaroon itself: a copy of that file can call SendPaymentV2 directly and LND will pay within the node's balances. Enforcement against a leaked credential has to live where the credential is checked, in the wallet or account backend, for example [Lightning Terminal accounts](https://docs.lightning.engineering/lightning-network-tools/lightning-terminal/accounts), which bind a macaroon to a balance that LND enforces. macwarden keeps credentials short-lived, scoped and revocable; it does not cap amounts.

```text
[placeholder: output of scenarios/5-concurrent-budget.sh from the release run]
```

## Design decisions

**Durable intent before submission.** The payer commits the operation, the payment hash (decoded from the invoice), the amount, the fee limit and any budget reservation in one transaction, then marks the payment `submitting` and counts the submission in a second committed transaction, and only then writes SendPaymentV2. After a crash at any point, the record says what may have been sent. The receiver works the same way: it generates the preimage, stores it with the hash, and then asks LND to create exactly that invoice (AddInvoice with `r_preimage`, or AddHoldInvoice with the hash), so a lost answer is resolved by looking the known hash up.

**Unresolved is a state, not an error.** A payment is `intent`, `submitting`, `in_flight`, `uncertain`, `succeeded` or `failed`. The middle three are unresolved: the operation stays open, the budget reservation stays held, and a partial unique index (one payment per operation unless it is `failed`) makes a replacement payment impossible in the database, whatever the code does. Only LND's terminal answer, through SendPaymentV2 or TrackPaymentV2, moves a payment to `succeeded` or `failed`.

**A timeout is not a failure.** A client timeout or a dropped connection means the client stopped listening. LND keeps routing the payment; a held HTLC can stay in flight for hours. Treating the timeout as a failure and paying again (or asking for a new invoice) is how a payment gets made twice. So a transport error after the connection was established marks the record `uncertain`, and the only way forward is TrackPaymentV2 until LND reports a terminal state. The one exception is a connection that was never established (refused or failed TLS handshake): the request cannot have reached LND, and the record returns to `intent`. If TrackPaymentV2 answers that LND has no payment for the hash and no HTLC attempt was ever recorded, the record also returns to `intent`; submitting it again uses the same payment hash, and LND refuses a second payment for a hash that is in flight or settled.

**SendPaymentV2 is called only by compare-and-set.** `intent → submitting` is a conditional update; two processes (a restarted worker and an old one, or two replicas) can never both submit the same record. A repeated request for an operation that was already submitted is answered from the record and TrackPaymentV2.

**Idempotency keys.** The payer's ledger is unique on (operation ID, payment hash, account); the receiver's fulfillment on (payment hash, order ID) and its ledger on (order ID, payment hash, account). Every path that learns of a settlement (subscription, lookup, the settle call itself) goes through one function that inserts with `ON CONFLICT DO NOTHING` and posts only when the insert happened. Every delivery is still logged, so repeats are visible.

**Subscriptions are a fast path; lookups are the ground truth.** The listener resumes SubscribeInvoices from its stored settle index (LND replays every settlement after a non-zero index) and also looks up every unresolved invoice at start and every few seconds, which covers the cursor-zero case and any gap between subscribing and LND registering the subscription.

**Reservations.** A budget reservation is principal plus fee allowance, and the fee allowance is also the fee limit passed to LND, so the reservation is an upper bound LND enforces. It is taken in the same `BEGIN IMMEDIATE` transaction as the intent, which holds SQLite's write lock from the start: concurrent workers serialise, and the second sees the first's reservation. It stays held while the payment is unresolved, is released when LND reports the payment failed, and becomes principal plus the actual fee when LND reports success.

**Accounting from LND's numbers.** On success the ledger posts LND's `value_msat` as principal and LND's `fee_msat` as the routing fee, and the HTLC attempts are stored next to them, so the books can be checked against the attempts and against the routing node's forwarding log.

**Storage: SQLite through Node's built-in `node:sqlite`.** SQLite gives transactions, cross-process locking and constraints, which the design relies on (the partial unique index, the unique ledger keys, the serialised reservation). WAL with `synchronous = FULL` makes each commit durable on disk before it returns. `node:sqlite` ships with the Node.js versions macwarden supports, so the lab has no native addon to compile and no runtime dependency; it is marked experimental in Node.js, and the lab uses only its basic synchronous API (`DatabaseSync`, prepared statements). The SQL works unchanged with a package such as `better-sqlite3`. A journaled JSON file with fsync was the alternative; it would need its own locking between processes and could not enforce the invariants as constraints. Each database file is created owner-only. The receiver's database holds invoice preimages, which are proofs of payment: in production, protect it like a credential.

**Least privilege, verified separately.** The payer's `pay-only` credential cannot list payments; the "only one payment was sent" evidence comes from the separate `read-only` credential. The service never uses the nodes' admin credentials.

## The service

`node src/cli.ts <component> <command>` (or `npm run service -- …`). Every command prints one JSON object per line. Run it without arguments for the full usage.

| Command | Purpose |
| --- | --- |
| `payer pay --as <profile> --operation <id> --kind <kind> --invoice <bolt11> --fee-limit-msat <n>` | record intent, submit, follow to a terminal state |
| `payer reconcile --as <profile> [--payment-hash <hex>]` | resolve unresolved payments with TrackPaymentV2 |
| `payer retry --as <profile> --operation <id>` | submit a payment LND reported failed again, same invoice |
| `payer show`, `payer budget-set`, `payer budget-show` | records and budgets |
| `receiver create-invoice --as <profile> --order <id> --amount-msat <n> [--hold]` | record the invoice identity, then create it |
| `receiver settle` / `cancel --order <id>` | release or cancel a hold invoice |
| `receiver listen` | settlement consumer with periodic reconciliation |
| `receiver reconcile [--order <id>]` | resolve invoices by lookup |
| `analysis payments --node <node> --payment-hash <hex>` | every payment LND holds for a hash |
| `analysis diagnose --node <node> --payer <profile> --operation <id>` | liquidity diagnosis for a payment |

Exit codes: 0 done; 1 payment failed according to LND; 2 usage error; 3 refused (budget, conflicting operation, wrong state); 4 configuration or node error; 75 unresolved: the outcome is not known yet and the record stays open for reconciliation.

## Limits

- Regtest only, three nodes, one route shape. Real networks add gossip delays, private channels, route hints, liquidity changing between attempts and nodes that do not report useful failures.
- The liquidity diagnosis sees only the sending node's channels. It cannot see other nodes' balances, and its sendable figure is an upper bound: LND also keeps a fee buffer for new HTLCs on channels it opened.
- A stream that goes silent is detected by TCP keepalive, which can take minutes. The service never treats that silence as a failure, only as a reason to reconnect.
- Reconciliation that ends without a terminal state (its deadline passes while LND still holds the payment) leaves the record unresolved; it must be run again. Production needs a supervisor that keeps doing so.
- If TrackPaymentV2 answers "not found" for a payment whose HTLC attempts were recorded (for example after an operator deleted payments from LND), the record stays unresolved for an operator to decide.
- The application budget limits this service only, not the credential (see scenario 5).
- The scenarios assert what they observe; they are demonstrations against real nodes, not a test suite with fault injection at every step.
- `node:sqlite` is experimental in Node.js (see Storage above).

## Files

| Path | Contents |
| --- | --- |
| `docker-compose.yml` | bitcoind and three LND v0.21.4-beta nodes, pinned by digest |
| `setup.sh`, `setup.ps1` → `lab/setup.ts` | builds the lab and bakes the credentials |
| `teardown.sh`, `teardown.ps1` | `docker compose down --volumes` for this project |
| `src/lnd/` | REST client (TLS pinned to the node's certificate, bounded responses), role-scoped RPC classes, parsers |
| `src/payer/` | payer records and the submit and reconcile workflow |
| `src/receiver/` | receiver records, invoice creation, hold settlement, the settlement listener |
| `src/analysis/` | ListPayments by hash, forwarding history, the liquidity diagnosis |
| `src/cli.ts` | the service's command line |
| `scenarios/` | the five scenario drivers and their `.sh` and `.ps1` wrappers |
| `runtime/` | created by setup, ignored by git: one directory per lab run |
