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

One operation has at most one pending payment (recorded and not yet terminal). One payment can take any number of RPC calls to learn its outcome and any number of HTLC attempts to execute. A lost RPC call says nothing about the payment; a failed HTLC attempt says nothing about the payment either, until LND reports the payment itself terminal.

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

Each profile's SQLite file also holds that component's double-entry books (`src/ledger/`): every state change that moves or commits money posts a balanced journal entry in the same transaction, and `ledger-verify` checks the books against themselves, the component's own records and LND (see [Ledger](#ledger)).

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
- LND v0.21.4-beta with the `invoicesrpc` and `routerrpc` subservers (the release images and binaries include them; a source build needs the `invoicesrpc` and `routerrpc` build tags). `docker-compose.yml` pins such an image. A build without them answers the lab's `/v2/invoices/...` and `/v2/router/...` calls with gRPC code 5 (NotFound) from its REST gateway, which the lab reads as LND having no such invoice or payment.
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

The output below is from a real run of the 1.2.0 release candidate on WSL Ubuntu (Node.js 22.23.3, Docker), 2026-10-09: setup, then each scenario in turn. Node keys, payment hashes and invoices are from the disposable regtest stack; long invoices are shortened.

### 1. Dropped connection after submission

`scenarios/1-dropped-connection.sh [--cut kill|drop]`

The merchant creates a hold invoice, so LND holds the HTLC and the payment stays in flight. The customer's worker records the operation and the payment hash, then calls SendPaymentV2. Once the merchant node reports the HTLC accepted, the worker is killed (`--cut kill`, the default: SIGKILL, or TerminateProcess on Windows) or destroys its own HTTP connection (`--cut drop`). The merchant then tries to issue a replacement invoice for the same order. A new process reconciles with TrackPaymentV2, the merchant settles the hold invoice, and a client repeats the original request.

It proves: after the cut the record is unresolved, not failed, and the operation stays open with nothing posted; LND still holds the payment; no replacement invoice can be issued while the first is unresolved; recovery uses TrackPaymentV2 only; there is one payment for the hash in ListPayments and one SendPaymentV2 call in total; the record's principal and routing fee equal LND's; the operation completes and the ledger is posted once; the repeated request is answered from the record; the merchant fulfills the order once.

```text
Scenario 1: dropped connection after submission
===============================================
  A hold invoice keeps the payment in flight; the payer loses its connection; recovery goes through TrackPaymentV2.
  lab run: /home/dennis/mw-120/examples/payment-lab/runtime/lab-20261009T191604Z
  run tag: 1009T191622922

> Merchant creates a hold invoice for order ORD-1-1009T191622922 (25,000 sat)
  The merchant generates the preimage and stores it before calling AddHoldInvoice, so LND will hold any HTLC until the merchant releases it.
  $ node src/cli.ts receiver create-invoice --as merchant --order ORD-1-1009T191622922 --amount-msat 25000000 --memo ORD-1-1009T191622922 --hold
  invoice created with AddHoldInvoice for ORD-1-1009T191622922
  outcome: created
  payment hash: 1a7c776231b8a01a953e8e31b8a158ad68b8a6090c3691e676b3fcc5e403396d

> Customer worker records operation PAY-ORD-1-1009T191622922 and the payment hash, then calls SendPaymentV2
  $ node src/cli.ts payer pay --as customer-payer --operation PAY-ORD-1-1009T191622922 --kind order-payment --invoice lnbcrt250u1p4vj0v8…ju3ahc --fee-limit-msat 1000000
  recorded intent: operation PAY-ORD-1-1009T191622922 -> payment 1a7c776231b8a01a...
  SendPaymentV2 called (submission counted in the record)
  SendPaymentV2: IN_FLIGHT (attempts 0: 0 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  SendPaymentV2: IN_FLIGHT (attempts 1: 1 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  The merchant node holds the HTLC (invoice state ACCEPTED). Nothing will settle or fail until the merchant decides.

> Kill the worker process while the HTLC is held
  worker exit: 128
  record state: in_flight
  operation state: open
  ok   record is unresolved after the cut, not failed: state in_flight (the last thing this worker knew; it had no chance to write anything)
  ok   business operation still open, nothing posted: operation open, 0 ledger entries
  ok   LND still holds the payment in flight: 1 payment(s) for the hash, status IN_FLIGHT

> Merchant tries to issue a replacement invoice for the same order
  $ node src/cli.ts receiver create-invoice --as merchant --order ORD-1-1009T191622922 --amount-msat 25000000 --hold
  outcome: refused (order ORD-1-1009T191622922 already has invoice 1a7c776231b8a01a953e8e31b8a158ad68b8a6090c3691e676b3fcc5e403396d in state open)
  ok   no replacement invoice while the first is unresolved: create-invoice exit 3 (3 = refused by the one-live-invoice-per-order constraint)

> Restart: a new process reconciles the record with TrackPaymentV2 (it never calls SendPaymentV2)
  $ node src/cli.ts payer reconcile --as customer-payer --payment-hash 1a7c776231b8a01a953e8e31b8a158ad68b8a6090c3691e676b3fcc5e403396d --timeout-s 300
  TrackPaymentV2 started (record in_flight)
  TrackPaymentV2: IN_FLIGHT (attempts 1: 1 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight

> Merchant settles the hold invoice with its stored preimage
  $ node src/cli.ts receiver settle --as merchant --order ORD-1-1009T191622922
  invoice update via lookup: ACCEPTED (settle index 0) -> state-updated
  SettleInvoice called with the stored preimage
  invoice update via settle-call: SETTLED (settle index 1) -> fulfilled
  outcome: settled
  TrackPaymentV2: SUCCEEDED (attempts 1: 0 in flight, 1 succeeded, 0 failed; fee 51000 msat) -> record succeeded
  ok   merchant settled the hold invoice: settle exit 0
  outcome: succeeded
  ok   reconciler reached a terminal state: reconcile exit 0 (0 = succeeded)

> A client repeats the original request for the same operation
  $ node src/cli.ts payer pay --as customer-payer --operation PAY-ORD-1-1009T191622922 --kind order-payment --invoice lnbcrt250u1p4vj0v8…ju3ahc --fee-limit-msat 1000000
  outcome: succeeded
  ok   repeat is answered from the record, not paid again: exit 0, SendPaymentV2 calls in the repeat: 0

> Merchant reconciles its order from the invoice state
  $ node src/cli.ts receiver reconcile --as merchant --order ORD-1-1009T191622922
  invoice update via lookup: SETTLED (settle index 1) -> duplicate
  outcome: 

> Verdict from node state and durable records
  ok   exactly one payment for the hash on the customer node: ListPayments: 1 payment(s)
  ok   LND reports it succeeded: status SUCCEEDED
  ok   one SendPaymentV2 call in total: submissions recorded: 1
  ok   record matches LND: principal and routing fee: record succeeded, value 25,000 sat / LND 25,000 sat, fee 51 sat / LND 51 sat
  ok   operation completed exactly once, ledger posted once: operation completed, completion events 1, ledger entries 2
  ok   merchant: one invoice, settled for the full amount, order fulfilled once: 1 invoice(s), LND state SETTLED, paid 25,000 sat, 1 fulfillment(s), 1 sales entry

VERDICT scenario 1: PASS (13/13 checks passed, computed from node state and durable records)
```

### 2. Settlement notification repeats after a restart

`scenarios/2-settlement-replay.sh`

The merchant's listener (SubscribeInvoices from its stored cursor) runs while two orders are paid. It is stopped and restarted from the cursor as it was after the first order, so LND replays the second order's settlement. A reconciliation pass then looks the invoice up as well.

The listener commits each effect and its cursor in one transaction, so a crash alone does not repeat a delivery. Repeats still happen in production whenever a listener starts from a cursor older than its effects: a cursor kept in another store, a second instance, a restored cursor, a replay after an incident. LND replays only for a non-zero settle index, so the scenario uses two orders and replays from the first one's index.

It proves, from the merchant's durable records: the settlement was delivered at least twice, including once by LND after the restart; the order was fulfilled once and the sale posted once (both keyed on payment hash and order ID), for the amount LND reports paid; the cursor caught up.

```text
Scenario 2: settlement notification repeats after a restart
===========================================================
  Two orders are paid while the merchant listener runs; a restarted listener receives the second settlement again.
  lab run: /home/dennis/mw-120/examples/payment-lab/runtime/lab-20261009T191604Z
  run tag: 1009T191626729

> Start the merchant settlement listener (SubscribeInvoices from its stored cursor)
  $ node src/cli.ts receiver listen --as merchant --reconcile-interval-s 5
  SubscribeInvoices from settle index 0

> Create and pay order ORD-2A-1009T191626729 (10,000 sat)
  $ node src/cli.ts receiver create-invoice --as merchant --order ORD-2A-1009T191626729 --amount-msat 10000000 --memo ORD-2A-1009T191626729
  invoice update via subscription: OPEN (settle index 0) -> state-updated
  invoice created with AddInvoice for ORD-2A-1009T191626729
  outcome: created
  $ node src/cli.ts payer pay --as customer-payer --operation PAY-ORD-2A-1009T191626729 --kind order-payment --invoice lnbcrt100u1p4vj0v2…2wuvg2 --fee-limit-msat 1000000
  recorded intent: operation PAY-ORD-2A-1009T191626729 -> payment d9cd96977a4c1ea4...
  SendPaymentV2 called (submission counted in the record)
  SendPaymentV2: IN_FLIGHT (attempts 0: 0 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  SendPaymentV2: IN_FLIGHT (attempts 1: 1 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  invoice update via subscription: SETTLED (settle index 3) -> fulfilled
  SendPaymentV2: SUCCEEDED (attempts 1: 0 in flight, 1 succeeded, 0 failed; fee 21000 msat) -> record succeeded
  outcome: succeeded
  settle index of ORD-2A-1009T191626729: 3

> Create and pay order ORD-2B-1009T191626729 (12,000 sat)
  $ node src/cli.ts receiver create-invoice --as merchant --order ORD-2B-1009T191626729 --amount-msat 12000000 --memo ORD-2B-1009T191626729
  invoice update via subscription: OPEN (settle index 0) -> state-updated
  invoice created with AddInvoice for ORD-2B-1009T191626729
  outcome: created
  $ node src/cli.ts payer pay --as customer-payer --operation PAY-ORD-2B-1009T191626729 --kind order-payment --invoice lnbcrt120u1p4vj0vt…6dfuwq --fee-limit-msat 1000000
  recorded intent: operation PAY-ORD-2B-1009T191626729 -> payment 105a79cfed570290...
  SendPaymentV2 called (submission counted in the record)
  SendPaymentV2: IN_FLIGHT (attempts 0: 0 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  SendPaymentV2: IN_FLIGHT (attempts 1: 1 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  invoice update via subscription: SETTLED (settle index 4) -> fulfilled
  SendPaymentV2: SUCCEEDED (attempts 1: 0 in flight, 1 succeeded, 0 failed; fee 25000 msat) -> record succeeded
  outcome: succeeded

> Stop the listener
  settled deliveries of ORD-2B-1009T191626729 so far: 1
  stored cursor (settle index): 4

> Restart the listener from an older cursor: settle index 3, as it was after ORD-2A-1009T191626729
  Simulates a listener whose cursor is behind its effects (cursor in another store, a second instance, a restored cursor).
  $ node src/cli.ts receiver cursor-set --as merchant --settle-index 3
  $ node src/cli.ts receiver listen --as merchant --reconcile-interval-s 5
  SubscribeInvoices from settle index 3
  invoice update via subscription: SETTLED (settle index 4) -> duplicate

> A reconciliation pass looks the invoice up as well (a third path to the same settlement)
  $ node src/cli.ts receiver reconcile --as merchant --order ORD-2B-1009T191626729
  invoice update via lookup: SETTLED (settle index 4) -> duplicate
  outcome: 

> Verdict from the merchant's durable records and LND
  delivery 2026-10-09T19:16:27.375Z via subscription: OPEN -> state-updated
  delivery 2026-10-09T19:16:27.713Z via subscription: SETTLED -> fulfilled
  delivery 2026-10-09T19:16:27.925Z via subscription: SETTLED -> duplicate
  delivery 2026-10-09T19:16:28.029Z via lookup: SETTLED -> duplicate
  ok   the settlement was delivered more than once: 3 SETTLED deliveries (subscription, subscription, lookup)
  ok   the restarted listener received it again from LND: 1 subscription redelivery(ies); outcomes fulfilled, duplicate, duplicate
  ok   order fulfilled exactly once: order fulfilled, 1 fulfillment row(s)
  ok   sale posted exactly once, for the amount LND received: 1 ledger entry of 12,000 sat; LND: SETTLED, paid 12,000 sat
  ok   cursor caught up with the replayed settlement: cursor 4, invoice settle index 4

VERDICT scenario 2: PASS (5/5 checks passed, computed from node state and durable records)
```

### 3. Directional liquidity

`scenarios/3-directional-liquidity.sh`

The merchant owes the customer a refund. The amount is set from the merchant's current channel balances (what it can send, plus 25,000 sat), so it cannot be sent whatever earlier scenarios did. The merchant has 4 BTC on-chain and channel C has 2,000,000 sat capacity. The refund fails. The lab then diagnoses the failure from the merchant's own read-only view: wallet balance, each channel's capacity, local and remote balance, both reserves, commitment fee and pending HTLCs, a QueryRoutes check, and the payment's failure reason and HTLC attempts. The operator opens a new channel from the merchant's on-chain funds, and the same refund (same invoice, same payment hash) is retried.

The diagnosis explains: on-chain funds are not Lightning liquidity until they are in a channel; capacity counts both sides, and only the local side can send; reserves and the commitment fee are not spendable; sending needs outbound balance at every hop while receiving needs inbound balance toward the receiver; and a failure names the first node that refused one attempt, so it does not always locate all of the missing liquidity, and the sender cannot see other nodes' balances.

It proves: the refund failed as LND reports it; on-chain funds and capacity each exceed the amount while the sendable balance does not; the record and operation are failed with nothing posted; after the new channel the retry succeeds, the customer receives the amount once, and the record shows two submissions of one payment with the actual fee.

```text
Scenario 3: directional liquidity
=================================
  A refund fails although the merchant has on-chain funds and channel capacity; the lab explains why, fixes it and retries.
  lab run: /home/dennis/mw-120/examples/payment-lab/runtime/lab-20261009T191604Z
  run tag: 1009T191628150

> Merchant liquidity before the refund (merchant read-only credential)
  on-chain confirmed: 400,000,000 sat
  channel capacity: 2,000,000 sat
  sendable from channels: 52,000 sat
  refund amount: 77,000 sat (sendable + 25000 sat, rounded up)

> Lab precondition, checked with the router's read-only credential (a real sender cannot see this)
  router outbound toward the customer: 1,048,678 sat

> Customer issues a refund invoice RFD-3-1009T191628150 for 77,000 sat
  $ node src/cli.ts receiver create-invoice --as customer --order RFD-3-1009T191628150 --amount-msat 77000000 --memo RFD-3-1009T191628150
  invoice created with AddInvoice for RFD-3-1009T191628150
  outcome: created

> Merchant refund worker pays it (operation REFUND-RFD-3-1009T191628150)
  $ node src/cli.ts payer pay --as merchant-refunds --operation REFUND-RFD-3-1009T191628150 --kind refund --invoice lnbcrt770u1p4vj0vv…e7f6ur --fee-limit-msat 1770000
  recorded intent: operation REFUND-RFD-3-1009T191628150 -> payment b50a0943b396bf3c...
  SendPaymentV2 called (submission counted in the record)
  SendPaymentV2: IN_FLIGHT (attempts 0: 0 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  SendPaymentV2: FAILED (attempts 0: 0 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record failed
  outcome: failed (FAILURE_REASON_INSUFFICIENT_BALANCE)
  worker exit: 1 (1 = LND reported the payment failed)
  ok   the refund failed, as LND reports it: exit 1; LND status FAILED, reason FAILURE_REASON_INSUFFICIENT_BALANCE, 0 HTLC attempt(s)

> Diagnosis from the merchant's own view (read-only credential)
  $ node src/cli.ts analysis diagnose --node merchant --payer merchant-refunds --operation REFUND-RFD-3-1009T191628150
  On-chain funds are not Lightning liquidity. The wallet holds 400,000,000 sat confirmed, enough for 77,000 sat, but a Lightning payment can only spend channel balance, and the channels can send at most 52,000 sat. On-chain funds become sendable only after they are moved into a channel (a new channel, or a splice).
  Capacity is not spendable balance. The 1 channel(s) have 2,000,000 sat capacity in total, split into 72,000 sat on this side (can be sent) and 1,924,530 sat on the peers' side (can be received). A payment moves balance from the local side to the remote side of every channel it crosses.
    channel 118747255996416: capacity 2,000,000 sat, local 72,000 sat (reserve 20,000 sat, sendable up to 52,000 sat), remote 1,924,530 sat (peer reserve 20,000 sat), commitment fee 2,810 sat paid by the peer, 0 pending HTLC(s)
  Reserves: each side must keep its channel reserve (20,000 sat on this side in total) and cannot send it; the side that opened a channel also pays its commitment fee from its balance, and LND keeps a further fee buffer for new HTLCs.
  Sending and receiving need opposite sides. Sending 77,000 sat needs that much local balance here and on the outgoing side of every hop to the destination; receiving needs remote (inbound) balance toward the receiver. This node could still receive up to 1,904,530 sat, which does not help it send.
  Route check: QueryRoutes: LND error (gRPC code 2): insufficient local balance.
  LND failed the payment with INSUFFICIENT_BALANCE: the local balance of this node's channels together was below the amount plus fees, so no HTLC was sent and nothing was learned about other nodes.
  Limits of this diagnosis: a failure names the first node that refused one attempt. The balances of other nodes' channels are not visible from here, a later attempt may fail elsewhere, and balances change between attempts, so one failure does not always locate all the missing liquidity.
  ok   diagnosis: on-chain funds cover the refund, channel balance does not: on-chain 400,000,000 sat, sendable 52,000 sat, refund 77,000 sat
  ok   diagnosis: capacity exceeds the refund, directional balance does not: capacity 2,000,000 sat
  ok   record and operation failed, nothing posted: record failed (FAILURE_REASON_INSUFFICIENT_BALANCE), operation failed

> Operator fix: move 177,000 sat of on-chain funds into a new channel merchant -> router
  Channel management needs the node operator's authority; the refund worker's pay-only credential cannot open channels.
  $ lncli openchannel --node_key <router> --local_amt 177000 --sat_per_vbyte 2   # on merchant
  mined to height: 119
  sendable from channels now: 223,760 sat

> Retry the same refund: the same invoice and payment hash, allowed because LND reported the first attempt failed
  $ node src/cli.ts payer retry --as merchant-refunds --operation REFUND-RFD-3-1009T191628150
  SendPaymentV2 called (submission counted in the record)
  SendPaymentV2: IN_FLIGHT (attempts 0: 0 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  SendPaymentV2: IN_FLIGHT (attempts 1: 1 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  SendPaymentV2: SUCCEEDED (attempts 1: 0 in flight, 1 succeeded, 0 failed; fee 155000 msat) -> record succeeded
  outcome: succeeded

> Verdict from node state and durable records
  ok   the retried refund succeeded: retry exit 0; LND payments for the hash: SUCCEEDED
  ok   the customer received the refund once, in full: customer invoice SETTLED, paid 77,000 sat
  ok   record shows two submissions of one payment and the actual fee: submissions 2, fee 155 sat / LND 155 sat
  ok   refund operation completed and posted once: operation completed, 2 ledger entries

VERDICT scenario 3: PASS (8/8 checks passed, computed from node state and durable records)
```

### 4. Multi-attempt settlement

`scenarios/4-multi-attempt.sh`

The amount is set above the local balance of each of the customer's two channels to the router (largest balance plus 20,000 sat), so LND must split the payment into parts and may retry some of them. The merchant creates the invoice, the customer pays with up to 16 parts.

It proves: the payment succeeded with at least two successful HTLC attempts and is one payment in ListPayments; the successful shards add up to the invoice amount; LND's total fee equals the sum of the successful attempts' route fees; the books hold one principal entry and one fee entry equal to LND's values; the stored attempts match LND's; the fee equals the router's policy (1,000 msat + 2,000 ppm) applied to each shard; the router's ForwardingHistory shows the same shards and the same total fee; the merchant received the amount once, in several HTLCs.

```text
Scenario 4: multi-attempt settlement
====================================
  One payment, several HTLC attempts over two channels; the books show one principal and the real total fee.
  lab run: /home/dennis/mw-120/examples/payment-lab/runtime/lab-20261009T191604Z
  run tag: 1009T191629839

> Customer channel balances (customer read-only credential)
  channel 118747255865344 local: 461,458 sat
  channel 118747256061952 local: 459,454 sat
  payment amount: 482,000 sat (above the largest single channel balance, 461,458 sat)

> Merchant creates an invoice for order ORD-4-1009T191629839
  $ node src/cli.ts receiver create-invoice --as merchant --order ORD-4-1009T191629839 --amount-msat 482000000 --memo ORD-4-1009T191629839
  invoice created with AddInvoice for ORD-4-1009T191629839
  outcome: created

> Customer pays it with up to 16 parts
  $ node src/cli.ts payer pay --as customer-payer --operation PAY-ORD-4-1009T191629839 --kind order-payment --invoice lnbcrt4820u1p4vj0v…gt22z5 --fee-limit-msat 14820000 --max-parts 16
  recorded intent: operation PAY-ORD-4-1009T191629839 -> payment 9b31820520104cda...
  SendPaymentV2 called (submission counted in the record)
  SendPaymentV2: IN_FLIGHT (attempts 0: 0 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  SendPaymentV2: IN_FLIGHT (attempts 1: 1 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  SendPaymentV2: IN_FLIGHT (attempts 2: 2 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  SendPaymentV2: IN_FLIGHT (attempts 2: 1 in flight, 1 succeeded, 0 failed; fee 483000 msat) -> record in_flight
  SendPaymentV2: SUCCEEDED (attempts 2: 0 in flight, 2 succeeded, 0 failed; fee 966000 msat) -> record succeeded
  outcome: succeeded
  worker exit: 0
  SendPaymentV2 updates received: 5

> Merchant reconciles its order from the invoice state
  $ node src/cli.ts receiver reconcile --as merchant --order ORD-4-1009T191629839
  invoice update via lookup: SETTLED (settle index 5) -> fulfilled
  outcome: 

> Verdict: the books against LND, the router's forwarding log and its fee policy
  attempt 5: SUCCEEDED, 241,000 sat over 118747255865344 > 118747255996416, fee 483 sat
  attempt 6: SUCCEEDED, 241,000 sat over 118747256061952 > 118747255996416, fee 483 sat
  ok   payment succeeded over several HTLC attempts: status SUCCEEDED; 2 attempts: 2 succeeded, 0 failed
  ok   one payment for the hash: ListPayments: 1
  ok   principal: the shards add up to the invoice amount: LND value 482,000 sat, sum of successful shards 482,000 sat, invoice 482,000 sat
  ok   fee: LND's total equals the fees of the successful attempts: LND fee 966 sat, sum over successful attempts 966 sat
  ok   books: one principal entry and one fee entry, equal to LND: principal 482,000 sat, fee 966 sat, operation completed
  ok   stored attempts match LND's attempts: 2 stored, 2 in LND
  ok   fee equals the router's policy applied per shard: 2 x 1000 msat base + 2000 ppm of each shard = 966 sat
  ok   the router's forwarding log shows the same fees: 2/2 shards found in ForwardingHistory, router earned 966 sat
  ok   merchant received the amount once, in several HTLCs: invoice SETTLED, paid 482,000 sat in 2 HTLCs, 1 fulfillment(s)

VERDICT scenario 4: PASS (9/9 checks passed, computed from node state and durable records)
```

### 5. Concurrent budget enforcement

`scenarios/5-concurrent-budget.sh`

A payout budget of 100,000 sat. Two worker processes each pay a 60,000 sat hold invoice with a 1,000 sat fee allowance; they decode their invoices, wait at a barrier, and reserve at the same instant. The admitted worker is killed while its HTLC is held. A small payout is admitted and then canceled by the payee. A 38,500 sat payout is tried while the first is still unresolved, and again after it settles.

It proves: exactly one of the two concurrent payouts is admitted and the refusal follows from the arithmetic; the reservation (principal plus fee allowance) stays held while the payment is unresolved; a payment LND reports failed releases its reservation; a payment that does not fit while a reservation is held is refused, and is admitted once the settled payment's reservation shrinks to principal plus actual fee if it then fits; LND shows one payment for each admitted payout and none for refused ones; the budget's consumed amount equals what LND paid, fees included, within the limit.

The budget is enforced by this service. It does not limit anyone who holds the `pay-only` macaroon itself: a copy of that file can call SendPaymentV2 directly and LND will pay within the node's balances. Enforcement against a leaked credential has to live where the credential is checked, in the wallet or account backend, for example [Lightning Terminal accounts](https://docs.lightning.engineering/lightning-network-tools/lightning-terminal/accounts), which bind a macaroon to a balance that LND enforces. macwarden keeps credentials short-lived, scoped and revocable; it does not cap amounts.

```text
Scenario 5: concurrent budget enforcement
=========================================
  Two concurrent payouts race for one budget; reservations hold while a payment is unresolved and settle to the actual fee.
  lab run: /home/dennis/mw-120/examples/payment-lab/runtime/lab-20261009T191604Z
  run tag: 1009T191630581

> Set payout budget PAYOUTS-5-1009T191630581 to 100,000 sat
  $ node src/cli.ts payer budget-set --as customer-payer --budget PAYOUTS-5-1009T191630581 --limit-msat 100000000
  budget at start: limit 100,000 sat, held 0 sat, consumed 0 sat, available 100,000 sat

> Payee creates two hold invoices of 60,000 sat: each fits the budget, both together do not
  $ node src/cli.ts receiver create-invoice --as merchant --order PO-5-1-1009T191630581 --amount-msat 60000000 --memo PO-5-1-1009T191630581 --hold
  invoice created with AddHoldInvoice for PO-5-1-1009T191630581
  outcome: created
  $ node src/cli.ts receiver create-invoice --as merchant --order PO-5-2-1009T191630581 --amount-msat 60000000 --memo PO-5-2-1009T191630581 --hold
  invoice created with AddHoldInvoice for PO-5-2-1009T191630581
  outcome: created

> Two worker processes decode their invoices, wait at a barrier, then reserve at the same instant
  $ node src/cli.ts payer pay --as customer-payer --operation PO-5-1-1009T191630581 --kind payout --invoice lnbcrt600u1p4vj0vw…m5fgag --fee-limit-msat 1000000 --budget PAYOUTS-5-1009T191630581 --wait-for-go
  $ node src/cli.ts payer pay --as customer-payer --operation PO-5-2-1009T191630581 --kind payout --invoice lnbcrt600u1p4vj0vw…2ydxde --fee-limit-msat 1000000 --budget PAYOUTS-5-1009T191630581 --wait-for-go
  [worker 1] recorded intent: operation PO-5-1-1009T191630581 -> payment 85da82f5e9147f08...
  [worker 2] refused: budget PAYOUTS-5-1009T191630581 has 39000000 msat available, 61000000 msat requested
  [worker 1] SendPaymentV2 called (submission counted in the record)
  [worker 1] SendPaymentV2: IN_FLIGHT (attempts 0: 0 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  [worker 1] SendPaymentV2: IN_FLIGHT (attempts 1: 1 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  ok   exactly one of the two concurrent payouts was admitted: admitted: worker 1, refused: worker 2
  ok   refusal follows from the reservation arithmetic: requested 61,000 sat, available 39,000 sat

> Kill the admitted worker while its HTLC is held: its payment is unresolved
  budget while unresolved: limit 100,000 sat, held 61,000 sat, consumed 0 sat, available 39,000 sat
  ok   the reservation stays held while the payment is unresolved: held 61,000 sat, consumed 0 sat

> A small payout (10,000 sat) fits; the payee cancels it, so LND reports it failed
  $ node src/cli.ts receiver create-invoice --as merchant --order PO-5-3-1009T191630581 --amount-msat 10000000 --memo PO-5-3-1009T191630581 --hold
  invoice created with AddHoldInvoice for PO-5-3-1009T191630581
  outcome: created
  $ node src/cli.ts payer pay --as customer-payer --operation PO-5-3-1009T191630581 --kind payout --invoice lnbcrt100u1p4vj0vs…nrlzhc --fee-limit-msat 1000000 --budget PAYOUTS-5-1009T191630581
  recorded intent: operation PO-5-3-1009T191630581 -> payment 5c3c5f4bae7d57f7...
  SendPaymentV2 called (submission counted in the record)
  SendPaymentV2: IN_FLIGHT (attempts 0: 0 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  SendPaymentV2: IN_FLIGHT (attempts 1: 1 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  budget with the small payout in flight: limit 100,000 sat, held 72,000 sat, consumed 0 sat, available 28,000 sat
  $ node src/cli.ts receiver cancel --as merchant --order PO-5-3-1009T191630581
  CancelInvoice called
  invoice update via lookup: CANCELED (settle index 0) -> state-updated
  outcome: canceled
  SendPaymentV2: IN_FLIGHT (attempts 1: 1 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  SendPaymentV2: FAILED (attempts 1: 0 in flight, 0 succeeded, 1 failed; fee 0 msat) -> record failed
  outcome: failed (FAILURE_REASON_INCORRECT_PAYMENT_DETAILS)
  budget after the failure: limit 100,000 sat, held 61,000 sat, consumed 0 sat, available 39,000 sat
  ok   a failed payment releases its reservation: small payout exit 1 (1 = failed per LND), available back to 39,000 sat

> A payout of 38,500 sat + 1,000 sat allowance while the first is still unresolved
  $ node src/cli.ts receiver create-invoice --as merchant --order PO-5-4-1009T191630581 --amount-msat 38500000 --memo PO-5-4-1009T191630581
  invoice created with AddInvoice for PO-5-4-1009T191630581
  outcome: created
  $ node src/cli.ts payer pay --as customer-payer --operation PO-5-4-1009T191630581 --kind payout --invoice lnbcrt385u1p4vj0v3…0t7mj3 --fee-limit-msat 1000000 --budget PAYOUTS-5-1009T191630581
  refused: budget PAYOUTS-5-1009T191630581 has 39000000 msat available, 39500000 msat requested
  ok   refused while the held reservation counts in full: exit 3; needs 39,500 sat, available 39,000 sat

> Restart: reconcile the first payout with TrackPaymentV2 while the payee settles it
  $ node src/cli.ts payer reconcile --as customer-payer --payment-hash 85da82f5e9147f081859f240f19e24d25d1f5b078b0a50ff2bfa82adbec38d57 --timeout-s 300
  TrackPaymentV2 started (record in_flight)
  TrackPaymentV2: IN_FLIGHT (attempts 1: 1 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  $ node src/cli.ts receiver settle --as merchant --order PO-5-1-1009T191630581
  invoice update via lookup: ACCEPTED (settle index 0) -> state-updated
  SettleInvoice called with the stored preimage
  invoice update via settle-call: SETTLED (settle index 6) -> fulfilled
  outcome: settled
  TrackPaymentV2: SUCCEEDED (attempts 1: 0 in flight, 1 succeeded, 0 failed; fee 121000 msat) -> record succeeded
  outcome: succeeded
  budget after settlement: limit 100,000 sat, held 0 sat, consumed 60,121 sat, available 39,879 sat
  ok   on success the reservation becomes principal + actual fee: consumed 60,121 sat = 60,000 sat + fee 121 sat; 879 sat of the allowance released

> The same payout request again, now that the reservation reflects the actual fee
  needs 39,500 sat, available 39,879 sat: fits
  $ node src/cli.ts payer pay --as customer-payer --operation PO-5-4-1009T191630581 --kind payout --invoice lnbcrt385u1p4vj0v3…0t7mj3 --fee-limit-msat 1000000 --budget PAYOUTS-5-1009T191630581
  recorded intent: operation PO-5-4-1009T191630581 -> payment aee3b4a21660c09d...
  SendPaymentV2 called (submission counted in the record)
  SendPaymentV2: IN_FLIGHT (attempts 0: 0 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  SendPaymentV2: IN_FLIGHT (attempts 1: 1 in flight, 0 succeeded, 0 failed; fee 0 msat) -> record in_flight
  SendPaymentV2: SUCCEEDED (attempts 1: 0 in flight, 1 succeeded, 0 failed; fee 78000 msat) -> record succeeded
  outcome: succeeded
  ok   admission follows the budget arithmetic: exit 0, expected 0 (paid)

> Release the refused payout's invoice
  $ node src/cli.ts receiver cancel --as merchant --order PO-5-2-1009T191630581
  CancelInvoice called
  invoice update via lookup: CANCELED (settle index 0) -> state-updated
  outcome: canceled

> Verdict from LND and the durable records
  ok   LND: the admitted payout paid once, the refused one never sent: admitted: SUCCEEDED; refused: 0 payment(s)
  ok   LND: the canceled payout failed; the near-limit payout matches its admission: small: FAILED; near-limit: SUCCEEDED
  budget at the end: limit 100,000 sat, held 0 sat, consumed 98,699 sat, available 1,301 sat
  ok   budget consumed equals what LND actually paid, within the limit: consumed 98,699 sat, LND paid 98,699 sat including fees, limit 100,000 sat
  budget refusals recorded: 2

> What this budget does not do
  The budget is enforced by this service, in its own database. It limits what this service sends. It does not limit
  anyone who holds the pay-only macaroon itself: a copy of that file can call SendPaymentV2 directly, and LND will pay
  within the node's balances. Enforcement against a leaked credential has to live where the credential is checked:
  in the wallet or account backend, for example Lightning Terminal accounts, which bind a macaroon to a spending
  balance that LND enforces. macwarden keeps such credentials short-lived, scoped and revocable; it does not cap amounts.

VERDICT scenario 5: PASS (10/10 checks passed, computed from node state and durable records)
```

## Explain

`payer explain --as <profile> --operation <id> | --payment-hash <hex> [--json] [--refresh]` and `receiver explain --as <profile> --order <id> | --payment-hash <hex> [--json] [--refresh]` print one page a support engineer can read: what happened to one operation (payer) or one order (receiver), from the component's own records, in the order the records say it happened, with the rule in [Design decisions](#design-decisions) (or [Ledger](#ledger), [Fulfillment](#fulfillment)) that made each decision. A payment hash names its operation or order.

| Section | What it holds |
| --- | --- |
| outcome | the operation's or order's state now and why, one line |
| timeline | every recorded fact, oldest first: payer: the operation, each payment's intent, each submission with LND's updates and its HTLC attempts (route length, fee, failure code and the index of the hop that failed it), connections lost, NotFound reverts, stale updates ignored, retries (the closed submission), the failure or success, withdrawn and double payments, budget refusals, reservations held, released and consumed with their amounts, journal entries, outbox rows; receiver: the order, each invoice's recorded identity, every delivery of an invoice update with its source and what it did, invoices not created, late or superseded, the fulfillment, journal entries, outbox rows |
| reservation | the budget (limit, held, consumed, available) and each reservation and refusal of the operation; none for a receiver |
| journal | the operation's or order's journal entries with their lines |
| outbox | its outbox row, its state and claims, and the file performing it writes |
| reconciliation | each decision of the timeline with its rule, quoted by the name this README gives it, and the oracle predicates of the [State-machine harness](#state-machine-harness) that check that rule |

The rules and their predicates are listed in `src/explain/rules.ts`; a test checks that every name appears in this README as cited. Timeline kinds: `operation`, `intent`, `submission`, `lnd-update`, `htlc-attempt`, `uncertain`, `track-interrupted`, `revert`, `not-found-after-attempts`, `stale-update`, `retry`, `failed`, `succeeded`, `success-after-failure`, `amount-mismatch`, `withdrawn`, `not-initiated`, `possible-double-payment`, `double-payment`, `budget-actual-principal`, `budget-overrun`, `budget-refused`, `reservation-held`, `reservation-released`, `reservation-consumed` (payer); `order`, `invoice-intent`, `delivery`, `not-created`, `late-invoice`, `superseded`, `fulfillment` (receiver); `journal`, `outbox-enqueued`, `outbox-done`, `outbox-pending`, `outcome`, `refreshed` (both); `event` for a record event of a kind this version does not know (its kind and raw detail, scrubbed, with no rule). A payment withdrawn because another payment of its operation succeeded is shown as `withdrawn` and then `not-initiated` (LND's NotFound confirming it was never sent); it is not reverted to intent. The records keep each HTLC attempt's last state only, so an `htlc-attempt` item shows that state ("its last recorded state", with LND's start time when LND reported one) at the end of its submission: at the next submission's start, or after the payment's last event; never earlier, as a terminal state before a disconnect that came first. Each `delivery` item is explained from what the records held at that delivery: "a replayed update after CANCELED" (rule "Canceled is final") only when an earlier delivery of the invoice was CANCELED, never because the invoice was canceled later. A `settlement-amount-conflict` delivery logged by the ledger migration (source `migration: …`) says the fulfilling amount stands; one from LND says the first does.

It reads the records only and writes nothing: it opens the database read-only, never creates one (a database that does not exist has no records: exit 3), and never migrates one (a database an older version wrote is refused with exit 4, unchanged; any command that records migrates it). The records are read in one read transaction, so the explanation is one snapshot even while a worker commits; `--refresh` reads LND after it. It never prints a preimage or a payment request, and it never reads either column: a payment or invoice appears as its hash's fingerprint, the first 8 and last 4 hex characters (`1a7c7762…396d`), with its amount. Any other string from the records or LND (an error message, a memo) is scrubbed, with invisible characters (format characters, fillers, variation selectors) skipped while matching so that none can split a secret in two: a BOLT 11 string (`lnbc`, `lntb`, `lnbcrt` or `lnsb` and at least 20 more letters or digits, in any case and anywhere in a word, as in `pay_lnbc…`) becomes `[payment request]`; a run of exactly 64 hex characters becomes its fingerprint when it is a payment hash of the subject, the subject's own ID or an outbox effect's hashed file name (shown as `=sha256-<fingerprint>`), and `[redacted]` otherwise; a longer hex run, which could hold a secret at any offset, becomes `[redacted hex N chars]` whole; a standalone run of 43 or 44 base64 characters (standard alphabet, `=` padding), the way LND's REST API writes 32 bytes such as a preimage, becomes `[redacted base64]` unless it is the subject's own ID; in text output, control characters, Unicode whitespace other than the space, bidirectional and invisible characters are escaped as macwarden's text output escapes them (`\xNN`, `\uNNNN`), and no line starts with `::`. Text lines are at most 120 characters.

A subject ID that is itself 64 hex is shown as its fingerprint, like a payment hash: in the header line, in `subject`, in `outcome` and in the unknown-subject error. `--operation <64 hex>` and `--order <64 hex>` still find it; the lookup uses the ID as given.

**Bounds.** So that no record set makes the output unbounded, the timeline keeps at most 2,000 items, the first 1,000 and the last 1,000 (the outcome is the last), and so does the reconciliation; the journal, the outbox and the reservation's reservations and refusals keep at most 200 each, the first and the last 100; a submission shows at most 200 HTLC attempts, the first and the last 100, with one `htlc-attempt` item counting the rest; the subject's payment hashes and the outcome's payments (payer) or invoices (receiver) keep at most 200, the first and the last 100 (`"truncated": {"payments": N}`), and the text header names at most three payment hashes, else it counts them and names the first and the last; and any one string is cut at 1,024 characters, followed by `…(N more)` (after scrubbing, so a cut never leaves part of a secret). Text output prints `… N items omitted …` (`entries`, `rows`, `reservations`, `refusals`, `decisions`) where the left-out items were; `--json` adds `"truncated": {"timeline": N, …}` to `result`, one count per list cut (`htlcAttempts` for the attempts), and leaves it out when nothing was. `--refresh` facts come after the cut. `--refresh` looks up at most 200 payment hashes (the first and the last 100; a `refreshed` fact counts the others, and `--json` adds `"truncated": {"refresh": N}`), one after another, each within 30 seconds and all within 60 seconds; a refresh that reaches its deadline stops there and exits 4 with the error `--refresh stopped at its 60 s deadline after N of M lookup(s)`, the explanation from the records printed all the same.

`--refresh` adds LND's current view, read-only: the payer reads each payment's current state with TrackPaymentV2 (its first message; the stream is then closed), the receiver looks each invoice up. Each answer is a `refreshed` fact saying whether it agrees with the record; nothing is applied, so a difference is for `payer reconcile` or `receiver reconcile` to act on. `--json` prints one document as macwarden's Output rules do: `{"schema":1,"command":"explain","ok":…,"warnings":[…],"result":{"subject","timeline":[{"at","kind","detail","rule"?}],"outcome","reservation","journal","outbox","reconciliation","truncated"?},"error":{"code","step","message"}|null}`, amounts as decimal msat strings, `ok` false exactly when `error` is set. A record the explanation cannot read (a damaged row) is exit 4 with `"error": {"code": 4, "step": "records", …}` in the same document. In text mode, warnings and the error go to stderr as `warning: <code>: <message>` and `error: <step>: <message>`.

Exit 0: explained. Exit 2: usage (neither or both of the subject options, a malformed hash or ID). Exit 3: the records have no such operation, order or payment hash. Exit 4: a `--refresh` lookup failed; the explanation from the records is printed all the same, with the warning `refresh-failed`.

## Fulfillment

A settlement pays for something. The receiver records that something as an outbox row in the same `BEGIN IMMEDIATE` transaction as the settlement, the `fulfillments` row and the invoice-settled journal entry; the payer does the same when an operation completes (LND reported its payment succeeded: an order payment confirmed, a refund issued, a payout confirmed). A worker performs the row later and acknowledges it. The intent and the state change commit together or not at all, so no crash can leave a settled order without its fulfillment or a fulfillment without its settlement.

| Column | Meaning |
| --- | --- |
| `outbox_id` | order of enqueueing; the worker takes due rows lowest first |
| `kind` | `fulfill-order` (receiver) or `confirm-operation` (payer) |
| `idempotency_key` | `order_id:payment_hash` or `operation_id:payment_hash`, unique: a repeated settlement or update enqueues nothing |
| `subject`, `payload` | the order or operation ID, and the effect's fields as JSON (amounts as decimal strings) |
| `state` | `pending`, `leased` (claimed by a worker until `lease_expires_at`), `done` |
| `attempts`, `next_attempt_at`, `last_error` | claims so far, when a failed row is due again, and why it failed |
| `created_at`, `acknowledged_at` | enqueued; performed and acknowledged (never earlier than `created_at`: a clock that stepped back records the acknowledgement at `created_at`) |

A second payment of a fulfilled order, an underpaid settlement and a second success of a completed operation move money (see [Ledger](#ledger)) but fulfil nothing, so they enqueue nothing.

**The effect.** In the lab the effect is a file: a receipt `<lab>/receipts/<profile>/<order_id>.json` (order, payment hash, amount paid, settle index, the invoice-settled entry's ID) or a confirmation `<lab>/confirmations/<profile>/<operation_id>.json` (operation, its kind, payment hash, value, fee, the payment-succeeded entry's ID), one directory per profile as there is one database per profile, so the same order or operation ID in two profiles (the `merchant` and `customer` receivers, the `customer-payer` and `merchant-refunds` payers) names two files. Each file also carries the row's kind and idempotency key and `hmacSha256`, an HMAC-SHA256 over those fields (as `[name, value]` pairs sorted by name, in JSON) with the lab's key `<lab>/outbox.key` (32 random bytes as hex, created with mode 0600 on first use). Anyone who can read the key can write a receipt or confirmation the worker accepts as already performed, so on Linux and macOS a key open to group or others is refused with an error naming it (`chmod 600` it, and replace it if someone else may have read it). On Windows the lab sets no ACL of its own: the key, the temporary files and `receipts/` and `confirmations/` inherit the lab directory's permissions, so keep the lab directory private to your account. The HMAC is a stand-in for a signed receipt: it lets the worker recognise a file it wrote. The key is created only while no receipt or confirmation exists, in `receipts/` and `confirmations/` or in any profile directory under them: if it is missing while such files exist, every command that needs it fails with an error naming `<lab>/outbox.key`, because a new key would make every one of those files fail verification. Restore the key from your copy; to start the lab over instead, move `receipts/` and `confirmations/` aside first.

**Upgrading a 1.3 lab.** 1.3 wrote every profile's effects straight into `receipts/` and `confirmations/`. When a profile's worker starts, each such file that the profile's records own (a valid HMAC, and an outbox row of that profile with the file's idempotency key) is moved into the profile's directory (an `outbox-effect-adopted` event names both paths), unless that already holds the name; the worker then finds it already present and does not write it again. Files no profile owns stay where they are.

In the file name, lower-case letters, digits, `_` and `-` of the ID stay as they are and every other byte is percent-encoded with upper-case hex, upper-case letters included (`ORD-7` is `%4F%52%44-7.json`), so two IDs never share a file, even on a file system that ignores case (Windows, macOS: `Order1` and `order1` are `%4Frder1.json` and `order1.json`). A Windows device name has its first letter encoded (`con` is `%63on.json`), and a name longer than 200 characters becomes `=sha256-<SHA-256 of the ID>.json`, which no encoded ID can be. The file is written to a temporary file `.<name>.json.<owner tag>.<lease end>.tmp` (mode 0600; on Windows it inherits the directory's permissions), fsynced and then hard-linked to its name, which fails if the name exists, so a reader never sees a partial file, only one writer creates it, and nothing is ever overwritten. The text is encoded to UTF-8 once and written in full (both halves, every byte), and after the link the file is read back and its HMAC checked before the row is acknowledged; a file that does not verify is reported `damaged`. On Linux and macOS the effect directory is fsynced after the link, and also when an attempt finds the effect already there (an earlier attempt may have died before syncing), and the lab directory is fsynced after `outbox.key` is created, so an acknowledged effect and the key survive power loss. A directory sync that fails for any reason other than the platform not supporting it is an error and the row is retried; on Windows, which cannot sync a directory, the lab relies on NTFS's own metadata journaling. The worker lists an effect directory's temporary files once per pass, so leftovers of a process killed during a pass are removed by the next pass.

**The worker.** `outbox-run` (and `receiver listen` after every reconciliation pass, `payer reconcile` after its pass) repeats:

1. claim, in one `BEGIN IMMEDIATE` transaction: the lowest due row (pending and `next_attempt_at` passed, or leased with an expired lease) becomes `leased` to this worker for 60 seconds, attempts + 1. Two workers serialise on SQLite's write lock, and neither can claim a row the other holds;
2. check, then perform: the row's `ledgerEntryId` must name its own entry in the journal (the invoice-settled or payment-succeeded entry for its payment hash), or nothing is written. An existing file with a valid HMAC over the same fields means an earlier attempt performed it, and nothing is written; any other existing file is never overwritten (see the failures below);
3. acknowledge: `done` with `acknowledged_at` and the lease cleared, in one statement, only if this worker still holds the lease.

A failed effect returns the row to `pending`, due again after 1 s, 2 s, 4 s, … capped at 5 minutes, with the same idempotency key; a row in backoff does not hold up the rows after it. The `outbox-failed` event's `reason` and the row's `last_error` (shown by `outbox-status` once the row is past its deadline) name the failure (`show` lists every row with its last error):

| `reason` | What it means | What to do |
| --- | --- | --- |
| `conflict` | a valid file for another idempotency key holds the name | find out which row the file belongs to; the worker never overwrites it |
| `damaged` | a file holds the name that does not verify under the lab's key: partial, edited, or signed with another key (the key changed or was recreated) | inspect the file and move it out of `receipts/<profile>/` or `confirmations/<profile>/`; the next attempt writes the effect. Nothing replaces it automatically |
| `ledger-entry-missing`, `ledger-entry-mismatch` | the row names no ledger entry, one that is not in the journal, or another payment's | run `ledger-verify`; the row stays pending and no file is written |
| `lease-expired` | this worker stalled past its lease, the worker that took the row over removed its temporary file, and the effect is not there | nothing: the row is retried. When the other worker already performed it, the stalled one reports `outbox-lease-lost` instead |

| Crash point | What is left | After a restart |
| --- | --- | --- |
| between the state change and the outbox insert | nothing: one transaction | the settlement and its row are both there, or neither |
| after the claim, before the effect | a leased row, no file | the lease runs out; the row is claimed again and performed once |
| mid-effect (temporary file half written) | a leased row and a temporary file | the next attempt removes temporary files of its own owner and of leases that have run out, never one of a lease still running; the effect is performed once |
| after the effect, before the ack | a leased row and the file | the file's HMAC matches: acknowledged without writing again |
| after the ack, before the lease release | nothing: the ack clears the lease in the same statement | the row is done; nothing to do |

Each point is covered by a test that kills the worker with SIGKILL there, restarts it, and checks one acknowledged row, one file with a valid HMAC, no temporary file and balanced books (`test/payment-lab-outbox.test.ts`).

`outbox-status --as <profile> [--json] [--deadline-s <n>]` lists the pending, leased and done counts, expired leases, the age of the oldest row not done and, oldest first, the rows not done more than the deadline (default 300 s) after they were enqueued, with their last error. It exits 0, or 75 when a row is past its deadline.

**Upgrading.** Opening a database without an outbox (receiver migration 4, payer migration 7) creates the table and enqueues a pending row for every fulfillment and completed operation already recorded, so their receipts and confirmations are written once like any other.

## Ledger

The lab's books are double-entry: every event that moves or commits money posts one journal entry whose debits equal its credits, in the same `BEGIN IMMEDIATE` transaction as the state change that caused it. The state change and its entry commit together or not at all; there is no point between them for a crash to land on. Each payer and receiver profile keeps its own journal in its own database file; both use one chart of accounts (`src/ledger/accounts.ts`). A payment hash gets one settlement entry, whichever comes first: if LND later reports the same invoice settled for a different amount, the receiver posts nothing, leaves the order as it was, and records the delivery as `settlement-amount-conflict`. An invoice settled for less than its order (`underpaid-settlement`) does not fulfil the order and is not its live invoice any more: the order still awaits payment, and `receiver create-invoice` issues a replacement for it (receiver migration 6 changes the one-live-invoice-per-order index accordingly).

| Account | What it carries |
| --- | --- |
| `customer-receivable` | order payments: the payer debits it when it pays an order, the receiver credits it when an order's invoice settles; across both books one order nets to zero |
| `lnd-wallet-incoming` | money received: LND's `amt_paid_msat` of every settled invoice |
| `lnd-wallet-outgoing` | money sent: LND's `value_msat` and `fee_msat` of every succeeded payment, as two lines |
| `routing-fees` | LND's `fee_msat` of every succeeded payment |
| `refunds-payable`, `payouts-payable` | refunds and payouts paid (debited on success; the lab does not accrue them when the operation is recorded) |
| `suspense-double-payment` | money that does not belong to an order: a second payment of an operation (payer) or order (receiver), an underpaid settlement |
| `budget:<id>`, `budget-commitments` | what each budget has committed: held reservations at principal plus fee allowance, consumed ones at principal plus actual fee; equal to the limit minus what is available |

| Event (where it is posted) | Debit | Credit |
| --- | --- | --- |
| invoice settled (receiver, `applyInvoice`) | `lnd-wallet-incoming` amt paid | `customer-receivable` |
| payment succeeded (payer, `applyUpdate`) | the operation kind's account (`customer-receivable`, `refunds-payable`, `payouts-payable`) value; `routing-fees` fee | `lnd-wallet-outgoing` value; `lnd-wallet-outgoing` fee |
| double payment, payer (the operation's other payment had succeeded) | `suspense-double-payment` value | the operation kind's account |
| double payment, receiver (`second-payment`) | `customer-receivable` | `suspense-double-payment` |
| underpaid settlement (receiver) | `lnd-wallet-incoming` | `suspense-double-payment` |
| budget reservation held (`recordIntent`, `prepareRetry`) | `budget:<id>` principal + allowance | `budget-commitments` |
| reservation released (failure, withdrawn replacement) | `budget-commitments` | `budget:<id>` principal + allowance |
| reservation consumed (success) | `budget-commitments` unused allowance (or `budget:<id>` principal, and `budget:<id>` fee, for a reservation a recorded failure had released) | `budget:<id>` (or `budget-commitments` principal, and `budget-commitments` fee) |

Every line is a non-negative millisatoshi amount bounded to int64 with a direction. An entry is unique on (event, reference), the payment hash or the reservation, so a repeated delivery or update posts nothing. Each line records its account's running balance after it, and a `balances` table holds every account's current balance, written in the same transaction. Running balances and every sum are computed in JavaScript bigints and stored as decimal text: a sum of int64 amounts need not fit in 64 bits, and SQLite's `SUM` fails past that. The columns accept canonical decimals only (`0` or `-?[1-9][0-9]*`, at most 39 digits), and every journal column CHECKs its storage type, so an `entry_id` that is text or a `leg` that is a blob is refused at the write. A live entry is posted at the later of the clock and the last live entry's `posted_at` (as the usage file is), when that one is at most 24 hours ahead of the clock: a wall clock stepped back, by NTP or by hand, posts at the previous time instead of before it, so live times never decrease. A last entry further ahead than that (a clock that once ran far ahead, or an entry moved forward) is not followed: the entry is posted at the clock, and `ledger-verify` names the one ahead. An entry ID outside ±(2^53 - 1), which an outbox row or a report could not carry exactly, is refused, and the state change with it. For the same reason a released reservation that is consumed posts its principal and its fee as two line pairs, not one sum: LND reports each as an int64, but principal plus fee can exceed 2^63 - 1 (a principal of 2^63 - 11 and a fee of 11), and one line of that sum would be refused, and with it the success.

`payer show` and `receiver show` print the operation's or order's `journal` next to the `ledger` view, which keeps its 1.2 shape (the payer's principal and routing-fee legs, the receiver's sales).

**Upgrading a 1.2 database.** Opening it runs the ledger migration (payer migration 6, receiver migration 3) in one transaction: every `ledger_entries` row becomes the balanced entry the 1.3 code would have posted (`principal` and `routing-fee` rows of a payment become one payment-succeeded entry against the operation kind's account; a `sales` row becomes an invoice-settled entry against `customer-receivable`; a second payment of an operation or order also gets its double-payment entry), with origin `migrated` and the row's original time; reservations still held or consumed get their budget entries, and every released reservation its budget-held and budget-released pair; a settled underpaid invoice, which 1.2 did not post, gets its underpaid-settlement entry; an invoice whose record kept an underpaid first settlement while its order was fulfilled by a later full one (1.2.1) takes the fulfilling amount, with a `settlement-amount-conflict` delivery naming both, and its receipt carries the entry's amount; and `ledger_entries` is dropped. The highest entry ID the migration posted is recorded in `journal_migration` (0 when there was nothing to convert). A database a 1.3.0 migration already converted is completed by a later migration (payer migration 10, receiver migration 7): it records that watermark, posts the missing pair of each released reservation (origin `live`, posted at the time of the upgrade) and corrects a record and a pending receipt that kept the underpaid amount. The conversion streams the 1.2 rows; the payer's step still holds one small record per payment while it pairs each payment's principal and fee rows.

**Verifying.** `payer ledger-verify --as <profile>` and `receiver ledger-verify --as <profile>` check, and list every difference per account with the first entry (lowest entry ID) that touches that account and explains it:

1. every entry balances, every line is readable, on an account in the chart, in range; and every entry is well formed (listed in `invalidEntries` with its entry ID): an event this book posts, with the lines its rule in the table above prescribes (accounts, directions, legs, line numbers 1 to n, each pair of equal amounts), a reference of the event's shape (the payment hash, or `reservation:<id>` of a reservation that exists), an operation and payment hash that agree with the payment, invoice or reservation record, origin `migrated` for an entry at or below the migration's watermark (`journal_migration`; 0 when there is none) and `live` above it, an entry ID within ±(2^53 - 1), and a readable `posted_at` that never decreases from one live entry to the next and is at most 24 hours ahead of the run's clock (migrated entries keep their 1.2 times and all come before the first live one). As posting clamps live times, a clock set back flags nothing; an entry out of order was moved, and of the two around the decrease the one its next live entry disagrees with is named (an entry moved forward, not the healthy entries after it). A column of the wrong type (an `entry_id` that is text, real or a blob, a blob `leg`, a damaged record row) is a finding on the entry or account, never an internal error. An unbalanced entry is listed once, under `unbalancedEntries`, with any shape problems in its reason;
2. every account's balance recomputed from the entries equals the stored running balance (each line's, and the `balances` row); every `balances` row is an account in the chart with a canonical decimal balance (an unreadable one is named corrupt, not read as 0), whose `last_entry_id` and `updated_at` are the last entry that touches the account and its `posted_at`;
3. each book equals its records, record by record and not only in total, without LND. Payer: each reservation's budget entries commit what it holds or consumed (a released reservation has its budget-held and budget-released entries, not only a net of zero), each succeeded payment has its payment-succeeded entry with the record's value and fee, no other payment posts to the wallet or fee accounts, and a double-payment entry exists exactly for each succeeded payment of an operation after its first, for that payment's value. Receiver: one settlement entry per invoice, exactly for the invoices the record says settled (or, recorded not-created, LND reported `SETTLED` for), for the record's `amt_paid_msat` (a late not-created invoice keeps no amount, so its settlement's amount is checked against LND only), `underpaid-settlement` exactly when that is less than the invoice's amount and `invoice-settled` otherwise; and a double-payment entry, for the settlement's amount, exactly for a paid invoice that did not fulfill its order because another invoice did. A settlement entry for an invoice whose record says open (or any state but settled) is a difference;
4. the wallet and fee accounts equal LND's view over the same window, the payment hashes the store knows: the sum of settled invoices' `amt_paid_msat` from ListInvoices (receiver, with its invoice-only credential), the sums of succeeded payments' `value_msat` and `fee_msat` from ListPayments (payer, with its node's read-only credential, because pay-only cannot list payments). Both lists are read in pages of 500, at most 200 pages; after 200 full pages one more item is asked for, and only a list that has it (more than 100,000 items) is `incomplete`.

Exit 0: balanced and in agreement with LND. Exit 1: not balanced (an unbalanced, unreadable or malformed entry, a stored balance or `balances` row, a record or LND differ). Exit 75: balanced, but LND could not be compared (no list call, a node error, more than 100,000 items, or LND reports a payment or settlement the records have not learned yet: reconcile, then verify again). Run it with the component quiet. On an in-memory store (one read through the store's own connection), LND is read before the store's snapshot is taken, so a payment that succeeds in between is a difference rather than `pending`. Both outputs list at most the first 100 unbalanced and the first 100 malformed entries (lowest entry ID first), with `unbalancedEntryCount` and `invalidEntryCount` counting them all, so a ledger with 100,000 broken entries prints a few kilobytes, not megabytes. `lndDifferences` lists the first 100 per-payment differences from LND (account, payment hash, the amounts, the entry), and `lndDifferenceCount` counts them all; each also explains its account, so two differences that cancel in an account's total are still reported and named in `firstDifference`. Without `--json` it prints a `ledger-account` event per account and a `ledger-verify` summary, which adds `unbalancedEntriesMore` or `invalidEntriesMore` (`"… N more"`) for a list that leaves entries out, and carries `lndDifferences`, `lndDifferenceCount` and `lndDifferencesMore` (`… N more`) when that list leaves some out, as `--json` does; with `--json`, one object:

```text
{"book":"payer","balanced":false,"entries":3,
 "unbalancedEntries":[{"entryId":2,"event":"payment-succeeded","reference":"<hash>","debitsMsat":"1011","creditsMsat":"1010","reason":"..."}],
 "unbalancedEntryCount":1,"invalidEntries":[],"invalidEntryCount":0,
 "accounts":[{"account":"routing-fees","computed":"11","stored":"10","difference":"1","records":"10","recordsDifference":"1",
              "lnd":"10","lndDifference":"1","firstEntry":{"account":"routing-fees","entryId":2,"event":"payment-succeeded",...}}, ...],
 "lnd":"compared","firstDifference":{"account":"routing-fees","entryId":2,"event":"payment-succeeded","reference":"<hash>","reason":"..."}}
```

Amounts are net debit (debits minus credits) in msat, as decimal strings. Verify reads the books in batches of 10,000 entries (and records) by ID inside one read transaction, on a read-only connection of its own (so the snapshot stays fixed while LND is read), and keeps per-account state only: memory does not grow with the size of the books (a 200,000-entry book peaks under 300 MB of heap), and a book of 100,000 entries verifies in about 2.5 s. From code (the harness calls it after every run):

```ts
import { verifyLedger } from './src/ledger/verify.ts';
verifyLedger(store: { db: DatabaseSync; book: 'payer' | 'receiver' }, api?: LndLedgerSource): Promise<LedgerVerification>
// store: a PayerStore or ReceiverStore. api: anything with listPaymentsPage (payer: ReadApi) or listInvoicesPage
// (receiver: InvoiceApi or ReadApi); without it, lnd is 'not-requested'. The result is the --json object with bigints;
// lnd is 'compared' | 'pending' | 'not-requested' | 'unavailable' | 'incomplete'.
```

## Design decisions

**Durable intent before submission.** The payer commits the operation, the payment hash (decoded from the invoice), the amount, the fee limit and any budget reservation in one transaction, then marks the payment `submitting` and counts the submission in a second committed transaction, and only then writes SendPaymentV2. After a crash at any point, the record says what may have been sent. The receiver works the same way: it generates the preimage, stores it with the hash, and then asks LND to create exactly that invoice (AddInvoice with `r_preimage`, or AddHoldInvoice with the hash), so a lost answer is resolved by looking the known hash up. A lookup that finds nothing decides the invoice only once the create call is over (LND itself refused it, or two minutes have passed since the intent, well beyond the call's 30-second timeout); until then the invoice stays `creating` and no replacement is issued. Only a definite refusal from LND counts as over: an application error with gRPC code 2, 3, 5, 6, 7, 8, 9, 11, 12 or 16, or a 400-class response other than 404 carrying a message. Cancelled (1), DeadlineExceeded (4), Aborted (10), Internal (13), Unavailable (14), DataLoss (15), an HTTP 408, 499, 502, 503 or 504 from a gateway or proxy, a 404 without gRPC code 5, and a transport error after connecting are ambiguous: LND may still be creating the invoice, so it waits for the window. (The list is in `definiteRefusal` in `src/lnd/errors.ts`; the payer applies the same classes to SendPaymentV2.)

**An invoice that turns up late.** A create call can stall in LND past the window and still succeed, after the order got a replacement. Whenever an invoice recorded not-created turns up in LND (the create call's late answer, the subscription, or a reconciliation lookup, which rechecks not-created invoices for 24 hours), it is recorded, and: if the order still awaits payment and has no other live invoice, it is adopted as the order's invoice; otherwise it is canceled in LND with CancelInvoice (retried by every reconciliation pass until LND reports it canceled), so the order never has two payable invoices. Canceled is final: a late invoice LND reports canceled is never adopted (it stays not-created, and its order keeps awaiting payment and may get a replacement), and neither a delayed create answer nor a replayed older update makes a canceled invoice live again. An invoice canceled while its create call was in flight makes `receiver create-invoice` report `canceled` (exit 3), not `created`, and reconciliation counts a canceled invoice resolved, never open. LND deletes canceled invoices (DeleteCanceledInvoice, or `gc-canceled-invoices-on-the-fly`/`-on-startup`; an expired invoice is canceled), and SubscribeInvoices does not report a cancel, so a NotFound for an invoice LND was seen to hold (recorded open or accepted, a late invoice recorded OPEN or ACCEPTED, or one the receiver has just asked LND to cancel) is recorded as LND's CANCELED, through the same rules, and counted resolved; a NotFound for an invoice still `creating` decides nothing inside the creation window, as before. Settled outranks canceled: if LND reports SETTLED for an invoice recorded canceled, the record becomes settled with LND's amount and settle index (a replayed OPEN or ACCEPTED still changes nothing). Open and accepted rank alike: LND returns a hold invoice from ACCEPTED to OPEN when its accepted HTLCs are canceled or time out, and the record follows it back to `open` with nothing paid. `receiver reconcile` counts every invoice it covers exactly once, as resolved (settled, canceled, or not-created and still absent from LND), open, or unknown; a superseded invoice whose CancelInvoice failed counts unknown even if it was counted open earlier in the pass, and settled and canceled invoices count resolved also when the pass is stopped before reaching them. If it was paid before the cancel reached LND, the payment is still recorded and posted, because the money arrived; an order is fulfilled once, by the first settlement, and a settlement of another invoice of a fulfilled order is a `second-payment`: posted, reported, not fulfilled again, to be returned to the payer. Whichever invoice settles first, the step that fulfills the order (the subscription, a reconciliation lookup, or the settlement of a late invoice) also cancels every other invoice of the order still `creating`, `open` or `accepted` in LND with CancelInvoice, retried by every reconciliation pass until LND reports it canceled, so a late original paid first leaves no payable replacement; one whose create call is still in flight is canceled as soon as it turns up, and `receiver settle` refuses to settle such a hold invoice. It checks again after its lookup, with nothing awaited between that check and SettleInvoice, so an order fulfilled by another invoice while the lookup was in flight is refused too.

**Unresolved is a state, not an error.** A payment is `intent`, `submitting`, `in_flight`, `uncertain`, `succeeded` or `failed`. The middle three are unresolved: the operation stays open, the budget reservation stays held, and a partial unique index (one pending payment per operation: `intent`, `submitting`, `in_flight` or `uncertain`) makes a replacement payment impossible in the database, whatever the code does. Succeeded payments are outside the index on purpose: LND can report success for a payment after it was recorded failed and a replacement was recorded, and that success is recorded (payment succeeded, ledger posted, budget consumed, operation completed). The replacement is then withdrawn if it was never sent, or, if it may have been sent, flagged with a `possible-double-payment` event on both payments and reconciled like any other; if LND reports it succeeded too, it is posted and consumed as well and flagged `double-payment`. Only LND's terminal answer, through SendPaymentV2 or TrackPaymentV2, moves a payment to `succeeded` or `failed`.

**A timeout is not a failure.** A client timeout or a dropped connection means the client stopped listening. LND keeps routing the payment; a held HTLC can stay in flight for hours. Treating the timeout as a failure and paying again (or asking for a new invoice) is how a payment gets made twice. So a transport error after the connection was established marks the record `uncertain`, and the only way forward is TrackPaymentV2 until LND reports a terminal state. The one exception is a connection that was never established (refused or failed TLS handshake): the request cannot have reached LND, and the record returns to `intent`. If TrackPaymentV2 answers that LND has no payment for the hash (gRPC code 5, NotFound, which LND's REST gateway always sends with its error, whatever the HTTP status; a 404 without that code, bodiless or with a proxy's own body such as `{"message":"Not Found"}`, comes from a proxy in front of LND and is no answer. A 404 with code 5 is the gateway's own answer, also when it is the gateway's `{"code":5,"message":"Not Found"}` for a path it does not serve; the lab cannot tell that apart from LND's NotFound, so it requires an LND that serves every path it calls, see [Requirements](#requirements)) and no HTLC attempt was recorded for the current submission, the record also returns to `intent`; submitting it again uses the same payment hash, and LND refuses a second payment for a hash that is in flight or settled. An error answer to SendPaymentV2 fails the payment (rejected before initiation, reservation released) only when it is a definite refusal and TrackPaymentV2 then has no payment for the hash. After an ambiguous error (DeadlineExceeded, Unavailable, a gateway's 502, 503 or 504) a NotFound is only a point-in-time absence: the request may still reach LND, so the payment stays `uncertain` with its reservation held for reconciliation to decide.

**SendPaymentV2 is called only by compare-and-set.** `intent → submitting` is a conditional update; two processes (a restarted worker and an old one, or two replicas) can never both submit the same record. A repeated request for an operation that was already submitted is answered from the record and TrackPaymentV2, before the invoice is decoded, so it does not depend on the invoice still being unexpired. The invoice is matched to the record by payment hash when it decodes offline, else by text compared case-insensitively (BOLT11 is case-insensitive; QR codes carry it in upper case); if the stored invoice is damaged, the invoice given is read with DecodePayReq and matched by hash, and a refusal says the record is damaged. Succeeded and failed are final: a later "not found" never fails a succeeded payment, and a completed operation is never retried. Every update and every call outcome is applied with the submission it was made for. A submission is superseded once a later one is claimed or `payer retry` prepares the next one; a late FAILED or IN_FLIGHT, a definite refusal, a refused connection or a stream that ended, for a superseded submission, is logged as `stale-update` and changes neither the payment nor its reservation, and that call reports its own outcome as `unresolved`, naming the live submission. A SUCCEEDED is recorded whichever submission it was read for, because the money left. A NotFound that sends a record back to intent supersedes nothing: if LND initiates that submission after all, its own IN_FLIGHT and FAILED still apply. After `payer retry`, LND keeps answering TrackPaymentV2 with the earlier submission's FAILED until the retry's SendPaymentV2 reaches it and initialises the payment again (its old HTLC attempts deleted, a new creation time). A TrackPaymentV2 snapshot read for the retry is therefore the retry's only when it carries an HTLC attempt not recorded under an earlier submission, or, carrying none, when LND created the payment later than any creation time it reported for an earlier submission (both times are LND's clock; the store keeps the latest one per submission). Otherwise it is logged as `stale-update` and decides nothing: `pay` and `retry` leave the payment unresolved (its reservation held, no replacement admitted), and `payer reconcile` treats an earlier submission's FAILED as it treats a NotFound for a first submission: a record that never saw LND acknowledge the retry goes back to `intent`, its reservation still held, and can be submitted again (this is the way out after a crash between the claim and the send, or a retry whose request never reached LND); if the retry's request reaches LND after all, its own updates still apply. SendPaymentV2's own stream reports only on its request, so its updates are not judged this way. A retry LND refused definitely while it still shows the earlier FAILED was not initiated and fails before initiation, as a definite refusal followed by NotFound does. Only when LND reported no creation time for an earlier submission (it was refused before LND initiated it) is a snapshot without attempts compared with the time the retry was claimed, which assumes the payer's clock and LND's agree. `payer retry` takes the operation's most recently recorded failed payment (by insertion order, not by a timestamp two payments can share) and reserves against that payment's budget, which `payer show` then reports. Once another payment completed the operation, a replacement is neither reverted to intent nor claimed, in the same transaction as the check: a NotFound for it, or a claim of it, withdraws it instead (failed with reason `WITHDRAWN`, its reservation released), so nothing is sent for a paid operation.

**Idempotency keys.** Each journal entry is unique on (event, reference): the payer's payment-succeeded entry on the payment hash, its budget entries on the reservation; the receiver's fulfillment on (payment hash, order ID), at most one per order, and its invoice-settled entry on the payment hash. Every path that learns of a settlement (subscription, lookup, the settle call itself) goes through one function that inserts with `ON CONFLICT DO NOTHING` and posts only when the insert happened. Every delivery that changed something is still logged, so repeated settlements are visible; a delivery that changed nothing (`unchanged`, or `unknown-invoice` for an invoice of another receiver) and repeats the latest one logged for its payment hash (same source, LND state, settle index and outcome) is not logged again, so a reconciliation pass every 10 seconds over an open invoice does not add a row each time.

**An answer about another invoice is no answer.** A lookup whose invoice has another payment hash, or whose payment request decodes (offline, `src/util/bolt11.ts`) to another payment hash, and a create answer (AddInvoice or AddHoldInvoice) whose payment request decodes to another payment hash, are unreadable answers: the lookup counts as unknown and nothing is recorded from it, and the creation is resolved by looking the hash up. A proxy or cache in front of LND, or a hostile node, therefore cannot make the receiver record another invoice's settlement or payment request for an order. A SETTLED report with nothing paid is unreadable too and changes nothing.

**Subscriptions are a fast path; lookups are the ground truth.** The listener resumes SubscribeInvoices from its stored settle index (LND replays every settlement after a non-zero index) and also looks up every unresolved invoice at start and every few seconds, which covers the cursor-zero case and any gap between subscribing and LND registering the subscription. Stopping the listener (or `receiver reconcile`) cuts off the lookup in progress and starts no further call; what was already recorded stays recorded, and the next pass picks up the rest.

**The settle cursor moves only over settlements the subscription delivered.** Only subscription deliveries move the settle cursor, never a lookup or the settle call. From a cursor c above zero it advances to c + 1 only when the subscription delivered settle index c + 1, and then on over c + 2, c + 3, … as long as each was delivered and recorded. SubscribeInvoices sends its add backlog first, each invoice in its current state, so an already-settled invoice with a high settle index can arrive before the settle backlog's lower ones; moving to the highest index seen would skip those if the listener stopped in between, and a restart from that cursor would never deliver them. A cursor of zero is the exception: LND replays no settlement for it, so the first settle index the subscription delivers becomes the cursor, and it moves on from there as above (settlements before it are found by reconciliation lookups). The add cursor keeps the highest add index seen, because the add backlog and new invoices arrive in add-index order.

**Reservations.** A budget reservation is principal plus fee allowance, and the fee allowance is also the fee limit passed to LND, so the reservation is an upper bound LND enforces. It is taken in the same `BEGIN IMMEDIATE` transaction as the intent, which holds SQLite's write lock from the start: concurrent workers serialise, and the second sees the first's reservation. It stays held while the payment is unresolved, is released when LND reports the payment failed, and becomes principal plus the actual fee when LND reports success. Admission reads the budget's reservations through an index on the budget, so other budgets' history adds no work under the write lock. The budget consumes what the ledger posts: if LND reports a succeeded value other than the invoice's amount (an `amount-mismatch` event), the reservation is released and a new one is recorded consumed at LND's value plus the actual fee (a `budget-actual-principal` event). The success is never refused, because the money left; if it takes the budget past its limit, a `budget-overrun` event records by how much, and the budget shows less than nothing available until its limit is raised.

**Accounting from LND's numbers.** On success the ledger posts LND's `value_msat` as principal and LND's `fee_msat` as the routing fee, and the HTLC attempts are stored next to them, so the books can be checked against the attempts and against the routing node's forwarding log. The books are double-entry and balanced by construction: an entry whose debits differ from its credits is refused, and the refusal rolls back the state change with it; `ledger-verify` proves the balance afterwards rather than assuming it (see [Ledger](#ledger)).

**Storage: SQLite through Node's built-in `node:sqlite`.** SQLite gives transactions, cross-process locking and constraints, which the design relies on (the partial unique index, the unique ledger keys, the serialised reservation). WAL with `synchronous = FULL` makes each commit durable on disk before it returns. `node:sqlite` ships with the Node.js versions macwarden supports, so the lab has no native addon to compile and no runtime dependency; it is marked experimental in Node.js, and the lab uses only its basic synchronous API (`DatabaseSync`, prepared statements). The SQL works unchanged with a package such as `better-sqlite3`. A journaled JSON file with fsync was the alternative; it would need its own locking between processes and could not enforce the invariants as constraints. Each database file is created owner-only. Opening a database runs the migrations it has not had, in one transaction with its `user_version`; a database whose `user_version` is newer than the migrations this code knows (written by a later version) is refused with both versions named, before anything is written, and a failure while opening closes the file again before the error is reported. This version has payer migrations 1 to 10 and receiver migrations 1 to 7 (payer 9 records when each submission was claimed; receiver 6 changes the one-live-invoice-per-order index and indexes deliveries by settle index; payer 10 and receiver 7 complete the 1.3.0 ledger migration), so 1.3.0 refuses a database this version wrote. The receiver's database holds invoice preimages, which are proofs of payment: in production, protect it like a credential.

**Least privilege, verified separately.** The payer's `pay-only` credential cannot list payments; the "only one payment was sent" evidence comes from the separate `read-only` credential. The service never uses the nodes' admin credentials.

## The service

`node src/cli.ts <component> <command>` (or `npm run service -- …`). Every command prints one JSON object per line. Run it without arguments for the full usage. Every command accepts `--lab <dir>`, and payer and receiver commands `--as <profile>`; beyond those a command takes only the options listed for it, and any other (one another command takes included), or one given twice, is a usage error. The commands that only read (`show`, `budget-show`, `ledger-verify`, `outbox-status`, `explain`, `analysis diagnose`) open their database read-only: they never create it (a missing database reads as empty) and never migrate it (a database an older version wrote is refused, exit 4, unchanged; `payer reconcile` or `receiver reconcile` migrates it). `payer show` prints `preimageRecorded` (true or false), never the preimage; `analysis payments` prints `preimagePresent`, never a preimage or a payment request.

| Command | Purpose |
| --- | --- |
| `payer pay --as <profile> --operation <id> --kind <kind> --invoice <bolt11> --fee-limit-msat <n>` | record intent, submit, follow to a terminal state |
| `payer reconcile --as <profile> [--payment-hash <hex>]` | resolve unresolved payments with TrackPaymentV2 |
| `payer retry --as <profile> --operation <id>` | submit a payment LND reported failed again, same invoice |
| `payer show --as <profile> --operation <id>`, `payer budget-set --as <profile> --budget <id> --limit-msat <n>`, `payer budget-show --as <profile> --budget <id>` | records and budgets |
| `payer ledger-verify --as <profile> [--json]` | check the payer's books against themselves, its records and ListPayments; the `ledger-verify` summary (or the `--json` object) lists unbalanced and malformed entries with their entry ID and reason |
| `receiver create-invoice --as <profile> --order <id> --amount-msat <n> [--hold]` | record the invoice identity, then create it |
| `receiver settle` / `cancel --order <id>` | release or cancel a hold invoice |
| `receiver listen` | settlement consumer with periodic reconciliation |
| `receiver reconcile [--order <id>]` | resolve invoices by lookup |
| `receiver ledger-verify --as <profile> [--json]` | check the receiver's books against themselves and ListInvoices |
| `payer outbox-run`, `receiver outbox-run --as <profile> [--once] [--interval-s <n>]` | perform pending outbox rows (confirmations, receipts); every `--interval-s` (default 5) until stopped, or one pass; a run whose stop signal is already set when it starts performs no pass |
| `payer outbox-status`, `receiver outbox-status --as <profile> [--json] [--deadline-s <n>]` | outbox counts per state and the oldest pending age |
| `payer explain --as <profile> --operation <id> \| --payment-hash <hex> [--json] [--refresh]` | one operation's timeline, outcome, reservations, journal and outbox, with the rule behind each decision (see [Explain](#explain)) |
| `receiver explain --as <profile> --order <id> \| --payment-hash <hex> [--json] [--refresh]` | the same for one order |
| `analysis payments --node <node> --payment-hash <hex>` | every payment LND holds for a hash, without its preimage (only `preimagePresent`) or payment request; `complete` is false when the scan stopped before the end of LND's payments |
| `analysis diagnose --node <node> --payer <profile> --operation <id>` | liquidity diagnosis for a payment |

Exit codes: 0 done; 1 payment failed according to LND; 2 usage error (also a malformed amount or payment hash, or an amount or index above 2^63 - 1, the most SQLite stores); 3 refused (budget, conflicting operation, wrong state); 4 configuration or node error; 75 unresolved: the outcome is not known yet and the record stays open for reconciliation. `payer reconcile` maps a payment's outcome the same way as `pay` and `retry`; for several payments, the first of 75, 3 and 1 that applies to any of them, else 0. Its outbox pass does not change the exit code, and it does not run once the reconcile was stopped (SIGINT, SIGTERM or `--timeout-s`): an `outbox-pass-skipped` event says so, as `receiver listen` runs no pass after it is stopped. `ledger-verify` exits 0 balanced, 1 unbalanced, 75 when LND could not be compared. `outbox-status` exits 75 when a row is not done past its deadline; `outbox-run --once` exits 75 when a row is not done after its pass (in backoff, or held by another worker), and a missing lab directory for the effects is a configuration error (4). Every argument is checked before anything is opened, so a usage error (exit 2) creates, migrates and changes no database: an option the command does not take (`unknown option --x for payer show`), an option given twice, a missing or malformed value, or an `--as` that is not a profile. `payer pay` for an operation already recorded must name its recorded `--kind`: another kind is a usage error (exit 2, `--kind refund differs from operation OP's recorded kind payout`) before anything is decoded, recorded or sent. A command or option name in a usage error is printed escaped, as text output escapes control characters. `payer reconcile` follows at most 16 payments at once (16 TrackPaymentV2 streams), and tracks a payment again after 1 s, 2 s, 4 s, … capped at 15 s; the pause starts again from 1 s after a stream that changed the record or stayed open at least 15 s.

## Limits

- Regtest only, three nodes, one route shape. Real networks add gossip delays, private channels, route hints, liquidity changing between attempts and nodes that do not report useful failures.
- The liquidity diagnosis sees only the sending node's channels. It cannot see other nodes' balances, and its sendable figure is an upper bound: LND also keeps a fee buffer for new HTLCs on channels it opened.
- A stream that goes silent is detected by TCP keepalive, which can take minutes. The service never treats that silence as a failure, only as a reason to reconnect.
- Reconciliation that ends without a terminal state (its deadline passes while LND still holds the payment) leaves the record unresolved; it must be run again. Production needs a supervisor that keeps doing so.
- Automatic invoice recovery has a horizon. A receiver invoice recorded `not-created` with no late state recorded (LND was never seen to hold it) is looked up again by `receiver reconcile` and `receiver listen` only for 24 hours after its intent. The subscription sees a late creation at any age once its cursor is past zero; a listener that never set its cursors and was not running when such an invoice was created and paid late leaves it to `receiver reconcile --as <profile> --order <id>`, which looks up every invoice of the order whatever its age.
- If TrackPaymentV2 answers "not found" for a payment whose current submission has recorded HTLC attempts (for example after an operator deleted payments from LND), the record stays unresolved for an operator to decide.
- The application budget limits this service only, not the credential (see scenario 5).
- The scenarios assert what they observe; they are demonstrations against real nodes, not a test suite with fault injection at every step.
- `node:sqlite` is experimental in Node.js (see Storage above).
- The harness's LND pays with max_parts 1 (one HTLC attempt at a time); multi-part payments, HTTP 500 answers with a partial body, split stream frames, INITIATED or UNKNOWN payment statuses, and lookup errors other than NotFound, transport errors and 504 are not generated. Operation kinds other than payout, a second budget and setBudget during a case are not generated either.
- The harness's end-of-case check that every settlement LND made is recorded holds only from a non-zero cursor: from a cursor of 0 LND replays no settlement, and a record already canceled is not looked up again, so a settlement nobody delivered then is not required.
- Mutants are run by the product suite through their replays only. Running every mutant through a seeded campaign as well (a slower job, minutes per mutant) would catch a replay that drifted; it is not part of CI.
- The commands that only read never migrate. A database 1.3.0 wrote (payer version 8, receiver version 5) must be opened once by a command that records, for example `payer reconcile` or `receiver reconcile`, before `show`, `explain` and the other read-only commands open it; until then they refuse it (exit 4) and leave it unchanged.

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
| `src/ledger/` | chart of accounts, posting rules, journal, the 1.2 migration, `verifyLedger` |
| `src/outbox/` | the outbox table and its intents, the receipt and confirmation files with their HMAC, the worker |
| `src/explain/` | `payer explain` and `receiver explain`: the timeline from the records, the table of README rules it cites, the text and JSON forms, `--refresh` |
| `src/cli.ts` | the service's command line |
| `scenarios/` | the five scenario drivers and their `.sh` and `.ps1` wrappers |
| `runtime/` | created by setup, ignored by git: one directory per lab run, with `outbox.key`, and `receipts/<profile>/` and `confirmations/<profile>/` written by the outbox worker |

## State-machine harness

`test/harness/` drives the payer's and the receiver's records through random interleavings of two service processes sharing one pair of database files, against a scripted LND, and checks the rules in [Design decisions](#design-decisions) after every store call and every step. It needs no Docker, node or credential: the stores run on `node:sqlite` in a temporary directory, and the harness is TypeScript run through Node's type stripping, like the service.

The events of a case: payment intents (with replacement invoices), submissions, retries and reconciliations; SendPaymentV2 requests that reach LND on time, late or never; stream messages delivered in any order, and streams cut by a transport error, a gateway's 502 or 504, a definite refusal or NotFound; HTLC attempts, and payments failing or succeeding; invoice creations answered, lost, refused or reaching LND after their caller gave up; lookups answered with the current state or with the state they read earlier; invoices paid, held HTLCs timing out, invoices expiring; `receiver settle`, `cancel` and `reconcile` (also through `cli.ts`, for its exit code), the settlement listener and cursor resets; the clock passing the creation window; outbox worker passes (`src/outbox/worker.ts`, writing the lab's receipts and confirmations in the case directory), killed after a claim, while writing an effect file, after the effect or after the acknowledgement; aborts, and process kills (the store is closed and reopened from its file, and nothing the killed process still had in flight is written). Faults are injected on purpose, each a case a rule is for: LND reporting an invoice canceled that is not (settled-outranks-canceled); a payment or an invoice paid for more or less than the invoice's amount; a settled invoice reported again for another amount (a hostile node: the first settlement wins); an invoice on the node the receiver never created. A case can also end a subscription while its process lives (`sub.end`: the listener sees the end and stops; a later `listen` subscribes again from the cursor), delete a canceled invoice in LND (`invoice` `delete`: its lookups answer NotFound from then on), and arm a `preempt`: right before a process's next call of a given store method, a message queued on the other process's streams is delivered, so the other process commits between a workflow's read of a record and its next write. The scripted LND answers SettleInvoice and CancelInvoice with LND's own errors (already settled, already canceled, still open, unable to locate invoice: gRPC 2, HTTP 500), pays with one HTLC attempt at a time (max_parts 1), and does not push ACCEPTED or CANCELED to SubscribeInvoices (LND dispatches those only to SubscribeSingleInvoice). A case ends by killing both processes, a subscription catch-up from the cursor, reconciling with every call answered (two passes), and running the worker until every outbox row is done.

Some paths need a dozen events in one order, which random draws rarely produce, so the generator also starts short plans: a request still on its way when the other process's NotFound sends the record back to `intent`, then refused, failed, or succeeding after a later submission failed (with a withdrawn or a paid replacement: a double payment); a FAILED that a tracker read before a retried submission succeeded; an invoice created late that is paid second (a second payment), paid first so that its order's other hold invoice is superseded while its cancel fails or is cut off by an abort and `receiver settle` runs before or after, or seen canceled and then settled or reported OPEN again; a paid hold invoice misreported canceled while another lookup's ACCEPTED is still on its way. A plan is a list of ordinary events chosen from the state at each step, so a case with a plan replays and shrinks like any other.

The oracle (`test/harness/oracle.ts`) states each rule as one named predicate, reading the records through its own read-only connection (and, after every step, running `ledger verify` on both books and reading the effect files with the lab's own HMAC check):

| Predicate | Rule |
| --- | --- |
| `one-pending-payment-per-operation` | an operation has at most one payment in `intent`, `submitting`, `in_flight` or `uncertain` |
| `reservation-held-iff-live` | a budgeted payment (its operation names a budget, or it has a reservation) holds one reservation, at its amount and fee limit, while unresolved; failed releases it; succeeded consumes one, at LND's value plus the actual fee |
| `ledger-once-per-succeeded-payment` | a payment LND reports succeeded is recorded succeeded at LND's value and fee (the oracle compares the record with LND itself) and posted once, with that value and fee; nothing else is posted: per payment hash only `payment-succeeded`, budget entries and, for every succeeded payment of an operation but the first, one `double-payment` entry; the operation is completed iff a payment succeeded; two succeeded payments of one operation are both flagged `double-payment` |
| `stale-submission-changes-nothing` | an update or call outcome other than SUCCEEDED for a superseded submission changes neither the payment, its operation nor its reservation |
| `notfound-revert-keeps-live-updates` | the live submission's IN_FLIGHT, FAILED or definite refusal applies, also after a NotFound sent the record back to `intent`; a TrackPaymentV2 snapshot LND took before the live submission's request reached it changes nothing |
| `terminal-states-final` | succeeded and a completed operation are final; failed changes only by `payer retry` or LND reporting success |
| `budget-admission-within-limit` | admission follows exact (bigint) arithmetic against what the payments themselves commit (amount plus fee limit for each unresolved budgeted payment, value plus fee for each succeeded one), and never throws on large sums; `budgetStatus` is exact; both the reservations and the payments stay within the limit unless LND reported success after a recorded failure or a `budget-overrun` event records the excess |
| `canceled-final-for-open-accepted` | a canceled invoice, or a late invoice LND was seen to cancel (its CANCELED is recorded), is not made live by a replayed OPEN or ACCEPTED or a delayed create answer |
| `settled-outranks-canceled` | SETTLED for an invoice recorded canceled makes it settled; at the end of a case no invoice LND holds SETTLED is recorded canceled |
| `settlement-posted-once` | every settlement LND reports is posted once, however often it is delivered, and a later report of another amount changes nothing; per payment hash one `invoice-settled` (paid in full) or `underpaid-settlement` entry, and a `double-payment` entry exactly when an `invoice-settled` one has no fulfillment; settled is final; an order has at most one fulfillment and is fulfilled iff it has one; at the end of a case every invoice LND holds SETTLED is recorded settled with exactly one settlement entry for the amount LND reports (except one the cursor passed undelivered: an explicit cursor-set, or a settlement below the first one delivered from a zero cursor, which LND never replays) |
| `cursor-moves-only-from-subscription` | the cursor moves only with subscription deliveries, or `receiver cursor-set`; its add index moves to the highest seen, its settle index only contiguously: from c to c + 1 when the subscription delivered settlement c + 1, then on while the subscription delivered each next one (from 0, the first settle index delivered becomes the cursor); lookups never move it |
| `reconcile-buckets-partition` | `receiver reconcile` counts each invoice it covers once (resolved + open + unknown = targets), each in a bucket it may be in (resolved: final when listed, or settled, canceled or not created as the record or the pass's lookups decided it; open: OPEN or ACCEPTED in LND as the pass looked it up; unknown: only when the pass was stopped, a lookup of it got no answer, a cancel of it by the pass failed, or a creating invoice was not found within its creation window), and exits 75 iff unknown > 0; the targets are computed by the oracle from the records, with the 24-hour recheck window for not-created invoices of unknown late state |
| `superseded-canceled-never-settled` | SettleInvoice is never called for an invoice of an order fulfilled by another; after reconciliation no order has two payable invoices |
| `ledger-balanced` | both books pass `ledger verify` after every step: every entry balances and follows its posting rule, stored balances equal the entries, the payer's budget, wallet and fee accounts equal its records, and the amounts posted equal what the scripted LND lists (ListPayments, ListInvoices) for every resolved record (not after a resettle fault, where LND reports two amounts for one invoice) |
| `effects-once` | every fulfilled order has one `fulfill-order` row (its fulfillment's, with the settlement's amount and entry) and every completed operation one `confirm-operation` row (its first succeeded payment's), and nothing else is enqueued; a done row has its receipt or confirmation, valid under the lab's key and carrying the row's fields; no effect is written twice, also when the worker is killed at any point; after the last pass every row is done |
| `no-internal-error` | store calls, workflows and the outbox worker on a live process do not throw (the one refusal by exception is a FAILED for a payment already succeeded) |

Each case is generated from a seed (the generator of `scripts/payment-fuzz.mjs`). A violation is shrunk by delta debugging over the events and written as a replay file: JSON with the case's configuration, the reduced events, the predicate, its message and the records before and after the violation; the file alone reproduces it. From the repository root:

```sh
npm run fuzz:lab                                        # 500 cases, a random seed (printed first)
node examples/payment-lab/test/harness/run.mjs --seed 7 --cases 2000 --steps 80 --replay-out examples/payment-lab/runtime/replays
node examples/payment-lab/test/harness/run.mjs --replay examples/payment-lab/runtime/replays/<file>.json
```

A campaign prints one JSON summary (cases, events, seconds, violations with their replay files, how often each event and plan ran) and exits 1 on any violation; each `VIOLATION` line shows the message the shrunk replay reproduces. A replay file is checked before anything of it runs (known event kinds, every field in range, known processes, answer modes for the call kind, a well-formed configuration): a bad file is reported with its name and step, the other files of a directory still run, and the exit code is 2 (1 is a violation, 0 none). `--collect` runs every case to its end and records each predicate it violates, not only the first; `--no-shrink` writes the unreduced case. `test/payment-lab-harness.test.ts` runs 40 cases with a fixed seed, and the replay corpus, in the product suite.

The replay corpus, `test/harness/replays/`, holds a replay per predicate (`<predicate>.json`) and more per predicate (`<predicate>--<what>.json`): 58 files. Every replay violates nothing on the current lab. Eleven are shrunk or scripted cases that violate their predicate on the 1.2.0 lab, so the corpus is also the regression history of the 1.2.1 audits and of this release's (`cursor-moves-only-from-subscription--add-backlog`: the settle cursor moving past settlements not yet delivered). The others prove their predicate against a kept mutant. A mutant, `test/harness/mutants/<predicate>.cjs` or `<predicate>--<what>.cjs`, is a scripted edit of the current lab source (each edit must match once), applied to a copy, and is proved by the replay of the same name: one recorded on it names it (`"mutant"`); a hand-written one (no violation recorded) is the scenario it breaks. `notfound-revert-keeps-live-updates` also retries the payment and lets another process read the earlier FAILED before the retry reaches LND, which 1.2.0 and 1.3.0 applied as the retry's failure. There are 46 kept mutants: the six of 1.3.0, the four that the pre-1.4 audit found passing every predicate (no reservation taken, a success recorded at the invoice amount, a listener dropping SETTLED for a canceled record, OPEN counted as unknown), and 36 of the 1.3.0 mutation table's 42 that still apply to the source. Of the table's other six, two are among the six of 1.3.0 (m5a, m11a), three no longer apply because the source they edit changed (m9a, m11b, m13c), and m6c (a FAILED overwriting a succeeded payment) was caught by none of 700 seeded cases nor by a scripted failed-after-success scenario: applyUpdate now sets aside, as stale, a TrackPaymentV2 snapshot taken before the live submission reached LND, so a FAILED after a success no longer reaches the code m6c edits. It is not kept. m6b (markUncertain also moving a failed payment) is caught only with a `preempt` event. `test/payment-lab-harness.test.ts` checks that every kept mutant is caught by its replay, and that every recorded replay violates its predicate on the 1.2.0 sources (`git archive v1.2.0`; the test fails when the tag is missing):

```sh
node examples/payment-lab/test/harness/run.mjs --replay examples/payment-lab/test/harness/replays/ledger-balanced.json \
  --mutant examples/payment-lab/test/harness/mutants/ledger-balanced.cjs --expect-violation
```

To run the corpus against 1.2.0:

```sh
mkdir -p examples/payment-lab/runtime/v1.2.0
git archive v1.2.0 examples/payment-lab/src examples/payment-lab/package.json | tar -x -C examples/payment-lab/runtime/v1.2.0
node examples/payment-lab/test/harness/run.mjs --replay examples/payment-lab/test/harness/replays \
  --lab-src examples/payment-lab/runtime/v1.2.0/examples/payment-lab/src --expect-violation
```

`--expect-violation` passes when every recorded replay violates its predicate and skips the hand-written ones and those recorded on a mutant. The `package.json` in the archive marks the old sources as ES modules.
