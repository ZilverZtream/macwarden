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

## Design decisions

**Durable intent before submission.** The payer commits the operation, the payment hash (decoded from the invoice), the amount, the fee limit and any budget reservation in one transaction, then marks the payment `submitting` and counts the submission in a second committed transaction, and only then writes SendPaymentV2. After a crash at any point, the record says what may have been sent. The receiver works the same way: it generates the preimage, stores it with the hash, and then asks LND to create exactly that invoice (AddInvoice with `r_preimage`, or AddHoldInvoice with the hash), so a lost answer is resolved by looking the known hash up. A lookup that finds nothing decides the invoice only once the create call is over (LND itself refused it, or two minutes have passed since the intent, well beyond the call's 30-second timeout); until then the invoice stays `creating` and no replacement is issued. Only a definite refusal from LND counts as over: an application error with gRPC code 2, 3, 5, 6, 7, 8, 9, 11, 12 or 16, or a 400-class response carrying LND's message. Cancelled (1), DeadlineExceeded (4), Aborted (10), Internal (13), Unavailable (14), DataLoss (15), an HTTP 408, 499, 502, 503 or 504 from a gateway or proxy, and a transport error after connecting are ambiguous: LND may still be creating the invoice, so it waits for the window. (The list is in `definiteRefusal` in `src/lnd/errors.ts`; the payer applies the same classes to SendPaymentV2.)

**An invoice that turns up late.** A create call can stall in LND past the window and still succeed, after the order got a replacement. Whenever an invoice recorded not-created turns up in LND (the create call's late answer, the subscription, or a reconciliation lookup, which rechecks not-created invoices for 24 hours), it is recorded, and: if the order still awaits payment and has no other live invoice, it is adopted as the order's invoice; otherwise it is canceled in LND with CancelInvoice (retried by every reconciliation pass until LND reports it canceled), so the order never has two payable invoices. Canceled is final: a late invoice LND reports canceled is never adopted (it stays not-created, and its order keeps awaiting payment and may get a replacement), and neither a delayed create answer nor a replayed older update makes a canceled invoice live again. An invoice canceled while its create call was in flight makes `receiver create-invoice` report `canceled` (exit 3), not `created`, and reconciliation counts a canceled invoice resolved, never open. If it was paid before the cancel reached LND, the payment is still recorded and posted, because the money arrived; an order is fulfilled once, by the first settlement, and a settlement of another invoice of a fulfilled order is a `second-payment`: posted, reported, not fulfilled again, to be returned to the payer. Whichever invoice settles first, the step that fulfills the order (the subscription, a reconciliation lookup, or the settlement of a late invoice) also cancels every other invoice of the order still `creating`, `open` or `accepted` in LND with CancelInvoice, retried by every reconciliation pass until LND reports it canceled, so a late original paid first leaves no payable replacement; one whose create call is still in flight is canceled as soon as it turns up, and `receiver settle` refuses to settle such a hold invoice. It checks again after its lookup, with nothing awaited between that check and SettleInvoice, so an order fulfilled by another invoice while the lookup was in flight is refused too.

**Unresolved is a state, not an error.** A payment is `intent`, `submitting`, `in_flight`, `uncertain`, `succeeded` or `failed`. The middle three are unresolved: the operation stays open, the budget reservation stays held, and a partial unique index (one pending payment per operation: `intent`, `submitting`, `in_flight` or `uncertain`) makes a replacement payment impossible in the database, whatever the code does. Succeeded payments are outside the index on purpose: LND can report success for a payment after it was recorded failed and a replacement was recorded, and that success is recorded (payment succeeded, ledger posted, budget consumed, operation completed). The replacement is then withdrawn if it was never sent, or, if it may have been sent, flagged with a `possible-double-payment` event on both payments and reconciled like any other; if LND reports it succeeded too, it is posted and consumed as well and flagged `double-payment`. Only LND's terminal answer, through SendPaymentV2 or TrackPaymentV2, moves a payment to `succeeded` or `failed`.

**A timeout is not a failure.** A client timeout or a dropped connection means the client stopped listening. LND keeps routing the payment; a held HTLC can stay in flight for hours. Treating the timeout as a failure and paying again (or asking for a new invoice) is how a payment gets made twice. So a transport error after the connection was established marks the record `uncertain`, and the only way forward is TrackPaymentV2 until LND reports a terminal state. The one exception is a connection that was never established (refused or failed TLS handshake): the request cannot have reached LND, and the record returns to `intent`. If TrackPaymentV2 answers that LND has no payment for the hash (gRPC NotFound, or a 404 carrying LND's message; a 404 without a body, which a proxy in front of LND can produce, is no answer) and no HTLC attempt was recorded for the current submission, the record also returns to `intent`; submitting it again uses the same payment hash, and LND refuses a second payment for a hash that is in flight or settled. An error answer to SendPaymentV2 fails the payment (rejected before initiation, reservation released) only when it is a definite refusal and TrackPaymentV2 then has no payment for the hash. After an ambiguous error (DeadlineExceeded, Unavailable, a gateway's 502, 503 or 504) a NotFound is only a point-in-time absence: the request may still reach LND, so the payment stays `uncertain` with its reservation held for reconciliation to decide.

**SendPaymentV2 is called only by compare-and-set.** `intent → submitting` is a conditional update; two processes (a restarted worker and an old one, or two replicas) can never both submit the same record. A repeated request for an operation that was already submitted is answered from the record and TrackPaymentV2, before the invoice is decoded, so it does not depend on the invoice still being unexpired. The invoice is matched to the record by payment hash when it decodes offline, else by text compared case-insensitively (BOLT11 is case-insensitive; QR codes carry it in upper case); if the stored invoice is damaged, the invoice given is read with DecodePayReq and matched by hash, and a refusal says the record is damaged. Succeeded and failed are final: a later "not found" never fails a succeeded payment, and a completed operation is never retried. Every update and every call outcome is applied with the submission it was made for. A submission is superseded once a later one is claimed or `payer retry` prepares the next one; a late FAILED or IN_FLIGHT, a definite refusal, a refused connection or a stream that ended, for a superseded submission, is logged as `stale-update` and changes neither the payment nor its reservation, and that call reports its own outcome as `unresolved`, naming the live submission. A SUCCEEDED is recorded whichever submission it was read for, because the money left. A NotFound that sends a record back to intent supersedes nothing: if LND initiates that submission after all, its own IN_FLIGHT and FAILED still apply. `payer retry` takes the operation's most recently recorded failed payment (by insertion order, not by a timestamp two payments can share) and reserves against that payment's budget, which `payer show` then reports.

**Idempotency keys.** The payer's ledger is unique on (operation ID, payment hash, account); the receiver's fulfillment on (payment hash, order ID), at most one per order, and its ledger on (order ID, payment hash, account). Every path that learns of a settlement (subscription, lookup, the settle call itself) goes through one function that inserts with `ON CONFLICT DO NOTHING` and posts only when the insert happened. Every delivery is still logged, so repeats are visible.

**Subscriptions are a fast path; lookups are the ground truth.** The listener resumes SubscribeInvoices from its stored settle index (LND replays every settlement after a non-zero index) and also looks up every unresolved invoice at start and every few seconds, which covers the cursor-zero case and any gap between subscribing and LND registering the subscription. Stopping the listener (or `receiver reconcile`) cuts off the lookup in progress and starts no further call; what was already recorded stays recorded, and the next pass picks up the rest.

**Reservations.** A budget reservation is principal plus fee allowance, and the fee allowance is also the fee limit passed to LND, so the reservation is an upper bound LND enforces. It is taken in the same `BEGIN IMMEDIATE` transaction as the intent, which holds SQLite's write lock from the start: concurrent workers serialise, and the second sees the first's reservation. It stays held while the payment is unresolved, is released when LND reports the payment failed, and becomes principal plus the actual fee when LND reports success. Admission reads the budget's reservations through an index on the budget, so other budgets' history adds no work under the write lock.

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

Exit codes: 0 done; 1 payment failed according to LND; 2 usage error (also a malformed amount or payment hash); 3 refused (budget, conflicting operation, wrong state); 4 configuration or node error; 75 unresolved: the outcome is not known yet and the record stays open for reconciliation. `payer reconcile` maps a payment's outcome the same way as `pay` and `retry`; for several payments, the first of 75, 3 and 1 that applies to any of them, else 0. Arguments are checked before anything is recorded, so a usage error leaves no change behind.

## Limits

- Regtest only, three nodes, one route shape. Real networks add gossip delays, private channels, route hints, liquidity changing between attempts and nodes that do not report useful failures.
- The liquidity diagnosis sees only the sending node's channels. It cannot see other nodes' balances, and its sendable figure is an upper bound: LND also keeps a fee buffer for new HTLCs on channels it opened.
- A stream that goes silent is detected by TCP keepalive, which can take minutes. The service never treats that silence as a failure, only as a reason to reconnect.
- Reconciliation that ends without a terminal state (its deadline passes while LND still holds the payment) leaves the record unresolved; it must be run again. Production needs a supervisor that keeps doing so.
- If TrackPaymentV2 answers "not found" for a payment whose current submission has recorded HTLC attempts (for example after an operator deleted payments from LND), the record stays unresolved for an operator to decide.
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
