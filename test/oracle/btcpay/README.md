# CP-034 independent BTCPay inventory

Supported source: BTCPay Server v2.4.4 at `2d5a0d8077bb33af080e949031da33d84b80638d`,
whose project references Lightning.All 1.7.8. The independently downloaded official
NuGet package references Lightning.LND 1.7.2; that package's repository metadata
pins `62164e9394295bb27ebd06b769c6038f9277fb37`. Both package hashes are recorded.
The committed nuspecs and source snapshots preserve this chain without credentials.

All 16 methods reachable through that LndClient interface are included, including
streaming calls, ConnectPeer's helper and PendingChannels' channel-opening failure
branch. Generated Swagger methods that this client never invokes are outside this
support claim. No exposed client operation is excluded to lower the grade.

`manifest.json` gives immutable URLs, line locations, exact source excerpts, Git
blob identities, REST selectors and permissions from LND v0.21.4-beta's immutable
revision `390b2d2b7bdcc335c183962e483f5daeceb8f0e7`. These independently parsed maps
agree with the existing committed ListPermissions snapshot. No snapshot update is
needed. The exact permission set is the sorted `uri:` form of each listed method;
OpenChannelSync and SendPaymentV2 determine the SPEND grade.

Native lncli covers 14 methods. Its pinned source has no SubscribeInvoices RPC,
and openchannel uses OpenChannel rather than OpenChannelSync. The command source
inventory records this limitation. The approved independent oracle uses the pinned
LND fixture's TLS-verified REST bindings for OpenChannelSync (`POST /v1/channels`)
and SubscribeInvoices (`GET /v1/invoices/subscribe`), retaining native lncli for
the other required methods and the denied unrelated-call control. Neither method
is omitted. OpenChannelSync must demonstrate passed authorization against an authorized
control using the same request. SubscribeInvoices must observe an actual fixture
invoice event or another documented affirmative authorization result. Parse
failures, an open socket or unexplained timeouts do not establish acceptance.

Existing requirement assertions reused without changes:

| CP-034 requirement | Existing independent assertion |
|---|---|
| Unknown and mixed preset refusals before LND | CP-023/B1 unknown preset, preset with permissions, preset with URI |
| Unassessed and unallowed ADMIN refusals | CP-023/B3 unknown entity/URI/action, admin without consent, admin with unassessed permission |
| No external-permission flag | CP-022/B2 exact wire body |
| B1–B16 failures, final verification and cleanup | CP-023/B1–B9; CP-025/B3 numbered failure cases |
| Windows current-user ACL and best-effort warning | CP-023/B7 in test/cp023-acl.windows-fs.test.ts |
| Fresh bounded root IDs | CP-022/B3; CP-025/B5 |

New behavior cases use the existing injected bake helper; injection does not prove
LND authorization. Only independent live probes can do that. The live tests share
one fixture bake and scan only their own temporary outputs and sentinels. They run
with the other oracle tests against the shared regtest fixture.

`test/helpers/cp034-capture-source.mjs` reproduces the capture using the pinned
official sources and the downloaded official packages plus LND tree JSON under
`test/.tmp/cp034/source/`. It never contacts LND.
