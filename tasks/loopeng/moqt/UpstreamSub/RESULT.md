# UpstreamSub.tla: TLC results (2026-10-05)

`java -cp tla2tools.jar tlc2.TLC -workers 1 -deadlock -config <cfg>
UpstreamSub.tla`; logs in `logs/`.

| Config | Constants | Result |
|---|---|---|
| `MC_main.cfg` | Subs={s1,s2,s3}, MaxGen=3, MaxPub=2 | **No error**: 11,326 states / 6,363 distinct, depth 27. Invariants `TypeOK`, `AnsweredOnce`, `AnswerMatchesPhase`, `NoOkBeforeUpstream`, `ActiveRidesUpstream`, `NoLeak`, `NoLeakOnClose`, `WaitHasUpstream`; liveness `EventuallyAnswered` |
| `MC_bug_NoCancel.cfg` | sweep never cancels an unwanted upstream | `NoLeak` violated (7 states: announce, subscribe, open, cancel) -- expected |
| `MC_bug_EarlyOk.cfg` | SUBSCRIBE_OK while upstream pending | `NoOkBeforeUpstream` violated (6 states) -- expected |
| `MC_reach_NoAggregatedOk.cfg` | witness | violated (8 states): two downstream subscriptions share one upstream |
| `MC_reach_NoStaleAnswer.cfg` | witness | violated (9 states): a cancelled generation's reply is still in flight while a new one is open |
| `MC_reach_NoUpErr.cfg` | witness | violated (6 states): upstream REQUEST_ERROR reaches a waiter |

Mapping to tests (`tests/app/moqtrun_upsub_test.c`): AnsweredOnce /
NoOkBeforeUpstream -> `upsub_ok_after_upstream`; aggregation ->
`upsub_two_share_one`; NoLeak -> `upsub_cancel_last_cancels_upstream`;
NoLeakOnClose -> `upsub_publisher_close`; UpErr -> `upsub_error_mapped`;
stale -> `upsub_stale_reply_ignored`; PubNs after Sub -> `upsub_rdv_then_ns`.
