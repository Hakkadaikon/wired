# Rendezvous.tla: TLC results (2026-10-05)

TLC2 2026.10.04 (rev 1813307), `-workers 1 -deadlock` (terminal states, where
every request is answered or cancelled and the clock has stopped, are expected
and are not errors). Logs are in `logs/`. Command:

```sh
java -cp <scratchpad>/tla2tools.jar tlc2.TLC -workers 1 -deadlock \
     -config <cfg> Rendezvous.tla
```

## Safety + liveness (expected: no error)

| Config | Constants | States generated / distinct | Depth | Time | Result |
|---|---|---|---|---|---|
| `MC_main.cfg` | Subs={s1,s2}, Pubs={p1,p2}, MaxRT=2, RelayMax=2, SubWindow=2, Cap=2 | 1,336,307 / 332,392 | 17 | 1m34s | **No error**: 10 invariants + `EventuallyAnswered` |
| `MC_tight.cfg` | same, RelayMax=1 (clamp below request), Cap=1 (table-full path) | 1,072,157 / 273,160 | 15 | 52s | **No error** |

Invariants checked: `TypeOK`, `AtMostOneAnswer`, `NoSilentDrop`,
`ResolveOnPublish`, `HeldHasDeadline`, `CorrectCode`, `ClampOK`,
`CapacityRespected`, `CancelClean`, `AnsweredNoUpstream`.
Liveness: `EventuallyAnswered`, i.e. every sent SUBSCRIBE ends answered or
cancelled. It holds under weak fairness of the relay's `Process`, the upstream
reply and `Tick`. Publishers and subscribers have no fairness.

## Mutation (expected: violation)

| Config | Mutation | Result |
|---|---|---|
| `MC_bug.cfg` | `BugFinDrops = TRUE`: a subscriber FIN on a held SUBSCRIBE ends the request without a reply. This mirrors `moqtrun_req_answered` (`q->kind && !q->live`) in moqtrun.c, which would FIN a held stream. | **`NoSilentDrop` violated**, depth 4: `Send(s1, rt=1)`, then `Process(s1)` gives held, then `Fin(s1)` gives gone, with no answer and no cancel. This becomes Gherkin scenario S7 in design.md. |

## Reachability witnesses (expected: violation, i.e. the path exists)

| Config | Witness | Result |
|---|---|---|
| `MC_reach_NoTimeoutAnswer.cfg` | a TIMEOUT answer happens | violated at depth 4 (reachable) |
| `MC_reach_NoLoadAnswer.cfg` (Cap=1) | an EXCESSIVE_LOAD answer happens | violated at depth 5 |
| `MC_reach_NoHeldThenOk.cfg` | a held request is later answered OK | violated at depth 4 |
| `MC_reach_NoUpstreamRetry.cfg` | a request is back to held while a namespace publisher exists (upstream refused) | violated at depth 5 |
| `MC_reach_NoTwoResolved.cfg` | both subscribers held, both resolved OK | violated at depth 6 |

So none of the safety results is vacuous. Every answer path the invariants talk
about is actually explored.

## What the model does NOT cover

- Object delivery and PUBLISH_DONE after SUBSCRIBE_OK. Those belong to gap G2
  in design.md, not to rendezvous.
- More than one simultaneous upstream SUBSCRIBE per held request. The draft
  says "each publisher". One is enough to expose the late-answer and expiry
  races, which is what `up = "stale"` models.
- REQUEST_UPDATE on a held stream. design.md §5.6 answers the hold first. It is
  sequential logic, so a plain TDD test covers it.
- Wall-clock granularity. A tick is abstract. In wired the expiry fires on the
  first `wired_moqt_tick` at or after the deadline, which is at most about 25 ms
  late (`SRVRUN_PTO_MS` poll cadence).
