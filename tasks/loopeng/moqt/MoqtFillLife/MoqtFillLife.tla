--------------------------- MODULE MoqtFillLife ---------------------------
(***************************************************************************)
(* Ledger 7-1 (b): the draft-22 fill fetch lifecycle (ledger item 4-6).    *)
(*                                                                         *)
(* One draft-22 subscriber session, a set of subscriptions on one track    *)
(* whose Largest Object is in group LG, served by the wired hub from its   *)
(* cache. Every SUBSCRIBE (and at most MaxUpd REQUEST_UPDATEs per          *)
(* subscription) may carry FILL_PARAMETERS.                                *)
(*                                                                         *)
(* Spec (draft-ietf-moq-transport-22):                                     *)
(*  3.4    fill range = LOCATION_FILTER inside FILL_PARAMETERS, or the     *)
(*         subscription's Location filter if it is omitted, evaluated with *)
(*         the Fetch rules of 9.20.9 (never past Largest Object); no       *)
(*         subscription filter or a zero-length/0x00 filter = whole track. *)
(*         Empty range or start after Largest: no fill fetch stream.       *)
(*         FETCH_HEADER Request ID = SUBSCRIBE's or REQUEST_UPDATE's.      *)
(*  3.4.1  opened only while not paused; resuming opens none; cancelled    *)
(*         subscription -> publisher MUST reset open fill streams; failure *)
(*         is signalled by a reset -- "it MUST open a fill fetch stream    *)
(*         and reset it immediately after the FETCH_HEADER if necessary";  *)
(*         completion = FIN.                                               *)
(*  9.9    PUBLISH_DONE Stream Count includes fill fetch streams.          *)
(*  9.20.15 FILL_PARAMETERS value = Parameters "as if for a separate       *)
(*         message"; 9.20: an unknown/invalid parameter closes the session *)
(*         with PROTOCOL_VIOLATION.                                        *)
(*                                                                         *)
(* Implementation transcribed from moqtrun.c (main tree, 2026-10-05):      *)
(*  2332 moqtrun_fill_rl        omitted LOCATION_FILTER == 0x00 == all     *)
(*  2342 moqtrun_fill_open      resolve; fetches[] slot, else fetch_waits  *)
(*  2289 moqtrun_fill_wait_put  both tables full -> return (dropped)       *)
(*  2372 moqtrun_fill_from_param malformed value -> return (no close)      *)
(*  1396-1397 SUBSCRIBE_OK is queued BEFORE moqtrun_fill_on_subscribe      *)
(*  2821-2822 REQUEST_OK is queued BEFORE moqtrun_fill_on_update           *)
(*  1786 moqtrun_fetch_open     refused open retried on later ticks        *)
(*  2063 moqtrun_fetches_cancel cancel resets open, frees held/waiting     *)
(*  2002 moqtrun_fill_upstream_gone_one  failed: open->reset, held->reset  *)
(*       when granted                                                       *)
(*  6790 moqtrun_sub_done       PUBLISH_DONE deferred while a fill is held *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
  Subs,        \* subscriptions (all on one draft-22 session)
  LG,          \* group of the track's Largest Object
  SubFilters,  \* subset of {"none", "next", "abs1"}
  FillFilters, \* subset of {"absent","omitted","none00","abs0","absPast",
               \*            "malformed"}; "absent" = no FILL_PARAMETERS
  MaxUpd,      \* REQUEST_UPDATEs per subscription
  Slots,       \* fetches[] capacity (WIRED_MOQTRUN_MAX_FETCHES, scaled)
  Waits        \* fetch_waits[] capacity (scaled)

Empty == <<1, 0>>                         \* lo > hi: empty range
IsEmpty(r) == r[1] > r[2]

\* 9.20.9 evaluated as a Fetch against Largest (group granularity).
FetchEval(f) ==
  CASE f = "none"    -> <<0, LG>>
    [] f = "next"    -> Empty               \* Next Object: past Largest
    [] f = "abs1"    -> <<1, LG>>
    [] f = "abs0"    -> <<0, LG>>
    [] f = "absPast" -> Empty               \* start after Largest
    [] f = "none00"  -> <<0, LG>>

\* draft-22 3.4: omitted -> the subscription's filter.
SpecRange(sf, ff) == IF ff = "omitted" THEN FetchEval(sf) ELSE FetchEval(ff)

\* moqtrun_fill_rl: has_filter 0 for both "omitted" and 0x00.
ImplRange(sf, ff) == IF ff = "omitted" THEN <<0, LG>> ELSE FetchEval(ff)

FillSt == {"none", "wait", "held", "open", "fin", "reset", "dropped",
           "freed"}

VARIABLES
  sub,      \* [Subs -> "idle"|"live"|"cancelled"|"ended"]
  sflt,     \* subscription Location filter
  fwd,      \* FORWARD state (0 = paused)
  nUpd,     \* REQUEST_UPDATEs sent
  reqs,     \* set of fill requests (records)
  failed,   \* upstream gone: every live fill must end in reset
  closed,   \* session closed with PROTOCOL_VIOLATION
  doneSent, \* [Subs -> BOOLEAN] PUBLISH_DONE emitted
  doneCnt   \* [Subs -> Nat] its Stream Count (fill part)

vars == <<sub, sflt, fwd, nUpd, reqs, failed, closed, doneSent, doneCnt>>

\* A fill request record. id = <<sub, n>>: n = 0 SUBSCRIBE, n > 0 UPDATE n
\* (its FETCH_HEADER Request ID). paused = FILL_PARAMETERS carried while
\* FORWARD 0.
Rec(s, n, ff, sf, paused, st) ==
  [owner |-> s, n |-> n, ff |-> ff,
   spec |-> IF ff = "malformed" THEN Empty ELSE SpecRange(sf, ff),
   impl |-> IF ff = "malformed" THEN Empty ELSE ImplRange(sf, ff),
   paused |-> paused, st |-> st]

InTable(st) == st \in {"held", "open"}
Used == Cardinality({r \in reqs : InTable(r.st)})
Waiting == Cardinality({r \in reqs : r.st = "wait"})

\* moqtrun_fill_open + moqtrun_fill_wait_put: where a new fill lands.
Place(range) ==
  IF IsEmpty(range) THEN "none"
  ELSE IF Used < Slots THEN "held"
  ELSE IF Waiting < Waits THEN "wait"
  ELSE "dropped"

\* What the hub does with one FILL_PARAMETERS (or none).
FillReq(s, n, ff, sf, f) ==
  IF ff = "absent" THEN reqs
  ELSE IF ff = "malformed" THEN reqs \cup {Rec(s, n, ff, sf, f = 0, "none")}
  ELSE IF f = 0 THEN reqs \cup {Rec(s, n, ff, sf, TRUE, "none")}
  ELSE reqs \cup {Rec(s, n, ff, sf, FALSE, Place(ImplRange(sf, ff)))}

TypeOK ==
  /\ sub \in [Subs -> {"idle", "live", "cancelled", "ended"}]
  /\ \A r \in reqs : r.st \in FillSt
  /\ Used <= Slots /\ Waiting <= Waits

Init ==
  /\ sub = [s \in Subs |-> "idle"]
  /\ sflt = [s \in Subs |-> "none"]
  /\ fwd = [s \in Subs |-> 1]
  /\ nUpd = [s \in Subs |-> 0]
  /\ reqs = {}
  /\ failed = FALSE
  /\ closed = FALSE
  /\ doneSent = [s \in Subs |-> FALSE]
  /\ doneCnt = [s \in Subs |-> 0]

\* SUBSCRIBE accepted: SUBSCRIBE_OK queued, then the fill (1396-1397).
Subscribe(s) ==
  /\ ~closed /\ ~failed
  /\ sub[s] = "idle"
  /\ \E sf \in SubFilters, ff \in FillFilters, f \in {0, 1} :
       /\ sub' = [sub EXCEPT ![s] = "live"]
       /\ sflt' = [sflt EXCEPT ![s] = sf]
       /\ fwd' = [fwd EXCEPT ![s] = f]
       /\ reqs' = FillReq(s, 0, ff, sf, f)
  /\ UNCHANGED <<nUpd, failed, closed, doneSent, doneCnt>>

\* REQUEST_UPDATE (may resume / pause; may carry FILL_PARAMETERS).
Update(s) ==
  /\ ~closed
  /\ sub[s] = "live"
  /\ nUpd[s] < MaxUpd
  /\ \E ff \in FillFilters, f \in {0, 1} :
       /\ fwd' = [fwd EXCEPT ![s] = f]
       /\ reqs' = FillReq(s, nUpd[s] + 1, ff, sflt[s], f)
  /\ nUpd' = [nUpd EXCEPT ![s] = @ + 1]
  /\ UNCHANGED <<sub, sflt, failed, closed, doneSent, doneCnt>>

\* The transport grants the uni stream: FETCH_HEADER goes out; a failed
\* fill is reset at once (moqtrun_fetch_fail_due).
OpenFill(r) ==
  /\ ~closed
  /\ r \in reqs /\ r.st = "held"
  /\ reqs' = (reqs \ {r}) \cup {[r EXCEPT !.st = IF failed THEN "reset"
                                               ELSE "open"]}
  /\ UNCHANGED <<sub, sflt, fwd, nUpd, failed, closed, doneSent, doneCnt>>

\* A fetches[] slot came free: a waiting fill takes it.
WaitConvert(r) ==
  /\ ~closed
  /\ r \in reqs /\ r.st = "wait" /\ Used < Slots
  /\ reqs' = (reqs \ {r}) \cup {[r EXCEPT !.st = "held"]}
  /\ UNCHANGED <<sub, sflt, fwd, nUpd, failed, closed, doneSent, doneCnt>>

\* Every object of the fill range delivered: FIN.
Serve(r) ==
  /\ ~closed
  /\ r \in reqs /\ r.st = "open"
  /\ reqs' = (reqs \ {r}) \cup {[r EXCEPT !.st = "fin"]}
  /\ UNCHANGED <<sub, sflt, fwd, nUpd, failed, closed, doneSent, doneCnt>>

\* Subscriber STOP_SENDING on one fill (3.4.1): only that fill ends.
StopFill(r) ==
  /\ ~closed
  /\ r \in reqs /\ r.st = "open"
  /\ reqs' = (reqs \ {r}) \cup {[r EXCEPT !.st = "reset"]}
  /\ UNCHANGED <<sub, sflt, fwd, nUpd, failed, closed, doneSent, doneCnt>>

\* Subscription cancelled (request stream reset, 6.4.2.3): open fills
\* reset CANCELLED, unopened ones freed (moqtrun_fetches_cancel).
Cancel(s) ==
  /\ ~closed
  /\ sub[s] = "live"
  /\ sub' = [sub EXCEPT ![s] = "cancelled"]
  /\ reqs' = {IF r.owner = s
                THEN [r EXCEPT !.st = CASE r.st = "open" -> "reset"
                                        [] r.st \in {"held", "wait"} -> "freed"
                                        [] OTHER -> r.st]
                ELSE r : r \in reqs}
  /\ UNCHANGED <<sflt, fwd, nUpd, failed, closed, doneSent, doneCnt>>

\* Upstream publisher session gone (wired_moqt_on_session_close):
\* PUBLISH_DONE TRACK_ENDED to every live subscription, open fills reset
\* INTERNAL_ERROR, held/waiting fills marked failed (reset when opened).
UpstreamGone ==
  /\ ~closed /\ ~failed
  /\ failed' = TRUE
  /\ sub' = [s \in Subs |-> IF sub[s] = "live" THEN "ended" ELSE sub[s]]
  /\ reqs' = {IF r.st = "open" THEN [r EXCEPT !.st = "reset"] ELSE r
              : r \in reqs}
  /\ UNCHANGED <<sflt, fwd, nUpd, closed, doneSent, doneCnt>>

Opened(s) == {r \in reqs : r.owner = s /\ r.st \in {"open", "fin", "reset"}}
HeldFor(s) == {r \in reqs : r.owner = s /\ r.st \in {"held", "wait"}}

\* PUBLISH_DONE once no fill of s waits for a stream (moqtrun_sub_done /
\* moqtrun_fill_opened). Its fill Stream Count was incremented at accept
\* time for every held/waiting/opened fill (2306, 2357).
EmitDone(s) ==
  /\ ~closed
  /\ sub[s] = "ended" /\ ~doneSent[s]
  /\ HeldFor(s) = {}
  /\ doneSent' = [doneSent EXCEPT ![s] = TRUE]
  /\ doneCnt' = [doneCnt EXCEPT ![s] = Cardinality(Opened(s))]
  /\ UNCHANGED <<sub, sflt, fwd, nUpd, reqs, failed, closed>>

Next ==
  \/ \E s \in Subs : Subscribe(s) \/ Update(s) \/ Cancel(s) \/ EmitDone(s)
  \/ \E r \in reqs : OpenFill(r) \/ WaitConvert(r) \/ Serve(r) \/ StopFill(r)
  \/ UpstreamGone

Fair ==
  /\ \A s \in Subs : WF_vars(EmitDone(s))
  /\ WF_vars(\E r \in reqs : OpenFill(r))
  /\ WF_vars(\E r \in reqs : WaitConvert(r))
  /\ WF_vars(\E r \in reqs : Serve(r))

Spec == Init /\ [][Next]_vars /\ Fair

(***************************** safety ************************************)

\* 3.4: the range the hub serves is the spec's fill range, and a stream
\* is opened exactly when that range is non-empty (and not paused).
FillRangeSpec ==
  \A r \in reqs : (r.ff # "malformed" /\ ~r.paused) =>
     /\ r.impl = r.spec
     /\ (r.st # "none") <=> ~IsEmpty(r.spec)

\* 3.4.1: FILL_PARAMETERS while paused opens nothing.
PausedNoFill == \A r \in reqs : r.paused => r.st = "none"

\* 3.4.1: an accepted fill is never silently dropped -- it ends in FIN or
\* reset (or, unopened, with its subscription's cancel).
NoSilentDrop == \A r \in reqs : r.st # "dropped"

\* 3.4.1: a cancelled subscription has no live fill stream left.
CancelResets ==
  \A r \in reqs : sub[r.owner] = "cancelled" =>
     r.st \notin {"open", "held", "wait"}

\* 9.20 / 9.20.15: a malformed FILL_PARAMETERS closes the session.
MalformedCloses ==
  \A r \in reqs : r.ff = "malformed" => closed

\* 9.9: Stream Count counts every fill stream opened, and PUBLISH_DONE
\* is never sent while a counted fill is still unopened.
DoneCountExact ==
  \A s \in Subs : doneSent[s] =>
     /\ doneCnt[s] = Cardinality(Opened(s))
     /\ HeldFor(s) = {}

Safety == TypeOK /\ FillRangeSpec /\ PausedNoFill /\ NoSilentDrop
          /\ CancelResets /\ MalformedCloses /\ DoneCountExact

(***************************** liveness **********************************)

\* Every fill the hub took on ends: FIN, reset, or freed by a cancel.
FillsEnd ==
  \A s \in Subs, n \in 0..MaxUpd :
     (\E r \in reqs : r.owner = s /\ r.n = n /\ r.st \in {"held", "wait"})
       ~> (\A r \in reqs : (r.owner = s /\ r.n = n) =>
                              r.st \in {"open", "fin", "reset", "freed"})

\* An ended subscription's PUBLISH_DONE eventually goes out.
DoneEventually ==
  \A s \in Subs : (sub[s] = "ended") ~> doneSent[s]
=============================================================================
