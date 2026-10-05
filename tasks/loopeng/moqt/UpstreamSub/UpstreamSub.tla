---------------------------- MODULE UpstreamSub ----------------------------
(***************************************************************************)
(* MoQT relay: a downstream SUBSCRIBE that misses every PUBLISHed track    *)
(* but whose namespace a publisher announced (PUBLISH_NAMESPACE) is sent   *)
(* upstream; one upstream subscription is shared by every downstream      *)
(* subscriber of the Track (aggregation).                                  *)
(*                                                                         *)
(* Sources (tasks/specs/):                                                 *)
(*   18/19 9.4, 22 7.4  MUST have an Established upstream subscription     *)
(*                      before SUBSCRIBE_OK; MAY aggregate                 *)
(*   18/19 9.5, 22 7.6  MUST send SUBSCRIBE to the namespace publisher;    *)
(*                      a PUBLISH_NAMESPACE arriving later triggers it     *)
(*   18/19 5.1, 22 3.1  exactly one SUBSCRIBE_OK or REQUEST_ERROR          *)
(*   19 3.3.3, 22 6.4.2.3  cancel = RESET_STREAM / STOP_SENDING            *)
(*                                                                         *)
(* One Full Track Name, one publisher that may announce, leave and come   *)
(* back (a new session). The hub runs moqtrun_reqs_tick (here Sweep)      *)
(* atomically at the end of every dispatch: `dirty` makes every event     *)
(* wait for the sweep, so invariants marked "clean" are checked only      *)
(* where the implementation can be observed.                               *)
(*                                                                         *)
(* Each upstream SUBSCRIBE has a generation g (its request stream). The   *)
(* publisher may answer a generation the hub already cancelled; the hub   *)
(* ignores it (the stream id no longer matches an entry).                 *)
(*                                                                         *)
(* Rendezvous holds (RENDEZVOUS_TIMEOUT > 0) are Rendezvous.tla's; here   *)
(* every waiter is an rt = 0 SUBSCRIBE that only waits on the upstream.   *)
(*                                                                         *)
(* Mutations: BugNoCancel -- the sweep never cancels an upstream nobody   *)
(* wants; BugEarlyOk -- a SUBSCRIBE arriving while the upstream is still  *)
(* pending is answered SUBSCRIBE_OK at once.                               *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS Subs, MaxGen, MaxPub, BugNoCancel, BugEarlyOk

Phases == {"idle", "wait", "ok", "err", "gone", "done"}

VARIABLES
    ph,       \* downstream request state per subscriber
    ans,      \* answers (SUBSCRIBE_OK + REQUEST_ERROR) sent on s's stream
    act,      \* s holds an active subscription on the upstream track
    okEst,    \* ghost: the upstream was Established when s got SUBSCRIBE_OK
    upSt,     \* hub's upstream entry: none / pending / est
    gen,      \* generation of the current entry (0 = never opened)
    inflight, \* generations the publisher has not answered yet
    pub,      \* publisher session: none / ns (announced) / gone
    pubs,     \* publisher sessions so far (bounds re-announcing)
    dirty     \* an event ran; the end-of-dispatch sweep is owed

vars == <<ph, ans, act, okEst, upSt, gen, inflight, pub, pubs, dirty>>

Waiting  == {s \in Subs : ph[s] = "wait"}
Interest == Waiting # {} \/ \E s \in Subs : act[s]

TypeOK ==
    /\ ph \in [Subs -> Phases]
    /\ ans \in [Subs -> 0..2]
    /\ act \in [Subs -> BOOLEAN]
    /\ okEst \in [Subs -> BOOLEAN]
    /\ upSt \in {"none", "pending", "est"}
    /\ gen \in 0..MaxGen
    /\ inflight \subseteq 1..MaxGen
    /\ pub \in {"none", "ns", "gone"}
    /\ pubs \in 0..MaxPub
    /\ dirty \in BOOLEAN

Init ==
    /\ ph = [s \in Subs |-> "idle"]
    /\ ans = [s \in Subs |-> 0]
    /\ act = [s \in Subs |-> FALSE]
    /\ okEst = [s \in Subs |-> FALSE]
    /\ upSt = "none"
    /\ gen = 0
    /\ inflight = {}
    /\ pub = "none"
    /\ pubs = 0
    /\ dirty = FALSE

Answer(s, kind) ==
    /\ ph' = [ph EXCEPT ![s] = kind]
    /\ ans' = [ans EXCEPT ![s] = @ + 1]

(* ---------------- events (each followed by Sweep) ---------------- *)

\* Downstream SUBSCRIBE, no PUBLISHed track. Established upstream: OK now
\* (attach). Pending upstream, or an announcing publisher: wait (held in
\* hub->rdv with no deadline). Neither: DOES_NOT_EXIST now.
Sub(s) ==
    /\ ~dirty /\ ph[s] = "idle"
    /\ IF upSt = "est" \/ (BugEarlyOk /\ upSt = "pending")
         THEN /\ Answer(s, "ok")
              /\ act' = [act EXCEPT ![s] = TRUE]
              /\ okEst' = [okEst EXCEPT ![s] = (upSt = "est")]
         ELSE IF upSt = "pending" \/ pub = "ns"
           THEN /\ ph' = [ph EXCEPT ![s] = "wait"]
                /\ UNCHANGED <<ans, act, okEst>>
           ELSE /\ Answer(s, "err")
                /\ UNCHANGED <<act, okEst>>
    /\ dirty' = TRUE
    /\ UNCHANGED <<upSt, gen, inflight, pub, pubs>>

\* RESET_STREAM / STOP_SENDING on the downstream request stream, or the
\* subscriber's session closes: nothing more is sent to s.
Cancel(s) ==
    /\ ~dirty /\ ph[s] \in {"wait", "ok"}
    /\ ph' = [ph EXCEPT ![s] = "gone"]
    /\ act' = [act EXCEPT ![s] = FALSE]
    /\ dirty' = TRUE
    /\ UNCHANGED <<ans, okEst, upSt, gen, inflight, pub, pubs>>

\* A publisher session announces the namespace (PUBLISH_NAMESPACE accepted).
PubNs ==
    /\ ~dirty /\ pub # "ns" /\ pubs < MaxPub
    /\ pub' = "ns" /\ pubs' = pubs + 1
    /\ dirty' = TRUE
    /\ UNCHANGED <<ph, ans, act, okEst, upSt, gen, inflight>>

\* The publisher session closes: its entry goes with no io, the track ends
\* (PUBLISH_DONE to every downstream subscription); answers the old session
\* had not sent never come.
PubClose ==
    /\ ~dirty /\ pub = "ns"
    /\ pub' = "gone"
    /\ upSt' = "none"
    /\ inflight' = {}
    /\ act' = [s \in Subs |-> FALSE]
    /\ ph' = [s \in Subs |-> IF act[s] THEN "done" ELSE ph[s]]
    /\ dirty' = TRUE
    /\ UNCHANGED <<ans, okEst, gen, pubs>>

\* Publisher answers generation g. Only the current pending entry acts.
Live(g) == g = gen /\ upSt = "pending"

UpOk(g) ==
    /\ ~dirty /\ g \in inflight /\ pub = "ns"
    /\ inflight' = inflight \ {g}
    /\ IF Live(g)
         THEN /\ upSt' = "est"
              /\ ph' = [s \in Subs |-> IF ph[s] = "wait" THEN "ok" ELSE ph[s]]
              /\ ans' = [s \in Subs |-> IF ph[s] = "wait" THEN ans[s] + 1
                                                         ELSE ans[s]]
              /\ act' = [s \in Subs |-> act[s] \/ ph[s] = "wait"]
              /\ okEst' = [s \in Subs |-> okEst[s] \/ ph[s] = "wait"]
         ELSE UNCHANGED <<upSt, ph, ans, act, okEst>>
    /\ dirty' = TRUE
    /\ UNCHANGED <<gen, pub, pubs>>

\* REQUEST_ERROR upstream: every waiter gets REQUEST_ERROR (its code).
UpErr(g) ==
    /\ ~dirty /\ g \in inflight /\ pub = "ns"
    /\ inflight' = inflight \ {g}
    /\ IF Live(g)
         THEN /\ upSt' = "none"
              /\ ph' = [s \in Subs |-> IF ph[s] = "wait" THEN "err" ELSE ph[s]]
              /\ ans' = [s \in Subs |-> IF ph[s] = "wait" THEN ans[s] + 1
                                                         ELSE ans[s]]
         ELSE UNCHANGED <<upSt, ph, ans>>
    /\ dirty' = TRUE
    /\ UNCHANGED <<act, okEst, gen, pub, pubs>>

\* PUBLISH_DONE upstream: relayed to every downstream subscription; the
\* track retires and the entry ends.
UpDone ==
    /\ ~dirty /\ upSt = "est" /\ pub = "ns"
    /\ upSt' = "none"
    /\ act' = [s \in Subs |-> FALSE]
    /\ ph' = [s \in Subs |-> IF act[s] THEN "done" ELSE ph[s]]
    /\ dirty' = TRUE
    /\ UNCHANGED <<ans, okEst, gen, inflight, pub, pubs>>

(* ---------------- the end-of-dispatch sweep (moqtrun_up_sync) -------- *)
\* 1. an entry nobody wants is cancelled (pending: RESET; est: RESET and
\*    the track retires);
\* 2. waiters with no entry: a new upstream SUBSCRIBE if a publisher
\*    announces (and a stream can be opened), else REQUEST_ERROR now.
Unwanted == upSt # "none" /\ ~Interest /\ ~BugNoCancel

Sweep ==
    /\ dirty
    /\ LET st1  == IF Unwanted THEN "none" ELSE upSt
           open == st1 = "none" /\ Waiting # {} /\ pub = "ns" /\ gen < MaxGen
           fail == st1 = "none" /\ Waiting # {} /\ ~open
       IN /\ upSt' = IF open THEN "pending" ELSE st1
          /\ gen' = IF open THEN gen + 1 ELSE gen
          /\ inflight' = IF open THEN inflight \cup {gen + 1} ELSE inflight
          /\ ph' = [s \in Subs |-> IF fail /\ ph[s] = "wait" THEN "err"
                                    ELSE ph[s]]
          /\ ans' = [s \in Subs |-> IF fail /\ ph[s] = "wait" THEN ans[s] + 1
                                     ELSE ans[s]]
    /\ dirty' = FALSE
    /\ UNCHANGED <<act, okEst, pub, pubs>>

Next ==
    \/ \E s \in Subs : Sub(s) \/ Cancel(s)
    \/ PubNs \/ PubClose \/ UpDone
    \/ \E g \in 1..MaxGen : UpOk(g) \/ UpErr(g)
    \/ Sweep

Fairness ==
    /\ WF_vars(Sweep)
    /\ \A g \in 1..MaxGen : WF_vars(UpOk(g) \/ UpErr(g))

Spec == Init /\ [][Next]_vars /\ Fairness

(* ---------------- invariants ---------------- *)

\* Downstream answered at most once, never both kinds.
AnsweredOnce == \A s \in Subs : ans[s] <= 1

\* Answered iff in an answered phase (a cancel after OK keeps its one).
AnswerMatchesPhase ==
    \A s \in Subs :
        /\ ph[s] \in {"ok", "err", "done"} => ans[s] = 1
        /\ ph[s] \in {"idle", "wait"} => ans[s] = 0

\* Never SUBSCRIBE_OK before the upstream is Established (9.4 / 7.4).
NoOkBeforeUpstream == \A s \in Subs : ph[s] \in {"ok", "done"} => okEst[s]

\* An active downstream subscription always rides an Established upstream.
ActiveRidesUpstream == \A s \in Subs : act[s] => upSt = "est"

\* The upstream is cancelled once the last downstream leaves (clean states).
NoLeak == ~dirty => (upSt # "none" => Interest)

\* No upstream entry outlives the publisher session.
NoLeakOnClose == pub # "ns" => upSt = "none"

\* A waiter always has a pending upstream to wait on (clean states).
WaitHasUpstream == ~dirty => (Waiting # {} => upSt = "pending")

(* ---------------- liveness ---------------- *)
\* Every waiter is answered or cancels.
EventuallyAnswered == \A s \in Subs : ph[s] = "wait" ~> ph[s] # "wait"

(* ---------------- reachability witnesses (EXPECTED violated) ---------- *)
NoAggregatedOk == ~(\E a, b \in Subs : a # b /\ act[a] /\ act[b])
NoStaleAnswer == ~(gen = 2 /\ 1 \in inflight)
NoUpErr == \A s \in Subs : ~(ph[s] = "err" /\ gen > 0 /\ upSt = "none"
                             /\ pub = "ns")
=============================================================================
