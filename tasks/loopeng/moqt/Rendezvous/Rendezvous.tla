----------------------------- MODULE Rendezvous -----------------------------
(***************************************************************************)
(* MoQT relay rendezvous: a SUBSCRIBE for a Track with no current         *)
(* publisher, held by the relay up to its RENDEZVOUS_TIMEOUT.             *)
(*                                                                         *)
(* Sources (texts in tasks/specs/):                                        *)
(*   draft-ietf-moq-transport-18 10.2.6, 19 10.2.6, 22 9.20.6  (the rule)  *)
(*   18/19 5.1, 22 3.1   exactly one SUBSCRIBE_OK or REQUEST_ERROR         *)
(*   18/19 9.4, 22 7.4   no SUBSCRIBE_OK before an Established upstream    *)
(*   18/19 9.5, 22 7.6   PUBLISH resolves a held SUBSCRIBE; a              *)
(*                       PUBLISH_NAMESPACE triggers an upstream SUBSCRIBE  *)
(*   18 3.3.2, 19 3.3.3, 22 6.4.2.3   cancel = RESET_STREAM/STOP_SENDING   *)
(*   19 3.3.2, 22 6.4.2.2             FIN is NOT a cancellation            *)
(*                                                                         *)
(* One Full Track Name. Subscribers s each send at most one SUBSCRIBE      *)
(* (on its own request stream) carrying RENDEZVOUS_TIMEOUT rt[s]           *)
(* (0 = absent or explicit 0, same meaning). Publishers p arrive with a    *)
(* PUBLISH of the track ("track") or a PUBLISH_NAMESPACE covering it       *)
(* ("ns"), and may leave ("gone").                                         *)
(*                                                                         *)
(* Abstractions: at most one upstream SUBSCRIBE per held request at a time *)
(* (the draft says "each publisher"; one is enough to expose the races);   *)
(* object delivery and PUBLISH_DONE after SUBSCRIBE_OK are out of scope.   *)
(*                                                                         *)
(* BugFinDrops = TRUE injects the wired-specific hazard: moqtrun_req_settle *)
(* reads kind && !live as "answered", so a held SUBSCRIBE whose subscriber *)
(* FINned its side would be ended without any reply.                       *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Subs,        \* subscriber request streams (one SUBSCRIBE each)
    Pubs,        \* publishers
    MaxRT,       \* largest RENDEZVOUS_TIMEOUT a subscriber asks for (ticks)
    RelayMax,    \* relay clamp (MAY use a shorter timeout)
    SubWindow,   \* SUBSCRIBEs are sent while now < SubWindow
    Cap,         \* relay pending-table capacity
    BugFinDrops  \* TRUE: inject the FIN-ends-held-request bug

NoDl == -1       \* "no rendezvous deadline"

Phases == {"idle", "sent", "held", "upq", "ok", "err", "gone"}
Codes  == {"none", "DNE", "TIMEOUT", "LOAD"}
Pending == {"held", "upq"}

VARIABLES
    now,        \* relay clock, in ticks
    phase,      \* relay-side state of each subscriber's request
    rt,         \* requested RENDEZVOUS_TIMEOUT
    dl,         \* rendezvous deadline (NoDl when none)
    nOk,        \* SUBSCRIBE_OK messages sent on s's stream
    nErr,       \* REQUEST_ERROR messages sent on s's stream
    code,       \* error code of the REQUEST_ERROR, "none" otherwise
    ansAt,      \* clock when the answer went out (-1 before)
    fin,        \* subscriber FINned its side (half-close, not a cancel)
    cancelled,  \* subscriber reset the stream / closed its session
    up,         \* hub-originated upstream SUBSCRIBE: none/inflight/stale
    pub         \* publisher state: none/track/ns/gone

vars == <<now, phase, rt, dl, nOk, nErr, code, ansAt, fin, cancelled, up, pub>>

Min(a, b) == IF a < b THEN a ELSE b
MaxNow == SubWindow + 2 * RelayMax

\* Rendezvous holds occupying the relay's pending table (a request with no
\* RENDEZVOUS_TIMEOUT forwarded upstream is ordinary relaying, not a hold).
PendingSet == {s \in Subs : phase[s] \in Pending /\ dl[s] # NoDl}
TrackLive  == \E p \in Pubs : pub[p] = "track"
NsLive     == \E p \in Pubs : pub[p] = "ns"
Deadline(s) == IF rt[s] > 0 THEN now + Min(rt[s], RelayMax) ELSE NoDl

TypeOK ==
    /\ now \in 0..MaxNow
    /\ phase \in [Subs -> Phases]
    /\ rt \in [Subs -> 0..MaxRT]
    /\ dl \in [Subs -> {NoDl} \cup 0..MaxNow]
    /\ nOk \in [Subs -> 0..2]
    /\ nErr \in [Subs -> 0..2]
    /\ code \in [Subs -> Codes]
    /\ ansAt \in [Subs -> -1..MaxNow]
    /\ fin \in [Subs -> BOOLEAN]
    /\ cancelled \in [Subs -> BOOLEAN]
    /\ up \in [Subs -> {"none", "inflight", "stale"}]
    /\ pub \in [Pubs -> {"none", "track", "ns", "gone"}]

Init ==
    /\ now = 0
    /\ phase = [s \in Subs |-> "idle"]
    /\ rt = [s \in Subs |-> 0]
    /\ dl = [s \in Subs |-> NoDl]
    /\ nOk = [s \in Subs |-> 0]
    /\ nErr = [s \in Subs |-> 0]
    /\ code = [s \in Subs |-> "none"]
    /\ ansAt = [s \in Subs |-> -1]
    /\ fin = [s \in Subs |-> FALSE]
    /\ cancelled = [s \in Subs |-> FALSE]
    /\ up = [s \in Subs |-> "none"]
    /\ pub = [p \in Pubs |-> "none"]

(* ---------------- subscriber side ---------------- *)

\* SUBSCRIBE leaves the subscriber with RENDEZVOUS_TIMEOUT t.
Send(s, t) ==
    /\ phase[s] = "idle" /\ now < SubWindow
    /\ phase' = [phase EXCEPT ![s] = "sent"]
    /\ rt' = [rt EXCEPT ![s] = t]
    /\ UNCHANGED <<now, dl, nOk, nErr, code, ansAt, fin, cancelled, up, pub>>

\* Subscriber FINs its sending side right after SUBSCRIBE (19 3.3.2: MAY,
\* not a cancellation). With BugFinDrops the hub ends a held request.
Fin(s) ==
    /\ phase[s] \in {"sent", "held", "upq"} /\ ~fin[s]
    /\ fin' = [fin EXCEPT ![s] = TRUE]
    /\ IF BugFinDrops /\ phase[s] \in Pending
         THEN /\ phase' = [phase EXCEPT ![s] = "gone"]
              /\ up' = [up EXCEPT ![s] = IF @ = "inflight" THEN "stale" ELSE @]
         ELSE UNCHANGED <<phase, up>>
    /\ UNCHANGED <<now, rt, dl, nOk, nErr, code, ansAt, cancelled, pub>>

\* RESET_STREAM / STOP_SENDING on the request stream, or the subscriber's
\* session closes: the request is cancelled, nothing more is sent on it,
\* and an upstream SUBSCRIBE made for it is cancelled too.
Cancel(s) ==
    /\ phase[s] \in {"sent", "held", "upq"}
    /\ phase' = [phase EXCEPT ![s] = "gone"]
    /\ cancelled' = [cancelled EXCEPT ![s] = TRUE]
    /\ up' = [up EXCEPT ![s] = IF @ = "inflight" THEN "stale" ELSE @]
    /\ UNCHANGED <<now, rt, dl, nOk, nErr, code, ansAt, fin, pub>>

(* ---------------- relay side ---------------- *)

\* The relay handles the SUBSCRIBE.
Process(s) ==
    /\ phase[s] = "sent"
    /\ CASE TrackLive ->
              /\ phase' = [phase EXCEPT ![s] = "ok"]
              /\ nOk' = [nOk EXCEPT ![s] = @ + 1]
              /\ ansAt' = [ansAt EXCEPT ![s] = now]
              /\ UNCHANGED <<dl, nErr, code, up>>
         [] ~TrackLive /\ (rt[s] = 0 \/ Cardinality(PendingSet) < Cap) /\ NsLive ->
              \* publisher available via PUBLISH_NAMESPACE: subscribe upstream
              /\ phase' = [phase EXCEPT ![s] = "upq"]
              /\ dl' = [dl EXCEPT ![s] = Deadline(s)]
              /\ up' = [up EXCEPT ![s] = "inflight"]
              /\ UNCHANGED <<nOk, nErr, code, ansAt>>
         [] ~TrackLive /\ ~NsLive /\ rt[s] = 0 ->
              \* 0 / absent: MUST answer DOES_NOT_EXIST immediately
              /\ phase' = [phase EXCEPT ![s] = "err"]
              /\ nErr' = [nErr EXCEPT ![s] = @ + 1]
              /\ code' = [code EXCEPT ![s] = "DNE"]
              /\ ansAt' = [ansAt EXCEPT ![s] = now]
              /\ UNCHANGED <<dl, nOk, up>>
         [] ~TrackLive /\ rt[s] > 0 /\ Cardinality(PendingSet) >= Cap ->
              \* table full: explicit refusal, never a silent drop
              /\ phase' = [phase EXCEPT ![s] = "err"]
              /\ nErr' = [nErr EXCEPT ![s] = @ + 1]
              /\ code' = [code EXCEPT ![s] = "LOAD"]
              /\ ansAt' = [ansAt EXCEPT ![s] = now]
              /\ UNCHANGED <<dl, nOk, up>>
         [] ~TrackLive /\ ~NsLive /\ rt[s] > 0 /\ Cardinality(PendingSet) < Cap ->
              \* hold it
              /\ phase' = [phase EXCEPT ![s] = "held"]
              /\ dl' = [dl EXCEPT ![s] = Deadline(s)]
              /\ UNCHANGED <<nOk, nErr, code, ansAt, up>>
    /\ UNCHANGED <<now, rt, fin, cancelled, pub>>

\* PUBLISH of the track: every held/upstream-pending request proceeds
\* (18 9.5 MUST proceed with the SUBSCRIBE). An upstream SUBSCRIBE still in
\* flight for it becomes stale (its late answer is ignored).
Publish(p) ==
    /\ pub[p] = "none"
    /\ pub' = [pub EXCEPT ![p] = "track"]
    /\ phase' = [s \in Subs |-> IF phase[s] \in Pending THEN "ok" ELSE phase[s]]
    /\ nOk' = [s \in Subs |-> IF phase[s] \in Pending THEN nOk[s] + 1 ELSE nOk[s]]
    /\ ansAt' = [s \in Subs |-> IF phase[s] \in Pending THEN now ELSE ansAt[s]]
    /\ up' = [s \in Subs |-> IF phase[s] = "upq" /\ up[s] = "inflight"
                              THEN "stale" ELSE up[s]]
    /\ UNCHANGED <<now, rt, dl, nErr, code, fin, cancelled>>

\* PUBLISH_NAMESPACE covering the track: every held request gets an
\* upstream SUBSCRIBE (18 9.5 / 22 7.6 MUST send a SUBSCRIBE).
PublishNs(p) ==
    /\ pub[p] = "none"
    /\ pub' = [pub EXCEPT ![p] = "ns"]
    /\ phase' = [s \in Subs |-> IF phase[s] = "held" THEN "upq" ELSE phase[s]]
    /\ up' = [s \in Subs |-> IF phase[s] = "held" THEN "inflight" ELSE up[s]]
    /\ UNCHANGED <<now, rt, dl, nOk, nErr, code, ansAt, fin, cancelled>>

\* Publisher withdraws (PUBLISH cancelled, namespace withdrawn, or its
\* session closed). Already-answered subscriptions are not modelled further.
Leave(p) ==
    /\ pub[p] \in {"track", "ns"}
    /\ pub' = [pub EXCEPT ![p] = "gone"]
    /\ UNCHANGED <<now, phase, rt, dl, nOk, nErr, code, ansAt, fin, cancelled, up>>

\* The upstream publisher answers the hub's SUBSCRIBE.
UpOk(s) ==
    /\ up[s] \in {"inflight", "stale"}
    /\ up' = [up EXCEPT ![s] = "none"]
    /\ IF up[s] = "inflight" /\ phase[s] = "upq"
         THEN /\ phase' = [phase EXCEPT ![s] = "ok"]
              /\ nOk' = [nOk EXCEPT ![s] = @ + 1]
              /\ ansAt' = [ansAt EXCEPT ![s] = now]
         ELSE UNCHANGED <<phase, nOk, ansAt>>
    /\ UNCHANGED <<now, rt, dl, nErr, code, fin, cancelled, pub>>

UpErr(s) ==
    /\ up[s] \in {"inflight", "stale"}
    /\ up' = [up EXCEPT ![s] = "none"]
    /\ IF up[s] = "inflight" /\ phase[s] = "upq"
         THEN IF dl[s] = NoDl
                THEN \* not a rendezvous: the refusal is the answer
                     /\ phase' = [phase EXCEPT ![s] = "err"]
                     /\ nErr' = [nErr EXCEPT ![s] = @ + 1]
                     /\ code' = [code EXCEPT ![s] = "DNE"]
                     /\ ansAt' = [ansAt EXCEPT ![s] = now]
                ELSE \* keep waiting for another publisher until dl
                     /\ phase' = [phase EXCEPT ![s] = "held"]
                     /\ UNCHANGED <<nErr, code, ansAt>>
         ELSE UNCHANGED <<phase, nErr, code, ansAt>>
    /\ UNCHANGED <<now, rt, dl, nOk, fin, cancelled, pub>>

\* The clock advances; every pending request whose deadline has come is
\* answered REQUEST_ERROR TIMEOUT in the same step (wired_moqt_tick).
Due(s, t) == phase[s] \in Pending /\ dl[s] # NoDl /\ dl[s] <= t

Tick ==
    /\ \/ now < SubWindow
       \/ \E s \in Subs : phase[s] \in Pending /\ dl[s] # NoDl /\ dl[s] > now
    /\ now < MaxNow
    /\ now' = now + 1
    /\ phase' = [s \in Subs |-> IF Due(s, now + 1) THEN "err" ELSE phase[s]]
    /\ nErr' = [s \in Subs |-> IF Due(s, now + 1) THEN nErr[s] + 1 ELSE nErr[s]]
    /\ code' = [s \in Subs |-> IF Due(s, now + 1) THEN "TIMEOUT" ELSE code[s]]
    /\ ansAt' = [s \in Subs |-> IF Due(s, now + 1) THEN now + 1 ELSE ansAt[s]]
    /\ up' = [s \in Subs |-> IF Due(s, now + 1) /\ up[s] = "inflight"
                              THEN "stale" ELSE up[s]]
    /\ UNCHANGED <<rt, dl, nOk, fin, cancelled, pub>>

Next ==
    \/ \E s \in Subs, t \in 0..MaxRT : Send(s, t)
    \/ \E s \in Subs : Fin(s) \/ Cancel(s) \/ Process(s) \/ UpOk(s) \/ UpErr(s)
    \/ \E p \in Pubs : Publish(p) \/ PublishNs(p) \/ Leave(p)
    \/ Tick

\* The relay is fair; publishers and subscribers are free to never act.
Fairness ==
    /\ \A s \in Subs : WF_vars(Process(s))
    /\ \A s \in Subs : WF_vars(UpOk(s) \/ UpErr(s))
    /\ WF_vars(Tick)

Spec == Init /\ [][Next]_vars /\ Fairness

(* ---------------- invariants ---------------- *)

\* Exactly-once: at most one answer, never both kinds (5.1 / 3.1).
AtMostOneAnswer == \A s \in Subs : nOk[s] + nErr[s] <= 1

\* Never silently dropped: a request leaves the pending states only by an
\* answer or by the subscriber's own cancellation, and a cancelled request
\* is never answered afterwards.
NoSilentDrop ==
    \A s \in Subs :
        /\ phase[s] \in {"ok", "err"} => nOk[s] + nErr[s] = 1
        /\ phase[s] = "gone" => cancelled[s]
        /\ cancelled[s] => nOk[s] + nErr[s] = 0

\* Resolves on arrival: nothing stays held while the track is published.
ResolveOnPublish == TrackLive => \A s \in Subs : phase[s] # "held"

\* A held request always had a non-zero timeout and a deadline.
HeldHasDeadline ==
    \A s \in Subs : phase[s] = "held" => rt[s] > 0 /\ dl[s] # NoDl

\* Error codes match the rule that produced them.
CorrectCode ==
    \A s \in Subs :
        /\ code[s] = "TIMEOUT" => rt[s] > 0 /\ dl[s] # NoDl /\ ansAt[s] >= dl[s]
        /\ code[s] = "LOAD" => rt[s] > 0
        /\ (code[s] = "DNE" /\ dl[s] # NoDl) => FALSE
        /\ nOk[s] = 1 => (dl[s] = NoDl \/ ansAt[s] < dl[s])

\* The deadline honours the relay clamp (a deadline is never further out
\* than RelayMax ticks past the last moment a SUBSCRIBE can be processed).
ClampOK == \A s \in Subs : dl[s] # NoDl => dl[s] <= MaxNow

CapacityRespected == Cardinality(PendingSet) <= Cap

\* Cancellation is clean: no upstream SUBSCRIBE is left live for it.
CancelClean == \A s \in Subs : phase[s] = "gone" => up[s] # "inflight"

\* An answered request never has an upstream SUBSCRIBE counted as live.
AnsweredNoUpstream ==
    \A s \in Subs : phase[s] \in {"ok", "err"} => up[s] # "inflight"

(* ---------------- reachability witnesses ---------------- *)
\* Each is EXPECTED to be violated (MC_reach.cfg checks one at a time): a
\* violation proves the path is reachable, so the safety results above are
\* not vacuous.
NoTimeoutAnswer == \A s \in Subs : code[s] # "TIMEOUT"
NoLoadAnswer    == \A s \in Subs : code[s] # "LOAD"
NoHeldThenOk    == \A s \in Subs : ~(nOk[s] = 1 /\ dl[s] # NoDl)
NoUpstreamRetry == \A s \in Subs : ~(phase[s] = "held" /\ \E p \in Pubs : pub[p] = "ns")
NoTwoResolved   == ~(\A s \in Subs : nOk[s] = 1 /\ dl[s] # NoDl)

(* ---------------- liveness ---------------- *)

EventuallyAnswered ==
    \A s \in Subs : (phase[s] = "sent") ~> (phase[s] \in {"ok", "err", "gone"})

=============================================================================
