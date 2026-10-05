---------------------------- MODULE MoqtXRelay ----------------------------
(***************************************************************************)
(* Ledger 7-1 (c): cross-version relay -- subscription and FETCH           *)
(* correspondence through the wired hub (ledger items 5-1 / 5-2).          *)
(*                                                                         *)
(* One publisher session P and subscriber sessions, each on its own draft  *)
(* (PeerVer). The hub never forwards a request upstream: it answers        *)
(* SUBSCRIBE / FETCH / fill from its own track state and cache, relays the *)
(* data plane verbatim (5-1: byte-identical across 18/19/22), and encodes  *)
(* every control message per destination (moqtrun_envelope_put with the   *)
(* destination peer's p->ver).                                             *)
(*                                                                         *)
(* Features that exist in only some drafts (spec sections):                *)
(*  "fill"        FILL_PARAMETERS 0x23 / fill fetch stream   22 9.20.15    *)
(*  "eor20C"      End of Timed-Out Range 0x20C               22 11.4.1     *)
(*  "joining"     Joining FETCH                              18/19 10.12   *)
(*  "rangefilter" SUBGROUP_FILTER ... 0x25-0x29              19/22         *)
(*  "dupsub"      REQUEST_ERROR DUPLICATE_SUBSCRIPTION 0x19  18 10.6       *)
(*  "subended"    PUBLISH_DONE SUBSCRIPTION_ENDED 0x3        18/19 10.11   *)
(*  "notify"      PUBLISH_STATE_NOTIFY 0x22                  22 9.10       *)
(* A message parameter outside the negotiated version MUST close the      *)
(* session with PROTOCOL_VIOLATION (19 10.2 l.3332-3335; same rule in 18   *)
(* 10.2 and 22 9.20); a draft-22 Joining FETCH has no wire form            *)
(* (22 9.11) -> PROTOCOL_VIOLATION.                                        *)
(*                                                                         *)
(* Implementation transcribed from moqtrun.c (main tree, 2026-10-05):      *)
(*  1725 moqtrun_handle_subscribe   decode failure -> return (silent)      *)
(*  2536 moqtrun_handle_fetch       decode failure -> PROTOCOL_VIOLATION   *)
(*  2518 moqtrun_fetch_route        d22 Joining -> PROTOCOL_VIOLATION      *)
(*  1442 moqtrun_sub_held_reply     d18 dup -> DUPLICATE_SUBSCRIPTION      *)
(*  2174 moqtrun_fetch_accept       0x20C allowed iff dest has the cap     *)
(*  2271 moqtrun_fill_flag          fill streams: 0x20C (d22 only)         *)
(*  6770 moqtrun_done_emit          status via moqctl_publish_done_for     *)
(*  3911 moqtrun_dispatch_pub_notify  PUBLISH_STATE_NOTIFY not forwarded   *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
  Subs,          \* subscriber sessions
  PubVer,        \* publisher session's draft
  SubVer,        \* [Subs -> draft]
  ReqFeats,      \* features a subscriber may put on a request
  MaxReq,        \* requests per subscriber
  HubSilentDrop  \* TRUE = the shipped SUBSCRIBE decode path (silent return)

Feat(v) ==
  CASE v = "18" -> {"base", "joining", "eor10C", "dupsub", "subended"}
    [] v = "19" -> {"base", "joining", "eor10C", "rangefilter", "subended"}
    [] v = "22" -> {"base", "fill", "eor10C", "eor20C", "rangefilter",
                    "notify"}

Kinds == {"SUBSCRIBE", "FETCH"}

\* Which (kind, feature) pairs are a request shape at all.
Shape(k, f) ==
  CASE k = "SUBSCRIBE" -> f \in {"base", "fill", "rangefilter"}
    [] k = "FETCH"     -> f \in {"base", "joining", "rangefilter"}

VARIABLES
  published, \* the track is live at the hub
  ended,     \* the publisher left (TRACK_ENDED sent to its subscribers)
  subs,      \* hub subscription table: set of subscriber sessions
  reqs,      \* requests: [id, from, k, f, st]
  out,       \* [Subs -> set of messages/streams the hub sent]
  closed,    \* [Subs -> BOOLEAN] session closed PROTOCOL_VIOLATION
  nReq       \* [Subs -> Nat]

vars == <<published, ended, subs, reqs, out, closed, nReq>>

Msg(t, d, fs) == [t |-> t, enc |-> SubVer[d], feats |-> fs]

Init ==
  /\ published = FALSE
  /\ ended = FALSE
  /\ subs = {}
  /\ reqs = {}
  /\ out = [d \in Subs |-> {}]
  /\ closed = [d \in Subs |-> FALSE]
  /\ nReq = [d \in Subs |-> 0]

\* PUBLISH from P (any draft): the hub owns the track state from now on.
Publish ==
  /\ ~published /\ ~ended
  /\ published' = TRUE
  /\ UNCHANGED <<ended, subs, reqs, out, closed, nReq>>

\* An Object on P's subgroup stream: relayed verbatim to every subscriber.
RelayObject ==
  /\ published
  /\ subs # {}
  /\ out' = [d \in Subs |-> IF d \in subs /\ ~closed[d]
                              THEN out[d] \cup {Msg("SUBGROUP", d, {"base"})}
                              ELSE out[d]]
  /\ UNCHANGED <<published, ended, subs, reqs, closed, nReq>>

\* P (draft-22 only) sends PUBLISH_STATE_NOTIFY: accepted, not forwarded.
PubNotify ==
  /\ published /\ PubVer = "22"
  /\ UNCHANGED vars

\* P leaves: PUBLISH_DONE TRACK_ENDED (or the code it maps to) to subs.
DoneFeats(d, st) ==
  IF st = "SUBSCRIPTION_ENDED" /\ "subended" \in Feat(SubVer[d])
    THEN {"subended"} ELSE {"base"}

PubLeave ==
  /\ published
  /\ published' = FALSE
  /\ ended' = TRUE
  /\ \E st \in {"TRACK_ENDED", "SUBSCRIPTION_ENDED"} :
       out' = [d \in Subs |-> IF d \in subs /\ ~closed[d]
                 THEN out[d] \cup {Msg("PUBLISH_DONE", d, DoneFeats(d, st))}
                 ELSE out[d]]
  /\ subs' = {}
  /\ UNCHANGED <<reqs, closed, nReq>>

\* A subscriber sends one request.
Send(d) ==
  /\ ~closed[d]
  /\ nReq[d] < MaxReq
  /\ \E k \in Kinds, f \in ReqFeats :
       /\ Shape(k, f)
       /\ reqs' = reqs \cup {[id |-> <<d, nReq[d]>>, from |-> d, k |-> k,
                              f |-> f, st |-> "pending"]}
  /\ nReq' = [nReq EXCEPT ![d] = @ + 1]
  /\ UNCHANGED <<published, ended, subs, out, closed>>

Legal(r) == r.f \in Feat(SubVer[r.from])

SetSt(r, st) == (reqs \ {r}) \cup {[r EXCEPT !.st = st]}

Close(r) ==
  /\ closed' = [closed EXCEPT ![r.from] = TRUE]
  /\ reqs' = SetSt(r, "closed")
  /\ UNCHANGED <<subs, out>>

Reply(r, st, m) ==
  /\ reqs' = SetSt(r, st)
  /\ out' = [out EXCEPT ![r.from] = @ \cup m]
  /\ UNCHANGED closed

\* SUBSCRIBE at the hub.
DoSubscribe(r) ==
  LET d == r.from IN
  CASE ~Legal(r) /\ HubSilentDrop ->            \* moqtrun.c:1729
         /\ reqs' = SetSt(r, "ignored")
         /\ UNCHANGED <<subs, out, closed>>
    [] ~Legal(r) -> Close(r)
    [] ~published ->
         Reply(r, "err", {Msg("REQUEST_ERROR", d, {"base"})}) /\ UNCHANGED subs
    [] d \in subs /\ "dupsub" \in Feat(SubVer[d]) ->
         Reply(r, "err", {Msg("REQUEST_ERROR", d, {"dupsub"})})
         /\ UNCHANGED subs
    [] OTHER ->
         /\ subs' = subs \cup {d}
         /\ Reply(r, "ok",
              {Msg("SUBSCRIBE_OK", d, {"base"})} \cup
              (IF r.f = "fill"
                 THEN {Msg("FILL_STREAM", d, {"eor20C"})} ELSE {}))

\* FETCH at the hub (a d22 Joining FETCH is a decode-level violation).
DoFetch(r) ==
  LET d == r.from IN
  CASE ~Legal(r) -> Close(r)                    \* moqtrun.c:2539 / 2527
    [] ~published ->
         Reply(r, "err", {Msg("REQUEST_ERROR", d, {"base"})})
    [] r.f = "joining" /\ d \notin subs ->
         Reply(r, "err", {Msg("REQUEST_ERROR", d, {"joining"})})
    [] OTHER ->
         Reply(r, "ok", {Msg("FETCH_OK", d, {"base"}),
                         Msg("FETCH_STREAM", d, {"eor10C"})})

Process(r) ==
  /\ r \in reqs /\ r.st = "pending" /\ ~closed[r.from]
  /\ IF r.k = "SUBSCRIBE" THEN DoSubscribe(r)
                         ELSE DoFetch(r) /\ UNCHANGED subs
  /\ UNCHANGED <<published, ended, nReq>>

Next ==
  \/ Publish \/ RelayObject \/ PubNotify \/ PubLeave
  \/ \E d \in Subs : Send(d)
  \/ \E r \in reqs : Process(r)

Spec == Init /\ [][Next]_vars /\ WF_vars(\E r \in reqs : Process(r))

(***************************** safety ************************************)

\* Every message the hub sends d is encoded in d's own draft.
EncodedForDest == \A d \in Subs : \A m \in out[d] : m.enc = SubVer[d]

\* Nothing the hub sends d uses a feature d's draft lacks.
FeaturesSupported ==
  \A d \in Subs : \A m \in out[d] : m.feats \subseteq Feat(SubVer[d])

\* A request using a feature its sender's draft lacks is never accepted,
\* and is refused the way the spec says: PROTOCOL_VIOLATION close.
UnsupportedRefused ==
  \A r \in reqs : (~Legal(r) /\ r.st # "pending") => r.st = "closed"

\* No request is silently dropped: each ends answered or closed.
NoSilentDrop == \A r \in reqs : r.st # "ignored"

\* Subscription correspondence: a subscriber holds a hub subscription
\* only if one of its own SUBSCRIBEs was accepted, at most one per track
\* on draft-18 (DUPLICATE_SUBSCRIPTION), and only while the track lives.
SubCorrespondence ==
  /\ \A d \in subs : \E r \in reqs : r.from = d /\ r.k = "SUBSCRIBE"
                                     /\ r.st = "ok"
  /\ subs # {} => published
  /\ \A d \in Subs : SubVer[d] = "18" =>
        Cardinality({r \in reqs : r.from = d /\ r.k = "SUBSCRIBE"
                                  /\ r.st = "ok"}) <= 1

\* FETCH correspondence: an accepted FETCH got FETCH_OK and its stream in
\* the requester's draft; a Joining FETCH only on a draft that has it.
FetchCorrespondence ==
  \A r \in reqs : (r.k = "FETCH" /\ r.st = "ok") =>
     /\ Msg("FETCH_OK", r.from, {"base"}) \in out[r.from]
     /\ (r.f = "joining" => SubVer[r.from] # "22")

\* A fill stream exists only on a draft-22 session.
FillOnlyOn22 ==
  \A d \in Subs : (\E m \in out[d] : m.t = "FILL_STREAM") => SubVer[d] = "22"

Safety == EncodedForDest /\ FeaturesSupported /\ UnsupportedRefused
          /\ NoSilentDrop /\ SubCorrespondence /\ FetchCorrespondence
          /\ FillOnlyOn22

(***************************** liveness **********************************)

\* Every request is eventually answered or its session closed.
RequestResolved ==
  \A d \in Subs, i \in 0..(MaxReq - 1) :
     (\E r \in reqs : r.id = <<d, i>>)
       ~> (closed[d] \/ \E r \in reqs : r.id = <<d, i>>
                                        /\ r.st \in {"ok", "err"})
=============================================================================
