---------------------------- MODULE MoqtRawConn ----------------------------
(***************************************************************************)
(* Ledger 13-2 (plan tasks/loopeng/moqt/RawQuic/plan.md S5.1).            *)
(*                                                                         *)
(* One srvrun connection slot (the srvrun_conn memory that holds the       *)
(* wired_wt_session `wt`, slot 0) is reused by a sequence of connection    *)
(* attempts Conns.  Each attempt negotiates an ALPN (client preference     *)
(* order, R5), then either                                                 *)
(*   - raw MoQT (alpn in RawList): an IMPLICIT session is created at       *)
(*     handshake confirmation (plan 4.4, S9), or                           *)
(*   - WebTransport (alpn = "h3"): a session is created by an Extended      *)
(*     CONNECT after the H3 SETTINGS (srvrun_start_wt), or                 *)
(*   - hq-interop / none: no session at all.                               *)
(* The app (the MoQT hub) sees on_session / on_stream_data /               *)
(* on_session_close as the history appEv.  The hub decides the SETUP       *)
(* verdict (PATH / AUTHORITY, d18 10.3.1.1-2 / d19 10.3.1.1-2 /            *)
(* d22 9.1.1-2) and may close the session (latch -> drain), which goes on  *)
(* the wire as CONNECTION_CLOSE 0x1d with the MoQT code on raw QUIC and as  *)
(* CLOSE_WEBTRANSPORT_SESSION on WT (d18 3.5 / d19 3.5 / d22 6.6).         *)
(*                                                                         *)
(* Switches (all FALSE/TRUE in MC_base = the planned design):              *)
(*   MutLateSession  raw stream bytes reach the app without the session    *)
(*                   gate; the session is created later (sess_on_step).    *)
(*   MutWtPath       the WT-only PATH/AUTHORITY rule is applied on raw     *)
(*                   (today's moqtrun_setup_opt_bad, REQ-B).               *)
(*   MutH3Gate       SETTINGS gated on alpn # hq-interop instead of = h3.  *)
(*   MutKeepActive   raw close fires on_session_close but leaves the      *)
(*                   session slot active (wt_active stays 1).              *)
(*   CloseTearsDown  TRUE  = a server CONNECTION_CLOSE enters the closing  *)
(*                           state (RFC 9000 10.2.1) and ends the session  *)
(*                           at once (planned design);                     *)
(*                   FALSE = today's srvrun_send_app_close: the frame is   *)
(*                           sent, nothing else changes until the idle     *)
(*                           sweep / peer close frees the slot.            *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Conns,          \* connection attempts reusing ONE srvrun_conn slot
          Offers,         \* set of client ALPN offer sequences (preference order)
          RawList,        \* server raw_alpns (wired_srvboot_id.raw_alpns)
          SetupOpts,      \* client SETUP option shapes, see SpecVerdict
          MaxData,        \* stream chunks the peer sends per connection
          None,           \* model value: the slot is free
          MutLateSession, MutWtPath, MutH3Gate, MutKeepActive, CloseTearsDown,
          ViolationsOn    \* FALSE: no connection-level violation close

NoCode == 999             \* "no code latched / no close recorded"

VARIABLES conn,       \* [c |-> "idle"|"hs"|"confirmed"|"closing"|"gone"]
          alpn,       \* [c |-> chosen ALPN, "-" before ClientHello]
          opt,        \* [c |-> SETUP option shape the client sends]
          slot,       \* which attempt currently owns the srvrun_conn memory
          sessActive, \* wt_active (session slot 0 of that memory)
          hub,        \* [c |-> "none"|"setup_wait"|"established"|"closing"|"closed"]
          hubErr,     \* [c |-> error code the hub's SETUP verdict closed with]
          pend,       \* [c |-> peer chunks reassembled, not yet delivered]
          sent,       \* [c |-> peer chunks sent]
          latch,      \* [c |-> wt_close_pending code, NoCode = none]
          appEv,      \* history of app callbacks <<kind, c>>
          wire,       \* [c |-> set of frames emitted to the peer]
          ccCount,    \* [c |-> CONNECTION_CLOSE frames (any origin) sent]
          ccAt,       \* [c |-> Len(appEv) when the first one was sent]
          setupLog    \* {<<transport, opt, code>>} verdicts the hub took

vars == <<conn, alpn, opt, slot, sessActive, hub, hubErr, pend, sent, latch,
          appEv, wire, ccCount, ccAt, setupLog>>

-----------------------------------------------------------------------------
(* ALPN (R3/R5, RFC 7301 3.1): first entry of the client's list the server  *)
(* supports, in CLIENT order (salpn_negotiate walks the client list).       *)
Supported == {"h3", "hq-interop"} \cup RawList
Pick(o) == LET ok == {i \in 1..Len(o) : o[i] \in Supported}
           IN IF ok = {} THEN "none"
              ELSE o[CHOOSE i \in ok : \A j \in ok : i <= j]

Transport(c) == IF alpn[c] \in RawList THEN "raw"
                ELSE IF alpn[c] = "h3" THEN "wt" ELSE "none"

(* Spec oracle for the SETUP Path/Authority verdict, written as a table   *)
(* straight from the text (d22 9.1.1/9.1.2 = d18/d19 10.3.1.1/10.3.1.2):  *)
(*   NONE     no PATH, no AUTHORITY                                       *)
(*   PATH     well-formed, supported PATH;  AUTH: same for AUTHORITY      *)
(*   BADPATH  PATH not RFC 3986 conformant; BADAUTH: same for AUTHORITY   *)
(*   REFPATH  well-formed PATH the server does not support (hook refuses) *)
(*   REFAUTH  well-formed AUTHORITY the server does not support           *)
(*   BOTH     well-formed, supported PATH and AUTHORITY together: what a  *)
(*            conforming raw client sends for a moqt:// URI (R8/R9 MUST)  *)
(*   [review 2026-10-05: REFAUTH/BOTH added, EXTRACT M5 + plan 5.1]       *)
(* WT: any PATH -> INVALID_PATH 0x8, any AUTHORITY -> INVALID_AUTHORITY   *)
(*     0x19 ("received while WebTransport is used").                       *)
(* raw: malformed -> MALFORMED_PATH 0x9 / MALFORMED_AUTHORITY 0x1A,       *)
(*      unsupported -> 0x8 / 0x19, otherwise accept.                      *)
SpecVerdict(t, o) ==
  CASE t = "wt"  /\ o \in {"PATH", "BADPATH", "REFPATH", "BOTH"} -> 8
    [] t = "wt"  /\ o \in {"AUTH", "BADAUTH", "REFAUTH"}          -> 25
    [] t = "raw" /\ o = "BADPATH"                        -> 9
    [] t = "raw" /\ o = "BADAUTH"                        -> 26
    [] t = "raw" /\ o = "REFPATH"                        -> 8
    [] t = "raw" /\ o = "REFAUTH"                        -> 25
    [] OTHER                                             -> 0

(* Implementation shape: moqraw_setup_verdict(raw, setup, policy) (plan    *)
(* S3) -- WT keeps today's moqtrun_setup_opt_bad.                          *)
WtRule(o)  == IF o \in {"PATH", "BADPATH", "REFPATH", "BOTH"} THEN 8
              ELSE IF o \in {"AUTH", "BADAUTH", "REFAUTH"} THEN 25 ELSE 0
RawRule(o) == IF o = "BADPATH" THEN 9
              ELSE IF o = "BADAUTH" THEN 26
              ELSE IF o = "REFPATH" THEN 8
              ELSE IF o = "REFAUTH" THEN 25 ELSE 0
HubVerdict(t, o) == IF t = "wt" \/ MutWtPath THEN WtRule(o) ELSE RawRule(o)

(* srvloop/respond.c:67 build_settings_frame gate. *)
SettingsGate(c) == IF MutH3Gate THEN alpn[c] # "hq-interop" ELSE alpn[c] = "h3"

(* Delivery gate: srvrun_deliver_wt_stream_delta's wt_stream_delta_ready  *)
(* (sidx >= 0, i.e. an active session) plus the closing state.            *)
DeliverGate(c) ==
  IF MutLateSession /\ Transport(c) = "raw"
  THEN conn[c] \in {"hs", "confirmed"}
  ELSE sessActive /\ conn[c] = "confirmed"

-----------------------------------------------------------------------------
Init ==
  /\ conn = [c \in Conns |-> "idle"]
  /\ alpn = [c \in Conns |-> "-"]
  /\ opt = [c \in Conns |-> "NONE"]
  /\ slot = None
  /\ sessActive = FALSE
  /\ hub = [c \in Conns |-> "none"]
  /\ hubErr = [c \in Conns |-> NoCode]
  /\ pend = [c \in Conns |-> 0]
  /\ sent = [c \in Conns |-> 0]
  /\ latch = [c \in Conns |-> NoCode]
  /\ appEv = <<>>
  /\ wire = [c \in Conns |-> {}]
  /\ ccCount = [c \in Conns |-> 0]
  /\ ccAt = [c \in Conns |-> NoCode]
  /\ setupLog = {}

AddWire(c, f) == wire' = [wire EXCEPT ![c] = @ \cup {f}]
CloseEv(c) == /\ appEv' = Append(appEv, <<"close", c>>)
              /\ hub' = [hub EXCEPT ![c] = "closed"]
NoteCC(c) == /\ ccCount' = [ccCount EXCEPT ![c] = @ + 1]
             /\ ccAt' = [ccAt EXCEPT ![c] = IF @ = NoCode THEN Len(appEv) ELSE @]

(* ClientHello: srvrun_open_slot claims the (free) slot; sdrv picks the    *)
(* ALPN.  No overlap -> TLS no_application_protocol, CONNECTION_CLOSE      *)
(* 0x178 (R11), boot failure frees the slot again (srvrun_open_done).     *)
ClientHello(c) ==
  /\ conn[c] = "idle" /\ slot = None
  /\ \E o \in Offers, s \in SetupOpts :
       LET a == Pick(o) IN
       /\ alpn' = [alpn EXCEPT ![c] = a]
       /\ opt' = [opt EXCEPT ![c] = s]
       /\ IF a = "none"
          THEN /\ conn' = [conn EXCEPT ![c] = "gone"]
               /\ AddWire(c, <<"ALERT_NO_ALPN", 376>>)
               /\ UNCHANGED slot
          ELSE /\ conn' = [conn EXCEPT ![c] = "hs"]
               /\ slot' = c
               /\ UNCHANGED wire
  /\ UNCHANGED <<sessActive, hub, hubErr, pend, sent, latch, appEv, ccCount,
                 ccAt, setupLog>>

CreateSess(c) ==
  /\ sessActive' = TRUE
  /\ hub' = [hub EXCEPT ![c] = "setup_wait"]
  /\ appEv' = Append(appEv, <<"session", c>>)

(* Handshake confirmed (wired_server_is_confirmed first 1).  h3: SETTINGS  *)
(* on control stream 3.  raw (design): claim session slot 0 and call       *)
(* raw_on_session in the same step, before any delivery.                   *)
Confirm(c) ==
  /\ slot = c /\ conn[c] = "hs"
  /\ conn' = [conn EXCEPT ![c] = "confirmed"]
  /\ IF SettingsGate(c) THEN AddWire(c, <<"H3CTRL", 0>>) ELSE UNCHANGED wire
  /\ IF Transport(c) = "raw" /\ ~MutLateSession
     THEN CreateSess(c)
     ELSE UNCHANGED <<sessActive, hub, appEv>>
  /\ UNCHANGED <<alpn, opt, slot, hubErr, pend, sent, latch, ccCount, ccAt,
                 setupLog>>

(* Mutation only: the raw session is created in a later pass.             *)
RawCreateLate(c) ==
  /\ MutLateSession
  /\ slot = c /\ Transport(c) = "raw" /\ conn[c] = "confirmed"
  /\ hub[c] = "none" /\ ~sessActive
  /\ CreateSess(c)
  /\ UNCHANGED <<conn, alpn, opt, slot, hubErr, pend, sent, latch, wire,
                 ccCount, ccAt, setupLog>>

(* WT: Extended CONNECT accepted after SETTINGS (srvrun_start_wt).        *)
WtConnect(c) ==
  /\ slot = c /\ Transport(c) = "wt" /\ conn[c] = "confirmed"
  /\ <<"H3CTRL", 0>> \in wire[c] /\ hub[c] = "none" /\ ~sessActive
  /\ CreateSess(c)
  /\ UNCHANGED <<conn, alpn, opt, slot, hubErr, pend, sent, latch, wire,
                 ccCount, ccAt, setupLog>>

(* Peer sends one stream chunk (its control stream starts with SETUP).    *)
(* Reassembled into a wt slot table (srvloop), not yet delivered.          *)
PeerStream(c) ==
  /\ slot = c /\ conn[c] \in {"hs", "confirmed", "closing"}
  /\ sent[c] < MaxData
  /\ sent' = [sent EXCEPT ![c] = @ + 1]
  /\ pend' = [pend EXCEPT ![c] = @ + 1]
  /\ UNCHANGED <<conn, alpn, opt, slot, sessActive, hub, hubErr, latch, appEv,
                 wire, ccCount, ccAt, setupLog>>

(* srvrun_offer_and_deliver_wt[_uni]_slot -> wt_on_stream_data.  The first *)
(* chunk the hub sees in setup_wait is the peer SETUP: take the verdict.   *)
Deliver(c) ==
  /\ slot = c /\ pend[c] > 0 /\ DeliverGate(c)
  /\ pend' = [pend EXCEPT ![c] = @ - 1]
  /\ IF hub[c] = "setup_wait"
     THEN LET v == HubVerdict(Transport(c), opt[c]) IN
          /\ setupLog' = setupLog \cup {<<Transport(c), opt[c], v>>}
          /\ appEv' = Append(appEv, <<"data", c>>)
          /\ IF v = 0
             THEN /\ hub' = [hub EXCEPT ![c] = "established"]
                  /\ UNCHANGED <<latch, hubErr>>
             ELSE /\ hub' = [hub EXCEPT ![c] = "closing"]
                  /\ latch' = [latch EXCEPT ![c] = v]
                  /\ hubErr' = [hubErr EXCEPT ![c] = v]
     ELSE /\ appEv' = Append(appEv, <<"data", c>>)
          /\ UNCHANGED <<hub, hubErr, latch, setupLog>>
  /\ UNCHANGED <<conn, alpn, opt, slot, sessActive, sent, wire, ccCount, ccAt>>

(* Hub ends an established session on its own (NO_ERROR): io.close_session *)
(* -> wired_server_wt_close_session latches wt_close_pending.              *)
HubClose(c) ==
  /\ slot = c /\ conn[c] = "confirmed" /\ sessActive
  /\ hub[c] = "established" /\ latch[c] = NoCode
  /\ latch' = [latch EXCEPT ![c] = 0]
  /\ hub' = [hub EXCEPT ![c] = "closing"]
  /\ UNCHANGED <<conn, alpn, opt, slot, sessActive, hubErr, pend, sent, appEv,
                 wire, ccCount, ccAt, setupLog>>

(* srvrun_drain_wt_close_one: consume the latch.                           *)
(*  WT : CLOSE_WEBTRANSPORT_SESSION, srvrun_close_wt_session_slot.         *)
(*  raw: CONNECTION_CLOSE 0x1d carrying the MoQT code (R10).               *)
DrainRaw(c) ==
  /\ AddWire(c, <<"CC", latch[c]>>)
  /\ NoteCC(c)
  /\ CASE MutKeepActive ->
            /\ CloseEv(c)
            /\ conn' = [conn EXCEPT ![c] = "closing"]
            /\ UNCHANGED sessActive
       [] CloseTearsDown ->
            /\ CloseEv(c)
            /\ conn' = [conn EXCEPT ![c] = "closing"]
            /\ sessActive' = FALSE
       [] OTHER -> UNCHANGED <<appEv, hub, conn, sessActive>>

DrainWt(c) ==
  /\ AddWire(c, <<"CLOSE_WT", latch[c]>>)
  /\ CloseEv(c)
  /\ sessActive' = FALSE
  /\ UNCHANGED <<conn, ccCount, ccAt>>

DrainClose(c) ==
  /\ slot = c /\ conn[c] = "confirmed" /\ latch[c] # NoCode
  /\ latch' = [latch EXCEPT ![c] = NoCode]
  /\ IF ~sessActive
     THEN UNCHANGED <<appEv, hub, conn, sessActive, wire, ccCount, ccAt>>
     ELSE IF Transport(c) = "wt" THEN DrainWt(c) ELSE DrainRaw(c)
  /\ UNCHANGED <<alpn, opt, slot, hubErr, pend, sent, setupLog>>

(* Any connection-level violation close (bad qsid, H3_FRAME_ERROR, AEAD     *)
(* limit, reset flood, shutdown drain): srvrun_send_app_close /            *)
(* srvrun_send_transport_close.  Once per connection in the model.        *)
ViolationClose(c) ==
  /\ ViolationsOn /\ slot = c /\ conn[c] = "confirmed" /\ ccCount[c] = 0
  /\ AddWire(c, <<"CCX", 0>>)
  /\ NoteCC(c)
  /\ IF CloseTearsDown
     THEN /\ conn' = [conn EXCEPT ![c] = "closing"]
          /\ IF sessActive
             THEN CloseEv(c) /\ sessActive' = FALSE
             ELSE UNCHANGED <<appEv, hub, sessActive>>
     ELSE UNCHANGED <<conn, appEv, hub, sessActive>>
  /\ UNCHANGED <<alpn, opt, slot, hubErr, pend, sent, latch, setupLog>>

(* Server shutdown GOAWAY (srvrun.c:4165 gate: alpn == h3).               *)
Goaway(c) ==
  /\ slot = c /\ conn[c] = "confirmed" /\ alpn[c] = "h3"
  /\ <<"H3GOAWAY", 0>> \notin wire[c]
  /\ AddWire(c, <<"H3GOAWAY", 0>>)
  /\ UNCHANGED <<conn, alpn, opt, slot, sessActive, hub, hubErr, pend, sent,
                 latch, appEv, ccCount, ccAt, setupLog>>

(* srvrun_free_slot: peer CONNECTION_CLOSE (srvrun_step_and_reap), idle    *)
(* sweep, boot deadline, PTO budget, closing-period end.  close_all_wt     *)
(* fires on_session_close for every ACTIVE session before the memory can   *)
(* be reused.                                                              *)
ConnEnd(c) ==
  /\ slot = c /\ conn[c] \in {"hs", "confirmed", "closing"}
  /\ conn' = [conn EXCEPT ![c] = "gone"]
  /\ slot' = None
  /\ pend' = [pend EXCEPT ![c] = 0]
  /\ latch' = [latch EXCEPT ![c] = NoCode]
  /\ IF sessActive
     THEN CloseEv(c) /\ sessActive' = FALSE
     ELSE UNCHANGED <<appEv, hub, sessActive>>
  /\ UNCHANGED <<alpn, opt, hubErr, sent, wire, ccCount, ccAt, setupLog>>

Next ==
  \E c \in Conns :
    \/ ClientHello(c) \/ Confirm(c) \/ RawCreateLate(c) \/ WtConnect(c)
    \/ PeerStream(c) \/ Deliver(c) \/ HubClose(c) \/ DrainClose(c)
    \/ ViolationClose(c) \/ Goaway(c) \/ ConnEnd(c)

Fairness ==
  \A c \in Conns :
    /\ WF_vars(Confirm(c)) /\ WF_vars(Deliver(c))
    /\ WF_vars(DrainClose(c)) /\ WF_vars(RawCreateLate(c))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
TypeOK ==
  /\ conn \in [Conns -> {"idle", "hs", "confirmed", "closing", "gone"}]
  /\ slot \in Conns \cup {None}
  /\ sessActive \in BOOLEAN
  /\ hub \in [Conns -> {"none", "setup_wait", "established", "closing", "closed"}]
  /\ pend \in [Conns -> 0..MaxData] /\ sent \in [Conns -> 0..MaxData]

Idx == 1..Len(appEv)
Ev(i, k, c) == appEv[i] = <<k, c>>
Has(k, c) == \E i \in Idx : Ev(i, k, c)
NClose(c) == Cardinality({i \in Idx : Ev(i, "close", c)})

(* T-E8: no stream byte reaches the app before on_session for its conn.    *)
SessBeforeData ==
  \A i \in Idx : appEv[i][1] = "data" =>
    \E j \in 1..(i - 1) : Ev(j, "session", appEv[i][2])

(* on_session_close fires at most once per session.                        *)
CloseOnce == \A c \in Conns : NClose(c) <= 1

(* A session that was announced is closed before its conn is gone, and a   *)
(* close is never fired for a session that was never announced.            *)
CloseIffSession ==
  \A c \in Conns :
    /\ (conn[c] = "gone" /\ Has("session", c)) => Has("close", c)
    /\ Has("close", c) => Has("session", c)

(* The session pointer (slot memory) is bound to one conn at a time: no    *)
(* data after that conn's close, and a reuse (next on_session) only after  *)
(* the previous owner's close.                                             *)
NoGhost ==
  /\ \A i, j \in Idx : (j < i /\ appEv[i][1] = "data"
                        /\ Ev(j, "close", appEv[i][2])) => FALSE
  /\ \A i, k \in Idx :
       (i < k /\ appEv[i][1] = "session" /\ appEv[k][1] = "session"
        /\ appEv[i][2] # appEv[k][2])
         => \E j \in Idx : i < j /\ j < k /\ Ev(j, "close", appEv[i][2])

(* REQ-C / T-E1: no HTTP/3 control stream, SETTINGS or H3 GOAWAY on raw.   *)
NoH3OnRaw ==
  \A c \in Conns : Transport(c) = "raw" =>
    \A f \in wire[c] : f[1] \notin {"H3CTRL", "H3GOAWAY"}

(* REQ-D / R10 / T-E5: hub-initiated closes are CONNECTION_CLOSE with the   *)
(* MoQT code on raw and CLOSE_WEBTRANSPORT_SESSION on WT, never crossed.   *)
RawCloseShape ==
  \A c \in Conns : \A f \in wire[c] :
    /\ (f[1] = "CC" => Transport(c) = "raw")
    /\ (f[1] = "CLOSE_WT" => Transport(c) = "wt")

(* REQ-B / R8 / R9: every verdict the hub took equals the spec table.      *)
PathRule == \A r \in setupLog : r[3] = SpecVerdict(r[1], r[2])

(* RFC 9000 10.2.1 closing state: after the server sent CONNECTION_CLOSE,   *)
(* no further app delivery for that connection, and at most one close      *)
(* frame (with one code) per connection.                                   *)
NoDataAfterClose ==
  \A i \in Idx : appEv[i][1] = "data" => i <= ccAt[appEv[i][2]]
SingleCloseFrame == \A c \in Conns : ccCount[c] <= 1

(* No session for hq-interop / failed ALPN connections.                    *)
SessOnlyOnApp ==
  \A i \in Idx : appEv[i][1] = "session" =>
    Transport(appEv[i][2]) \in {"raw", "wt"}

-----------------------------------------------------------------------------
GoodSetup(c) == opt[c] \in {"NONE", "PATH", "AUTH", "BOTH"}

(* L1: a raw connection whose client sent a well-formed, supported SETUP   *)
(* reaches Established unless the connection ends for an outside reason.   *)
EstablishLive ==
  \A c \in Conns :
    (Transport(c) = "raw" /\ GoodSetup(c) /\ sent[c] >= 1
      /\ conn[c] = "confirmed" /\ hub[c] \in {"none", "setup_wait"})
    ~> (hub[c] = "established"
        \/ (hubErr[c] = NoCode /\ conn[c] \in {"closing", "gone"}))

(* L2: a hub close request always ends in exactly the on_session_close     *)
(* the hub needs to free its peer slot, without waiting for the peer.      *)
CloseLive == \A c \in Conns : hub[c] = "closing" ~> hub[c] = "closed"
=============================================================================
