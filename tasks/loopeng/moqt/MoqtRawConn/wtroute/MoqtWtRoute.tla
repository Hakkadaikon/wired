---------------------------- MODULE MoqtWtRoute ----------------------------
(***************************************************************************)
(* Side model for discrepancy D1 (ledger 13-2, RESULT.md).  One WT         *)
(* connection with flow control on (two session slots, srvrun_wt_free_slot)*)
(* and one client stream x.                                                *)
(*   srvrun_offer_wt[_uni]_slot   : x is associated with the FIRST active   *)
(*                                  slot and slot->wt_session_slot records *)
(*                                  it (srvrun.c:2312 / 2642).              *)
(*   srvrun_offer_and_deliver_wt[_uni]_slot: every later delivery          *)
(*                                  recomputes the FIRST active slot       *)
(*                                  (srvrun.c:2456 / 2682) -- RouteByOwner *)
(*                                  = FALSE; the fix delivers to           *)
(*                                  slot->wt_session_slot (TRUE).          *)
(* Closing a session resets/frees the streams it owns (owner slot match,   *)
(* srvrun_reset_wt_streams_for_session).                                   *)
(***************************************************************************)
EXTENDS Integers, FiniteSets
CONSTANTS Sess, MaxChunks, RouteByOwner
Slots == {0, 1}
VARIABLES act,    \* [i \in Slots |-> session in slot i, or "free"]
          st,     \* [s \in Sess |-> "new" | "open" | "closed"]
          own,    \* slot x was offered to; -1 = not offered, -2 = freed
          assoc,  \* session x was associated with at offer time
          left,   \* chunks of x still to deliver
          bad     \* a chunk of x went to a session other than assoc
vars == <<act, st, own, assoc, left, bad>>

Active == {i \in Slots : act[i] # "free"}
First(S) == CHOOSE i \in S : \A j \in S : i <= j

Init == /\ act = [i \in Slots |-> "free"] /\ st = [s \in Sess |-> "new"]
        /\ own = -1 /\ assoc = "none" /\ left = MaxChunks /\ bad = FALSE

Open(s) == /\ st[s] = "new" /\ Active # Slots
           /\ act' = [act EXCEPT ![First(Slots \ Active)] = s]
           /\ st' = [st EXCEPT ![s] = "open"]
           /\ UNCHANGED <<own, assoc, left, bad>>

Close(s) == /\ st[s] = "open"
            /\ LET i == CHOOSE k \in Slots : act[k] = s IN
               /\ act' = [act EXCEPT ![i] = "free"]
               /\ own' = IF own = i THEN -2 ELSE own
            /\ st' = [st EXCEPT ![s] = "closed"]
            /\ UNCHANGED <<assoc, left, bad>>

Offer == /\ own = -1 /\ Active # {}
         /\ own' = First(Active) /\ assoc' = act[First(Active)]
         /\ UNCHANGED <<act, st, left, bad>>

Deliver == /\ own >= 0 /\ left > 0
           /\ LET tgt == IF RouteByOwner THEN act[own] ELSE act[First(Active)]
              IN bad' = (bad \/ tgt # assoc)
           /\ left' = left - 1
           /\ UNCHANGED <<act, st, own, assoc>>

Next == \/ \E s \in Sess : Open(s) \/ Close(s)
        \/ Offer \/ Deliver
Spec == Init /\ [][Next]_vars

DeliverToOwner == ~bad
=============================================================================
