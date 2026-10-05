---- MODULE MC_mut_cancel ----
EXTENDS MoqtFillLife
MCSubFilters == {"none"}
MCFillFilters == {"abs0"}
\* Mutation: cancelling the subscription leaves its fills alone.
MutCancel(s) ==
  /\ ~closed
  /\ sub[s] = "live"
  /\ sub' = [sub EXCEPT ![s] = "cancelled"]
  /\ UNCHANGED <<sflt, fwd, nUpd, reqs, failed, closed, doneSent, doneCnt>>
=====
