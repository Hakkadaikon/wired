---- MODULE MC_mut_done ----
EXTENDS MoqtFillLife
MCSubFilters == {"none"}
MCFillFilters == {"abs0"}
\* Mutation: PUBLISH_DONE not deferred while a fill still waits for a stream.
MutEmitDone(s) ==
  /\ ~closed
  /\ sub[s] = "ended" /\ ~doneSent[s]
  /\ doneSent' = [doneSent EXCEPT ![s] = TRUE]
  /\ doneCnt' = [doneCnt EXCEPT ![s] = Cardinality(Opened(s))]
  /\ UNCHANGED <<sub, sflt, fwd, nUpd, reqs, failed, closed>>
=====
