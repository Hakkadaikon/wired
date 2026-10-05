---- MODULE MC_mut_done ----
EXTENDS MoqtXRelay
MCSubVer == ("a" :> "22" @@ "b" :> "19")
MCFeats == {"base"}
\* Mutation: PUBLISH_DONE status passed through without the per-draft map.
MutDoneFeats(d, st) ==
  IF st = "SUBSCRIPTION_ENDED" THEN {"subended"} ELSE {"base"}
=====
