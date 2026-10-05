---- MODULE MC_mut_enc ----
EXTENDS MoqtXRelay
MCSubVer == ("a" :> "18" @@ "b" :> "22")
MCFeats == {"base"}
\* Mutation: relayed control plane encoded in the publisher's draft.
MutMsg(t, d, fs) == [t |-> t, enc |-> PubVer, feats |-> fs]
=====
