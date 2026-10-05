---- MODULE MC_mut_gate ----
EXTENDS MoqtVerCtl
MCOffers == {<<"19">>, <<>>}
MCServerList == <<"22", "19", "18">>
MCTable == {"22", "19", "18"}
MCCtl == {<<"S", "M">>}
\* Mutation: a token session lifts the hold gate once the hub's own SETUP
\* went out (the legacy rule) -- requests may then run before peer SETUP.
MutHoldGate(p) == hubCtl[p] = "none"
=====
