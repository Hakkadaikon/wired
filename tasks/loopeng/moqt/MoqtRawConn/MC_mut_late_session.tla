---- MODULE MC_mut_late_session ----
EXTENDS MoqtRawConn
\* Mutation: raw bytes delivered without the session gate, session created later (expect SessBeforeData).
MCOffers == {<<"moqt-18", "h3">>}
=====
