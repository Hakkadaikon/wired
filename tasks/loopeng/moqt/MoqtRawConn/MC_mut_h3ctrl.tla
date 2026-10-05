---- MODULE MC_mut_h3ctrl ----
EXTENDS MoqtRawConn
\* Mutation: SETTINGS gated on alpn # hq-interop instead of = h3 (expect NoH3OnRaw).
MCOffers == {<<"moqt-18", "h3">>}
=====
