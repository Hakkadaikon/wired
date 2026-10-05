---- MODULE MC_mut_double_close ----
EXTENDS MoqtRawConn
\* Mutation: raw close fires on_session_close but keeps wt_active; free_slot fires it again (expect CloseOnce).
MCOffers == {<<"moqt-18", "h3">>}
=====
