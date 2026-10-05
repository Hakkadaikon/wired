---- MODULE MC_shipped_appclose_live ----
EXTENDS MoqtRawConn
\* Current code (D2), liveness only: a raw hub close waits for the peer/idle to deliver on_session_close (expect CloseLive).
MCOffers == {<<"moqt-18", "h3">>}
=====
