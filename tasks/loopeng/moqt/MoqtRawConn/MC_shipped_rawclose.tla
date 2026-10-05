---- MODULE MC_shipped_rawclose ----
EXTENDS MoqtRawConn
\* Current code: srvrun_send_app_close has no closing state / teardown (D2). Safety (expect NoDataAfterClose or SingleCloseFrame).
MCOffers == {<<"moqt-18", "h3">>}
=====
