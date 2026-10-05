---- MODULE MC_shipped_appclose ----
EXTENDS MoqtRawConn
\* Current code: srvrun_send_app_close has no closing state / teardown (D2). Safety (expect NoDataAfterClose or SingleCloseFrame).
MCOffers == {<<"moqt-18", "h3">>, <<"h3", "moqt-22">>}
=====
