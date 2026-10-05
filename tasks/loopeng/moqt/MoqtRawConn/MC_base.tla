---- MODULE MC_base ----
EXTENDS MoqtRawConn
\* Base: the planned design (S9 + S3 + closing state). Two attempts reuse one slot.
MCOffers == {<<"moqt-18", "h3">>, <<"h3", "moqt-22">>, <<"hq-interop">>, <<"moqt-16">>, <<"moq-00", "moqt-19">>}
=====
