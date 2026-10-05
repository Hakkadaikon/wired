---- MODULE MC_reach ----
EXTENDS MoqtRawConn
\* Non-vacuity: each Reach* invariant states that a wanted base behaviour is
\* UNreachable; TLC must violate every one of them.
MCOffers == {<<"moqt-18", "h3">>, <<"h3", "moqt-22">>, <<"hq-interop">>}
CONSTANTS c1, c2
ReachRawEstablished == ~(\E c \in Conns : Transport(c) = "raw" /\ hub[c] = "established")
ReachWtEstablished == ~(\E c \in Conns : Transport(c) = "wt" /\ hub[c] = "established")
ReachSlotReused == ~(Has("session", c1) /\ Has("session", c2))
ReachRawMalformedClose == ~(\E c \in Conns : <<"CC", 9>> \in wire[c] /\ conn[c] = "gone")
ReachWtPathClose == ~(\E c \in Conns : <<"CLOSE_WT", 8>> \in wire[c])
ReachRawDataAfterEstablish == ~(\E c \in Conns : Transport(c) = "raw" /\ hub[c] = "closed" /\ Len(appEv) >= 4)
=====
