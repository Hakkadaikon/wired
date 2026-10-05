---- MODULE MC_shipped_rawclose_TTrace_1791207282 ----
EXTENDS Sequences, TLCExt, Toolbox, MC_shipped_rawclose, Naturals, TLC, MC_shipped_rawclose_TEConstants

_expression ==
    LET MC_shipped_rawclose_TEExpression == INSTANCE MC_shipped_rawclose_TEExpression
    IN MC_shipped_rawclose_TEExpression!expression
----

_trace ==
    LET MC_shipped_rawclose_TETrace == INSTANCE MC_shipped_rawclose_TETrace
    IN MC_shipped_rawclose_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        conn = ((c1 :> "confirmed"))
        /\
        alpn = ((c1 :> "moqt-18"))
        /\
        hubErr = ((c1 :> 999))
        /\
        slot = (c1)
        /\
        sent = ((c1 :> 2))
        /\
        wire = ((c1 :> {<<"CC", 0>>}))
        /\
        ccCount = ((c1 :> 1))
        /\
        opt = ((c1 :> "NONE"))
        /\
        setupLog = ({<<"raw", "NONE", 0>>})
        /\
        hub = ((c1 :> "closing"))
        /\
        appEv = (<<<<"session", c1>>, <<"data", c1>>, <<"data", c1>>>>)
        /\
        latch = ((c1 :> 999))
        /\
        ccAt = ((c1 :> 2))
        /\
        sessActive = (TRUE)
        /\
        pend = ((c1 :> 0))
    )
----

_init ==
    /\ wire = _TETrace[1].wire
    /\ conn = _TETrace[1].conn
    /\ pend = _TETrace[1].pend
    /\ alpn = _TETrace[1].alpn
    /\ ccCount = _TETrace[1].ccCount
    /\ slot = _TETrace[1].slot
    /\ setupLog = _TETrace[1].setupLog
    /\ ccAt = _TETrace[1].ccAt
    /\ hubErr = _TETrace[1].hubErr
    /\ hub = _TETrace[1].hub
    /\ sent = _TETrace[1].sent
    /\ latch = _TETrace[1].latch
    /\ opt = _TETrace[1].opt
    /\ sessActive = _TETrace[1].sessActive
    /\ appEv = _TETrace[1].appEv
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ wire  = _TETrace[i].wire
        /\ wire' = _TETrace[j].wire
        /\ conn  = _TETrace[i].conn
        /\ conn' = _TETrace[j].conn
        /\ pend  = _TETrace[i].pend
        /\ pend' = _TETrace[j].pend
        /\ alpn  = _TETrace[i].alpn
        /\ alpn' = _TETrace[j].alpn
        /\ ccCount  = _TETrace[i].ccCount
        /\ ccCount' = _TETrace[j].ccCount
        /\ slot  = _TETrace[i].slot
        /\ slot' = _TETrace[j].slot
        /\ setupLog  = _TETrace[i].setupLog
        /\ setupLog' = _TETrace[j].setupLog
        /\ ccAt  = _TETrace[i].ccAt
        /\ ccAt' = _TETrace[j].ccAt
        /\ hubErr  = _TETrace[i].hubErr
        /\ hubErr' = _TETrace[j].hubErr
        /\ hub  = _TETrace[i].hub
        /\ hub' = _TETrace[j].hub
        /\ sent  = _TETrace[i].sent
        /\ sent' = _TETrace[j].sent
        /\ latch  = _TETrace[i].latch
        /\ latch' = _TETrace[j].latch
        /\ opt  = _TETrace[i].opt
        /\ opt' = _TETrace[j].opt
        /\ sessActive  = _TETrace[i].sessActive
        /\ sessActive' = _TETrace[j].sessActive
        /\ appEv  = _TETrace[i].appEv
        /\ appEv' = _TETrace[j].appEv

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("MC_shipped_rawclose_TTrace_1791207282.json", _TETrace)

=============================================================================

 Note that you can extract this module `MC_shipped_rawclose_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `MC_shipped_rawclose_TEExpression.tla` file takes precedence 
  over the module `MC_shipped_rawclose_TEExpression` below).

---- MODULE MC_shipped_rawclose_TEExpression ----
EXTENDS Sequences, TLCExt, Toolbox, MC_shipped_rawclose, Naturals, TLC, MC_shipped_rawclose_TEConstants

expression == 
    [
        \* To hide variables of the `MC_shipped_rawclose` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        wire |-> wire
        ,conn |-> conn
        ,pend |-> pend
        ,alpn |-> alpn
        ,ccCount |-> ccCount
        ,slot |-> slot
        ,setupLog |-> setupLog
        ,ccAt |-> ccAt
        ,hubErr |-> hubErr
        ,hub |-> hub
        ,sent |-> sent
        ,latch |-> latch
        ,opt |-> opt
        ,sessActive |-> sessActive
        ,appEv |-> appEv
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_wireUnchanged |-> wire = wire'
        
        \* Format the `wire` variable as Json value.
        \* ,_wireJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(wire)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_wireModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].wire # _TETrace[s-1].wire
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE MC_shipped_rawclose_TETrace ----
\*EXTENDS IOUtils, MC_shipped_rawclose, TLC, MC_shipped_rawclose_TEConstants
\*
\*trace == IODeserialize("MC_shipped_rawclose_TTrace_1791207282.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE MC_shipped_rawclose_TETrace ----
EXTENDS MC_shipped_rawclose, TLC, MC_shipped_rawclose_TEConstants

trace == 
    <<
    ([conn |-> (c1 :> "idle"),alpn |-> (c1 :> "-"),hubErr |-> (c1 :> 999),slot |-> None,sent |-> (c1 :> 0),wire |-> (c1 :> {}),ccCount |-> (c1 :> 0),opt |-> (c1 :> "NONE"),setupLog |-> {},hub |-> (c1 :> "none"),appEv |-> <<>>,latch |-> (c1 :> 999),ccAt |-> (c1 :> 999),sessActive |-> FALSE,pend |-> (c1 :> 0)]),
    ([conn |-> (c1 :> "hs"),alpn |-> (c1 :> "moqt-18"),hubErr |-> (c1 :> 999),slot |-> c1,sent |-> (c1 :> 0),wire |-> (c1 :> {}),ccCount |-> (c1 :> 0),opt |-> (c1 :> "NONE"),setupLog |-> {},hub |-> (c1 :> "none"),appEv |-> <<>>,latch |-> (c1 :> 999),ccAt |-> (c1 :> 999),sessActive |-> FALSE,pend |-> (c1 :> 0)]),
    ([conn |-> (c1 :> "confirmed"),alpn |-> (c1 :> "moqt-18"),hubErr |-> (c1 :> 999),slot |-> c1,sent |-> (c1 :> 0),wire |-> (c1 :> {}),ccCount |-> (c1 :> 0),opt |-> (c1 :> "NONE"),setupLog |-> {},hub |-> (c1 :> "setup_wait"),appEv |-> <<<<"session", c1>>>>,latch |-> (c1 :> 999),ccAt |-> (c1 :> 999),sessActive |-> TRUE,pend |-> (c1 :> 0)]),
    ([conn |-> (c1 :> "confirmed"),alpn |-> (c1 :> "moqt-18"),hubErr |-> (c1 :> 999),slot |-> c1,sent |-> (c1 :> 1),wire |-> (c1 :> {}),ccCount |-> (c1 :> 0),opt |-> (c1 :> "NONE"),setupLog |-> {},hub |-> (c1 :> "setup_wait"),appEv |-> <<<<"session", c1>>>>,latch |-> (c1 :> 999),ccAt |-> (c1 :> 999),sessActive |-> TRUE,pend |-> (c1 :> 1)]),
    ([conn |-> (c1 :> "confirmed"),alpn |-> (c1 :> "moqt-18"),hubErr |-> (c1 :> 999),slot |-> c1,sent |-> (c1 :> 2),wire |-> (c1 :> {}),ccCount |-> (c1 :> 0),opt |-> (c1 :> "NONE"),setupLog |-> {},hub |-> (c1 :> "setup_wait"),appEv |-> <<<<"session", c1>>>>,latch |-> (c1 :> 999),ccAt |-> (c1 :> 999),sessActive |-> TRUE,pend |-> (c1 :> 2)]),
    ([conn |-> (c1 :> "confirmed"),alpn |-> (c1 :> "moqt-18"),hubErr |-> (c1 :> 999),slot |-> c1,sent |-> (c1 :> 2),wire |-> (c1 :> {}),ccCount |-> (c1 :> 0),opt |-> (c1 :> "NONE"),setupLog |-> {<<"raw", "NONE", 0>>},hub |-> (c1 :> "established"),appEv |-> <<<<"session", c1>>, <<"data", c1>>>>,latch |-> (c1 :> 999),ccAt |-> (c1 :> 999),sessActive |-> TRUE,pend |-> (c1 :> 1)]),
    ([conn |-> (c1 :> "confirmed"),alpn |-> (c1 :> "moqt-18"),hubErr |-> (c1 :> 999),slot |-> c1,sent |-> (c1 :> 2),wire |-> (c1 :> {}),ccCount |-> (c1 :> 0),opt |-> (c1 :> "NONE"),setupLog |-> {<<"raw", "NONE", 0>>},hub |-> (c1 :> "closing"),appEv |-> <<<<"session", c1>>, <<"data", c1>>>>,latch |-> (c1 :> 0),ccAt |-> (c1 :> 999),sessActive |-> TRUE,pend |-> (c1 :> 1)]),
    ([conn |-> (c1 :> "confirmed"),alpn |-> (c1 :> "moqt-18"),hubErr |-> (c1 :> 999),slot |-> c1,sent |-> (c1 :> 2),wire |-> (c1 :> {<<"CC", 0>>}),ccCount |-> (c1 :> 1),opt |-> (c1 :> "NONE"),setupLog |-> {<<"raw", "NONE", 0>>},hub |-> (c1 :> "closing"),appEv |-> <<<<"session", c1>>, <<"data", c1>>>>,latch |-> (c1 :> 999),ccAt |-> (c1 :> 2),sessActive |-> TRUE,pend |-> (c1 :> 1)]),
    ([conn |-> (c1 :> "confirmed"),alpn |-> (c1 :> "moqt-18"),hubErr |-> (c1 :> 999),slot |-> c1,sent |-> (c1 :> 2),wire |-> (c1 :> {<<"CC", 0>>}),ccCount |-> (c1 :> 1),opt |-> (c1 :> "NONE"),setupLog |-> {<<"raw", "NONE", 0>>},hub |-> (c1 :> "closing"),appEv |-> <<<<"session", c1>>, <<"data", c1>>, <<"data", c1>>>>,latch |-> (c1 :> 999),ccAt |-> (c1 :> 2),sessActive |-> TRUE,pend |-> (c1 :> 0)])
    >>
----


=============================================================================

---- MODULE MC_shipped_rawclose_TEConstants ----
EXTENDS MC_shipped_rawclose

CONSTANTS c1

=============================================================================

---- CONFIG MC_shipped_rawclose_TTrace_1791207282 ----
CONSTANTS
    Conns = { c1 }
    Offers <- MCOffers
    RawList = { "moqt-18" , "moqt-19" , "moqt-22" }
    SetupOpts = { "NONE" }
    MaxData = 2
    None = None
    MutLateSession = FALSE
    MutWtPath = FALSE
    MutH3Gate = FALSE
    MutKeepActive = FALSE
    CloseTearsDown = FALSE
    ViolationsOn = FALSE
    None = None
    c1 = c1

INVARIANT
    _inv

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Mon Oct 05 13:34:43 UTC 2026