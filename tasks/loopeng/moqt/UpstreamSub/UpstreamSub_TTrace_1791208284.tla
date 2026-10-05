---- MODULE UpstreamSub_TTrace_1791208284 ----
EXTENDS Sequences, TLCExt, UpstreamSub, Toolbox, UpstreamSub_TEConstants, Naturals, TLC

_expression ==
    LET UpstreamSub_TEExpression == INSTANCE UpstreamSub_TEExpression
    IN UpstreamSub_TEExpression!expression
----

_trace ==
    LET UpstreamSub_TETrace == INSTANCE UpstreamSub_TETrace
    IN UpstreamSub_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        dirty = (FALSE)
        /\
        gen = (1)
        /\
        pubs = (1)
        /\
        act = ((s1 :> FALSE @@ s2 :> FALSE))
        /\
        ans = ((s1 :> 0 @@ s2 :> 0))
        /\
        okEst = ((s1 :> FALSE @@ s2 :> FALSE))
        /\
        ph = ((s1 :> "gone" @@ s2 :> "idle"))
        /\
        upSt = ("pending")
        /\
        pub = ("ns")
        /\
        inflight = ({1})
    )
----

_init ==
    /\ pub = _TETrace[1].pub
    /\ inflight = _TETrace[1].inflight
    /\ dirty = _TETrace[1].dirty
    /\ gen = _TETrace[1].gen
    /\ pubs = _TETrace[1].pubs
    /\ ans = _TETrace[1].ans
    /\ upSt = _TETrace[1].upSt
    /\ okEst = _TETrace[1].okEst
    /\ ph = _TETrace[1].ph
    /\ act = _TETrace[1].act
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ pub  = _TETrace[i].pub
        /\ pub' = _TETrace[j].pub
        /\ inflight  = _TETrace[i].inflight
        /\ inflight' = _TETrace[j].inflight
        /\ dirty  = _TETrace[i].dirty
        /\ dirty' = _TETrace[j].dirty
        /\ gen  = _TETrace[i].gen
        /\ gen' = _TETrace[j].gen
        /\ pubs  = _TETrace[i].pubs
        /\ pubs' = _TETrace[j].pubs
        /\ ans  = _TETrace[i].ans
        /\ ans' = _TETrace[j].ans
        /\ upSt  = _TETrace[i].upSt
        /\ upSt' = _TETrace[j].upSt
        /\ okEst  = _TETrace[i].okEst
        /\ okEst' = _TETrace[j].okEst
        /\ ph  = _TETrace[i].ph
        /\ ph' = _TETrace[j].ph
        /\ act  = _TETrace[i].act
        /\ act' = _TETrace[j].act

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("UpstreamSub_TTrace_1791208284.json", _TETrace)

=============================================================================

 Note that you can extract this module `UpstreamSub_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `UpstreamSub_TEExpression.tla` file takes precedence 
  over the module `UpstreamSub_TEExpression` below).

---- MODULE UpstreamSub_TEExpression ----
EXTENDS Sequences, TLCExt, UpstreamSub, Toolbox, UpstreamSub_TEConstants, Naturals, TLC

expression == 
    [
        \* To hide variables of the `UpstreamSub` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        pub |-> pub
        ,inflight |-> inflight
        ,dirty |-> dirty
        ,gen |-> gen
        ,pubs |-> pubs
        ,ans |-> ans
        ,upSt |-> upSt
        ,okEst |-> okEst
        ,ph |-> ph
        ,act |-> act
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_pubUnchanged |-> pub = pub'
        
        \* Format the `pub` variable as Json value.
        \* ,_pubJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(pub)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_pubModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].pub # _TETrace[s-1].pub
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE UpstreamSub_TETrace ----
\*EXTENDS IOUtils, UpstreamSub, UpstreamSub_TEConstants, TLC
\*
\*trace == IODeserialize("UpstreamSub_TTrace_1791208284.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE UpstreamSub_TETrace ----
EXTENDS UpstreamSub, UpstreamSub_TEConstants, TLC

trace == 
    <<
    ([dirty |-> FALSE,gen |-> 0,pubs |-> 0,act |-> (s1 :> FALSE @@ s2 :> FALSE),ans |-> (s1 :> 0 @@ s2 :> 0),okEst |-> (s1 :> FALSE @@ s2 :> FALSE),ph |-> (s1 :> "idle" @@ s2 :> "idle"),upSt |-> "none",pub |-> "none",inflight |-> {}]),
    ([dirty |-> TRUE,gen |-> 0,pubs |-> 1,act |-> (s1 :> FALSE @@ s2 :> FALSE),ans |-> (s1 :> 0 @@ s2 :> 0),okEst |-> (s1 :> FALSE @@ s2 :> FALSE),ph |-> (s1 :> "idle" @@ s2 :> "idle"),upSt |-> "none",pub |-> "ns",inflight |-> {}]),
    ([dirty |-> FALSE,gen |-> 0,pubs |-> 1,act |-> (s1 :> FALSE @@ s2 :> FALSE),ans |-> (s1 :> 0 @@ s2 :> 0),okEst |-> (s1 :> FALSE @@ s2 :> FALSE),ph |-> (s1 :> "idle" @@ s2 :> "idle"),upSt |-> "none",pub |-> "ns",inflight |-> {}]),
    ([dirty |-> TRUE,gen |-> 0,pubs |-> 1,act |-> (s1 :> FALSE @@ s2 :> FALSE),ans |-> (s1 :> 0 @@ s2 :> 0),okEst |-> (s1 :> FALSE @@ s2 :> FALSE),ph |-> (s1 :> "wait" @@ s2 :> "idle"),upSt |-> "none",pub |-> "ns",inflight |-> {}]),
    ([dirty |-> FALSE,gen |-> 1,pubs |-> 1,act |-> (s1 :> FALSE @@ s2 :> FALSE),ans |-> (s1 :> 0 @@ s2 :> 0),okEst |-> (s1 :> FALSE @@ s2 :> FALSE),ph |-> (s1 :> "wait" @@ s2 :> "idle"),upSt |-> "pending",pub |-> "ns",inflight |-> {1}]),
    ([dirty |-> TRUE,gen |-> 1,pubs |-> 1,act |-> (s1 :> FALSE @@ s2 :> FALSE),ans |-> (s1 :> 0 @@ s2 :> 0),okEst |-> (s1 :> FALSE @@ s2 :> FALSE),ph |-> (s1 :> "gone" @@ s2 :> "idle"),upSt |-> "pending",pub |-> "ns",inflight |-> {1}]),
    ([dirty |-> FALSE,gen |-> 1,pubs |-> 1,act |-> (s1 :> FALSE @@ s2 :> FALSE),ans |-> (s1 :> 0 @@ s2 :> 0),okEst |-> (s1 :> FALSE @@ s2 :> FALSE),ph |-> (s1 :> "gone" @@ s2 :> "idle"),upSt |-> "pending",pub |-> "ns",inflight |-> {1}])
    >>
----


=============================================================================

---- MODULE UpstreamSub_TEConstants ----
EXTENDS UpstreamSub

CONSTANTS s1, s2

=============================================================================

---- CONFIG UpstreamSub_TTrace_1791208284 ----
CONSTANTS
    Subs = { s1 , s2 }
    MaxGen = 2
    MaxPub = 1
    BugNoCancel = TRUE
    BugEarlyOk = FALSE
    s2 = s2
    s1 = s1

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
\* Generated on Mon Oct 05 13:51:26 UTC 2026