# MoqtVerCtl: requirements and variables (ledger 7-1 (a))

Scope: version negotiation and the control-stream pair (ledger 1-1). Spec text is in
`tasks/specs/draft-ietf-moq-transport-{18,19,22}.txt`. Code was read from the main
tree at HEAD `206c185` (2026-10-05).

## Spec requirements

| id | level | text (section) |
|----|-------|----------------|
| V1 | MUST (mechanism) | The version is negotiated only through ALPN or `WT-Available-Protocols`. The token is `moqt-NN`. SETUP carries no version. (18 §3.1 l.1272, 19 §3.1 l.1321, 22 §6.2 l.2475) |
| V2 | — | SETUP (0x2F00) is the same message in 18, 19 and 22 (18 §10.3, 19 §10.3, 22 §9.1). |
| C1 | MUST | Each peer opens one unidirectional control stream that begins with SETUP. (19 §3.3 l.1525, 22 §6.3 l.2527) |
| C2 | MUST | SETUP is the first message each endpoint sends on its control stream. (22 §9.1 l.3886, 19 §10.3) |
| C3 | MUST | A control stream is never closed at the transport layer. Closing one is a PROTOCOL_VIOLATION. (22 §6.3) |
| C4 | SHOULD | Requests and Object streams that arrive before setup completes are buffered until "both control streams arrive and setup is complete". (22 §6.3) |
| C5 | MUST | An unknown unidirectional stream type closes the session. (22 §6.4.1) |
| C6 | — | A second control stream or a second SETUP is a PROTOCOL_VIOLATION. wired implements this in `moqsess` and `moqtrun_second_ctl`. |
| T1 | transport | A STREAM-frame boundary is not preserved on delivery (RFC 9000 §2.2), so a peer's SETUP can arrive split at any byte. |
| W1 | ruling 9-3 | A session with no token, such as a browser, uses the legacy single bidirectional stream and sends no SETUP. It is exempt from C1, C2 and C4. |

## Implementation (moqtrun.c @206c185)

- `srvrun_wt_select` (srvrun.c:6214) picks the first client-offered token that appears in the server's list.
- `moqtrun_negotiated_ver` (:251) maps an empty or unlisted token to draft-19.
- `moqtrun_legacy_token` (:259) marks an empty or unlisted token as legacy.
- `moqtrun_ctl_open` (:184) opens a uni stream for a token session and a bidi stream for legacy. If the open is refused, `moqtrun_ctl_retry` tries again later.
- `moqtrun_fresh_uni_ctl` (:5945) adopts a stream only when the first varint of *this delivery* classifies as CONTROL.
- `moqtrun_hold_gate` (:5963): a legacy session is held until `ctl_opened`; a token session is held until `moqsess_established`.
- `moqtrun_dispatch_data_stream` (:6069, hold check at :6082) keeps every later delivery of a held stream held.
- `moqtrun_bidi_is_setup` (:6318) decides the bidi path the same way.

## Model variables

| variable | meaning |
|----------|---------|
| `offer` | client's preference-ordered offer |
| `token` | token both sides learned |
| `hver`, `legacy` | `p->ver` and `p->legacy` |
| `cver` | client's view of the version |
| `hubCtl` | hub's own control stream (none / uni / bidi) |
| `setupRecv`, `nSetup`, `peerCtl`, `asm` | SETUP acceptance and control-stream reassembly |
| `held` | hold log, by stream |
| `ctlQ`, `reqQ` | undelivered chunks, in order within each stream |
| `first` | first control message the hub acted on |
| `reqDone`, `reqEarly` | the client's request was processed / was processed before setup completed |
| `sent` | drafts the hub encoded outgoing messages in |

A control-stream chunk is one of:

- `S`: a delivery starting with SETUP's whole Type varint.
- `H`: a delivery holding only the first byte of that 2-byte varint.
- `R`: the rest of the SETUP after an `H`.
- `M`: any other control message.
