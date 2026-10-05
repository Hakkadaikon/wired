# MoqtVerCtl: TLC results (ledger 7-1 (a))

TLC2 2026.10.04 was run with `-workers 1`. Logs are in `logs/<cfg>.out`. Code was
read at HEAD `206c185`.

## Invariants and properties

**Safety invariants:**

- `TypeOK`
- `VersionAgree`: both ends hold the same version, and legacy mode holds exactly when there is no token.
- `BindingAgree`: the hub uses a uni control stream exactly when a known token was negotiated.
- `SetupFirst`: on a token session, the peer's SETUP is the first control message the hub acts on.
- `OneSetup`: a second SETUP closes the session.
- `NoEarlyRequest`: no request is processed before the hub's SETUP has gone out and, on a token session, before the peer's SETUP has arrived. This is judged from the spec condition, not from the C hold gate.
- `SentInPeerVersion`: every message to p is encoded in p's version, and nothing is sent before the hub's own SETUP.

**Action property:** `VersionFixed`: the negotiated version never changes once chosen.

**Liveness under weak fairness:**

- `EventuallyEstablished`: a token session eventually becomes established or closed.
- `RequestAnswered`: the client's request is eventually processed or the session closed.

## Runs

| cfg | constants | states generated / distinct / depth | result |
|-----|-----------|-------------------------------------|--------|
| `MC_base` | Peers={p1,p2}; 8 offers (empty, 18, 19, 22, 22+19, 19+18, 17, 17+22); scripts `S,M` and `S,S` | 127,449 / 32,041 / 11 | **No error.** All 7 invariants, VersionFixed and both liveness properties hold. |
| `MC_split` | p1; offers 19 or 22; scripts `S,M` and `H,R,M` | 139 / 61 / 7 | **Violated:** `EventuallyEstablished` and `RequestAnswered`. See below. |
| `MC_splitfix` | `MC_split` with `FixSplit=TRUE` (wait for the whole varint, then classify) | 107 / 45 / 6 | **No error.** The proposed fix restores both liveness properties. |
| `MC_misconfig` | ServerList = 17,19 (contains a token moqver does not know) | 3 / 3 / 2 | **Violated:** `VersionAgree` (client 17, hub 19). This is a latent hazard only. |
| `MC_mut_gate` | mutation: a token session uses the legacy hold gate | 14 / 13 / 4 | **Violated:** `NoEarlyRequest`. The mutation is killed, so the invariant is not vacuous. |

## Findings

### F-A1 (real, liveness): a client control stream split inside SETUP's Type varint never establishes

Counterexample trace (`logs/split.out`):

1. The client connects with `moqt-22`. The token session and the hub's uni control stream are both set up.
2. The first delivery on the client's uni control stream is the single byte `0xAF`, the first byte of the 2-byte vi64 for 0x2F00.
3. `moqdata_classify` returns INSUFFICIENT, which is not CONTROL. The stream is not adopted.
4. `moqtrun_hold_gate` is closed (not established), so the byte goes into the hold log.
5. The hub's SETUP goes out.
6. The client's request arrives and is held.
7. The rest of the SETUP arrives. `moqtrun_hold_has` (:6082) sends it to the hold log as well.
8. Setup never completes, so the hold never replays. The hub never sees the client's SETUP, and every request is held until the hold buffer overflows (`EXCESSIVE_LOAD`).

The same pattern exists on the bidi path: `moqtrun_bidi_is_setup` at :6318 runs `moqvi_take` on a 1-byte delivery. RFC 9000 §2.2 allows this split, and srvrun delivers each contiguous delta (srvrun.c:2408). Self-loopback tests always send SETUP in one call, so they cannot see this. Details are in `counterexample.feature`.

### F-A2 (latent, not a current bug)

If srvrun's `wt_protocols` ever listed a token that `moqver_table` does not know, the hub would send `WT-Protocol: moqt-NN` and then speak legacy draft-19 (`moqtrun_negotiated_ver` and `moqtrun_legacy_token`). The only caller builds the list with `wired_moqt_wt_protocols` (`examples/moqt_interop/wired_server.c:151`), so this cannot happen today.

### Holds as modeled

Version agreement, a fixed version, uni-iff-token, SETUP-first on token sessions, single SETUP, buffering before establishment, and per-peer encoding all hold.

The legacy browser session acts on control messages without any SETUP. That is the documented ruling 9-3 exemption, so it is excluded from `SetupFirst` by design.
