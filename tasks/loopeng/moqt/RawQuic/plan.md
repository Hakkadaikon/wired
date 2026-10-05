# Raw (native) QUIC transport for the wired MoQT hub: plan

Status: plan (2026-10-05). Ledger: `tasks/moqt-multidraft-ledger.md` §13 (13-0).
Read-only survey baseline: main tree at `3070f3d`. No `src/` was edited for this plan.
Spec texts: `tasks/specs/draft-ietf-moq-transport-{18,19,22}.txt`. These were
already present, and every citation below was read from them, not from a search
snippet. Runner: `/home/user/moq-interop-runner` (the Hakkadaikon fork, HEAD `a93b3f1`).

---

## 0. Summary

wired's hub (`src/app/moqt/run/moqtrun.c`) already uses `wired_wt_session*` as
an opaque identity and never reads its fields. Every byte it sends goes through
the `wired_moqt_io` table. A raw-QUIC MoQT session can therefore be added
without a second hub. Four changes are needed:

1. **TLS ALPN layer**: the server learns to select a configured list of
   "raw application" ALPNs (`moqt-22 moqt-19 moqt-18`) beside `h3`/`hq-interop`,
   following the client's preference order. A client that offers `[moqt-18, h3]`
   gets raw MoQT, and one that offers `[h3, moqt-22]` gets WebTransport. One UDP
   port serves both, which matches the spec's dual-ALPN model
   (d18 §3.1.2 end / d19 §3.1.3 / d22 §6.1.2).
2. **Server loop (srvloop/srvrun)**: a connection whose ALPN is raw gets one
   *implicit session* in a WT session slot, created when the handshake is
   confirmed. The connection gets:
   - no HTTP/3 control stream, QPACK streams or SETTINGS;
   - every client stream routed to the session with no WT signal prefix;
   - DATAGRAMs carried without the RFC 9297 quarter-stream-id;
   - stream reset codes sent and received verbatim, without the WT→H3 code
     mapping;
   - session close sent as an application `CONNECTION_CLOSE` (0x1d) carrying
     the MoQT code, instead of `CLOSE_WEBTRANSPORT_SESSION`.
3. **MoQT layer**:
   - a new `src/app/moqt/qraw/` domain (`moqraw_*`) holds the raw-transport
     Setup Option policy: PATH and AUTHORITY are required-to-accept on raw
     QUIC and are a close on WT;
   - a transport-multiplexing `wired_moqt_io` table that prefixes WT signals
     only for WT sessions;
   - a tiny serial hub edit: `wired_moqt_on_session_raw`, a per-peer `raw`
     flag, and delegating `moqtrun_setup_opt_bad` to `moqraw`.
4. **Interop**: the example listens on both ALPNs on one port, and the runner
   fork gains a second relay entry `wired-quic` with `"url": "moqt://relay:4443"`.
   This follows the `aiomoqt-relay` / `aiomoqt-relay-quic` precedent. It unblocks
   the raw-only clients (moqtopus, xquic-draft-18, mlmtest), plus the raw
   column of the dual clients (quic-zig, moq5, aiomoqt and others).

---

## 1. Spec rules (per draft, with section references)

Section numbers differ between drafts. The rules themselves are the same across
18, 19 and 22 unless a row says otherwise. Line numbers refer to the files in
`tasks/specs/`.

| # | Rule | d18 | d19 | d22 |
|---|------|-----|-----|-----|
| R1 | MOQT runs over native QUIC or WebTransport, with the same stream/datagram semantics. Only server identification and connection setup differ. | §3.1 (l.1259) | §3.1 | §6.2 (l.2448) |
| R2 | **The QUIC DATAGRAM extension (RFC 9221) MUST be supported and negotiated** on the QUIC connection used for MOQT. d22 adds "directly over QUIC or over WebTransport on HTTP/3". | §3.1 (l.1264) | §3.1 (l.1313) | §6.2 (l.2456) |
| R3 | **Version negotiation = ALPN** on QUIC, and `WT-Available-Protocols` on WT. The final ALPN is `moqt`; a draft's ALPN is `"moqt-" + NN` (`moqt-18`, `moqt-19`, `moqt-22`). Drafts before -15 used `moq-00` plus SETUP-level version negotiation, which is out of scope. | §3.1 (l.1272-1284) | §3.1 (l.1321-1335) | §6.2 (l.2479-2493) |
| R4 | URI scheme `moqt://authority path-abempty [?query]`. The authority MUST NOT have an empty host. The default port is 443. | §3.1.1, §3.1.2 end | §3.1.1, §3.1.3 | §6.1, §6.1.2 |
| R5 | **Dual-ALPN dereference**: on QUIC the client offers any combination of MOQT ALPNs **and h3** in its ClientHello, in preference order. If the server selects an MOQT ALPN, the connection is native QUIC (R6). If it selects h3, the client does WebTransport. → one UDP port MAY serve both. | §3.1.2 end (l.1353-1361) | §3.1.3 (l.1412-1420) | §6.1.2 (l.2438-2446) |
| R6 | **Native QUIC**: the client connects to the host:port of the authority. The authority, path-abempty and query are sent **in Setup Options** (not in any request). | §3.1.4 (l.1373) | §3.1.5 (l.1432) | §6.2.2 (l.2505) |
| R7 | **Control streams = a pair of uni streams.** Each peer opens one, starting with SETUP; the stream type 0x2F00 is the SETUP Type varint itself. Requests use bidi streams (7 request types). Objects use uni streams. Streams that arrive before the control streams SHOULD be buffered or MAY be reset. Closing a control stream at the transport layer means PROTOCOL_VIOLATION. Unknown uni stream type → close the session. | §3.3, §3.4 | §3.3, §3.4 | §6.3, §6.4.1, §6.4.2 |
| R8 | **AUTHORITY Setup Option (type 0x05)**: client only, native QUIC only. Received from a server, received over WT, or naming an authority the server does not support → close with **INVALID_AUTHORITY (0x19)**. A client connecting via a `moqt` URI **MUST** set it to the URI's authority. Not RFC 3986-conformant → **MALFORMED_AUTHORITY (0x1A)**. | §10.3.1.1 (l.3554) | §10.3.1.1 (l.3890) | §9.1.1 (l.3930) |
| R9 | **PATH Setup Option (type 0x01)**: client only, native QUIC only. Received from a server, over WT, or naming an unsupported path → **INVALID_PATH (0x8)**. The client MUST set it to path-abempty, plus `?query` when a query is present. Not conformant → **MALFORMED_PATH (0x9)**. | §10.3.1.2 (l.3571) | §10.3.1.2 (l.3907) | §9.1.2 (l.3947) |
| R10 | **Termination**: on native QUIC the session is closed with a **CONNECTION_CLOSE frame** (RFC 9000 §19.19); on WT it is closed with `CLOSE_WEBTRANSPORT_SESSION`. The codes are the MoQT Session Termination codes (0x0 NO_ERROR, 0x1 INTERNAL, 0x2 UNAUTHORIZED, 0x3 PROTOCOL_VIOLATION, 0x4 INVALID_REQUEST_ID, 0x5 DUPLICATE_TRACK_ALIAS, 0x6 KVP_FORMAT, 0x8/0x9 PATH, 0x10 GOAWAY_TIMEOUT, 0x11/0x12 timeouts, 0x13-0x18 auth, 0x19/0x1A AUTHORITY, d19+/d22: 0x1B TOO_MANY_REQUEST_UPDATES). On raw QUIC this is the application-variant CONNECTION_CLOSE (type 0x1d), whose Error Code is the MoQT code itself. | §3.5 (l.1688ff) | §3.5 (l.1762) | §6.6 (l.2818), codes §12.2 (l.6733) |
| R11 | **VERSION_NEGOTIATION_FAILED (0x15)** exists in d18/d19 and was **removed in d22** (#1867, changelog A.3 l.8467). On raw QUIC, a client offering no ALPN the server supports never reaches MoQT: the server fails TLS with `no_application_protocol` (RFC 7301 §3.2; RFC 9001 §8.1 → CONNECTION_CLOSE 0x0100+120 = **0x178**). | §3.5 | §3.5 | (removed) |
| R12 | **Stream reset / STOP_SENDING codes** (0x0 INTERNAL, 0x1 CANCELLED, 0x2 DELIVERY_TIMEOUT, 0x3 SESSION_CLOSED, 0x4 GOING_AWAY, 0x5 TOO_FAR_BEHIND, 0x6 UNKNOWN_OBJECT_STATUS, 0x7 EXPIRED_AUTH_TOKEN, 0x9 EXCESSIVE_LOAD, 0x12 MALFORMED_TRACK). On raw QUIC they go **directly** into the RESET_STREAM/STOP_SENDING Application Error Code. On WT the HTTP/3 mapping applies (webtrans-http3 §4.4: `0x52e4a40fa8db + n + floor(n/0x1e)`). This is an implementation fact of the WT binding, not of MoQT. | §3.3.3 | §3.3.4 (l.1685) | §12.5 (l.6955) |
| R13 | An unknown error code in any context MUST be treated as INTERNAL_ERROR for that context. Never close solely because of an unknown code. | (implicit) | (implicit) | §13 (grease, l.7035) |
| R14 | **Datagrams**: one Object per QUIC DATAGRAM, carrying OBJECT_DATAGRAM as is. A datagram larger than the session's max datagram size is dropped silently. On WT, the HTTP Datagram's quarter-stream-id prefix (RFC 9297 §2.1) belongs to the WT binding. On raw QUIC there is **no prefix**. | §11.3 | §11.3 (l.5509) | §11.2 (l.6036) |
| R15 | **GOAWAY**: a server's New Session URI is optional, zero-length means "reuse the current URI", and the URI "SHOULD use the same scheme as the current URI". The maximum is 8,192 bytes. A client MUST send zero length. Timeout, then GOAWAY_TIMEOUT. d18 also has a Request ID. There is no transport-level drain on raw QUIC (WT has `WT_DRAIN_SESSION`). | §3.6, §10.4 (l.3661-3718) | §3.6, §10.4 (l.4042-4099) | §6.6.1, §9.2 (l.4076-4133) |
| R16 | **0-RTT**: allowed on native QUIC, and not expected on WT (CONNECT is unsafe). MoQT messages are mostly replay-safe. "Relays MAY defer initiating upstream subscriptions until the handshake is complete or reject 0-RTT entirely." | §3.3.1 | §3.3.1 | §6.3.1 |
| R17 | **Flow control**: on raw QUIC there is only QUIC-level MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS. On WT there are also the WT_MAX_DATA / WT_MAX_STREAMS session capsules. MoQT itself defines no extra credit (MAX_REQUEST_UPDATES in d19/d22 is per request stream and is transport-neutral). | (QUIC) | (QUIC) | (QUIC) |

Consequences for wired (each one becomes a requirement below):

- **REQ-A (R3, R5)**: TLS ALPN selection must accept `moqt-NN` from a
  configured list, in client-preference order, mixed with `h3`. No overlap → the
  existing handshake failure (`no_application_protocol`).
- **REQ-B (R6, R8, R9)**: on raw QUIC, the hub must **accept** client
  PATH/AUTHORITY. Today `moqtrun_setup_opt_bad` (`moqtrun.c:3869`) closes any
  session that carries them, which is right on WT but would kill every
  conforming raw client on the first SETUP. Malformed values close with
  0x9/0x1A, and an unsupported value closes with 0x8/0x19. Policy: accept every
  well-formed path/authority by default, with an optional app hook.
- **REQ-C (R7)**: on raw QUIC, server uni stream ids start at 3 (no H3
  control/QPACK). The client's control stream is its first uni stream (id 2 by
  convention, but never assumed). Request streams are `id % 4 == 0`, which the
  hub already uses (`moqtrun.c:6123`).
- **REQ-D (R10, R11)**: a session close on raw QUIC is `CONNECTION_CLOSE`
  (0x1d, code = MoQT code, reason phrase ≤ path budget).
- **REQ-E (R12, R13)**: raw resets carry MoQT codes unmapped in both
  directions. A received code > u32 or unknown counts as INTERNAL_ERROR.
- **REQ-F (R2, R14)**: raw datagrams carry no qsid. The server must advertise
  `max_datagram_frame_size` on raw connections (it already does when
  `wired_srvboot_id.max_datagram_frame_size` is set). If the peer did not
  advertise it, nothing is sent (srvrun's existing size gate).
- **REQ-G (R15)**: GOAWAY's URI is one app-supplied string for all sessions.
  Document that d18+ clients treat `moqt://` as canonical for both transports.
  There is no WT_DRAIN_SESSION input on raw.
- **REQ-H (R16)**: phase 1 refuses 0-RTT on raw MoQT ALPNs, which the spec
  explicitly permits for relays. Accepting it is a later ledger item.

---

## 2. Runner integration (moq-interop-runner fork)

### 2.1 How the runner picks the relay URL today

- Docker mode (`run-interop-tests.sh` `list_endpoints`, l.304-344) emits one
  `docker|<image>` endpoint per relay. `make test` → `RESOLVE_RELAY_URL`
  (`Makefile` l.45-60) looks up `roles.relay.docker.url` **by image name**
  (`select(.value.roles.relay.docker.image == $image) | head -n1`) and passes it
  as `RELAY_URL` to the client container (`docker-compose.test.yml`, which
  defaults to `https://relay:4443`).
- Remote mode: one run per `roles.relay.remote[]` entry, each with
  `{url, transport: quic|webtransport}`. Transport filters apply only here.
- Schema (`implementations.schema.json`): `docker_config.url` is a single
  string `^(https://|moqt://)...`. The only way to get two docker transports is
  **two implementation entries with two different images**, which is what
  `aiomoqt-relay` + `aiomoqt-relay-quic` do. `moqlivemock` instead registers
  only `moqt://` on a dual-port relay, which hides its WT side.
- `docs/TEST-CLIENT-INTERFACE.md` "URL Schemes" and
  `docs/decisions/003-url-scheme-transport-selection.md`: clients still use the
  scheme as the transport selector. `https://` is the legacy WT locator and
  `moqt://` means native QUIC (for d18+ it is canonical for both).

### 2.2 Client transport capabilities (probed from the local images, 2026-10-05)

| Client | Drafts | Transport | Evidence |
|--------|--------|-----------|----------|
| moqtopus | d18 | **raw QUIC only** (ALPN `moqt-18`) | binary string "moqtopus only supports raw QUIC relay URLs using moqt://". `--list` prints 1..6 cases. Image default `RELAY_URL=moqt://relay:4443` |
| xquic-draft-18 | d18 | **raw QUIC only for d18 cases** | "error: draft-18 interop cases currently support raw QUIC (moqt://) only". 6 cases: setup-only, announce-only, publish-namespace-done, subscribe-error, announce-subscribe, subscribe-before-announce (`docs/XQUIC-DRAFT18.md`) |
| moqlivemock `mlmtest` | d18 | **raw QUIC** | registry note "registered with a moqt:// URL because mlmtest dials raw QUIC". `-r "Relay URL (moqt:// for QUIC)"` |
| quic-zig | d17, d18 (ALPN `moqt-17`, `moqt-18`) | both, chosen by scheme (`Peer(.quic)` / `Peer(.webtransport)`) | 7 cases incl. rendezvous-timeout |
| moq5 | d16, d18 | both by scheme. Some backends are raw-only ("backend … is raw-QUIC only; use a moqt:// relay URL") | binary strings |
| aiomoqt | d14/16/18 | both by scheme (`moqt://` handling in `aiomoqt.tools.moq_interop_client`) | python package grep |
| moq-rs-draft-18, moq-dev-rs, stitcher, imquic, moqx, moxygen, moq-playa, moq-dev-js | various | WT today against wired. The raw column is still to be probed for each one in step S11 | — |

### 2.3 Proposed fork change (`implementations.json`)

Keep `wired` (WT, `https://`) unchanged so the WT column keeps its coverage, and
add:

```json
"wired-quic": {
  "name": "wired (relay, raw QUIC)",
  "organization": "Hakkadaikon",
  "repository": "https://github.com/Hakkadaikon/wired",
  "draft_versions": ["draft-22", "draft-19", "draft-18"],
  "notes": "Same wired binary as `wired`; one UDP port serves both h3 (WebTransport) and ALPN moqt-22/moqt-19/moqt-18 (raw QUIC). Registered separately so docker mode exercises the moqt:// transport.",
  "roles": {
    "relay": {
      "docker": {
        "image": "ghcr.io/hakkadaikon/wired-moqt-interop-quic:latest",
        "url": "moqt://relay:4443",
        "notes": "Re-tag of ghcr.io/hakkadaikon/wired-moqt-interop (identical image); the separate tag exists only because RESOLVE_RELAY_URL keys the URL on the image name."
      }
    }
  }
}
```

Also update `wired.notes`: remove "WebTransport only" and replace it with "WT
entry; see wired-quic for raw QUIC". The image is a plain re-tag
(`docker tag ghcr.io/hakkadaikon/wired-moqt-interop:latest
ghcr.io/hakkadaikon/wired-moqt-interop-quic:latest`). Both entries run the same
dual-ALPN binary, so no second Dockerfile is needed. Optional future step: when
runner Phase 2 (decision 003, an explicit transport constraint env) lands, fold
`wired-quic` back into one entry.

Clients and cases that become runnable against `wired-quic` (docker):

- moqtopus: its 6 cases. xquic-draft-18: 6 core cases. mlmtest: its d18 list.
- quic-zig: 7 cases including rendezvous-timeout, which depends on ledger 12-1.
- moq5, aiomoqt: d18 cases.
- Cases that depend on 12-1/12-2/12-3 (rendezvous, PUBLISH_DONE forwarding,
  upstream SUBSCRIBE) fail on raw QUIC for the same hub reasons as on WT.
  Record them as hub-caused, not transport-caused.

### 2.4 Endpoint script / image

- `interop/run_endpoint_moqt.sh`: there are no new flags in the default path.
  The binary always serves both ALPN sets. Optional env `MOQT_TRANSPORT=wt|quic|both`
  (default `both`) maps to `--no-raw` / `--no-h3` for debugging single-transport
  behaviour.
- `interop/Dockerfile.moqt`: update the header comment only (it lists the
  transports). The image is unchanged.

---

## 3. wired's current server path (survey findings)

### 3.1 ALPN

- `src/tls/ext/salpn/negotiate.{h,c}`: `salpn_choice` is a closed enum
  `{SALPN_NONE, SALPN_H3, SALPN_HQ}`. `salpn_negotiate` walks the client's
  ProtocolNameList in **client order** and returns the first that is h3 or
  hq-interop. `salpn_build_response` hard-codes the two names.
- `src/tls/handshake/core/sdrv/sdrv.c:425` `sdrv_negotiate_alpn` stores
  `s->alpn`. `eebuild` (EncryptedExtensions) takes a `salpn_choice`.
  `resume.h` records the negotiated ALPN in tickets
  (`resume_alpn_compatible`, RFC 8446 §4.6.1).
- ALPN-gated server behaviour today:
  - `srvloop/respond.c:67` opens the H3 control stream/SETTINGS only for
    `SALPN_H3`, so a raw ALPN already suppresses it.
  - `srvrun.c:4165` sends H3 GOAWAY only on h3.
  - `dispatch.c:1313/1356/1378` and `srvrun.c:6611` handle hq-interop request
    shaping.
  - `alpnver.h` (RFC 9368 compatibility) knows only h3 and has no callers.
- **One UDP port can serve both h3 and moqt-NN** once the enum grows a raw
  member. Selection is per connection, inside the TLS handshake.

### 3.2 How streams/datagrams reach the app (WT only today)

- `srvloop/dispatch.c` classifies every client STREAM frame for the HTTP/3 world:
  - bidi with leading 0x41 → `wt_streams[]`, otherwise an H3 request;
  - uni with leading 0x54 → `wt_uni_streams[]`, otherwise an H3 control/QPACK
    type;
  - DATAGRAM → `rx_datagrams`.
- `srvrun.c` then strips the signal + session id, maps the stream to the
  `wired_wt_session` slot, and calls `wt_on_stream_data(app_ctx, s, id, data, fin)`.
  It parses the RFC 9297 qsid off each datagram (`srvrun.c:2601`, a bad qsid
  closes the connection) and calls `wt_on_datagram`.
- There is **no raw-QUIC app API**. hq-interop (`hq09`) is the only non-h3
  protocol and is wired inside the h3 request path (GET line), so it is a
  precedent for ALPN branching but not a stream API.
- WT sessions are slots inside `srvrun_conn` (`SRVRUN_MAX_WT_SESSIONS 2` per
  connection). `srvrun_session_conn(s)` maps a `wired_wt_session*` back to its
  connection.

### 3.3 `wired_moqt_io` for WT (`examples/moqt_interop/wired_server.c`)

- The op table (`moqtrun.h:39-138`) has 14 entries:
  `open_bidi_stream, stream_send, send_uni, open_uni_stream, stream_fin,
  stream_reset, send_uni2, send_datagram, stream_hold, send_budget,
  close_session, stream_reply_open, stream_priority, stream_stop`.
- The example maps each one to `wired_server_wt_*`, and **the example itself**
  prefixes the WT stream signal (`open_signalled`, `wired_wtwire_signal_put`)
  on the three stream-opening entries.
- `send_budget` reads `s->max_data/sent_data` (WT_MAX_DATA).
- `srvrun` itself applies the WT-binding transforms:
  - qsid prefix on `wired_server_wt_send_datagram_to` (`srvrun_dgring_fill`,
    `srvrun.c:5262`);
  - `wired_wterrmap_to_http3` on resets (`srvrun.c:3739`), and
    `wired_wterrmap_from_http3` on received resets (`srvrun.c:3836`, which
    yields `mapped`);
  - `CLOSE_WEBTRANSPORT_SESSION` capsule on `wired_server_wt_close_session`
    (`srvrun.c:5378`).

### 3.4 Every place that assumes WebTransport

Hub (`src/app/moqt/run/`):

| # | Where | Assumption | Raw-QUIC change |
|---|-------|-----------|-----------------|
| H1 | `moqtrun.c:3867-3872` `moqtrun_setup_opt_bad` | PATH/AUTHORITY always mean close (correct only on WT) | per-peer `raw`. Raw → `moqraw_setup_verdict` (accept well-formed, 0x9/0x1A malformed, 0x8/0x19 hook-refused) |
| H2 | `moqtrun.c:275` `wired_moqt_on_session(app_ctx, s, path, protocol)` | session comes from an Extended CONNECT. `protocol` is the WT subprotocol. An empty or unlisted token means `legacy` (bidi control, `moqtrun.c:270`) | new `wired_moqt_on_session_raw(app_ctx, s, alpn)`: same init with `raw=1, legacy=0`. ALPN `moqt-NN` → `moqver_find` (same tokens) |
| H3 | `moqtrun.h:40-138` io docs | "WT" wording; `close_session` = WT_CLOSE_SESSION; `send_budget` = WT_MAX_DATA | semantics unchanged. Docs become transport-neutral. The backend decides the wire form |
| H4 | `moqtrun.c:1110` `wired_moqt_on_session_draining` | WT_DRAIN_SESSION is the only peer-drain input | none on raw (R15). No change |
| H5 | `moqtrun.c:177` comment "io open ops prefix the WT signal" | — | the backend mux prefixes only WT sessions |
| H6 | `wired_moqt_goaway(new_uri)` | one URI for all sessions | unchanged (REQ-G). Documented |
| H7 | `wired_moqt_on_stream_reset(…, mapped, app_error_code)` | mapped/app code unused | unchanged. Raw sets mapped=1 with the raw code |
| H8 | `moqtrun.c:6123` `(stream_id & 3) == 0` request stream | RFC 9000 numbering. Valid on raw | none |
| H9 | `wired_moqt_on_datagram` doc "close not possible" | — | none (the io now has close_session, already used elsewhere) |

Server (`src/app/http3/server/`):

| # | Where | Assumption | Raw change |
|---|-------|-----------|-----------|
| S1 | `srvrun.c:4552` `srvrun_next_uni_id` = `11 + 4*n` | ids 3/7 are the H3 control/QPACK streams | raw: `3 + 4*n`. Skipping would implicitly open 3 and 7 on the peer (RFC 9000 §3.2) and burn its MAX_STREAMS_UNI |
| S2 | `srvrun.c:5254` datagram gate `l.h3.settings_sent`; `srvrun.c:4205` same gate | h3 SETTINGS precede any datagram/WT send | raw: gate on "raw session established" |
| S3 | `srvrun.c:5262` qsid prefix on send; `srvrun.c:2601` qsid parse on receive (bad → H3_DATAGRAM_ERROR close) | RFC 9297 framing | raw: no prefix. The whole payload goes to the single raw session |
| S4 | `srvrun.c:3739` `wterrmap_to_http3`; `srvrun.c:3836` `wterrmap_from_http3` | WT error-space mapping | raw: identity (`rawq_reset_code_out/in`) |
| S5 | `srvrun.c:5378` close → WT capsule on CONNECT stream | WT termination | raw: `srvrun_send_app_close` (0x1d, `srvrun.c:2004-2040` already exists) with the MoQT code + reason, then teardown → `wt_on_session_close` once |
| S6 | `srvrun.c:6290` `srvrun_start_wt` | session born from CONNECT 2xx; `connect_stream_id` = identity; limits from SETTINGS_WT_* | raw: born at handshake confirmation. `connect_stream_id` = a sentinel (e.g. `(u64)-1`, never used on the wire). `flow_control = 0` (no WT credit) |
| S7 | `dispatch.c` 0x41/0x54 classification; uni-type/QPACK parsing; request path | HTTP/3 stream world | raw: every client bidi → `wt_streams[]` slot with `sig_len 0`; every client uni → `wt_uni_streams[]` slot with `sig_len 0`; never the request/QPACK paths |
| S8 | `srvrun.c:702/4066` QPACK encoder stream opened after SETTINGS | h3 | never on raw (follows from S2) |
| S9 | boot/idle reaping keyed on h3 progress (check `srvrun_boot_overdue`, `settings_sent`) | an h3-only notion of "app is live" | raw: confirmed handshake counts as live |
| S10 | example `io_send_budget` reads `max_data` | WT credit | raw: `(usz)-1`. QUIC MAX_DATA gating stays inside srvrun's own send credit. Risk K5 |
| S11 | 0-RTT accepted for any ALPN with a compatible ticket (`resume_alpn_compatible`) | h3 replay rules | raw: refuse early data for raw ALPNs (REQ-H) |

---

## 4. Architecture

### 4.1 Layering (MECE; one responsibility per directory)

```
 tls/ext/salpn/        (+ salpn_raw.c)   ALPN: pick h3 | hq | raw-token from a configured list
 tls/handshake/...     (sdrv, eebuild)   carry the chosen raw token into EncryptedExtensions,
                                          tickets; refuse 0-RTT for raw
 app/rawquic/          NEW  rawq_*       pure transport-binding helpers: stream routing kind,
                                          reset-code in/out, datagram framing, close kind
 app/http3/server/srvloop  (dispatch.c)  route raw-ALPN streams into wt slot tables, sig_len 0
 app/http3/server/srvrun   (srvrun.c/.h) implicit raw session lifecycle; raw branches in the
                                          WT send API; new opt.raw_on_session; is_raw query
 app/moqt/qraw/        NEW  moqraw_*     MoQT-over-raw-QUIC policy: Setup Option verdict
                                          (PATH/AUTHORITY RFC 3986 checks) + transport-mux
                                          wired_moqt_io (WT signal prefix only for WT)
 app/moqt/run/         (moqtrun.c/.h)    +on_session_raw, +peer.raw, setup verdict delegate
 examples/moqt_interop, interop/          serve both ALPNs; use the mux io table
```

Why an *implicit session* in srvrun rather than a separate `wired_server_raw_*`
API: the WT send machinery (`srvrun_wtsend` slots, stream credit, pacing,
loss/ACK, hold, priority, reset latch, datagram ring) is about 3k lines of
already-proven code. A parallel raw API would duplicate all of it. The
differences are confined to five binding transforms (S1-S5), which are pure
functions in `rawq_*` plus one `raw` bit per connection. The hub keeps a single
session type, so no `moqtrun.c` refactor is needed while other agents are
editing it.

### 4.2 Names (uniqueness checked with `grep -rn` over `src tests examples` on 2026-10-05: all 0 hits)

| Name | Kind | Owner file |
|------|------|-----------|
| `SALPN_RAW` | enum member in `salpn_choice` | `tls/ext/salpn/negotiate.h` |
| `salpn_raw_pick`, `salpn_raw_list_has` | fns | `tls/ext/salpn/salpn_raw.{h,c}` (new) |
| `salpn_negotiate_raw` | fn (generalized negotiate) | `tls/ext/salpn/negotiate.c` |
| `salpn_build_response_tok` | fn | `tls/ext/salpn/negotiate.c` |
| `rawq_*` (`rawq_route`, `rawq_reset_code_out`, `rawq_reset_code_in`, `rawq_dgram_prefix_len`, `rawq_uni_first_id`, `RAWQ_*` consts) | fns/macros | `app/rawquic/rawq.{h,c}` (new) |
| `moqraw_setup_verdict`, `moqraw_path_ok`, `moqraw_authority_ok`, `moqraw_policy` | fns/type | `app/moqt/qraw/moqraw.{h,c}` (new) |
| `moqraw_io_*` statics + `wired_moqraw_io` (returns a filled `wired_moqt_io`) | fns | `app/moqt/qraw/moqrawio.{h,c}` (new) |
| `wired_moqt_on_session_raw` | public hub fn | `app/moqt/run/moqtrun.{h,c}` |
| `wired_rawq_on_session` | callback typedef | `app/http3/server/srvrun/srvrun.h` |
| `wired_srvrun_opt.raw_on_session`, `.raw_session_ctx` | opt fields | srvrun.h |
| `wired_srvboot_id.raw_alpns` | `const char*` (space-separated, 0 = off) | srvboot.h |
| `wired_server_session_is_raw` | public fn | srvrun.h |

`wired_*` names are app-facing, so `docs/api-stability.md` needs new rows (S12).
Before coding, re-run `grep -rn '<name>' src/` for every name in this table, in
case another branch has landed in the meantime.

### 4.3 The `wired_moqt_io` raw backend (`app/moqt/qraw/moqrawio.c`)

One table serves both transports, so the hub never branches on transport for
I/O:

| op | WT session | raw session |
|----|-----------|-------------|
| `open_bidi_stream` | signal(0x41, sid) + payload → `wired_server_wt_open_bidi_stream` | (never called: raw is never legacy) → `-1` |
| `send_uni` / `open_uni_stream` | signal(0x54, sid) + payload → `wired_server_wt_open_uni[_stream]` | payload as is → the same srvrun fns (srvrun picks id 3+4n) |
| `send_uni2` | 0 (unchanged) | 0 |
| `stream_send`, `stream_fin`, `stream_hold`, `stream_priority`, `stream_reply_open` | srvrun as today | identical (srvrun calls are transport-neutral once the stream exists) |
| `stream_reset`, `stream_stop` | srvrun (srvrun maps through wterrmap) | srvrun (raw: identity via `rawq_reset_code_out`) |
| `send_datagram` | srvrun (srvrun prefixes qsid) | srvrun (raw: no prefix) |
| `send_budget` | WT_MAX_DATA remainder | `(usz)-1`. QUIC MAX_DATA is enforced by srvrun send credit (K5) |
| `close_session` | WT capsule | srvrun → CONNECTION_CLOSE 0x1d |

The only branch inside the mux is "prefix a signal or not", which uses
`wired_server_session_is_raw(s)` and keeps CCN at 1. Both examples
(`moqt_interop`, and later `moqt_chat`) can drop their private
`open_signalled` copies and use `wired_moqraw_io()`. That deduplicates per
naming-and-unity-build.md.

### 4.4 ALPN dispatch in the server

- `wired_srvboot_id.raw_alpns = "moqt-22 moqt-19 moqt-18"`. The example builds
  this string with the existing `wired_moqt_wt_protocols` (same tokens, same
  order, one table: moqver).
- `sdrv_negotiate_alpn` → `salpn_negotiate_raw(ext, raw_list, &tok)`: first
  client-offered entry that is `h3`, `hq-interop`, or a member of `raw_list`.
  `tok` is a view into the static config string, so it outlives the
  connection.
- EE builds the ALPN response from `tok`, and the ticket remembers `tok`.
- `SALPN_RAW` → srvloop routes raw (S7). srvrun creates the implicit session
  when `wired_server_is_confirmed` first becomes 1, then calls
  `opt.raw_on_session(ctx, s, tok)` **before** delivering any stream byte of
  that step (TLA+ invariant SessBeforeData).

### 4.5 examples / interop

- `examples/moqt_interop/wired_server.c`:
  - `id.raw_alpns = <wired_moqt_wt_protocols string>`;
  - `opt.run.raw_on_session = wired_moqt_on_session_raw`;
  - `g_io = wired_moqraw_io()`;
  - keep every existing `wt_*` hook (`on_stream_data`, `on_datagram`,
    `on_stream_reset`, `on_session_close` are shared, because raw sessions
    arrive through the same callbacks);
  - CLI `--no-raw`/`--no-h3` (debug).
- `interop/run_endpoint_moqt.sh`: optional `MOQT_TRANSPORT` → the flags above.
- Runner fork: §2.3.

---

## 5. State machines and the verification layer

Layer choice (rfc-and-verification-layers.md):

| Concern | Layer | Why |
|---------|-------|-----|
| Connection → raw session lifecycle (create on confirm, deliver, close by hub/peer/idle, slot reuse) | **TLA+** | ordering + multiple concurrent actors (peer, srvrun step, hub, idle sweep); the pointer-reuse hazard is a known failure class (`srvrun.h` on_session_close doc) |
| Close/error code mapping, ALPN pick, PATH/AUTHORITY syntax | **TDD** (exhaustive tables) | total pure functions, no state; Lean would be over-engineering |
| MoQT session (SETUP pair, request streams) | existing models (`MoqtSessionMV`, `MoqtVerCtl`) | transport-neutral, unchanged; only the "WT ⇒ PATH is a close" guard becomes "transport-dependent", which is added as a parameter in MoqtRawConn below |

### 5.1 Model `MoqtRawConn` (to write in `tasks/loopeng/moqt/RawQuic/`)

```tla
---------------------------- MODULE MoqtRawConn ----------------------------
EXTENDS Naturals, Sequences, FiniteSets
CONSTANTS Conns,          \* connection attempts reusing ONE session slot memory
          Alpns,          \* {"h3","moqt-18","moqt-19","moqt-22","none"}
          RawList,        \* server raw_alpns
          SetupOpts       \* subsets of {"PATH","AUTH","BADPATH","BADAUTH"}
VARIABLES conn,    \* [c \in Conns |-> "idle"|"hs"|"confirmed"|"closing"|"gone"]
          alpn,    \* chosen ALPN per conn
          sess,    \* slot owner: Conns \cup {None}
          hub,     \* [c |-> "none"|"setup_wait"|"established"|"closed"]
          appEv,   \* sequence of app callbacks <<kind, c>> (session/data/close)
          wire     \* frames emitted to peer: CONNECTION_CLOSE(code) / CLOSE_WT(code) / H3CTRL
Transport(c) == IF alpn[c] \in RawList THEN "raw" ELSE IF alpn[c]="h3" THEN "wt" ELSE "none"
\* Actions:
\*  ClientHello(c, offer)     -> alpn[c] := first(offer \cap ({"h3"} \cup RawList)) or "none"
\*  NoAlpn(c)                 -> wire += TLS alert 0x178 ; conn[c] := "gone"   (R11)
\*  Confirm(c)  [raw]         -> sess := c ; append <<"session",c>> ; hub[c] := "setup_wait"
\*  PeerStream(c, kind)       -> if hub[c]="none" then buffer else append <<"data",c>>
\*  PeerSetup(c, opts)        -> verdict(Transport(c), opts) : accept | close(code)
\*  HubClose(c, code)         -> wire += CONNECTION_CLOSE(code) [raw] / CLOSE_WT(code) [wt];
\*                               conn[c]:="closing"
\*  PeerClose(c) / Idle(c)    -> conn[c]:="gone"
\*  Teardown(c)               -> append <<"close",c>> once ; sess := None
\*  Reuse(c2)                 -> a later conn claims the same slot memory
\* Safety:
\*  SessBeforeData   == \A i : appEv[i]=<<"data",c>> => \E j<i : appEv[j]=<<"session",c>>
\*  CloseOnce        == \A c : Cardinality({i : appEv[i]=<<"close",c>>}) <= 1
\*  CloseIffSession  == \A c : conn[c]="gone" /\ (<<"session",c>> \in Range(appEv))
\*                                         => <<"close",c>> \in Range(appEv)
\*  NoGhost          == \A i : appEv[i]=<<"data",c>> => no <<"close",c>> before i
\*  NoH3OnRaw        == \A c : Transport(c)="raw" => H3CTRL \notin wire[c]
\*  RawCloseShape    == \A c : Transport(c)="raw" => \A f \in wire[c] : f.kind # "CLOSE_WT"
\*  PathRule         == PeerSetup with PATH on "wt" => close(0x8); on "raw" well-formed => accept
\*  SingleCloseFrame == at most one CONNECTION_CLOSE(code) per conn from the hub path
\* Liveness (WF on Confirm, PeerSetup, Teardown):
\*  <>(raw conn that sent a well-formed SETUP and never closes ~> hub[c]="established")
\*  conn[c]="gone" ~> <<"close",c>> emitted (if session was emitted)
=============================================================================
```

MC configs (same practice as the other MoqtXxx dirs: base, plus one mutation per
safety property, each of which must yield a counter-example):

- `MC_base`: 2 conns, Alpns full, RawList = {18,19,22}, all SetupOpts.
- `MC_mut_late_session`: deliver before Confirm, which must break SessBeforeData.
- `MC_mut_wt_path`: the WT rule applied on raw, which must break liveness
  (reproduces REQ-B).
- `MC_mut_h3ctrl`: SETTINGS gated on `!= HQ` instead of `== H3`, which must
  break NoH3OnRaw.
- `MC_mut_double_close`: hub close and peer close race without the latch, which
  must break CloseOnce.

The counter-examples become Gherkin acceptance specs, and those specs become
tests in §7 (T-L*).

---

## 6. Implementation plan (MECE, parallel → serial)

Rules for every coder:

- Edit only your assigned files. Do NOT `git add`/`commit`, and do not wire
  `tests/run.c` or the `justfile`.
- Verify in `$TMPDIR`. Run `lizard <your file> --CCN 3 -w`.
- `grep src/` for every new name before writing it.
- Emit tool calls as structured calls.
- No push.
- Diagnostics live in ONE probe file and are removed when the cause is
  confirmed.

### Phase 0 (serial, 1 worker): interfaces and model

- **S0a — headers frozen** (planner/aggregator): write the `.h` files for
  `salpn_raw.h`, `rawq.h`, `moqraw.h`, `moqrawio.h`, and the srvrun.h/srvboot.h
  field and decl additions (declarations only), so Phase 1 workers code
  against a fixed API.
  - Effort: 0.5 d.
- **S0b — TLA+ `MoqtRawConn`**: as in §5.1, with mutations and a reviewer pass
  (loop-engineering-reviewer, as for 1-1).
  - Effort: 1 d.

### Phase 1 (parallel, new files only)

| Step | Owner files (new) | Content | Depends | Effort |
|------|-------------------|---------|---------|--------|
| **S1** ALPN pick | `src/tls/ext/salpn/salpn_raw.{h,c}`, `tests/tls/salpn_raw_test.c` | `salpn_raw_list_has(list, name)` (space-separated list, exact byte match, case-sensitive per RFC 7301 §3.1); `salpn_raw_pick(ext, list, &tok)`: client-order walk across h3/hq/raw | S0a | 0.5 d |
| **S2** binding helpers | `src/app/rawquic/rawq.{h,c}`, `tests/app/rawq_test.c` | `rawq_route(raw, stream_id, first_bytes)` → {REQUEST_H3, WT_BIDI, WT_UNI, RAW_BIDI, RAW_UNI, H3_UNI}; `rawq_reset_code_out(raw, app)` (raw: identity / WT: `wired_wterrmap_to_http3`); `rawq_reset_code_in(raw, wire, &app)` (raw: mapped=1 if ≤ u32 / WT: from_http3); `rawq_dgram_prefix_len(raw)`; `rawq_uni_first_id(raw)` (3 / 11) | S0a | 0.5 d |
| **S3** MoQT raw policy | `src/app/moqt/qraw/moqraw.{h,c}`, `tests/app/moqraw_test.c` | `moqraw_setup_verdict(raw, const moqctl_setup*, const moqraw_policy*)` → 0 / 0x8 / 0x9 / 0x19 / 0x1A. RFC 3986 subset: `moqraw_path_ok` (empty, or starts with "/", pchar / "/" / "?" query chars, %HH valid, no "#", no CTL/space/non-ASCII); `moqraw_authority_ok` (non-empty host: reg-name / IPv4 / `[IPv6]`, optional `:port` digits ≤ 65535, optional userinfo@). Policy hook `int (*accept)(ctx, path, authority)`, 0 = accept-all. Table-driven char classes to keep CCN ≤ 3 | S0a | 1 d |
| **S4** io mux | `src/app/moqt/qraw/moqrawio.{h,c}`, `tests/app/moqrawio_test.c` | `wired_moqraw_io()` per §4.3. The signal prefix is applied via `wired_wtwire_signal_put` only when `!wired_server_session_is_raw(s)`. Testability: the unity build links the real srvrun, so `wired_server_*` cannot be stubbed by symbol. Instead the mux goes through an internal `moqrawio_backend` function-pointer struct (open/is_raw/…), which `wired_moqraw_io()` fills with srvrun functions and the test fills with recorders | S0a | 0.5 d |
| **S5** TLA+ to code trace table | `tasks/loopeng/moqt/RawQuic/design.md` | maps each model action and invariant to a file:function and a test id | S0b | 0.25 d |

### Phase 2 (parallel, existing files, one owner each, distinct files)

| Step | Owner files | Content | Depends | Effort |
|------|-------------|---------|---------|--------|
| **S6** TLS plumbing | `tls/ext/salpn/negotiate.{h,c}`, `tls/handshake/core/sdrv/sdrv.{h,c}`, `sdrv_flight.c`, `tls/handshake/roles/eebuild/eebuild.{h,c}`, `tls/handshake/flight/resume/*` (if the token type changes) | `SALPN_RAW`; `sdrv_init_in.raw_alpns`, `sdrv.alpn_tok`; EE ALPN from tok; ticket ALPN = tok; `early_data_accepted = 0` when `alpn == SALPN_RAW` (REQ-H) | S1 | 1 d |
| **S7** srvloop routing | `app/http3/server/srvloop/dispatch.c`, `srvloop.h` | one early branch per STREAM frame: `rawq_route(...)` on `sdrv.alpn == SALPN_RAW` → claim the wt/wt_uni slot with `sig_len = 0`, skip the 0x41/0x54 checks and the request/QPACK paths. DATAGRAM queueing unchanged | S2 | 1-1.5 d |
| **S8** srvboot field | `app/http3/server/srvboot/srvboot.{h,c}` | `wired_srvboot_id.raw_alpns` → `sdrv_init_in.raw_alpns` | S6 header | 0.25 d |

### Phase 3 (serial, single owner of `srvrun.c/.h`)

**S9 — srvrun raw sessions** (depends on S2, S6, S7, S8). Effort: 2 d.

- `opt.raw_on_session` / `raw_session_ctx`; `wired_server_session_is_raw`;
  the raw bit lives in the connection (from `sdrv.alpn`).
- On the first step where `wired_server_is_confirmed` holds and the ALPN is
  raw:
  - claim session slot 0;
  - `wired_wt_session_init(s, RAWQ_NO_CONNECT_ID)`;
  - `flow_control = 0`;
  - `establish`;
  - call `raw_on_session(ctx, s, tok)`, before the stream-delta delivery of
    that step.
- S1 `srvrun_next_uni_id` → `rawq_uni_first_id(raw) + 4n`.
- S2 send gates: `settings_sent || raw_established`.
- S3 datagram:
  - send: `rawq_dgram_prefix_len` 0 → no qsid;
  - receive: skip the qsid parse and deliver to the raw session.
- S4 resets: the in/out codes go through `rawq_reset_code_*`.
- S5 close: `wired_server_wt_close_session` on a raw session →
  `srvrun_send_app_close(code, reason)`, then the existing teardown fires
  `wt_on_session_close` exactly once.
- S9 (§3.4 server table) reaping: a confirmed raw connection counts as live.
- Peer CONNECTION_CLOSE / idle → the same `wt_on_session_close`.

### Phase 4 (serial, hub; after the in-flight `moqtrun.c` branches of other agents are merged into main)

**S10 — hub edits** (`app/moqt/run/moqtrun.{h,c}`; about 40 lines). Effort: 0.5 d.

- `wired_moqtrun_peer.raw` (u8);
- `wired_moqt_on_session_raw(app_ctx, s, alpn)` →
  `moqtrun_init_peer(..., ver = moqtrun_negotiated_ver(alpn), legacy = 0)`
  then `p->raw = 1`. Set it before `ctl_open`: initialize `raw` inside init,
  via a parameter, to keep ordering;
- `moqtrun_setup_opt_bad(m)` → `moqraw_setup_verdict(p->raw, m, &hub->raw_policy)`;
- `wired_moqt_hub.raw_policy` (zero = accept-all);
- docs for H3/H5/H6.
- First step: `git merge main` and confirm that the base sha equals current
  `main` (parallel-and-commit.md).

### Phase 5 (serial, aggregator)

**S11 — example + interop**. Effort: 0.5 d code, plus 1 d runs.

- Edit `examples/moqt_interop/wired_server.c` (§4.5) and
  `interop/run_endpoint_moqt.sh` / `Dockerfile.moqt` comments.
- Runner fork: the `implementations.json` entry from §2.3, the re-tag, a
  `validate-registration.sh` run, and the matrix:
  - `--relay wired-quic`, every client;
  - `--relay wired` as a WT regression.
- Record each PASS with its `results/<ts>/` log path (tasks-ledger.md).

**S12 — wiring + docs + gate**. Effort: 0.5 d.

- `tests/run.c`: production includes for `salpn_raw.c`, `rawq.c`, `moqraw.c`,
  `moqrawio.c`; their `*_test.c`; and the `test_*()` calls. Prove each with a
  grep.
- Run the count check.
- Update `docs/api-stability.md` (new `wired_*` rows), the `docs/features/`
  MoQT page (transport row), the guide if it lists transports, the `moqtrun.h`
  docs, and `docs/syscalls.md` (no new syscalls are expected; verify with the
  skill).
- Gate:
  - the three-point gate;
  - `just test` once, for unity collisions;
  - `just docs`;
  - `just fuzz-smoke` (sdrv/eebuild signature change, K7);
  - `fmt-check`/`lint` via the pinned toolchain, or else state that it was not
    run.
- Commit as conventional micro-commits.
- Valgrind `--track-origins` once on the new test binary.

Critical path: S0a → S1 → S6 → S9 → S10 → S11, about 5.5 working days. With
S2/S3/S4/S7 in parallel, the total is about 8-9 days of effort.

---

## 7. TDD test list

Production buffer sizes are shared via the production `#define`s
(`WIRED_MOQTRUN_CTL_SEND_BUF`, srvloop slot sizes), never re-typed.

### 7.1 S1 ALPN (`salpn_raw_test.c`)

- T-A1: list `"moqt-22 moqt-19 moqt-18"` has `moqt-19` → 1. It does not have
  `moqt-1`, `moqt-190`, `MOQT-19` or the empty name (boundaries, case
  sensitivity).
- T-A2: offer `[moqt-18, h3]` → SALPN_RAW, tok=`moqt-18`. Offer
  `[h3, moqt-22]` → SALPN_H3. Offer `[moq-00, moqt-18]` → RAW `moqt-18`. Offer
  `[moqt-16]` → NONE. Offer `[moqt-18]` with an empty raw list → NONE
  (feature off is byte-identical to today).
- T-A3: malformed lists (list_len overrun, entry len 0, entry overrun) → NONE.
  There is no OOB read: run the fuzz-shaped random lengths.
- T-A4 **pinned bytes**: the EE ALPN extension for `moqt-19` is exactly
  `00 10 00 0a 00 08 07 6d 6f 71 74 2d 31 39` (RFC 7301 §3.1: ext type 0x0010,
  ext len 10, list len 8, name len 7). Hand-derived. Also pin `h3` and `hq`
  unchanged.

### 7.2 S2 binding helpers (`rawq_test.c`)

- T-B1: the route table (raw × stream id mod 4 × first bytes). On raw, a
  leading 0x41/0x54 is still RAW (no signal semantics). On WT, today's
  classification is unchanged.
- T-B2: `rawq_reset_code_out(raw=1, n) == n` for every MoQT reset code (R12
  list) plus grease `0x9D`. With `raw=0` it equals `wired_wterrmap_to_http3(n)`;
  pin `n=1` → `0x52e4a40fa8dc` (`0x52e4a40fa8db + 1 + 0`).
- T-B3: in-mapping. Raw wire `0x12` → mapped=1/app=0x12. Raw wire `2^32` →
  mapped=0 (treated as INTERNAL per R13). WT behaviour is unchanged.
- T-B4: `rawq_uni_first_id(1)=3`, `(0)=11`; `rawq_dgram_prefix_len(1)=0`.

### 7.3 S3 MoQT raw policy (`moqraw_test.c`)

- T-C1 (R9): PATH absent → 0. `""` → 0. `"/"` → 0. `"/moq?x=1"` → 0. `"moq"`
  (no leading slash) → 0x9. `"/a b"` → 0x9. `"/a#f"` → 0x9. `"/%zz"` → 0x9.
  Non-ASCII → 0x9.
- T-C2 (R8): AUTHORITY `relay:4443` → 0, `[::1]:443` → 0, `a@b` → 0,
  `:443` (empty host) → 0x1A, `relay:99999` → 0x1A, `relay:` → 0 (empty port
  is allowed by RFC 3986), `[::1` → 0x1A.
- T-C3: on WT (raw=0), PATH present → 0x8 and AUTHORITY → 0x19. This must
  equal today's `moqtrun_setup_opt_bad`, so the existing tests 9 and 10 keep
  passing.
- T-C4: a hook that refuses the path → 0x8, a hook that refuses the authority
  → 0x19. Both present and both bad → PATH first (matches today's order).
- T-C5: unknown Setup Options are ignored, and duplicates of unknown options
  are allowed (§10.3 / §9.1).

### 7.4 S4 io mux (`moqrawio_test.c`, recorder backend)

- T-D1: WT session `open_uni_stream(p)` → the backend receives
  `signal(0x54, sid) ‖ p`. Raw session → the backend receives `p` byte for
  byte.
- T-D2: raw `open_bidi_stream` → -1, with no backend call.
- T-D3: raw `send_budget` → `(usz)-1`. WT → `max_data - sent_data`, and 0 when
  exceeded.
- T-D4: an oversized payload (> staging) → -1 on both transports
  (production staging size).

### 7.5 S6/S7/S9 server (`srvrun_test.c`, `dispatch` tests, extending the existing fixtures)

- T-E1: a raw ALPN connection opens no H3 control stream (no STREAM frame on
  id 3 carrying 0x00 type + SETTINGS) and no QPACK stream (id 7).
- T-E2: the first `wired_server_wt_open_uni_stream` on raw returns id 3, then
  7, 11, and so on. On h3 it is still 11.
- T-E3: a client uni STREAM frame `6f 00 …` on id 2 is delivered to
  `wt_on_stream_data` with data starting `6f 00` (no signal strip). A client
  bidi on id 0 starting `03 …` (SUBSCRIBE) is delivered whole, never to the h3
  request decoder.
- T-E4: a DATAGRAM frame payload `P` on raw → `wt_on_datagram(P)` whole. On
  WT, an invalid qsid still closes with H3_DATAGRAM_ERROR (regression).
- T-E5 **pinned bytes**: raw `close_session(s, 0x3, "")` → the sealed 1-RTT
  payload contains `1d 03 00` (type 0x1d, error 0x3, reason len 0;
  RFC 9000 §19.19). With `0x8, "bad path"` → `1d 08 08 62 61 64 20 70 61 74 68`.
- T-E6 **pinned bytes**: raw `stream_reset(s, 3, 0x1)` → `04 03 01 <final size>`
  (RFC 9000 §19.4). WT → the error field is the 8-byte varint
  `c0 00 52 e4 a4 0f a8 dc`.
- T-E7: raw send DATAGRAM `P` → the DATAGRAM frame data equals `P` (no qsid).
  WT → `qsid ‖ P`.
- T-E8: `raw_on_session` fires once, at confirm, before any stream data of the
  same step (SessBeforeData). `wt_on_session_close` fires exactly once on peer
  CONNECTION_CLOSE, on hub close, and on idle. A reused slot after close gets a
  fresh on_session (NoGhost).
- T-E9: a 0-RTT ClientHello with a raw-ALPN ticket → `early_data_accepted == 0`
  (REQ-H). An h3 ticket is unchanged.
- T-E10: a raw connection is not reaped as "boot overdue" after confirmation
  (S9 regression).

### 7.6 S10 hub (`moqtrun_test.c` / `mtctl_*` helpers)

- T-F1: `wired_moqt_on_session_raw(hub, s, "moqt-18")` → `p->ver == MOQVER_D18`,
  `p->raw == 1`, `legacy == 0`. The server SETUP goes out on `open_uni_stream`
  (never `open_bidi_stream`) and starts `6f 00` (pin).
- T-F2: a raw peer SETUP with PATH `/` and AUTHORITY `relay:4443` → accepted,
  and the session becomes Established. The same bytes on a WT peer → close
  0x8. This is the core regression for REQ-B.
- T-F3: a raw peer SETUP with PATH `moq` → close 0x9 via `io.close_session`.
- T-F4: the hub calls `io.close_session` with MoQT codes only (no WT-specific
  constants). An exhaustive check over the `WIRED_MOQTRUN_CLOSE_*` set.

### 7.7 Loopback and pinned-peer (the real gate for wire-visible behaviour)

- **T-L1 in-process raw MoQT loopback** (`tests/app/moqraw_loopback_test.c`).
  Build on the `h3_loopback_test.c` fixture (real AEAD, client key schedule).
  - The client ClientHello offers ALPN `[moqt-19]`, and the server config has
    `raw_alpns = "moqt-22 moqt-19 moqt-18"`.
  - Assert:
    - the EE carries `moqt-19` (T-A4 bytes);
    - after the client Finished, the server's first 1-RTT stream frame is on
      id 3 and begins `6f 00` (server SETUP);
    - the client sends uni id 2 `6f 00 <len> <PATH="/"> <AUTHORITY="localhost:4443">`
      and the hub reaches Established;
    - the client sends SUBSCRIBE for an unknown track on bidi id 0 and gets
      REQUEST_ERROR on the same stream;
    - the client sends an OBJECT_DATAGRAM, which is delivered unprefixed;
    - the hub `close_session(NO_ERROR)` reaches the client as `1d 00 00`.
  - Socket-free buffer path first, as srvloop_test does; the UDP variant is a
    benign skip when the sandbox forbids sockets.
- **T-L2 pinned real-peer trace**: the loopback alone does not prove interop
  (rule #28).
  - During S11, capture one xquic-draft-18 run and one moqtopus `setup-only`
    run against `wired-quic`, using a temporary single-file probe that dumps
    the decrypted client control-stream bytes and the ClientHello ALPN list.
  - Freeze them in `tests/app/moqraw_golden.h` and feed them to
    `moqraw_setup_verdict` and `salpn_raw_pick` in a test.
  - Delete the probe once captured.
  - Until T-L2 exists, every wire-facing 13-x item stays `[~]`.
- **T-L3 runner matrix**: each client → `wired-quic` case. PASS is recorded
  only with a `✓` and an existing log directory (rfc-and-verification-layers.md).

---

## 8. Risks / unknowns

- **K1 PATH/AUTHORITY values sent by real clients**: unknown until T-L2.
  Clients may send `PATH=""`, `"/"`, or omit it, and AUTHORITY could be
  `relay:4443` or `relay`. The accept-all policy is safe, but the syntax
  validator must not be stricter than the clients. Mitigation: T-L2 goldens
  before tightening, plus a `MALFORMED_*` counter visible in the log.
- **K2 Client ALPN lists**:
  - quic-zig offers `moqt-17`/`moqt-18`; moq5 `moqt-16`/`moqt-18`; moqtopus
    `moqt-18`; xquic `moqt-18` (+`moq-00`).
  - Whether a client lists `h3` *before* `moqt-NN` on a `moqt://` URL is
    unknown. If it does, wired selects h3 (client order), and a raw-only
    client then hangs.
  - Mitigation: log the offered list. If needed, add a server-preference
    option "prefer raw over h3 when the client offers both", which RFC 7301
    permits.
- **K3 Capacity**:
  - `WIRED_SRVLOOP_MAX_WT_UNI_STREAMS 6` concurrent peer uni streams per
    connection. A raw client opening one uni stream per subgroup can exhaust
    it, as on WT, but raw clients do it more readily.
  - `WIRED_MOQTRUN_MAX_SESSIONS 32` is shared by both transports.
  - `SRVRUN_MAX_WT_SESSIONS 2` per connection is enough (raw uses 1).
  - Watch the stat counters during S11. If anything is widened, record the
    reason next to the constant.
- **K4 Stream credit / MAX_STREAMS replenishment** for client uni/bidi on raw:
  it uses the existing QUIC logic, which was so far exercised mostly with WT
  traffic. Verify with T-L3 announce-subscribe runs that open many streams.
- **K5 Budget**: raw `send_budget = (usz)-1` relies on srvrun refusing rounds
  beyond QUIC MAX_DATA. If srvrun does not gate on connection-level credit for
  wtsend, the reliable relay could over-queue. Check `srvrun_wtsend` credit
  handling in S9 and add a real QUIC budget query if missing.
- **K6 Implicit session identity**: `connect_stream_id` gets a sentinel that
  must never reach the wire. Grep every `connect_stream_id` use in srvrun
  (qsid, capsules, signal) and assert that the raw branches avoid them.
- **K7 Signature changes in tls/** (eebuild/sdrv/salpn) can break `fuzz/*.c`
  harnesses that the three-point gate never compiles. That happened on
  2026-08-21. Run `just fuzz-smoke`.
- **K8 0-RTT**: refusing it is spec-permitted (R16), but some client could
  hard-fail on a refused 0-RTT ticket. This is unlikely, because rejection is
  standard TLS.
- **K9 QUIC v2 / compatible version negotiation**: `alpnver_compatible` lists
  only h3. It has no callers today, but if it gets wired in, it must accept
  raw tokens.
- **K10 GOAWAY URI scheme** (R15): a mixed WT/raw hub sends one URI to both.
  A d18+ client accepts `moqt://` for both, while legacy WT clients expect
  `https://`. Use an empty URI (reuse) in interop. A per-transport URI is
  deferred.
- **K11 Concurrent hub edits**: other agents are changing `moqtrun.c`. S10 is
  deliberately tiny, comes last, and starts with `git merge main` plus a base
  sha check.
- **K12 Runner semantics**: decision 003 Phase 2 may later replace scheme-based
  selection. The `wired-quic` entry is the Phase 1-compatible form. Revisit it
  when the runner adds the constraint env.
- **K13 DATAGRAM negotiation MUST** (R2): if a raw client does not advertise
  `max_datagram_frame_size`, the spec says DATAGRAM "MUST be negotiated". Do
  not close (be liberal). Datagram sends are simply dropped. Record this as a
  deliberate leniency.
- **K14 hq-interop interaction**: the raw list must never contain
  `hq-interop` or `h3`. `salpn_raw_list_has` rejects them in config (assert at
  init).

---

## 9. Ledger-ready items (paste into `tasks/moqt-multidraft-ledger.md` §13)

The ledger is written in Japanese, so these items are in Japanese.

- [x] 13-0 計画: `tasks/loopeng/moqt/RawQuic/plan.md`(版ごとの仕様 R1-R17、runner 連携、アーキテクチャ、TLA+ 対象、並列分割、TDD リスト、リスク K1-K14)。
- [ ] 13-1 インタフェース凍結(S0a): `salpn_raw.h`/`rawq.h`/`moqraw.h`/`moqrawio.h` と srvrun.h/srvboot.h の追加宣言。名前は plan §4.2、着手前に再 grep。
- [ ] 13-2 TLA+ `MoqtRawConn`(S0b/S5): 接続→raw セッション生成・配送・クローズ・スロット再利用。安全性 SessBeforeData/CloseOnce/CloseIffSession/NoGhost/NoH3OnRaw/RawCloseShape/PathRule、活性 2、ミューテーション 4 件で反例確認、reviewer 合格。
- [ ] 13-3 ALPN 選択(S1+S6+S8): `SALPN_RAW`、`wired_srvboot_id.raw_alpns`、クライアント選好順で h3/hq/moqt-NN を混在選択、EE と ticket に選択トークン、raw ALPN では 0-RTT 拒否(d18 §3.3.1 / d22 §6.3.1 の relay MAY)。固定バイト T-A4。
- [ ] 13-4 raw 束縛ヘルパ(S2): `app/rawquic/rawq_*`(ストリーム経路、reset コードの無変換/WT 写像、datagram 前置なし、uni 初番 3)。T-B1〜B4。
- [ ] 13-5 srvloop の raw 経路(S7): raw ALPN 接続ではクライアントの全 bidi/uni を sig_len 0 で WT スロットへ、h3 要求/QPACK 経路に入れない。T-E3。
- [ ] 13-6 srvrun の暗黙セッション(S9): 確認時に生成し `raw_on_session`、H3 制御/QPACK を開かない、uni id 3 起点、datagram に qsid なし、reset コード無変換、クローズは CONNECTION_CLOSE 0x1d(MoQT コード)、on_session_close はちょうど 1 回。T-E1〜E10(E5/E6/E7 は固定バイト)。
- [ ] 13-7 MoQT raw ポリシー(S3): PATH(0x01)/AUTHORITY(0x05) を raw では受理、不正形式は MALFORMED_PATH 0x9 / MALFORMED_AUTHORITY 0x1A、フック拒否は 0x8/0x19、WT は従来どおり 0x8/0x19(d18 §10.3.1.1-2、d19 §10.3.1.1-2、d22 §9.1.1-2)。T-C1〜C5。
- [ ] 13-8 io 多重化(S4): `wired_moqraw_io()`、WT セッションだけ signal 前置、moqt_interop/moqt_chat の `open_signalled` 重複を除去。T-D1〜D4。
- [ ] 13-9 hub(S10、他エージェントの moqtrun.c 作業のマージ後): `wired_moqt_on_session_raw`、peer.raw、`moqtrun_setup_opt_bad` を moqraw へ委譲、`hub.raw_policy`。T-F1〜F4。
- [ ] 13-10 example/interop(S11): moqt_interop が同一ポートで h3 と moqt-22/19/18 を受ける、run_endpoint_moqt.sh の `MOQT_TRANSPORT`、runner fork に `wired-quic`(`moqt://relay:4443`、同一イメージの再タグ)を追加し `wired` の notes から "WebTransport only" を外す。
- [ ] 13-11 検証: in-process raw ループバック T-L1、実ピア固定トレース T-L2(xquic-draft-18 と moqtopus の SETUP/ALPN を golden 化)、runner 行列 T-L3(moqtopus/xquic-draft-18/mlmtest/quic-zig/moq5/aiomoqt → wired-quic、`results/<ts>/` ログ付き)。T-L2 が揃うまでワイヤに出る項目は `[~]` のまま。
- [ ] 13-12 配線・文書・ゲート(S12): run.c 配線、`docs/api-stability.md`(新 `wired_*`)、features ページの transport 行、moqtrun.h の WT 前提コメント、`just docs`/`just fuzz-smoke`/三点ゲート/`just test`、valgrind 1 回。
- 対象外(再登録条件つき): raw 上の 0-RTT 受理(条件: 0-RTT を要求する対向が現れたとき)、トランスポート別の GOAWAY URI(条件: 混在環境で https:// 前提の WT クライアントへ移行先を出す必要が出たとき)、wired 側 raw MoQT クライアント(条件: relay 以外の role を runner に登録するとき)、`moq-00`(draft-14 以前)の ALPN。
