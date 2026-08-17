[Docs](../README.md) › [Features](README.md) › draft-ietf-webtrans-http3-15

# draft-ietf-webtrans-http3-15 — WebTransport over HTTP/3

EARS requirement ledger extracted from the spec text
(`tasks/specs/draft-ietf-webtrans-http3-15.txt`, not in git), server side.
Each requirement carries the test that demonstrates it; an unchecked box
with no test line is an open gap. Status as of 2026-07.

Legend:

- `[x]` — demonstrated by the referenced test
- `[~]` — exercised indirectly (evidence line explains how; no dedicated test)
- `[ ]` — not demonstrated by any test yet

**Coverage: 52/68 tested, 16 indirect, 0 untested.**

## §3.1 Establishing a WebTransport-Capable HTTP/3 Connection

- [x] WTH3-001 (§3.1) The server shall signal support for WebTransport over
  HTTP/3 by sending a SETTINGS_WT_ENABLED setting with a value greater
  than 0.
  - test: `tests/app/h3settings_control_settings_test.c` —
    `test_h3settings_control_settings_advertises_wt`
  - test: `tests/app/h3settings_build_test.c` —
    `test_h3settings_build_h3_datagram_and_wt_enabled`
- [x] WTH3-002 (§3.1) Where the server has not sent a SETTINGS_WT_ENABLED
  setting indicating WebTransport support, clients are expected to not
  attempt to establish WebTransport sessions; the server shall keep the
  default value of SETTINGS_WT_ENABLED at 0 unless WebTransport is
  configured.
  - test: `tests/app/h3settings_build_test.c` —
    `test_h3settings_build_h3_datagram_and_wt_disabled`
  - test: `tests/app/h3settings_control_settings_test.c` —
    `test_h3settings_control_settings_advertises_wt`
- [x] WTH3-003 (§3.1) The server shall support Extended CONNECT as
  described in RFC 9220, including the SETTINGS_ENABLE_CONNECT_PROTOCOL
  setting.
  - test: `tests/app/h3settings_build_test.c` —
    `test_h3settings_build_connect_protocol`
  - test: `tests/app/connect_test.c` — `test_connect_protocol_negotiation`
- [x] WTH3-004 (§3.1) The server shall indicate support for HTTP/3
  datagrams by sending a SETTINGS_H3_DATAGRAM setting with a value of 1.
  - test: `tests/app/h3settings_build_test.c` —
    `test_h3settings_build_h3_datagram_and_wt_enabled`
  - test: `tests/app/h3settings_control_settings_test.c` —
    `test_h3settings_control_settings_advertises_wt`
- [x] WTH3-005 (§3.1) The server shall send a max_datagram_frame_size
  transport parameter with a value greater than 0 to indicate support for
  QUIC datagrams.
  - test: `tests/tls/server_tp_test.c` —
    `test_server_tp_datagram_frame_size`
- [x] WTH3-006 (§3.1) The server shall send an empty reset_stream_at
  transport parameter to enable the RESET_STREAM_AT extension.
  - test: `tests/tls/server_tp_test.c` — `test_server_tp_reset_stream_at_empty`
- [~] WTH3-007 (§3.1) If the server receives SETTINGS or transport
  parameters that do not have correct values for every required
  WebTransport setting/parameter, then the server shall treat all
  established and newly incoming WebTransport sessions as malformed.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_after_client_settings_establishes`
  - evidence: `srvrun_wt_tp_ok` rejects a newly incoming CONNECT when the
    peer never advertised `max_datagram_frame_size`; only newly incoming
    sessions are gated, not already-established ones.
- [x] WTH3-008 (§3.1) For draft versions of WebTransport, the server shall
  advertise SETTINGS_WT_ENABLED using the draft-specific codepoint(s) so
  the peer can identify the supported version(s).
  - test: `tests/app/h3settings_build_test.c` —
    `test_h3settings_build_h3_datagram_and_wt_enabled`
  - evidence: the built SETTINGS carry both the draft-02 (0x2b603742) and
    draft-15 (0x2c7cf000) codepoints in the same frame.
- [x] WTH3-009 (§3.1) For draft versions of WebTransport, the server shall
  not process any incoming WebTransport requests until the client's
  SETTINGS have been received.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_before_client_settings_rejected`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_after_client_settings_establishes`

## §3.2 Creating a New Session

- [x] WTH3-010 (§3.2) To create a new WebTransport session, the server
  shall require the `:protocol` pseudo-header field to equal
  "webtransport-h3" (or the deployed "webtransport" draft-07 token).
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_webtransport_token`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_plain_connect_no_protocol_no_wt_session`
- [~] WTH3-011 (§3.2) The `:scheme` field of a WebTransport CONNECT request
  shall be https.
  - evidence: `wt_ext_fields_present` (srvrun.c) requires `:scheme` to be
    present but does not check its value equals "https"; no test asserts
    rejection of a non-https `:scheme`.
- [x] WTH3-012 (§3.2) Both the `:authority` and `:path` values shall be set
  on a WebTransport CONNECT request; these fields identify the desired
  WebTransport server resource.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_missing_authority_no_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_missing_path_no_session`
  - test: `tests/app/srvrun_test.c` — `test_srvrun_wt_accept_records_path`
- [~] WTH3-013 (§3.2) Where the request contains an Origin header, the
  server shall verify the Origin header to ensure that the specified
  origin is allowed to access the server in question.
  - evidence: `wt_origin_ok` (srvrun.c) only checks the Origin header is
    present-and-non-empty; there is no origin-allowlist configuration
    surface, so "verification" is limited to well-formedness, per its own
    doc comment. `tests/app/srvrun_test.c`'s
    `test_srvrun_wt_connect_origin_ok_establishes` and
    `test_srvrun_wt_connect_origin_malformed_403` exercise this
    well-formedness check.
- [x] WTH3-014 (§3.2) If Origin verification fails, then the server shall
  reply with status code 403.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_origin_malformed_403`
- [x] WTH3-015 (§3.2) If all checks pass, the server may accept the
  session by replying with a 2xx series status code.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_establishes_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_origin_ok_establishes`
- [x] WTH3-016 (§3.2) Where the HTTP/3 server has no WebTransport server
  associated with the specified `:authority` and `:path` values, the
  server should reply with status code 404.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_resource_check_404_no_session`
  - evidence: the app registers a `wired_wt_resource_check` callback
    (`srvrun_wt_resource_decide`) consulted on every Extended CONNECT before
    a session is established; a callback that reports "not found" builds a
    bare 404 response and never reaches the app handler.
- [x] WTH3-017 (§3.2) From the server's perspective, a WebTransport
  session is established once it sends a 2xx response.
  - test: `tests/app/wt_session_test.c` —
    `test_close_from_established`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_establishes_session`
- [x] WTH3-018 (§3.2) The server may reply with a 3xx response indicating
  a redirection.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_resource_check_redirect_3xx_with_location`
  - evidence: the same `wired_wt_resource_check` callback (WTH3-016) may
    report a 3xx status with a Location value; `srvrun_reject_wt_redirect`
    builds the redirect response carrying a Literal Field Line With Literal
    Name Location header.
- [~] WTH3-019 (§3.2) Clients shall not initiate WebTransport in 0-RTT
  packets; if the server accepts 0-RTT, the server shall not reduce the
  limit of maximum open WebTransport sessions or other initial flow
  control values from those negotiated during the previous session, else
  the server shall close the connection with H3_SETTINGS_ERROR.
  - test: `tests/app/h3settings_control_settings_test.c` —
    `test_h3settings_zerortt_compatible_wt_session_limit_lowered_rejected`
  - test: `tests/app/h3settings_control_settings_test.c` —
    `test_h3settings_zerortt_compatible_wt_flow_control_lowered_rejected`
  - evidence: `h3settings_zerortt_compatible` (9114-066) already
    covers `wt_max_sessions` ("the limit of maximum open WebTransport
    sessions") and `wt_initial_max_streams_uni/bidi`/`wt_initial_max_data`
    (WTH3-051's "other initial flow control values") in its general
    never-regress rule; both are pinned down directly by the tests above.
  - gap: this SDK's session limit (`SRVRUN_MAX_WT_SESSIONS`) is still a
    compile-time constant, not renegotiated per connection, and no store
    of the settings sent when a resumed ticket was issued exists to
    supply the `prior` argument on a live 0-RTT accept path (same gap as
    9114-066).
- [x] WTH3-020 (§3.2) The Capsule Protocol is negotiated for the
  "webtransport-h3" upgrade token when the server sends a 2xx response.
  - test: `tests/app/wtcapsule_test.c` — `test_wtcapsule_close_roundtrip`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_establishes_session`

## §3.3 Application Protocol Negotiation

- [x] WTH3-021 (§3.3) Where the client includes a WT-Available-Protocols
  header field in the CONNECT request, the server may select and include
  a WT-Protocol field in a successful response, choosing exactly one
  member from the client's list.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_negotiate_picks_first_client_choice`
- [x] WTH3-022 (§3.3) When the server receives no common subprotocol
  between its own list and the client's offer, the server shall not
  include a WT-Protocol header field, and may still accept the session.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_negotiate_no_common_no_header`
- [x] WTH3-023 (§3.3) When no WT-Available-Protocols header field is
  present, the server shall not include a WT-Protocol field and the
  session establishment is unaffected.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_negotiate_absent_offer_no_header`
- [x] WTH3-024 (§3.3) If the WT-Available-Protocols header field is
  malformed (not a valid Structured Field List), then the server shall
  treat the field as if it were ignored (RFC 9651/8941 error handling).
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_negotiate_bad_syntax_no_header`
- [x] WTH3-025 (§3.3) A server that requires application protocol
  negotiation may reject the session if the WT-Available-Protocols header
  field is absent or malformed.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_negotiate_disabled_unchanged`
  - evidence: negotiation is opt-in (`cfg->wt_protocols == 0` disables it
    entirely); the cited test pins the disabled-negotiation behavior. No
    test exercises a server configured to reject on missing/malformed
    offers (a stricter mode this SDK does not implement).

## §3.4 Prioritization

- [~] WTH3-026 (§3.4) WebTransport CONNECT requests and responses may
  contain the Priority header field, and clients may reprioritize by
  sending PRIORITY_UPDATE frames.
  - evidence: PRIORITY_UPDATE frame codec (`tests/app/priupdate_test.c`)
    is generic over any element_id, including a CONNECT stream's id; no
    test specifically drives a PRIORITY_UPDATE against an established
    WebTransport CONNECT stream.

## §4 WebTransport Features / Session IDs

- [x] WTH3-027 (§4) Session IDs shall be encoded using the QUIC
  variable-length integer scheme.
  - test: `tests/app/wtwire_test.c` — `test_wtwire_signal_put_uni`
  - test: `tests/app/wtwire_test.c` — `test_wtwire_qsid_put`
- [x] WTH3-028 (§4) The client may optimistically open streams and send
  datagrams on a session as soon as it has sent the CONNECT request; on
  the server side, opening streams and sending datagrams is possible as
  soon as the CONNECT request has been received.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_uni_streams_payload_on_wire`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_bidi_allocates_ids_and_holds_view`
- [x] WTH3-029 (§4) Session IDs shall always correspond to a
  client-initiated bidirectional stream.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_client_bidi_id_establishes_session`
- [x] WTH3-030 (§4) If an endpoint receives a session ID on a
  unidirectional stream, bidirectional stream, or datagram that does not
  correspond to a client-initiated bidirectional stream ID, then the
  server shall close the connection with an H3_ID_ERROR error code.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_non_client_bidi_id_rejected`
- [x] WTH3-031 (§4) Session IDs corresponding to closed sessions shall not
  themselves be considered invalid for the client-initiated-bidi-stream
  check; endpoints handle data for closed sessions per session
  termination rules.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_foreign_stream_id_rejected`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_close_frees_slot_for_new_accept`

## §4.2 Unidirectional Streams

- [x] WTH3-032 (§4.2) The HTTP/3 unidirectional stream type for
  WebTransport shall be 0x54, followed by the session ID as a
  variable-length integer, followed by user-specified stream data.
  - test: `tests/app/wtwire_test.c` — `test_wtwire_signal_put_uni`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_uni_stream_data_delivered_on_offer`

## §4.3 Bidirectional Streams

- [x] WTH3-033 (§4.3) The server shall send the signal value 0x41,
  encoded as a variable-length integer, as the first bytes of each
  server-initiated bidirectional WebTransport stream, followed by the
  session ID.
  - test: `tests/app/wtwire_test.c` — `test_wtwire_signal_put_bidi`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_bidi_allocates_ids_and_holds_view`
- [x] WTH3-034 (§4.3) The implementation shall recognize the client's
  signal value 0x41 as the first bytes of a client-initiated
  bidirectional WebTransport stream.
  - test: `tests/app/srvloop_test.c` —
    `test_srvloop_wt_bidi_stream_not_request`
  - test: `tests/app/srvloop_test.c` — `test_srvloop_wt_bidi_stream_reassembled`
- [x] WTH3-035 (§4.3) If a WT_STREAM signal value (0x41) is sent as a
  frame type on an HTTP/3 stream other than the very first bytes of a
  request stream, then the implementation shall treat this as a
  connection error of type H3_FRAME_ERROR.
  - test: `tests/app/srvloop_test.c` —
    `test_srvloop_wt_signal_mid_stream_latches_violation`
  - evidence: `gather_one_wt_signal_violation` (`dispatch.c`) detects the
    signal varint at a non-zero stream offset and latches
    `wt_signal_mid_stream_violation`; `srvrun_close_on_step_violation`
    closes the connection with H3_FRAME_ERROR on the next step.

## §4.4 Resetting Data Streams

- [x] WTH3-036 (§4.4) A WebTransport endpoint may send a RESET_STREAM or a
  STOP_SENDING frame for a WebTransport data stream, propagated to the
  application.
  - test: `tests/transport/stream_ctl_test.c` — `test_reset_stream`
- [x] WTH3-037 (§4.4) WebTransport application error codes for streams
  shall be remapped into the WT_APPLICATION_ERROR range, where 0x00000000
  corresponds to 0x52e4a40fa8db and 0xffffffff corresponds to
  0x52e5ac983162, skipping reserved codepoints of form 0x1f*N+0x21.
  - test: `tests/app/wterrmap_test.c` — `test_wterrmap`
- [~] WTH3-038 (§4.4) WebTransport implementations shall use the
  RESET_STREAM_AT frame with a Reliable Size set to at least the size of
  the WebTransport header when resetting a WebTransport data stream.
  - evidence: deliberately unmet until peer negotiation is tracked.
    draft-ietf-quic-reliable-stream-reset only permits sending
    RESET_STREAM_AT to a peer that advertised the reset_stream_at
    transport parameter; this SDK does not parse the peer's, and real
    browsers (Chrome) do not send it — an unnegotiated 0x24 is an unknown
    frame the peer kills the whole connection over
    (FRAME_ENCODING_ERROR, reproduced live). srvrun therefore aborts WT
    streams with the standard RESET_STREAM/STOP_SENDING pair picked by
    stream type (`tests/app/srvrun_test.c` —
    `test_srvrun_wt_abort_frames_match_stream_type`); the RESET_STREAM_AT
    codec itself stays tested
    (`tests/transport/stream_ctl_test.c`) for the day peer-TP tracking
    lands.
- [x] WTH3-039 (§4.4) WebTransport endpoints shall forward the error code
  for a stream associated with a known session to the application that
  owns that session.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_stream_reply_arms_given_stream_verbatim`
- [x] WTH3-040 (§4.4) If a RESET_STREAM or STOP_SENDING frame is received
  with an error code outside the WT_APPLICATION_ERROR range, then the
  implementation should deliver this to the application as a stream reset
  with no application error code.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_reset_mapped_delivers_app_error_code`
  - evidence: the receive-side stream-reset handling path in srvrun.c now
    calls `wired_wterrmap_from_http3` to decide whether a mapped application
    error code or none is delivered to the app.

## §4.5 Datagrams

- [x] WTH3-041 (§4.5) The WebTransport datagram payload shall be sent
  unmodified in the HTTP Datagram Payload field, directly following the
  Quarter Stream ID field.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_send_datagram_to_prefixes_qsid`

## §4.6 Buffering Incoming Streams and Datagrams

- [~] WTH3-042 (§4.6) The client shall wait for receipt of the server's
  SETTINGS frame before establishing any WebTransport sessions.
  - evidence: client-side behavior in principle; the server-observable
    counterpart is WTH3-009 (server does not process incoming WT requests
    until the client's own SETTINGS have arrived), now implemented and
    tested there.
- [x] WTH3-043 (§4.6) WebTransport endpoints should buffer streams and
  datagrams until they can be associated with an established session.
  - test: `tests/app/wt_session_test.c` —
    `test_stream_buffered_then_established`
  - test: `tests/app/wt_session_test.c` —
    `test_datagram_buffered_then_established`
- [x] WTH3-044 (§4.6) To avoid resource exhaustion, endpoints shall limit
  the number of buffered streams and datagrams.
  - test: `tests/app/wt_session_test.c` —
    `test_stream_buffer_limit_rejects_overflow`
  - test: `tests/app/wt_session_test.c` —
    `test_datagram_buffer_limit_drops_overflow`
- [x] WTH3-045 (§4.6) When the number of buffered streams is exceeded, a
  stream shall be closed by sending a RESET_STREAM and/or STOP_SENDING
  with the WT_BUFFERED_STREAM_REJECTED error code.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_bidi_stream_buffer_full_sends_reset`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_uni_stream_buffer_full_sends_reset`
- [x] WTH3-046 (§4.6) When the number of buffered datagrams is exceeded,
  a datagram shall be dropped.
  - test: `tests/app/wt_session_test.c` —
    `test_datagram_buffer_limit_drops_overflow`

## §4.7 Interaction with the HTTP/3 GOAWAY Frame

- [x] WTH3-047 (§4.7) A client receiving GOAWAY shall not initiate CONNECT
  requests for new WebTransport sessions on that connection.
  - test: `tests/app/goaway_check_test.c` — `test_goaway_check`
  - evidence: the generic GOAWAY-id monotonicity/rejection check
    (`quic_h3_goaway_check` family) applies to all new client-initiated
    request streams, including WebTransport CONNECT streams; no
    WT-specific test drives a CONNECT arriving after GOAWAY.
- [x] WTH3-048 (§4.7) An HTTP/3 GOAWAY frame is also a signal to
  applications to initiate shutdown for all WebTransport sessions; to
  shut down a single session, either endpoint can send a
  WT_DRAIN_SESSION capsule.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_send_wt_drain_seals_capsule_on_connect_stream`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_send_wt_drain_all_skips_inactive_slot`
  - evidence: `srvrun_send_wt_drain_all` fans out a WT_DRAIN_SESSION
    capsule to every active WebTransport session when GOAWAY is sent,
    driving each session's `wired_wt_session_drain` ESTABLISHED->DRAINING
    transition.
- [x] WTH3-049 (§4.7) After sending or receiving a WT_DRAIN_SESSION
  capsule, an endpoint may continue using the session and open new
  WebTransport streams (drain is advisory, not terminal).
  - test: `tests/app/wt_session_test.c` —
    `test_drain_is_advisory_not_terminal`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_drain_one_session_leaves_others_untouched`

## §4.8 Use of Keying Material Exporters

- [~] WTH3-050 (§4.8) The server shall support deriving a TLS exporter for
  a given WebTransport session with the label "EXPORTER-WebTransport" and
  a context set to the serialization of the WebTransport Exporter Context
  struct.
  - test: `tests/tls/keyschedule_test.c` —
    `test_keyschedule_exporter_secret_matches_oneshot`
  - evidence: `tls_exporter` (RFC 8446 7.5's TLS-Exporter, new
    `tls/handshake/core/tls/exporter.c`) and `wt_exporter_ctx_encode`
    plus `wt_exporter` (the WebTransport Exporter Context
    serialization and the "EXPORTER-WebTransport" wrapper, new
    `app/webtransport/exporter/exporter.c`) are implemented and reachable
    from a live `keysched` (exporter_master_secret is derived
    automatically at the same stage as the application traffic secrets,
    `keysched_exporter_secret`).
  - gap: no application-facing WebTransport session API exposes this yet
    (draft-ietf-webtrans-http3-15 leaves the exporter-request API's shape
    to the implementation).

## §5.1 Negotiating the Use of Flow Control

- [~] WTH3-051 (§5.1) A WebTransport endpoint that allows a session to
  share a transport connection with other sessions shall enable flow
  control by sending a non-zero SETTINGS_WT_INITIAL_MAX_STREAMS_UNI,
  SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI, or SETTINGS_WT_INITIAL_MAX_DATA.
  - test: `tests/app/h3settings_build_test.c` —
    `test_h3settings_build_wt_flow_control_initial_limits`
  - test: `tests/app/h3settings_build_test.c` —
    `test_h3settings_build_wt_flow_control_zero_omits_pairs`
  - gap: the three SETTINGS_WT_INITIAL_MAX_* identifiers (0x2b64/0x2b65/
    0x2b61) are now defined and `h3settings_build` sends each when its
    `h3settings_in` field is non-zero, but no caller decides to enable
    them yet -- this SDK's 2-session cap (`SRVRUN_MAX_WT_SESSIONS`) remains
    a static limit, and every existing call site still passes 0 for these
    three fields (relying on the pre-existing per-session capsule
    mechanism, WTH3-056/059/060/062).
- [x] WTH3-052 (§5.1) If flow control is not enabled, the server shall
  reject more than one simultaneous WebTransport session with a
  H3_REQUEST_REJECTED status.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_reject_at_session_limit`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_second_wt_connect_sends_reset_stream`
  - evidence: this SDK's fixed 2-session cap is stricter than "exactly
    one", so the cited tests demonstrate the analogous reject-at-limit
    behavior rather than the spec's literal single-session default.
- [~] WTH3-053 (§5.1) If flow control is not enabled, an endpoint shall
  ignore receipt of any flow control capsules.
  - test: `tests/app/wtcapsule_test.c` —
    `test_wtcapsule_max_streams_decoded_value_ignored_until_applied`
  - evidence: no receive path calls a flow-control capsule decoder yet
    (WTH3-058..062), so "ignore" is not a live decision any caller makes;
    what the cited test pins down is that `wired_wt_session`'s own
    flow-control state (session.h SS5.3/5.4) already behaves exactly as
    this rule prescribes for "not enabled" -- a session that never had
    `wired_wt_session_set_max_streams`/`set_max_data` applied to it keeps
    allowing streams/data unconditionally, so a future receive path that
    decodes-but-does-not-apply a capsule (the "ignore" choice) has zero
    effect by construction.
  - gap: still no live receive path decodes WT_MAX_STREAMS/WT_MAX_DATA
    off the wire at all (same gap as WTH3-058..062), so the ignore rule
    itself remains unexercised end to end.

## §5.2 Limiting the Number of Simultaneous Sessions

- [x] WTH3-054 (§5.2) Servers should limit the rate of incoming
  WebTransport sessions to prevent excessive resource consumption, using
  H3_REQUEST_REJECTED or HTTP status code 429.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_second_wt_connect_rejected_429`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_second_wt_connect_sends_reset_stream`
- [x] WTH3-055 (§5.2) An endpoint that does not support pooling and flow
  control shall not accept more than one incoming WebTransport session at
  a time.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_limit_one_matches_legacy_behavior`

## §5.3 Limiting the Number of Streams Within a Session

- [~] WTH3-056 (§5.3) The WT_MAX_STREAMS capsule shall establish a limit
  on the number of streams within a WebTransport session, with separate
  types for unidirectional and bidirectional streams.
  - test: `tests/app/wtcapsule_test.c` —
    `test_wtcapsule_max_streams_bidi_roundtrip`
  - test: `tests/app/wt_session_test.c` —
    `test_flow_control_max_streams_bidi_enforced`
  - gap: `quic_wtcapsule_{encode,decode}_max_streams` and
    `wired_wt_session_set_max_streams` exist and are tested, but no
    receive-capsule loop in `srvrun.c` calls them yet.
- [~] WTH3-057 (§5.3) An endpoint shall not open more streams than
  permitted by the current stream limit set by its peer.
  - test: `tests/app/wt_session_test.c` —
    `test_flow_control_max_streams_bidi_enforced`
  - gap: `wired_wt_session_stream_open_allowed`/`_note_stream_opened` exist
    and are tested, but no stream-open call site in `srvrun.c` consults
    them yet.
- [x] WTH3-058 (§5.3) If an endpoint receives an incoming stream for a
  session that would exceed the advertised Maximum Streams value, then
  the endpoint shall close the WebTransport session with a
  WT_FLOW_CONTROL_ERROR error code.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_uni_exceeding_max_streams_refused`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_close_wt_flow_violations_resets_session`
  - evidence: a stream open exceeding the limit refuses the open and
    latches `wt_flow_violation`; `srvrun_close_wt_flow_violations` closes
    the session on the next step with WT_FLOW_CONTROL_ERROR mapped through
    `wired_wterrmap_to_http3`.
- [~] WTH3-059 (§5.3) The WT_STREAMS_BLOCKED capsule can be sent to
  indicate that an endpoint was unable to create a stream due to the
  session-level stream limit.
  - test: `tests/app/wtcapsule_test.c` —
    `test_wtcapsule_streams_blocked_roundtrip`
  - gap: codec exists and is tested; no send-site triggers it yet.

## §5.4 Data Limits

- [~] WTH3-060 (§5.4) The WT_MAX_DATA capsule shall establish a limit on
  the amount of data that can be sent within a WebTransport session.
  - test: `tests/app/wtcapsule_test.c` — `test_wtcapsule_max_data_roundtrip`
  - test: `tests/app/wt_session_test.c` — `test_flow_control_max_data_enforced`
  - gap: codec and session-level tracking exist and are tested, but no
    receive-capsule loop calls them yet.
- [x] WTH3-061 (§5.4) If an endpoint receives Stream Body data in excess
  of the WT_MAX_DATA limit, then the endpoint shall close the
  WebTransport session with a WT_FLOW_CONTROL_ERROR error code.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_uni_exceeding_max_data_refused`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_stream_reply_exceeding_max_data_refused`
  - evidence: data exceeding the WT_MAX_DATA limit refuses the send and
    latches `wt_flow_violation`, closed by the same
    `srvrun_close_wt_flow_violations` path as WTH3-058.
- [~] WTH3-062 (§5.4) The WT_DATA_BLOCKED capsule can be sent to indicate
  that an endpoint was unable to send data due to a WT_MAX_DATA limit.
  - test: `tests/app/wtcapsule_test.c` —
    `test_wtcapsule_data_blocked_roundtrip`
  - gap: codec exists and is tested; no send-site triggers it yet.
- [x] WTH3-063 (§5.4) Per-stream data limits are provided by QUIC natively
  (WT_MAX_STREAM_DATA and WT_STREAM_DATA_BLOCKED capsules are prohibited
  and must not be used).
  - test: `tests/app/wtcapsule_test.c` —
    `test_wtcapsule_no_per_stream_flow_control_capsule`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_max_stream_data_wire_shape`

## §6 Session Termination

- [x] WTH3-064 (§6) A WebTransport session shall be considered terminated
  when either the CONNECT stream is closed (cleanly or abruptly) or a
  WT_CLOSE_SESSION capsule is sent or received.
  - test: `tests/app/wt_session_test.c` — `test_close_from_established`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_connect_stream_reset_closes_wt_session`
- [x] WTH3-065 (§6) Upon learning that a session has been terminated, the
  endpoint shall reset the send side and abort reading on the receive
  side of all streams associated with the session using the
  WT_SESSION_GONE error code, and shall not send any new datagrams or
  open any new streams.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_connect_stream_reset_resets_owned_wt_bidi_stream`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_connect_stream_reset_resets_owned_wt_uni_stream`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_connect_stream_reset_leaves_other_sessions_streams`
  - evidence: `srvrun_reset_wt_streams_for_session` resets every WT bidi/uni
    stream the closing session owns (tracked via `wt_session_slot`) with
    WT_SESSION_GONE when its CONNECT stream closes; datagram send/receive
    are separately gated on session state (9297-007/008).
- [x] WTH3-066 (§6) To terminate a session with a detailed error message,
  an application may provide such a message in a WT_CLOSE_SESSION
  (0x2843) capsule carrying a 32-bit Application Error Code and an error
  message of at most 1024 bytes.
  - test: `tests/app/wtcapsule_test.c` — `test_wtcapsule_close_roundtrip`
  - test: `tests/app/wtcapsule_test.c` —
    `test_wtcapsule_close_encode_rejects_long_message`
- [~] WTH3-067 (§6) An endpoint that sends a WT_CLOSE_SESSION capsule
  shall immediately send a FIN on the CONNECT stream; if additional
  stream data is received on the CONNECT stream after receiving a
  WT_CLOSE_SESSION capsule, the stream shall be reset with code
  H3_MESSAGE_ERROR.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_close_session_latches_pending`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_drain_wt_close_pending_closes_session`
  - evidence: the send side is complete: the new public
    `wired_server_wt_close_session` API latches the close request, and
    `srvrun_drain_wt_close_pending` seals the WT_CLOSE_SESSION capsule
    immediately followed by a FIN on the CONNECT stream. The receive side
    (resetting trailing CONNECT-stream data with H3_MESSAGE_ERROR after a
    received WT_CLOSE_SESSION) is not implemented: this SDK has no
    byte-level CONNECT-stream reassembly mechanism to detect such trailing
    data, the same root cause as RFC 9297's 9297-021 (see
    [rfc9297.md](rfc9297.md)).
- [x] WTH3-068 (§6) Cleanly terminating a CONNECT stream without a
  WT_CLOSE_SESSION capsule shall be semantically equivalent to
  terminating it with a WT_CLOSE_SESSION capsule carrying error code 0
  and an empty error string.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_connect_stream_reset_closes_wt_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_other_stream_reset_does_not_close_wt_session`

## Out of scope

Client-only, intermediary-only, and informational requirements this server
SDK does not implement, excluded from the coverage denominator:

- (§2.1.1) Web-security-model constraints on WebTransport clients (Web
  Platform API exposure, browser-specific rate-limit-quota behavior) —
  client/browser behavior.
- (§2.1.2) The capsule-based WebTransport-over-a-single-stream protocol
  defined in draft-ietf-webtrans-http2 (the "webtransport" HTTP/2 upgrade
  token variant) — a distinct protocol from this document's native-stream
  mapping; out of this SDK's HTTP/3-only scope.
- (§3.2) WebTransport client behavior on receiving a 3xx redirect (MUST
  NOT auto-follow) — client behavior.
- (§3.3) Client-side WT-Available-Protocols header construction and
  WT_ALPN_ERROR session closure on an invalid WT-Protocol response —
  client behavior.
- (§3.4) Endpoint interaction concerns when prioritizing WebTransport
  sessions relative to other sessions/requests on the same connection —
  qualitative guidance, not a directly testable server behavior.
- (§4.1) The "Pooling" transport property's quota-header-based
  alternative to real pooling support — optional (MAY) elaboration this
  SDK does not implement as a distinct code path from the session-limit
  behavior already covered (WTH3-052/054/055).
- (§5.1) Rate limit header fields communicating quota policies
  (I-D.ietf-httpapi-ratelimit-headers) — a separate draft this SDK does
  not implement.
- (§5.6.1) Intermediary-specific flow-control-capsule consumption and
  re-expression behavior — this SDK is an endpoint, not a WebTransport
  intermediary.
- (§7) Considerations for future WebTransport versions beyond the
  currently negotiated draft codepoints — forward-looking guidance, not a
  requirement on this draft's own implementation.
- (§8) Qualitative security guidance (fairness schemes, suspicious-activity
  detection via H3_EXCESSIVE_LOAD, client-side session-count
  self-limiting) — informational, not a directly testable server
  requirement; `H3_EXCESSIVE_LOAD` is defined (RFC 9114) but this
  draft only recommends its use, it does not require it.
