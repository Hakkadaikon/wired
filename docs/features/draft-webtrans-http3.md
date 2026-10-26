[Docs](../README.md) › [Features](README.md) › draft-ietf-webtrans-http3-16

# draft-ietf-webtrans-http3-16 — WebTransport over HTTP/3

EARS requirement ledger extracted from the spec text
(`tasks/specs/draft-ietf-webtrans-http3-16.txt`, not in git), server side.
Each requirement carries the test that demonstrates it; an unchecked box
with no test line is an open gap. Status as of 2026-10.

Legend:

- `[x]` — demonstrated by the referenced test
- `[~]` — exercised indirectly (evidence line explains how; no dedicated test)
- `[ ]` — not demonstrated by any test yet

**Coverage: 73/81 tested, 8 indirect, 0 untested.**

## §3.1 Establishing a WebTransport-Capable HTTP/3 Connection

- [x] WTH3-001 (§3.1) The server shall signal support for WebTransport over
  HTTP/3 by sending a SETTINGS_WT_ENABLED setting with the value 1.
  - test: `tests/app/h3settings_control_settings_test.c` —
    `test_h3settings_control_settings_advertises_wt`
  - test: `tests/app/h3settings_build_test.c` —
    `test_h3settings_build_h3_datagram_and_wt_enabled`
- [x] WTH3-002 (§3.1) Where WebTransport is not configured, the server shall
  leave SETTINGS_WT_ENABLED at its default value 0 by not sending it.
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
- [x] WTH3-005 (§3.1) Where WebTransport is configured, the server shall
  send a max_datagram_frame_size transport parameter with a value greater
  than 0 to indicate support for QUIC datagrams.
  - test: `tests/tls/server_tp_test.c` —
    `test_server_tp_datagram_frame_size`
- [x] WTH3-006 (§3.1) The server shall send an empty reset_stream_at
  transport parameter to enable the RESET_STREAM_AT extension.
  - test: `tests/tls/server_tp_test.c` — `test_server_tp_reset_stream_at_empty`
- [x] WTH3-007 (§3.1) If the server receives SETTINGS or transport
  parameters that do not have correct values for every required
  WebTransport setting/parameter, then the server shall treat all
  established and newly incoming WebTransport sessions as malformed.
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_settings_h3_datagram_required`
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_no_datagram_tp_malformed`
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_h3_token_requires_reset_stream_at`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_held_connect_rejected_after_settings`
  - evidence: a CONNECT is reset with H3_MESSAGE_ERROR (RFC 9114 4.1.2)
    unless the client sent SETTINGS_H3_DATAGRAM=1, a non-zero
    max_datagram_frame_size and -- for the `webtransport-h3` token; the
    draft-07 `webtransport` token predates it -- reset_stream_at
    (`srvrun_wt_peer_ok`). No session can be established before the
    client's SETTINGS (WTH3-009) and a second SETTINGS frame is a
    connection error, so the per-CONNECT check also covers established
    sessions.
- [x] WTH3-008 (§3.1, §7.1) For draft versions of WebTransport, the server
  shall send SETTINGS_WT_ENABLED with the codepoint of each draft version
  it supports, so the peer can identify the supported version(s).
  - test: `tests/app/h3settings_build_test.c` —
    `test_h3settings_build_h3_datagram_and_wt_enabled`
  - evidence: the built SETTINGS carry both the draft-02 (0x2b603742) and
    the current (0x2c7cf000, -16 §9.2) codepoints in the same frame.
- [x] WTH3-009 (§3.1, §7.1) For draft versions of WebTransport, the server
  shall not process any incoming WebTransport requests until the client's
  SETTINGS have been received.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_before_client_settings_held`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_two_held_connects_each_processed_once`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_after_client_settings_establishes`
  - evidence: a CONNECT that arrives first is held without a response and
    processed once the client's SETTINGS arrive, instead of being refused.

## §3.2 Creating a New Session

- [x] WTH3-010 (§3.2) To create a new WebTransport session, the server
  shall require the `:protocol` pseudo-header field to equal
  "webtransport-h3" (or the deployed "webtransport" draft-07 token).
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_establishes_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_webtransport_token`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_plain_connect_no_protocol_no_wt_session`
- [x] WTH3-011 (§3.2) The `:scheme` field of a WebTransport CONNECT request
  shall be https.
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_connect_http_scheme_malformed`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_missing_scheme_no_session`
- [x] WTH3-012 (§3.2) Both the `:authority` and `:path` values shall be set
  on a WebTransport CONNECT request; these fields identify the desired
  WebTransport server resource.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_missing_authority_no_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_missing_path_no_session`
  - test: `tests/app/srvrun_test.c` — `test_srvrun_wt_accept_records_path`
- [x] WTH3-013 (§3.2) Where the request contains an Origin header, the
  server shall verify the Origin header to ensure that the specified
  origin is allowed to access the server in question.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_origin_check_allowed_establishes`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_origin_check_disallowed_403`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_origin_check_absent_empty_span`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_origin_check_unset_unchanged`
  - evidence: the application's `wired_srvrun_opt.wt_origin_check` callback
    decides each Origin (an absent header reaches it as an empty span); a
    present-but-empty Origin is refused with 403 before the callback. With
    no callback set, only the well-formedness check applies.
- [x] WTH3-014 (§3.2) If Origin verification fails, then the server should
  reply with status code 403.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_origin_malformed_403`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_origin_check_disallowed_403`
- [x] WTH3-015 (§3.2) If all checks pass, the server may accept the
  session by replying with a 2xx series status code.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_establishes_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_origin_ok_establishes`
- [x] WTH3-016 (§3.2) Where the target resource does not support
  WebTransport, the server should reply with status code 405.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_resource_check_405_no_session`
  - evidence: the app registers a `wired_wt_resource_check` callback
    (`srvrun_wt_resource_decide`) consulted on every Extended CONNECT before
    a session is established; a callback that reports "not found" builds a
    bare 405 response and never reaches the app handler.
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
- [~] WTH3-019 (§3.2) If the server accepts 0-RTT, then the server shall
  not reduce the WebTransport-related initial flow control SETTINGS values
  from those negotiated during the previous session.
  - evidence: the server's SETTINGS_WT_INITIAL_* values are compile-time
    constants (`DEFAULT_WT_INITIAL_*`, control_settings.c), so they never
    decrease between sessions; `h3settings_zerortt_compatible` also checks
    the never-reduce rule, but its WebTransport test functions in
    `tests/app/h3settings_control_settings_test.c` are not invoked from
    `tests/run.c`.
  - gap: no store of the settings sent when a resumed ticket was issued
    exists to supply the `prior` argument on a live 0-RTT accept path (same
    gap as 9114-066).
- [x] WTH3-020 (§3.2) The Capsule Protocol is negotiated for the
  "webtransport-h3" upgrade token when the server sends a 2xx response.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_connect_establishes_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_close_session_capsule_received`
  - vuln: V-0496
- [~] WTH3-075 (§3.2) The server shall not process bytes received on the
  CONNECT stream as capsules until it sends a 2xx response accepting the
  session, and shall discard them if the session is rejected.
  - evidence: the capsule receive cursor is armed only when
    `srvrun_start_wt` establishes the session (`srvrun_wt_capsule_arm`),
    starting right after the request HEADERS (`tests/app/srvrun_test.c` —
    `test_srvrun_wt_capsule_start_skips_connect_headers`); no test sends
    capsules ahead of the 2xx or on a rejected CONNECT.

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
- [x] WTH3-024 (§3.3) If the WT-Available-Protocols header field holds a
  value type other than String (or is otherwise not a valid Structured
  Field List), then the server shall ignore the entire field.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_negotiate_bad_syntax_no_header`
- [x] WTH3-076 (§3.3) The server shall ignore any parameters on
  WT-Available-Protocols list members.
  - test: `tests/app/sfield_test.c` — `test_sfield_parameters_are_skipped`

## §3.4 Prioritization

- [~] WTH3-026 (§3.4) WebTransport CONNECT requests and responses may
  contain the Priority header field, and clients may reprioritize by
  sending PRIORITY_UPDATE frames.
  - evidence: PRIORITY_UPDATE frame codec (`tests/app/priupdate_test.c`)
    is generic over any element_id, including a CONNECT stream's id; no
    test specifically drives a PRIORITY_UPDATE against an established
    WebTransport CONNECT stream. Server-side, the application can set an
    RFC 9218 urgency per WebTransport stream with
    `wired_server_wt_stream_priority`, and the send pump serves lower
    urgency first (`tests/app/srvrun_test.c` —
    `test_srvrun_wt_priority_lower_urgency_first`,
    `test_srvrun_wt_priority_blocked_urgent_does_not_starve`);
    `wired_server_wt_stream_schedule` adds a second class key and a
    per-flow order (`test_srvrun_wt_sched_better_class_first`,
    `test_srvrun_wt_sched_one_slice_per_pass`).

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
- [x] WTH3-030 (§4) If the server receives a session ID on a
  unidirectional stream, bidirectional stream, or datagram that does not
  correspond to a client-initiated bidirectional stream ID, then the
  server shall close the connection with an H3_ID_ERROR error code.
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_non_client_bidi_session_id_closes`
  - evidence: a datagram's Quarter Stream ID always maps to a multiple of
    4, so only the WT stream headers can carry such an id; a CONNECT on a
    non-client-bidi id cannot be opened by a client at all (it still gets
    H3_ID_ERROR, `test_srvrun_wt_connect_non_client_bidi_id_rejected`).
- [x] WTH3-031 (§4) Session IDs corresponding to closed sessions shall not
  themselves be considered invalid for the client-initiated-bidi-stream
  check; endpoints handle data for closed sessions per session
  termination rules.
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_closed_session_id_not_an_id_error`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_foreign_stream_id_rejected`

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
- [~] WTH3-035 (§4.3) If a WT_STREAM signal value (0x41) is received as a
  frame type on an HTTP/3 stream other than the very first bytes of a
  request stream, then the server shall treat this as a connection error
  of type H3_FRAME_ERROR.
  - test: `tests/app/srvloop_test.c` —
    `test_srvloop_wt_signal_mid_stream_latches_violation`
  - evidence: the test asserts the detection latch
    (`wt_signal_mid_stream_violation`); the close with H3_FRAME_ERROR that
    `srvrun_close_on_step_violation` performs on the next step is not
    asserted by any test.

## §4.4 Resetting Data Streams

- [x] WTH3-036 (§4.4) The server shall propagate a RESET_STREAM or
  STOP_SENDING for a WebTransport data stream to the application, and
  shall take an application error code for each reset/stop it sends.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_reset_mapped_delivers_app_error_code`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_stream_reset_sends_reset_and_frees_slot`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_stream_stop_sends_stop_sending`
- [x] WTH3-037 (§4.4) WebTransport application error codes for streams
  shall be remapped into the WT_APPLICATION_ERROR range, where 0x00000000
  corresponds to 0x52e4a40fa8db and 0xffffffff corresponds to
  0x52e5ac983162, skipping reserved codepoints of form 0x1f*N+0x21.
  - test: `tests/app/wterrmap_test.c` — `test_wterrmap`
- [x] WTH3-038 (§4.4) WebTransport implementations shall use the
  RESET_STREAM_AT frame with a Reliable Size set to at least the size of
  the WebTransport header when resetting a WebTransport data stream.
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_reset_stream_at_covers_header`
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_reset_stream_at_fallbacks`
  - test: `tests/tls/sdrv_test.c` —
    `test_sdrv_recv_client_hello_reset_stream_at`
  - evidence: sent only to a peer that advertised the reset_stream_at
    transport parameter (draft-ietf-quic-reliable-stream-reset-09 3; an
    unnegotiated 0x24 kills Chrome's connection), else RESET_STREAM
    (`test_srvrun_wt_abort_frames_match_stream_type`). The header bytes
    ride the same kept packet as a STREAM frame, so they are resent until
    ACKed after the send slot is released. A client-initiated stream
    carries no header on the server's half, so it is reset with
    RESET_STREAM (Reliable Size 0 is equivalent, rsr-09 4).
- [x] WTH3-039 (§4.4) The server shall deliver the error code of a stream
  reset associated with a known session unchanged to the application that
  owns that session.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_reset_mapped_delivers_app_error_code`
- [x] WTH3-040 (§4.4) If a RESET_STREAM or STOP_SENDING frame is received
  with an error code outside the WT_APPLICATION_ERROR range, then the
  implementation should deliver this to the application as a stream reset
  with no application error code.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_reset_unmapped_delivers_no_app_error_code`

## §4.5 Datagrams

- [x] WTH3-041 (§4.5) The WebTransport datagram payload shall be sent
  unmodified in the HTTP Datagram Payload field, directly following the
  Quarter Stream ID field.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_send_datagram_to_prefixes_qsid`

## §4.6 Buffering Incoming Streams and Datagrams

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

- [~] WTH3-047 (§4.7) When the server has sent GOAWAY, the server shall not
  accept CONNECT requests for new WebTransport sessions on streams at or
  past the GOAWAY stream ID.
  - evidence: `srvrun_start_resp` refuses any request stream at or past the
    sent GOAWAY id with H3_REQUEST_REJECTED before method dispatch, so a
    WebTransport CONNECT takes the same path (`tests/app/srvrun_test.c` —
    `test_srvrun_goaway_id_past_largest_accepted`, driven with GET); no
    test drives a CONNECT past GOAWAY.
- [x] WTH3-048 (§4.7) An HTTP/3 GOAWAY frame is also a signal to
  applications to initiate shutdown for all WebTransport sessions; to
  shut down a single session, either endpoint can send a
  WT_DRAIN_SESSION capsule.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_send_wt_drain_seals_capsule_on_connect_stream`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_send_wt_drain_all_skips_inactive_slot`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_drain_session_sends_once`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_drain_rx_notifies_app`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_drain_rx_with_value_closes`
  - evidence: `srvrun_send_wt_drain_all` fans out a WT_DRAIN_SESSION
    capsule to every active WebTransport session when GOAWAY is sent,
    driving each session's `wired_wt_session_drain` ESTABLISHED->DRAINING
    transition. `wired_server_wt_drain_session` drains one session, at most
    once; a peer's WT_DRAIN_SESSION reaches the application through
    `wt_on_session_draining`, and a DRAIN carrying a value closes the
    session as malformed.
- [x] WTH3-049 (§4.7) After sending or receiving a WT_DRAIN_SESSION
  capsule, an endpoint may continue using the session and open new
  WebTransport streams (drain is advisory, not terminal).
  - test: `tests/app/wt_session_test.c` —
    `test_drain_is_advisory_not_terminal`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_drain_one_session_leaves_others_untouched`

## §4.8 Use of Keying Material Exporters

- [x] WTH3-050 (§4.8) The server shall support deriving a TLS exporter for
  a given WebTransport session with the label "EXPORTER-WebTransport" and
  a context set to the serialization of the WebTransport Exporter Context
  struct.
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_exporter_matches_tls_exporter`
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_exporter_sha384_suite`
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_exporter_refusals`
  - test: `tests/tls/keyschedule_test.c` —
    `test_keyschedule_exporter_secret_matches_oneshot`

## §5.1 Negotiating the Use of Flow Control

- [x] WTH3-051 (§5.1, §8) The server shall enable flow control by sending
  non-zero SETTINGS_WT_INITIAL_MAX_STREAMS_UNI,
  SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI and SETTINGS_WT_INITIAL_MAX_DATA.
  - test: `tests/app/h3settings_control_settings_test.c` —
    `test_h3settings_control_settings_advertises_wt`
  - evidence: the server sends 2^60 / 2^60 / 2^62-1
    (`DEFAULT_WT_INITIAL_*`, control_settings.c); the test checks each
    advertised value is accepted as a non-zero limit and that 1000 streams
    fit under it. Flow control is then on whenever the client also sends
    a non-zero one (`srvrun_wt_seed_limits`).
- [x] WTH3-052 (§5.1) If flow control is not enabled and the server
  receives more than one WebTransport session on the connection, then the
  server shall reset the excessive CONNECT streams with
  H3_REQUEST_REJECTED.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_second_wt_connect_rejected_when_flow_control_disabled`
  - vuln: V-0503, V-0509
- [x] WTH3-053 (§5.1) If flow control is not enabled, then the server
  shall ignore receipt of any flow control capsules.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_max_data_capsule_ignored_when_flow_control_disabled`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_max_streams_capsule_ignored_when_flow_control_disabled`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_streams_blocked_ignored_when_flow_control_disabled`
  - vuln: V-0505

## §5.2 Limiting the Number of Simultaneous Sessions

- [x] WTH3-054 (§5.2) Servers should limit the rate of incoming
  WebTransport sessions to prevent excessive resource consumption, using
  H3_REQUEST_REJECTED or HTTP status code 429.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_reject_at_session_limit`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_session_creation_rate_limited`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_second_wt_connect_rejected_429`
  - test: `tests/app/srvrun_test.c` — `test_srvrun_wt_occupancy_counts_open`
  - evidence: `wired_server_wt_occupancy` reports the open sessions and
    the cap, so an application can shed load before the limit is hit.
  - vuln: V-0506
- [x] WTH3-055 (§5.2) While flow control is not enabled, the server shall
  not accept more than one incoming WebTransport session at a time.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_second_wt_connect_rejected_when_flow_control_disabled`
  - vuln: V-0503, V-0509

## §5.3 Limiting the Number of Streams Within a Session

- [x] WTH3-056 (§5.3) The WT_MAX_STREAMS capsule shall establish a limit
  on the number of streams within a WebTransport session, with separate
  types for unidirectional and bidirectional streams.
  - test: `tests/app/wtcapsule_test.c` —
    `test_wtcapsule_max_streams_bidi_roundtrip`
  - test: `tests/app/wt_session_test.c` —
    `test_flow_control_max_streams_bidi_enforced`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_rx_max_streams_capsules_raise_limits`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_rx_max_streams_capsule_via_dispatch_raises_limit`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_initial_max_streams_from_settings`
- [x] WTH3-057 (§5.3) An endpoint shall not open more streams than
  permitted by the current stream limit set by its peer.
  - test: `tests/app/wt_session_test.c` —
    `test_flow_control_max_streams_bidi_enforced`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_uni_exceeding_max_streams_refused`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_bidi_exceeding_max_streams_refused`
- [~] WTH3-058 (§5.3) If an endpoint receives an incoming stream for a
  session that would exceed the advertised Maximum Streams value, then
  the endpoint shall close the WebTransport session with a
  WT_FLOW_CONTROL_ERROR error code.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_refused_stream_reset_and_credited`
  - evidence: this server advertises 2^60 streams per direction
    (WTH3-051) and never lowers it with a WT_MAX_STREAMS of its own, so an
    incoming stream can never exceed the limit and the receiver-side close
    cannot trigger. What does bound incoming streams is the fixed stream
    table: a stream beyond it is reset with H3_REQUEST_REJECTED and its
    QUIC stream credit is returned.
- [x] WTH3-059 (§5.3, §5.6.3) When the server wishes to open a stream but is
  unable to due to the session-level stream limit set by its peer, the
  server should send a WT_STREAMS_BLOCKED capsule.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_uni_blocked_sends_streams_blocked`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_bidi_blocked_sends_streams_blocked`
  - test: `tests/app/wtcapsule_test.c` —
    `test_wtcapsule_streams_blocked_roundtrip`
- [x] WTH3-069 (§5.6.2) If a received WT_MAX_STREAMS value does not
  increase the session's current stream limit for that direction (the
  same value or a decrease) or exceeds 2^60, then the server shall close
  the WebTransport session with a WT_FLOW_CONTROL_ERROR error code.
  - test: `tests/app/wt_session_test.c` —
    `test_flow_control_max_streams_equal_value_rejected`
  - test: `tests/app/wt_session_test.c` —
    `test_flow_control_max_streams_decreasing_rejected`
  - test: `tests/app/wt_session_test.c` —
    `test_flow_control_max_streams_over_ceiling_rejected`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_nonincreasing_flow_control_capsule_closes_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_max_streams_over_ceiling_closes_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_initial_max_streams_from_settings`
- [x] WTH3-070 (§5.6.3) If a received WT_STREAMS_BLOCKED value exceeds
  2^60, then the server shall close the WebTransport session with a
  WT_FLOW_CONTROL_ERROR error code.
  - test: `tests/app/wt_session_test.c` — `test_streams_blocked_ceiling`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_streams_blocked_over_ceiling_closes_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_streams_blocked_within_ceiling_is_noop`

## §5.4 Data Limits

- [x] WTH3-060 (§5.4) The WT_MAX_DATA capsule shall establish a limit on
  the amount of data that can be sent within a WebTransport session.
  - test: `tests/app/wtcapsule_test.c` — `test_wtcapsule_max_data_roundtrip`
  - test: `tests/app/wt_session_test.c` — `test_flow_control_max_data_enforced`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_rx_max_data_capsule_via_dispatch_unblocks_send`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_rx_max_data_capsule_via_on_step_raises_max_data`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_initial_max_data_from_settings`
- [x] WTH3-077 (§5.6.4) The server shall not send Stream Body data on a
  session's streams in excess of the Maximum Data value advertised by the
  peer.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_uni_exceeding_max_data_refused`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_stream_reply_exceeding_max_data_refused`
- [~] WTH3-061 (§5.4) If an endpoint receives Stream Body data in excess
  of the WT_MAX_DATA limit, then the endpoint shall close the
  WebTransport session with a WT_FLOW_CONTROL_ERROR error code.
  - evidence: this server advertises 2^62-1 bytes (WTH3-051) and never
    lowers it, so received data can never exceed the limit and the
    receiver-side close cannot trigger; QUIC stream and connection credit
    bound received data instead.
- [x] WTH3-062 (§5.4, §5.6.5) When the server wishes to send data but is
  unable to due to session-level flow control, the server should send a
  WT_DATA_BLOCKED capsule.
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_data_limited_send_emits_data_blocked_once`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_open_uni_blocked_by_data_limit_sends_data_blocked`
- [x] WTH3-063 (§5.4) If the server receives a WT_MAX_STREAM_DATA or a
  WT_STREAM_DATA_BLOCKED capsule, then the server shall treat it as a
  session error.
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_stream_level_flow_capsule_session_error`
  - evidence: the session closes with WT_FLOW_CONTROL_ERROR (the draft
    names no code for this session error) and a FIN on the CONNECT stream.
- [x] WTH3-071 (§5.6.4) If a received WT_MAX_DATA value does not increase
  the session's current data limit (the same value or a decrease), then
  the server shall close the WebTransport session with a
  WT_FLOW_CONTROL_ERROR error code.
  - test: `tests/app/wt_session_test.c` —
    `test_flow_control_max_data_equal_value_rejected`
  - test: `tests/app/wt_session_test.c` —
    `test_flow_control_max_data_decreasing_rejected`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_nonincreasing_flow_control_capsule_closes_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_initial_max_data_from_settings`

## §5.6 Flow Control Capsules

- [~] WTH3-078 (§5.6) While flow control is enabled, the server should send
  WT_MAX_DATA and WT_MAX_STREAMS capsules as it consumes data or closes
  streams, and shall not wait for a WT_DATA_BLOCKED or WT_STREAMS_BLOCKED
  capsule before sending them.
  - evidence: the server never sends WT_MAX_DATA/WT_MAX_STREAMS; it
    advertises effectively unbounded initial limits instead (2^60 streams,
    2^62-1 bytes, WTH3-051), which a peer cannot exhaust
    (`tests/app/h3settings_control_settings_test.c` —
    `test_h3settings_control_settings_advertises_wt`), so no credit
    update is ever owed.

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
  WT_SESSION_GONE error code -- a protocol-level HTTP/3 error code, sent
  raw and never mapped into the WebTransport application error code
  range -- and shall not send any new datagrams or open any new streams.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_connect_stream_reset_resets_owned_wt_bidi_stream`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_connect_stream_reset_resets_owned_wt_uni_stream`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_connect_stream_reset_leaves_other_sessions_streams`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_send_datagram_to_requires_send_side_open`
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
- [x] WTH3-067 (§6) When the server sends a WT_CLOSE_SESSION capsule, the
  server shall immediately send a FIN on the CONNECT stream.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_send_wt_close_seals_capsule_with_fin`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_close_session_latches_pending`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_drain_wt_close_pending_closes_session`
  - evidence: the public `wired_server_wt_close_session` API latches the
    close request, and `srvrun_drain_wt_close_pending` seals the
    WT_CLOSE_SESSION capsule as the CONNECT stream's last round, so the FIN
    follows it; capsules travel inside HTTP/3 DATA frames on the CONNECT
    stream (RFC 9297 3.2, see 9297-024 in [rfc9297.md](rfc9297.md)). The
    sending side was checked against webtransport-go.
- [x] WTH3-079 (§6) When the server receives a WT_CLOSE_SESSION capsule,
  the server shall either close or reset the CONNECT stream in response.
  - test: `tests/app/srvrun_close_test.c` —
    `test_srvrun_close_peer_capsule_fins_connect`
  - test: `tests/app/srvrun_close_test.c` —
    `test_srvrun_close_peer_fin_fins_connect`
  - test: `tests/app/srvrun_close_test.c` —
    `test_srvrun_close_peer_capsule_and_fin_one_fin`
  - test: `tests/app/srvrun_close_test.c` —
    `test_srvrun_close_bad_capsule_resets_no_fin`
  - evidence: `srvrun_wt_connect_fin` closes this server's side with a FIN
    at the stream's current end, once (an invalid close body resets the
    stream instead, WTH3-072). Loopback-tested only; the moq-playa interop
    case (`transport.closed`) has not been re-run.
- [x] WTH3-080 (§6) If additional stream data is received on the CONNECT
  stream after a WT_CLOSE_SESSION capsule, then the server shall reset the
  stream with code H3_MESSAGE_ERROR.
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_data_after_close_same_frame_resets`
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_data_after_close_later_frame_resets`
  - test: `tests/app/srvrun_wtsess_test.c` —
    `test_srvrun_wt_fin_after_close_no_reset`
  - evidence: one CONNECT stream is watched per connection after its
    close (`wired_srvloop_wt_watch`); a second session closing meanwhile
    replaces the watch.
- [x] WTH3-068 (§6) Cleanly terminating a CONNECT stream without a
  WT_CLOSE_SESSION capsule shall be semantically equivalent to
  terminating it with a WT_CLOSE_SESSION capsule carrying error code 0
  and an empty error string.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_connect_stream_reset_closes_wt_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_other_stream_reset_does_not_close_wt_session`
- [x] WTH3-072 (§6) If a received WT_CLOSE_SESSION capsule's Application
  Error Message exceeds 1024 bytes or is not valid UTF-8, then the server
  shall reset the CONNECT stream with error code H3_MESSAGE_ERROR (which
  also terminates the session, per WTH3-064).
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_close_message_too_long_resets_and_closes`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_close_message_invalid_utf8_resets_and_closes`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_close_message_at_max_len_closes_session`
  - test: `tests/app/wtcapsule_test.c` — `test_wt_utf8_valid_ascii`
  - test: `tests/app/wtcapsule_test.c` —
    `test_wt_utf8_invalid_truncated_sequence`
- [x] WTH3-073 (§6) When truncating an application-provided
  WT_CLOSE_SESSION Application Error Message to the 1024-byte cap, the
  server shall truncate at the last whole UTF-8 character boundary at or
  before the cap, never splitting a multi-byte sequence.
  - test: `tests/app/wtcapsule_test.c` —
    `test_wt_utf8_truncate_len_backs_off_before_split_sequence`
  - test: `tests/app/wtcapsule_test.c` —
    `test_wt_utf8_truncate_len_keeps_sequence_ending_at_cap`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_close_session_truncates_at_utf8_boundary`
- [x] WTH3-081 (§6) When the server sends a WT_CLOSE_SESSION and intends to
  close the QUIC connection, the server should wait until all CONNECT
  streams have been closed by the peer before sending CONNECTION_CLOSE.
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_shutdown_waits_for_connect_close`
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_shutdown_wait_ends_on_reset_or_closing`
  - evidence: graceful shutdown (srvrun_loop) sends WT_CLOSE_SESSION on
    every live session after the GOAWAY drain, then serves until the peer
    closed those CONNECT streams (bounded, SRVRUN_WT_CLOSE_TICKS) before
    the H3_NO_ERROR CONNECTION_CLOSE. Error closes stay immediate.

## §8 Security Considerations

- [x] WTH3-082 (§8) The server should track the use of WebTransport
  features, such as the number of incoming streams and datagrams, and set
  limits on their use.
  - test: `tests/app/srvrun_test.c` — `test_srvrun_wt_usage_counters_exposed`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_stream_churn_bounded_by_slot_table`
  - vuln: V-0494, V-0512
- [x] WTH3-083 (§8) The server should implement a fairness scheme that
  gives each session sharing a connection a reasonable share of sending
  and stream-opening resources.
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_fair_pass_equal_per_session`
  - test: `tests/app/srvrun_wtflow_test.c` —
    `test_srvrun_wt_open_capped_per_session`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_sched_equal_flows_share`
  - evidence: in each send pass every session with ready streams sends the
    same number of slices (the smallest ready count among them), rotating
    among its own streams; a session may hold at most its even share of
    the send-slot table the connection plumbing leaves free.

## §9.5 HTTP/3 Error Code Registration

- [x] WTH3-074 (§9.5) WT_BUFFERED_STREAM_REJECTED and WT_SESSION_GONE are
  HTTP/3-level error codes registered in the IANA "HTTP/3 Error Code"
  registry, and the server shall send them as their own raw value, never
  mapped into the WebTransport application error code range.
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_wt_bidi_stream_buffer_full_sends_reset`
  - test: `tests/app/srvrun_test.c` —
    `test_srvrun_connect_stream_reset_resets_owned_wt_bidi_stream`

## Out of scope

Client-only, intermediary-only, and informational requirements this server
SDK does not implement, excluded from the coverage denominator:

- (§2.1.1) QPACK static decompression and Huffman decoding support —
  tracked in the RFC 9204 ledger.
- (§2.1.2) The capsule-based WebTransport-over-a-single-stream protocol
  defined in draft-ietf-webtrans-http2 (the "webtransport" HTTP/2 upgrade
  token variant) and the SHOULD to prefer this document's protocol — a
  distinct protocol from this document's native-stream mapping; out of
  this SDK's HTTP/3-only scope.
- (§3.1) Client duties: treating SETTINGS_WT_ENABLED > 1 as
  H3_SETTINGS_ERROR, not attempting sessions before the server's setting,
  sending the draft codepoint, not establishing sessions when server
  requirements are unmet, and the optional WT_REQUIREMENTS_NOT_MET close —
  client behavior.
- (§3.2) The browser client's duty to send Origin, not auto-following a 3xx
  redirect, and closing with H3_SETTINGS_ERROR when resumed SETTINGS reduce
  flow control values — client behavior.
- (§3.3) A server that requires application protocol negotiation rejecting
  a request with no suitable or a malformed WT-Available-Protocols —
  optional (MAY) strict mode this SDK does not ship; negotiation is opt-in
  and never rejects.
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
- (§4.3) The client's duty to send the 0x41 signal on the bidirectional
  streams it opens — client behavior (server recognition is WTH3-034).
- (§4.4) An intermediary forwarding RESET_STREAM/STOP_SENDING with the
  same frame type and error code — intermediary behavior.
- (§4.6) The client waiting for the server's SETTINGS before sending
  CONNECT — client behavior (the server-side hold is WTH3-009).
- (§4.7) A client that received GOAWAY opening a new connection for new
  sessions — client behavior.
- (§5.1) Clients not attempting more than one session when flow control is
  not enabled — client behavior (the server-side reject is WTH3-052).
- (§5.2) Rate limit header fields communicating quota policies
  (I-D.ietf-httpapi-ratelimit-headers) — a separate draft this SDK does
  not implement.
- (§5.6.1-§5.6.5) Intermediary-specific flow-control-capsule consumption
  and re-expression behavior — this SDK is an endpoint, not a WebTransport
  intermediary.
- (§7) Considerations for future WebTransport versions beyond the
  currently negotiated draft codepoints — forward-looking guidance, not a
  requirement on this draft's own implementation.
- (§8) Client-side session-count self-limiting, and the optional (MAY)
  H3_EXCESSIVE_LOAD close on suspicious activity — client behavior /
  optional; `H3_EXCESSIVE_LOAD` is defined (RFC 9114) but not used here.
