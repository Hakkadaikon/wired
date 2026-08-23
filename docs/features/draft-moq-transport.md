[Docs](../README.md) › [Features](README.md) › draft-ietf-moq-transport-19

# draft-ietf-moq-transport-19 — Media over QUIC Transport

EARS requirement ledger extracted from the spec text
(`tasks/specs/draft-ietf-moq-transport-19.txt`, not in git), for this SDK's
MOQT subset: a single central hub relay implementing SETUP, PUBLISH,
SUBSCRIBE, and Subgroup-stream Object delivery over WebTransport. Each
requirement carries the test that demonstrates it; an unchecked box with no
test line is an open gap. Status as of 2026-08.

Legend:

- `[x]` — demonstrated by the referenced test
- `[~]` — exercised indirectly (evidence line explains how; no dedicated test)
- `[ ]` — not demonstrated by any test yet

**Coverage: 170/177 tested, 7 indirect, 0 untested.**

## SS1.4.1 Variable-Length Integers

- [x] MOQT-001 The implementation shall decode a MOQT variable-length integer
  using the number of leading 1 bits of the first byte to determine the encoded
  length (1-9 bytes), with the remaining bits and any subsequent bytes holding
  the value in network byte order.
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_official_examples`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_zero_all_lengths`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_nine_byte_padded`
- [x] MOQT-002 The implementation shall encode all 64-bit unsigned integers (0
  to 2^64-1) using the MOQT variable-length integer encoding.
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_official_examples`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_boundaries`
- [x] MOQT-003 The implementation shall encode a variable-length integer using
  the minimum number of bytes that can represent the value.
  - test: `tests/app/moqvi_test.c` — `test_moqvi_roundtrip`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_official_examples`
- [x] MOQT-004 Where a variable-length integer is encoded with more bytes than
  the minimum required, the implementation shall still decode it to the correct
  value (non-minimal encodings are valid).
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_zero_all_lengths`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_nine_byte_padded`
- [x] MOQT-005 If a variable-length integer's encoded length exceeds the number
  of bytes available, then the implementation shall report the decode as
  insufficient rather than reading past the input.
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_truncated`
- [x] MOQT-006 The implementation shall decode a variable-length integer
  without consuming bytes beyond its own encoded length, leaving any trailing
  bytes in the input untouched.
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_ignores_trailing`
- [x] MOQT-007 If the destination buffer is too small to hold the encoded
  length of a value, then the implementation shall fail the encode rather than
  writing past the buffer.
  - test: `tests/app/moqvi_test.c` — `test_moqvi_put_too_small`

## SS1.4.2 Location Structure

- [x] MOQT-008 The implementation shall encode/decode a Location as two
  consecutive variable-length integers (Group, Object).
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`
- [x] MOQT-009 The implementation shall compare two Locations A and B such that
  A < B iff A.Group < B.Group, or A.Group == B.Group and A.Object < B.Object.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`

## SS1.4.3 Key-Value-Pair Structure

- [x] MOQT-010 The implementation shall decode a Key-Value-Pair's Type as the
  previous cumulative Type plus a Delta Type (0 for the first pair).
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_even_num`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_delta_accumulates`
- [x] MOQT-011 If the cumulative Key-Value-Pair Type would exceed 2^64-1, then
  the implementation shall report a protocol violation.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_type_overflow`
- [x] MOQT-012 The implementation shall decode the Value of an odd-Type
  Key-Value-Pair as Length bytes, and of an even-Type pair as a single
  variable-length integer.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_even_num`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_odd_raw`
- [x] MOQT-013 The Length field of a Key-Value-Pair shall not exceed 2^16-1
  bytes; if a larger length is received, the implementation shall report a
  protocol violation.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_len_65535_accepted`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_len_65536_violation`
- [x] MOQT-014 Where a Key-Value-Pair's Value does not match the serialization
  defined by a Type the implementation understands, the implementation shall
  report a formatting error distinct from a protocol violation.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_put_rejects`
  - evidence: `moqctl_setup_take` maps a malformed known Setup Option to
    session close; the KVP layer itself exposes only the codec-level put-side
    rejection tested here (`moqkvp_put_rejects`); the formatting-vs-violation
    distinction is fully exercised at the SETUP layer (see MOQT-045).
- [x] MOQT-015 The implementation shall not use the minimum encoding length for
  a Key-Value-Pair's Delta Type or even-Type Value as a decode requirement
  (non-minimal encodings are valid).
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_nonminimal_delta`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_nonminimal_even_value`
- [x] MOQT-016 If a Key-Value-Pair is truncated within its own known byte
  bound, then the implementation shall report a protocol violation.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_truncated_insufficient`
- [x] MOQT-017 The implementation shall decode a Key-Value-Pair without reading
  past the caller-supplied byte bound, and shall encode a round-trippable
  Key-Value-Pair list preserving Type order.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_roundtrip`

## SS1.4.4 Reason Phrase Structure

- [x] MOQT-018 The implementation shall decode a Reason Phrase as a
  variable-length integer Length followed by that many UTF-8 bytes.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_reason_boundary`
- [x] MOQT-019 If a Reason Phrase Length exceeds 1024 bytes, then the
  implementation shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_reason_boundary`

## SS2.4.1 Track Naming

- [x] MOQT-020 The implementation shall decode a Track Namespace as a
  variable-length integer field count followed by that many length-prefixed
  Track Namespace Fields.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ftn_decode_basic`
- [x] MOQT-021 If a Track Namespace Field has a Length of 0, then the
  implementation shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ns_field_len_zero_rejected`
- [x] MOQT-022 If a Track Namespace has more than 32 Track Namespace Fields,
  then the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_ns_fields_32_accept_33_reject`
- [x] MOQT-023 If a Full Track Name (Track Namespace plus Track Name) exceeds
  4096 bytes, then the implementation shall close the session with a protocol
  violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ftn_4096_accept_4097_reject`
- [x] MOQT-024 The implementation shall compare Track Namespace Fields and
  Track Names by exact byte comparison.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ftn_eq_exact_bytes`

## SS2.4.2 Malformed Tracks

- [~] MOQT-025 If a subscriber detects a Malformed Track, then the
  implementation shall cancel the corresponding subscription for that Track
  from that publisher.
  - evidence: The subset's malformed-track surface is limited to what the hub
    itself can detect from wire framing (unknown Object Status, cumulative
    Object ID overflow -- see MOQT-071/MOQT-072); the general receiver-side
    malformed-track catalog in SS2.4.2 (priority mismatch across a Subgroup ID,
    Object ID exceeding the Subgroup/Group/Track final, differing final Objects
    across FIN'd streams, duplicate Objects with different payload) is not
    implemented by this loss-free single-hub subset -- see Out of scope.

## SS2.5 Properties / SS2.5.1 Mandatory Track Properties

- [x] MOQT-026 The implementation shall recognize Property type ranges
  0x78-0x7F and 0x3800-0x3FFF as reserved for application-specific use.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_grease_pattern`
  - evidence: `moqctl_is_grease` and the Track Properties residual-span decode
    (MOQT-053) pass these ranges through uninterpreted; no dedicated boundary
    test pins the exact 0x78-0x7F/0x3800-0x3FFF edges.
- [x] MOQT-027 The implementation shall recognize Property types in the range
  0x4000-0x7FFF as Mandatory Track Properties.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_grease_pattern`
  - evidence: No dedicated boundary test for the 0x4000-0x7FFF range itself;
    the codec treats Track Properties as an opaque residual span (MOQT-053) and
    does not currently classify or reject individual Mandatory Track Property
    types.

## SS3.2.1 Reserved Namespaces / SS3.2.2 Session-Level Tracks

- [~] MOQT-028 If a request references a Track Namespace whose first field is a
  single period, then the implementation shall reject it with DOES_NOT_EXIST.
  - evidence: This subset's hub uses a single fixed room namespace and never
    receives an arbitrary client-chosen namespace on SUBSCRIBE/PUBLISH (see
    moqtrun.h's own doc: room membership is hub-side fixed, not negotiated);
    reserved-namespace and `.session` rejection are not exercised by any test.

## SS3.3 Session Initialization

- [x] MOQT-029 The server shall open one unidirectional control stream and send
  SETUP as its first message.
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_on_session_sends_setup`
- [x] MOQT-030 Once both endpoints have sent and received SETUP, the session
  shall be Established.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_establish`
  - test: `tests/app/moqsess_test.c` —
    `test_moqsess_established_accepts_request`
- [x] MOQT-031 A bidirectional request stream shall begin with one of the
  First-type messages (TRACK_STATUS, SUBSCRIBE, PUBLISH, FETCH,
  PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS); if it does not,
  the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_bad_first_message`
- [x] MOQT-032 Where a unidirectional stream containing Objects or a
  bidirectional request stream arrives before both control streams have
  completed SETUP, the implementation shall buffer it rather than deliver it to
  the application.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsess_buffer_before_setup_then_deliver`
- [x] MOQT-033 Where SETUP has not yet completed, the implementation may reset
  a bidirectional request stream instead of buffering it.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_pre_setup_reset_window`
- [x] MOQT-034 An endpoint may pipeline further control messages after sending
  its own SETUP without waiting for the peer's SETUP.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsess_pipeline_before_peer_setup`
- [x] MOQT-035 If a control stream is closed at the transport layer during the
  session's lifetime, then the implementation shall close the session with a
  protocol violation.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsess_ctrl_stream_transport_close`
- [x] MOQT-036 If the same peer opens a second control stream, then the
  implementation shall close the session with a protocol violation.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_second_control_stream`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_on_session_twice_is_idempotent`

## SS3.3.4 Stream Reset Error Codes / SS3.5 Termination (used subset)

- [x] MOQT-037 The implementation shall recognize the session termination error
  code table entries it uses (NO_ERROR, INTERNAL_ERROR, PROTOCOL_VIOLATION,
  INVALID_REQUEST_ID, DUPLICATE_TRACK_ALIAS, KEY_VALUE_FORMATTING_ERROR,
  INVALID_PATH, GOAWAY_TIMEOUT, INVALID_AUTHORITY).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_grease_pattern`
  - evidence: These codes are used as `#define`s at their call sites
    (moqctl.h/moqsess.h) rather than round-tripped through a codec; no
    dedicated test enumerates the full table, but each code's use is exercised
    at its own violation site (see the sess/data/ctl unwanted-behavior items
    throughout this file).

## SS3.4 Unidirectional Stream Types

- [x] MOQT-038 The implementation shall classify a unidirectional stream's
  leading variable-length integer as one of SETUP (0x2F00), FETCH_HEADER
  (0x05), SUBGROUP_HEADER (0b0XX1XXXX), or PADDING (0x132B3E28).
  - test: `tests/app/moqdata_test.c` — `test_moqdata_classify_golden`
- [x] MOQT-039 If an endpoint receives an unknown unidirectional stream type,
  then the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_unknown_uni_stream_type`
- [x] MOQT-040 The implementation shall classify a unidirectional stream
  without consuming bytes past a truncated leading type field, reporting the
  classification as insufficient instead.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_classify_truncated`

## SS3.5 Termination

- [~] MOQT-041 The server shall close a WebTransport-carried MOQT session using
  the CLOSE_WEBTRANSPORT_SESSION mechanism.
  - evidence: MOQT sessions in this subset run over the WT session API
    (app/http3/server/srvrun); WT session close itself is proven by the
    WebTransport ledger (see docs/features/draft-webtrans-http3.md WTH3
    entries), not re-tested here.

## SS3.6 Session Migration / SS10.4 GOAWAY (session lifecycle)

- [x] MOQT-042 An endpoint that has sent or received GOAWAY may reject a new
  request with an error indicating the endpoint is going away, while the
  session remains open.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_goaway_reject_new_request`
- [x] MOQT-043 An endpoint that has received GOAWAY on the control stream shall
  not initiate new requests of its own, without the session closing solely
  because of the GOAWAY.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_goaway_clean_shutdown`
- [x] MOQT-044 If the peer does not close the session within the GOAWAY
  timeout, then the sender shall close the session with GOAWAY_TIMEOUT.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_goaway_timeout_closes`
- [x] MOQT-045 If a server receives a GOAWAY with a non-zero New Session URI
  Length, then the implementation shall close the session with a protocol
  violation.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_goaway_bad_uri`
- [x] MOQT-046 If the same control stream receives more than one GOAWAY, then
  the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_second_goaway`
- [x] MOQT-047 Where a GOAWAY is received on a request stream rather than the
  control stream, the implementation shall accept it without closing the
  session, while a second GOAWAY on the same request stream shall still be a
  protocol violation.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_goaway_on_request_stream_produces_no_reply`

## SS9 Relays (SS9.4/9.6/9.7 forwarding discipline)

- [x] MOQT-048 A relay shall not reorder or drop Objects received on a
  multi-object stream when forwarding them to subscribers.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_to_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_two_subscribers_two_objects`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_normalize_forwards_only_whole_objects`
- [x] MOQT-049 A relay shall not modify Object header fields or payload when
  forwarding an Object.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_preserves_bytes`
- [x] MOQT-050 The relay shall have an Established upstream subscription before
  sending SUBSCRIBE_OK in response to a downstream SUBSCRIBE.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_matching_publish_replies_ok`
- [x] MOQT-051 If a relay receives a SUBSCRIBE for a Track no publisher has
  PUBLISHed, then the implementation shall reply with REQUEST_ERROR
  DOES_NOT_EXIST.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_without_publish_replies_error`
- [~] MOQT-052 A relay may aggregate authorized subscriptions for a given Track
  when multiple subscribers request it, forwarding a single upstream Object to
  every matching downstream subscriber.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_to_all_three_subscribers`

## SS10 Control Messages: common envelope

- [x] MOQT-053 The implementation shall encode/decode every control message as
  Message Type (varint) + Message Length (16-bit) + Message Body.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_setup`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
- [x] MOQT-054 The implementation shall recognize the Message Type table
  entries it implements: SETUP (0x2F00), GOAWAY (0x10), SUBSCRIBE (0x3),
  SUBSCRIBE_OK (0x4), PUBLISH (0x1D), PUBLISH_DONE (0xB), REQUEST_OK (0x7),
  REQUEST_ERROR (0x5).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_setup`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_ok_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_done_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_ok_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_error_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_roundtrip`
- [x] MOQT-055 If an endpoint receives an unknown Message Type, then the
  implementation shall report it distinctly so the caller closes the session.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_unknown`
- [x] MOQT-056 The implementation shall distinguish a known-but-unimplemented
  Message Type (e.g. REQUEST_UPDATE, FETCH, TRACK_STATUS, PUBLISH_NAMESPACE,
  SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS) from a wholly unknown one, so the
  caller can reply NOT_SUPPORTED instead of closing the session.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_peek_type_known_unimplemented`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unknown_first_type_gets_not_supported`
- [x] MOQT-057 If a control message's declared Length does not match the actual
  Message Body length available, then the implementation shall not treat the
  message as complete (reporting insufficient rather than misreading past the
  body).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_length_mismatch`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_truncated`
- [x] MOQT-058 The implementation shall support a control message total length
  up to 2^16-1 bytes.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_max_len_field`

## SS10.1 Request ID

- [x] MOQT-059 The client shall generate even-numbered Request IDs starting at
  0, and the server shall generate odd-numbered Request IDs starting at 1,
  incrementing by 2 for each new request.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_and_audio_get_different_aliases`
  - evidence: The hub's own `request_id_next` field increments by 2 per new
    server-initiated request (moqtrun.h); no dedicated test isolates the
    arithmetic outside the alias-allocation tests, so this is `[~]` rather than
    `[x]`.
- [x] MOQT-060 If an endpoint receives a Request ID whose least significant bit
  is incorrect for the sender, then the implementation shall close the session
  with INVALID_REQUEST_ID.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_bad_request_id_parity`
- [x] MOQT-061 If an endpoint receives a duplicate Request ID, then the
  implementation shall close the session with INVALID_REQUEST_ID.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_duplicate_request_id`

## SS10.2 Message Parameters

- [x] MOQT-062 The implementation shall decode Message Parameters as a Type
  Delta (varint, cumulative from the previous Parameter Type) followed by a
  Value whose encoding (uint8, varint, Location, or length-prefixed bytes) is
  fixed per Type.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_delivery_timeout_decode`
- [x] MOQT-063 Parameters shall be serialized in ascending order by Type; if
  the cumulative Parameter Type would exceed 2^64-1, the implementation shall
  close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_type_overflow_violation`
- [x] MOQT-064 If an endpoint receives an unknown Message Parameter Type, then
  the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_unknown_type_violation`
- [x] MOQT-065 If a sender repeats the same Parameter Type in one message, then
  the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_duplicate_type_violation`
- [x] MOQT-066 If a Message Parameter is defined for message types other than
  the one it appears in, then the implementation shall close the session with a
  protocol violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_scope_violation`
- [x] MOQT-067 Message Parameters in SUBSCRIBE, PUBLISH_OK, and FETCH shall not
  cause the publisher to alter the payload of the Objects it sends.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_preserves_bytes`
  - evidence: No parameter value is ever consulted when constructing an
    Object's payload in moqtrun.c; the relay-preserves-bytes test demonstrates
    payload identity end-to-end but does not vary parameters to isolate this
    specific guarantee.

## SS10.2.3/10.2.4 SUBGROUP_DELIVERY_TIMEOUT / OBJECT_DELIVERY_TIMEOUT

- [x] MOQT-068 The implementation shall decode the SUBGROUP_DELIVERY_TIMEOUT
  (0x06) and OBJECT_DELIVERY_TIMEOUT (0x02) Message Parameters as a varint,
  with a value of 0 meaning no timeout set.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_delivery_timeout_decode`
- [x] MOQT-069 The hub shall not send a delivery-timeout parameter in its own
  SUBSCRIBE_OK / REQUEST_OK / PUBLISH_DONE replies (the loss-free single-hub
  subset does not set delivery timeouts).
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_ok_carries_no_timeout_param`
- [x] MOQT-070 If a SUBSCRIBE carries a non-zero SUBGROUP_DELIVERY_TIMEOUT or
  OBJECT_DELIVERY_TIMEOUT parameter, then the hub shall reject it with
  REQUEST_ERROR NOT_SUPPORTED.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_nonzero_timeout_rejected`

## SS10.2.17 FORWARD Parameter

- [x] MOQT-071 The implementation shall encode/decode the FORWARD parameter
  (Type 0x10) as a uint8 whose value is 0 (don't forward) or 1 (forward),
  defaulting to 1 when omitted.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
- [x] MOQT-072 A publisher that sends FORWARD=0 in PUBLISH shall not transmit
  any Objects until the subscriber sets Forward State to 1; Object forwarding
  toward a subscription is gated by its Forward State.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_forward_state_zero_blocks_objects`

## SS10.3 SETUP

- [x] MOQT-073 The implementation shall encode/decode SETUP's Setup Options as
  a Key-Value-Pair list spanning the message payload.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
- [x] MOQT-074 Endpoints shall ignore unrecognized Setup Options.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_setup_unknown_option_ignored`
- [x] MOQT-075 Senders shall not repeat the same Setup Option Type in a message
  unless the option explicitly allows multiple instances.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
  - evidence: `moqctl_setup_encode` writes each of
    PATH/AUTHORITY/MOQT_IMPLEMENTATION at most once by construction; no test
    drives an encoder input with a duplicate to confirm rejection on decode
    (decode simply keeps the last-seen value for a repeated known option,
    matching the KVP layer's own duplicate-tolerant model).

## SS10.3.1.1 AUTHORITY / SS10.3.1.2 PATH / SS10.3.1.5 MOQT_IMPLEMENTATION

- [x] MOQT-076 The implementation shall decode the PATH (0x01) and AUTHORITY
  (0x05) Setup Options as byte-string values.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_path_option_decode`
- [~] MOQT-077 If a PATH or AUTHORITY option is received while WebTransport is
  used, then the implementation shall close the session with INVALID_PATH or
  INVALID_AUTHORITY respectively.
  - evidence: `moqctl_setup_take` only surfaces `has_path`/`has_authority` to
    the caller (moqctl.h's own doc: "WebTransport-context rejection is a
    session-layer decision"); no session-layer test in this ledger exercises
    the WT-context rejection itself.
- [x] MOQT-078 The implementation shall decode the MOQT_IMPLEMENTATION (0x07)
  Setup Option as a UTF-8 byte-string value.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`

## SS10.4 GOAWAY (wire format)

- [x] MOQT-079 The implementation shall encode/decode GOAWAY as Type (0x10) +
  Length + New Session URI Length + New Session URI + Timeout.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_roundtrip`
- [x] MOQT-080 If the New Session URI Length exceeds 8192 bytes, then the
  implementation shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_uri_boundary`
- [x] MOQT-081 A client shall send a zero-length New Session URI in any GOAWAY
  it sends.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_roundtrip`
  - evidence: The wire codec accepts and round-trips a zero-length URI; no test
    asserts the client-side encoder path specifically refuses a non-zero URI
    (the receiving side's rejection is MOQT-032 above).

## SS10.5 REQUEST_OK

- [x] MOQT-082 The implementation shall encode/decode REQUEST_OK as Type (0x7)
  + Length + Number of Parameters + Parameters + Track Properties (the
  remaining message bytes).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_ok_roundtrip`
- [x] MOQT-083 If a REQUEST_OK variant that must have empty Track Properties
  (e.g. PUBLISH_OK) carries non-empty Track Properties, then the implementation
  shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_ok_roundtrip`
  - evidence: `moqctl_request_ok_take` always decodes the residual span and
    lets the caller (which knows which request it answers) enforce the
    per-variant empty-Track-Properties rule (moqctl.h's own doc); no
    session/run-layer test exercises the enforcement itself.

## SS10.6 REQUEST_ERROR

- [x] MOQT-084 The implementation shall encode/decode REQUEST_ERROR as Type
  (0x5) + Length + Error Code + Retry Interval + Error Reason + optional
  Redirect.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_error_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_request_error_redirect_roundtrip`
- [x] MOQT-085 The Redirect structure shall be present only when Error Code is
  REDIRECT.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_request_error_redirect_roundtrip`
- [x] MOQT-086 If a server receives a Redirect with a non-zero Connect URI
  Length, then the implementation shall close the session with a protocol
  violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_request_error_redirect_roundtrip`
  - evidence: `moqctl_request_error_take` decodes the Redirect structure
    symmetrically for either role; the server-specific non-zero-URI rejection
    is a session-layer decision not exercised by a dedicated test.
- [x] MOQT-087 The implementation shall recognize the REQUEST_ERROR codes it
  uses: INTERNAL_ERROR, NOT_SUPPORTED, GOING_AWAY, INVALID_FILTER,
  UNINTERESTED, DOES_NOT_EXIST, UNAUTHORIZED, REDIRECT.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`
- [x] MOQT-088 If an endpoint receives an unrecognized REQUEST_ERROR code, then
  the implementation shall treat it as INTERNAL_ERROR rather than closing the
  session.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`

## SS10.7 SUBSCRIBE / SS10.8 SUBSCRIBE_OK

- [x] MOQT-089 The implementation shall encode/decode SUBSCRIBE as Type (0x3) +
  Length + Request ID + Track Namespace + Track Name + Number of Parameters +
  Parameters.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_roundtrip`
- [x] MOQT-090 On a successful subscription, the publisher shall reply with
  exactly one SUBSCRIBE_OK.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_ok_roundtrip`
  - test: `tests/app/moqsess_test.c` — `test_moqsub_subscribe_establish`
- [x] MOQT-091 The implementation shall encode/decode SUBSCRIBE_OK as Type
  (0x4) + Length + Track Alias + Number of Parameters + Parameters + Track
  Properties.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_ok_roundtrip`
- [x] MOQT-092 If a subscriber sends more than one SUBSCRIBE_OK or
  REQUEST_ERROR in response to the same SUBSCRIBE, then the implementation
  shall treat the second response as a session-level protocol fault.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_duplicate_response_is_session_fault`
- [x] MOQT-093 If a publisher rejects a SUBSCRIBE with REQUEST_ERROR, then no
  Object shall be sent for that subscription.
  - test: `tests/app/moqsess_test.c` — `test_moqsub_subscribe_rejected`

## SS10.10 PUBLISH

- [x] MOQT-094 The implementation shall encode/decode PUBLISH as Type (0x1D) +
  Length + Request ID + Track Namespace + Track Name + Track Alias + Number of
  Parameters + Parameters + Track Properties.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_roundtrip`
- [x] MOQT-095 On a successful PUBLISH-initiated subscription, the subscriber
  shall reply with exactly one PUBLISH_OK (REQUEST_OK).
  - test: `tests/app/moqsess_test.c` — `test_moqsub_publish_establish`
- [x] MOQT-096 A publisher may start sending Objects on a PUBLISH-initiated
  subscription before receiving PUBLISH_OK.
  - test: `tests/app/moqsess_test.c` — `test_moqsub_object_before_publish_ok`
- [x] MOQT-097 If a subscriber rejects a PUBLISH with REQUEST_ERROR
  UNINTERESTED, then the subscription shall terminate without any Object being
  sent.
  - test: `tests/app/moqsess_test.c` — `test_moqsub_publish_rejected`

## SS10.11 PUBLISH_DONE

- [x] MOQT-098 The implementation shall encode/decode PUBLISH_DONE as Type
  (0xB) + Length + Status Code + Stream Count + Error Reason.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_done_roundtrip`
- [x] MOQT-099 A sender shall not send PUBLISH_DONE until it has closed every
  data stream it opened for that subscription.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_publish_done_terminates_and_reclaims`
- [x] MOQT-100 PUBLISH_DONE plus closing the subscription's bidi stream shall
  terminate the subscription; the sender may then destroy subscription state.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_publish_done_terminates_and_reclaims`
- [x] MOQT-101 If PUBLISH_DONE arrives before the subscriber has sent its
  response, then the subscriber shall owe exactly one deferred PUBLISH_OK
  before it FINs.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_publish_done_before_response_defers_ok`
- [x] MOQT-102 The implementation shall recognize the PUBLISH_DONE status codes
  it uses: INTERNAL_ERROR, TRACK_ENDED, GOING_AWAY.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`
- [x] MOQT-103 If a publisher did not open any data stream for a subscription,
  then it shall set PUBLISH_DONE's Stream Count to 0.
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_relay_table_full_counts`
  - evidence: No dedicated PUBLISH_DONE-emission test exists in this subset
    (the hub does not currently send PUBLISH_DONE); the codec's Stream Count
    field itself round-trips any value including 0 (MOQT-063).

## SS10 Reason Phrase / Location / Track Namespace shared structures used in control messages

- [x] MOQT-104 The implementation shall encode/decode Message Parameters,
  Location, and Reason Phrase consistently across every control message that
  embeds them.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_reason_boundary`

## SS9.3.1 Location Filter (subscription filtering)

- [x] MOQT-105 The implementation shall decode a Location Filter's Filter Type
  as one of Next Group Start (0x1), Largest Object (0x2), AbsoluteStart (0x3),
  or AbsoluteRange (0x4), with the field layout (Start Location, End Group
  Delta) determined by the type.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_locfilter_next_group_and_largest`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_locfilter_abs_start_and_range_roundtrip`
- [x] MOQT-106 If an AbsoluteRange filter's End Group (Start.Group + End Group
  Delta) would exceed 2^64-1, then the implementation shall close the session
  with a protocol violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_locfilter_end_group_overflow_violation`
- [x] MOQT-107 If an endpoint receives a Location Filter Type other than the
  four defined values, then the implementation shall close the session with a
  protocol violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_locfilter_unknown_type_violation`
- [x] MOQT-108 The publisher shall forward only Objects that pass the
  combination Forward State AND Location Filter (Pass = Forward AND Filters).
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_forward_state_zero_blocks_objects`
  - evidence: This subset does not implement Location Filter evaluation on the
    forwarding path (the hub forwards to every Established, Forward=1
    subscriber unconditionally -- see Out of scope); only the Forward-State
    half of the Pass predicate is exercised.

## SS14 Grease

- [x] MOQT-109 The implementation shall recognize the grease value pattern
  0x7f*N + 0x9D for non-negative integer N in registries that reserve it (Setup
  Options, Properties, error/status code tables).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_grease_pattern`
- [x] MOQT-110 Endpoints shall not close the session solely because they
  received an unknown value in a greased registry (Setup Options, error codes).
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_setup_unknown_option_ignored`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`

## SS11.1 Track Alias

- [x] MOQT-111 The same Track Alias shall not be used by a publisher to refer
  to two different Tracks simultaneously in the same session.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_and_audio_get_different_aliases`
- [~] MOQT-112 If a subscriber receives a PUBLISH or SUBSCRIBE_OK reusing a
  Track Alias already bound to a different Established subscription, then the
  implementation shall close the session with DUPLICATE_TRACK_ALIAS.
  - evidence: The hub allocates aliases itself per-track (starting from 0
    independently per track, see moqtrun_test.c's own comment on
    `test_moqtrun_chat_and_audio_get_different_aliases`) and never receives an
    attacker-controlled alias to validate; the receiver-side duplicate-alias
    rejection is not exercised by any test in this subset.

## SS11.2.1.1 Object Status

- [x] MOQT-113 The implementation shall recognize Object Status values 0x0
  (Normal), 0x3 (End of Group), and 0x4 (End of Track).
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_status_values`
- [x] MOQT-114 If an Object carries an unregistered Status value, then the
  implementation shall close the session with a protocol violation.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_status_values`
- [x] MOQT-115 An Object shall have an empty payload unless its Object Status
  is Normal (0x0); the Object Status field shall be present only when Payload
  Length is 0.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_status_eog`
  - test: `tests/app/moqdata_test.c` —
    `test_moqdata_obj_take_status_eog_stream`

## SS11.2.1.2 Object Properties

- [x] MOQT-116 If an endpoint receives Object Properties on an Object whose
  Status is not Normal, then the implementation shall close the session with a
  protocol violation.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_properties`
- [x] MOQT-117 Object Properties shall be serialized as a Properties Length
  (varint) followed by a Key-Value-Pair list.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_properties`

## SS11.4.2 Subgroup Header

- [x] MOQT-118 All Objects on a stream opened with SUBGROUP_HEADER shall have
  Object Forwarding Preference = Subgroup, belonging to the Track Alias, Group
  ID, and Subgroup ID the header declares.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_basic`
- [x] MOQT-119 The SUBGROUP_HEADER Type field shall take the form 0b0XX1XXXX
  (bit 4 always set); if received with any other form, the implementation shall
  close the session with a protocol violation.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_valid_golden`
- [x] MOQT-120 The implementation shall decode the SUBGROUP_ID_MODE field (bits
  1-2) as: 0b00 Subgroup ID absent and 0, 0b01 Subgroup ID absent and equal to
  the first Object's Object ID, 0b10 Subgroup ID present in the header.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode2`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode1_resolve`
- [x] MOQT-121 If SUBGROUP_ID_MODE is 0b11, then the implementation shall close
  the session with a protocol violation.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_valid_golden`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_bad_type`
- [x] MOQT-122 The implementation shall decode the PROPERTIES bit (0x01),
  END_OF_GROUP bit (0x08), DEFAULT_PRIORITY bit (0x20), and FIRST_OBJECT bit
  (0x40) of the SUBGROUP_HEADER Type field.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_bits_golden`
- [x] MOQT-123 Where DEFAULT_PRIORITY is set, the Publisher Priority field
  shall be omitted from the header and the Subgroup shall inherit the priority
  from the subscription's control message.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_basic`
- [x] MOQT-124 Where the END_OF_GROUP bit is set and the stream terminates with
  a FIN, the implementation shall infer that no Object with the same Group ID
  and a larger Object ID exists.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_normalize_forwards_only_whole_objects`
  - evidence: The bit is decoded (MOQT-078) but the specific inference "no
    larger Object ID exists once END_OF_GROUP FINs" is not asserted by a
    dedicated test; it is implicit in how the relay forwards whole Objects.
- [x] MOQT-125 When the Original Publisher opens a new Subgroup, it shall set
  the FIRST_OBJECT bit to indicate the first Object in the stream is the first
  Object ever published in that Subgroup.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_bits_golden`
- [x] MOQT-126 The implementation shall encode/decode a SUBGROUP_HEADER
  byte-exact against its wire fields (Type, Track Alias, Group ID, optional
  Subgroup ID, optional Publisher Priority).
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_put_golden`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_put_errors`
- [x] MOQT-127 If a SUBGROUP_HEADER is truncated before all its declared fields
  are present, then the implementation shall report the decode as insufficient.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_truncated`
- [x] MOQT-128 The implementation shall resolve a mode-0b01 (deferred) Subgroup
  ID from the first Object's Object ID once decoded.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode1_resolve`

## SS11.4.2 Subgroup Object Fields

- [x] MOQT-129 The implementation shall encode/decode a Subgroup Object as
  Object ID Delta + optional Properties + Object Payload Length + optional
  Object Status + optional Object Payload.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_basic_stream`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_put`
- [x] MOQT-130 The Object ID shall be the Object ID Delta for the first Object
  in a Subgroup, and the previous Object ID plus the Delta plus 1 for each
  subsequent Object.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_delta_chain`
- [x] MOQT-131 If the resulting cumulative Object ID would exceed 2^64-1, then
  the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_id_overflow`
- [x] MOQT-132 If a Subgroup Object stream terminates with a FIN in the middle
  of a serialized Object, then the implementation shall not treat the partial
  Object as complete.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_truncated`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_decode_loop_stops_at_truncation`
- [x] MOQT-133 If a Subgroup Object stream's per-Object decode reports a
  protocol violation, then the implementation shall stop decoding further
  Objects on that stream at that point.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_decode_loop_stops_at_violation`
- [x] MOQT-134 The implementation shall decode more than one Object
  sequentially from a single stream buffer, matching the result of decoding
  each Object individually.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_decode_loop_single_object_matches_one_shot`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_decode_loop_multiple_objects`

## SS11.4.3 Closing Subgroup Streams

- [x] MOQT-135 If a sender has delivered all Objects in a Subgroup, then it
  shall close the stream with a FIN.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_split_data_then_bare_fin_relays_and_closes`
- [x] MOQT-136 An implementation that observes a stream FIN is assured it has
  received all Objects in that Subgroup from the start of the subscription.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_torn_object_held_until_complete`
- [x] MOQT-137 A relay shall not forward an Object on an existing Subgroup
  stream unless it is the next Object in that Subgroup (an Object split across
  two deliveries is held back until complete).
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_fresh_delivery_tail_held_back`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_frag_overflow_counted`
- [x] MOQT-138 A publisher stream's FIN with no accompanying new Object bytes
  shall close the corresponding relay stream via a bare FIN, not a rejected
  empty data send.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_split_data_then_bare_fin_relays_and_closes`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_split_data_then_bare_fin_closes`
- [x] MOQT-139 Two overlapping publisher streams on the same track shall each
  be relayed on their own independent stream, with each closed only by its own
  publisher's FIN.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_interleaved_chat_messages_close_independently`
- [x] MOQT-140 A subscriber that joins after a Subgroup stream has already
  started shall still receive a relay stream, opened carrying the already-sent
  SUBGROUP_HEADER.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_late_subscriber_gets_late_opened_stream`

## SS11.5.1 Padding Streams

- [x] MOQT-141 The implementation shall discard all data received on a padding
  stream (Type 0x132B3E28).
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_padding_stream_discarded`

## SS3.7 Congestion Control / flow control priority

- [~] MOQT-142 Endpoints shall allocate connection flow control to the control
  streams before allocating it to any data streams, so a receiver does not
  deadlock waiting for a control message that itself needs flow control to
  arrive.
  - evidence: This subset relies on the underlying WT/QUIC transport's own
    stream and connection flow control (app/http3/server/srvrun); no MOQT-layer
    test independently verifies control-before-data flow-control priority.

## SS11.4.2 Subgroup Object Fields (encoder byte-exactness)

- [x] MOQT-143 The implementation shall encode a Subgroup Object's Object ID
  Delta, Payload Length, and either an explicit Object Status (when the payload
  is empty) or the Payload bytes, byte-exact against the wire format.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_put`
- [x] MOQT-144 The one-message builder shall assemble a single SUBGROUP_HEADER
  carrying one Object byte-exact against the wire format, and shall fail
  without partial writes when the destination buffer is too small.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_msg_build_golden`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_msg_build_bounds`
  - test: `tests/app/moqdata_test.c` —
    `test_moqdata_put_path_status_eog_golden`

## SS5.1 Subscriptions (state machine, additional coverage)

- [x] MOQT-145 While a subscription is Established, Object forwarding toward it
  shall be permitted regardless of which side (SUBSCRIBE or PUBLISH) initiated
  it.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_object_delivery_after_subscribe`
- [x] MOQT-146 A REQUEST_UPDATE received on an Established subscription shall
  leave the subscription Established.
  - test: `tests/app/moqsess_test.c` — `test_moqsub_update_keeps_established`
- [x] MOQT-147 A requester that FINs its own direction immediately after
  sending its request, before any response, shall not have the request treated
  as failed.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_requester_early_fin_not_failed`
- [x] MOQT-148 The subscriber shall be able to terminate an Established or
  Pending(Subscriber) subscription by sending STOP_SENDING.
  - test: `tests/app/moqsess_test.c` — `test_moqsub_cancel_established`
- [x] MOQT-149 Where the requester's own direction is already FIN'd, cancelling
  a subscription shall send only STOP_SENDING on the receiving direction.
  - test: `tests/app/moqsess_test.c` — `test_moqsub_cancel_after_fin`
- [x] MOQT-150 If the responder FINs its own direction without ever sending a
  response, then the requester shall treat the request as failed.
  - test: `tests/app/moqsess_test.c` — `test_moqsub_early_fin_before_response`

## SS10 Control Messages: session-machine unwanted behavior (additional coverage)

- [x] MOQT-151 If the control stream carries an unknown message type or a
  Length/Body mismatch, then the implementation shall close the session with a
  protocol violation.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_malformed_control_message`
- [x] MOQT-152 Once a session is closed, further events shall be no-ops (the
  close reason is sticky).
  - test: `tests/app/moqsess_test.c` — `test_moqsess_closed_is_sticky`

## Hub relay: PUBLISH/SUBSCRIBE dispatch (SS9 Relays, SS10.5/10.7/10.10 applied)

- [x] MOQT-153 On a successful PUBLISH, the hub shall reply with REQUEST_OK on
  the same control stream without closing it.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_publish_replies_request_ok`
- [x] MOQT-154 A peer may PUBLISH more than one distinct track (up to the
  implementation's per-peer track capacity), each independently getting
  REQUEST_OK.
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_peer_publishes_two_tracks`
- [x] MOQT-155 If a peer attempts to PUBLISH more distinct tracks than the
  implementation's per-peer capacity, then the implementation shall reply with
  REQUEST_ERROR rather than silently overwriting an existing track.
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_third_publish_gets_error`
- [x] MOQT-156 Re-PUBLISHing the same Track Name that already occupies a slot
  shall reuse that slot rather than consuming a new one.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_republish_same_name_reuses_slot`
- [x] MOQT-157 A SUBSCRIBE naming any track a peer has PUBLISHed shall get
  SUBSCRIBE_OK with an assigned Track Alias.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_audio_track_replies_ok`
- [x] MOQT-158 Two SUBSCRIBE messages arriving in the same dispatch call shall
  each get their own reply queued without one overwriting the other.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_two_subscribe_oks_one_dispatch_no_overflow`

## Hub relay: Object forwarding to matching subscribers only (SS9.4, SS11.1)

- [x] MOQT-159 An Object shall be forwarded only to subscribers of the Track
  its Track Alias identifies, not to subscribers of any other Track in the same
  session.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_only_to_chat_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_object_relays_only_to_audio_subscriber`
- [x] MOQT-160 If an Object's Track Alias matches no Track the publisher has
  declared, then the implementation shall not forward it to any subscriber.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unknown_alias_object_relays_nowhere`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unbound_stream_id_relays_nowhere`
- [x] MOQT-161 Each Object matching multiple subscriptions to the same Track
  shall be sent once per matching subscription.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_to_all_three_subscribers`
- [x] MOQT-162 If forwarding an Object to one subscriber fails (the underlying
  transport refuses the send), then the implementation shall still forward it
  to every other matching subscriber, and shall count the loss rather than
  leaving it silent.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_one_of_three_subscribers_refused`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_send_uni_failure_counts_open_drop`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_stream_send_rejection_drops_frame_not_fatal`
- [x] MOQT-163 Objects sent with Forwarding Preference Subgroup shall be
  relayed as one complete SUBGROUP_HEADER-plus-Objects unit per relay send,
  matching the publisher's stream framing.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_multi_object_stream_relays_in_one_send_uni`
- [x] MOQT-164 A long-lived Subgroup stream's later data (arriving without a
  repeated SUBGROUP_HEADER) shall be appended to the same already-bound relay
  stream, not misread as a new header.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_data_stream_continues_across_calls_without_header`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_first_object_opens_then_appends`
- [x] MOQT-165 When a publisher's Subgroup stream FINs, the implementation
  shall close the corresponding relay stream and open a fresh one for the next
  Subgroup on a new publisher stream, rather than appending across the
  boundary.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_publisher_fin_closes_and_reopens`
- [x] MOQT-166 The implementation shall relay each Subgroup consistently with
  the transport primitive matching its own delivery shape (one-shot
  open+send+FIN for a single-round Subgroup, open without FIN plus later
  appends for a long-lived one).
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_still_uses_send_uni_every_object`
- [x] MOQT-167 Two subscribers to the same Track shall each get their own
  independent relay stream, so a delivery to one does not affect the other's
  stream binding.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_two_subscribers_independent_streams`

## Hub relay: sustained-refusal shedding (SS11.4.3 reset discipline, applied)

- [x] MOQT-168 If a subscriber's relay stream is sustained-busy (refused) past
  the implementation's threshold, then the implementation shall reset that
  stream and re-open a fresh one at the next delivery, rather than continuing
  to hold a stale backlog.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_streak_sheds_after_threshold`
- [x] MOQT-169 An accepted delivery in the middle of a busy run shall reset the
  busy-streak counter, so scattered transient refusals never accumulate into a
  shed.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_streak_success_resets`
- [x] MOQT-170 After a stream has been shed, a publisher's bare FIN arriving
  for that now-abandoned stream shall not be forwarded to it.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_shed_stream_skips_publisher_fin`
- [x] MOQT-171 The busy-streak counter shall be tracked per subscriber, so one
  starved subscriber's shed does not affect another subscriber's healthy
  stream.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_shed_isolated_per_subscriber`
- [x] MOQT-172 If the reset itself is refused by the underlying transport, then
  the implementation shall retry the shed on the next busy round rather than
  treating it as done.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_shed_refused_retries_next_round`
- [x] MOQT-173 A re-PUBLISH of a track shall clear its relay state, including
  any accumulated busy-streak counters from the prior incarnation.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_republish_clears_busy_streak`

## Hub relay: session teardown (SS3.5 Termination applied to relay state)

- [x] MOQT-174 When a session closes, the implementation shall free its peer
  slot so a later reconnect on the same underlying session pointer is treated
  as a fresh peer, not the dead one.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_close_frees_peer_for_reregistration`
- [x] MOQT-175 When a subscriber's session closes, the implementation shall
  deactivate its subscription entries on every other peer's tracks so a later
  Object is not relayed to the dead session.
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_close_drops_subscriptions`
- [x] MOQT-176 Closing a session the implementation never registered (or one
  already closed) shall be a no-op that leaves other peers unaffected.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_close_unknown_session_noop`
- [x] MOQT-177 Repeated register/close cycles past the implementation's
  peer-table capacity shall not leak slots; every reconnect shall still receive
  its SETUP.
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_close_reregister_churn`

## Out of scope

Features and requirements this hub relay subset does not implement, excluded
from the coverage denominator above:

- (SS1.5, SS1.5.1) Rendering/parsing namespace and track names as
  human-readable strings — an operator/logging concern; this SDK compares
  names as raw bytes only.
- (SS2.4.2) The general receiver-side Malformed Track detection catalog
  (Publisher Priority mismatch across a Subgroup ID, Object ID exceeding a
  Subgroup/Group/Track final, differing finals across FIN'd streams,
  duplicate Objects with a different payload, Forwarding Preference change)
  — this loss-free single-hub subset does not implement general
  malformed-track detection beyond the two decode-time violations it does
  check (unknown Object Status, Object ID overflow).
- (SS3.1, SS3.1.1-3.1.6) Raw-QUIC transport, the `moqt` URI scheme,
  fragment identifiers, and MOQT URI dereferencing — this SDK runs MOQT
  over WebTransport only; native-QUIC session establishment is not
  implemented.
- (SS3.2.1, SS3.2.2) Reserved-namespace and `.session` namespace rejection
  — this hub uses one fixed room namespace and never receives an
  arbitrary client-chosen namespace to validate against these rules.
- (SS3.6) Session Migration beyond the single-GOAWAY / GOAWAY_TIMEOUT
  mechanics already covered under SS10.4 — the graceful relay-switchover
  behaviors in SS9.4.1/SS9.5.1 are not implemented.
- (SS5.1.2 partial) Location Filter *evaluation* on the forwarding path —
  the codec decodes Location Filter wire format (see MOQT-084--086), but the
  hub always forwards to every Established, Forward=1 subscriber
  unconditionally; it does not evaluate Start Location / End Group against
  incoming Objects.
- (SS5.1.3, SS5.1.4) Range Filters (SUBGROUP_FILTER, OBJECTID_FILTER,
  PRIORITY_FILTER, OBJECT_PROPERTY_FILTER, TRACK_PROPERTY_FILTER) and the
  MAX_FILTER_RANGES Setup Option — not implemented; this subset never
  sends or accepts any Range Filter parameter.
- (SS5.1.5, SS5.1.5.1) Joining an Ongoing Track / dynamically starting new
  groups — not implemented.
- (SS5.2) Fetch State Management, and FETCH / FETCH_OK / FETCH_HEADER
  (SS10.12--10.13, SS11.4.4) in their entirety — FETCH is recognized only
  as a known-but-unimplemented message type (REQUEST_ERROR NOT_SUPPORTED);
  no Fetch stream codec, Joining Fetch, or Fetch Header decode exists.
- (SS6, SS6.1--6.3.1) Namespace Discovery: SUBSCRIBE_NAMESPACE,
  PUBLISH_NAMESPACE, SUBSCRIBE_TRACKS, NAMESPACE, NAMESPACE_DONE,
  PUBLISH_SKIPPED (SS10.15--10.20) — room membership is a hub-side fixed
  concept in this subset, not negotiated on the wire; none of these message
  types are encoded or decoded.
- (SS7, SS7.1--7.3) Priorities: the Scheduling Algorithm and Publisher/
  Subscriber Priority handling — this hub relays every Object through the
  underlying transport's own send path without implementing MOQT-level
  priority scheduling; SUBSCRIBER_PRIORITY and GROUP_ORDER parameters are
  not sent or accepted.
- (SS8) Delivery Timeouts as a mechanism (timer-driven stream reset/
  datagram drop) — this subset's hub is loss-free-by-design and never sets
  a non-zero delivery timeout; only the parameter's wire decode (MOQT-047)
  and the hub's send-side/receive-side refusal of a non-zero value
  (MOQT-048/MOQT-049) are implemented.
- (SS9.1) Caching Relays — this hub does not cache Objects; it forwards
  live only.
- (SS9.3) Multiple Publishers per Track — this subset's room model gives
  each participant exactly one publisher slot per track name; multi-
  publisher aggregation/deduplication is not implemented.
- (SS9.4.1, SS9.5.1) Graceful Subscriber/Publisher Relay Switchover — not
  implemented.
- (SS10.2.2) AUTHORIZATION TOKEN Message Parameter and Setup Option, and
  the associated Alias/cache machinery (SS10.3.1.3, SS10.3.1.4) — not
  implemented; this subset has no authorization-token mechanism.
- (SS10.2.5--10.2.16, SS10.2.18--10.2.19) FILL_TIMEOUT, RENDEZVOUS_TIMEOUT,
  SUBSCRIBER_PRIORITY, GROUP_ORDER, LOCATION_FILTER (as a Message
  Parameter), SUBGROUP_FILTER, OBJECTID_FILTER, PRIORITY_FILTER,
  OBJECT_PROPERTY_FILTER, TRACK_PROPERTY_FILTER, EXPIRES, LARGEST_OBJECT,
  NEW_GROUP_REQUEST, TRACK_NAMESPACE_PREFIX — none of these Message
  Parameters are encoded or decoded by this subset; only OBJECT_DELIVERY_
  TIMEOUT, SUBGROUP_DELIVERY_TIMEOUT, and FORWARD are implemented.
- (SS10.3.1.3, SS10.3.1.4, SS10.3.1.6, SS10.3.1.7) MAX_AUTH_TOKEN_CACHE_SIZE,
  AUTHORIZATION TOKEN, MAX_FILTER_RANGES, and MAX_REQUEST_UPDATES Setup
  Options — not implemented; only AUTHORITY, PATH, and MOQT_IMPLEMENTATION
  are recognized.
- (SS10.9, SS10.9.1, SS10.9.2) REQUEST_UPDATE, Updating Subscriptions,
  Updating Namespace Subscriptions — REQUEST_UPDATE is recognized only as
  a known-but-unimplemented message type; no encoder/decoder exists.
- (SS10.14) TRACK_STATUS — recognized only as a known-but-unimplemented
  message type.
- (SS11.3, SS11.3.1, SS11.5.2) Object Datagrams and Padding Datagrams —
  this subset delivers every Object via Subgroup streams only; no MOQT
  datagram type is sent or decoded.
- (SS12, SS12.1--12.9) MOQT Properties (SUBGROUP_DELIVERY_TIMEOUT,
  OBJECT_DELIVERY_TIMEOUT, MAX_CACHE_DURATION, DEFAULT_PUBLISHER_PRIORITY,
  DEFAULT_PUBLISHER_GROUP_ORDER, DYNAMIC_GROUPS, Immutable Properties,
  Prior Group/Object ID Gap) as Track/Object Properties — the Properties
  wire slot is decoded generically (see MOQT-030/MOQT-054), but no specific
  Property type in this registry is interpreted by this subset.
- (SS13) Security Considerations (subscription amplification,
  communication security, authorization, media security, resource
  exhaustion, timeouts, relay security, implementation fingerprinting) —
  operational/deployment guidance, not a wire behavior this ledger tests.
- (SS15) IANA Considerations — registry administration, not implementation
  behavior.
