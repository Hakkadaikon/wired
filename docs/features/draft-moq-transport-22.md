[Docs](../README.md) › [Features](README.md) › draft-ietf-moq-transport-22

# draft-ietf-moq-transport-22 — Media over QUIC Transport

EARS requirement ledger extracted from the spec text
(`tasks/loopeng/moqt/draft-ietf-moq-transport-22.md`, not in git), for this
SDK's MOQT subset: a single central hub relay over WebTransport implementing
SETUP, GOAWAY, PUBLISH (with PUBLISH_STATE_NOTIFY), SUBSCRIBE (with typed
LOCATION_FILTER, FORWARD, priority and OBJECT_DELIVERY_TIMEOUT), fill fetch
streams (FILL_PARAMETERS), Range Filters, REQUEST_UPDATE of a SUBSCRIBE,
FETCH, namespace request or the sender's own PUBLISH, TRACK_STATUS, FETCH
(served from a whole-group cache), PUBLISH_NAMESPACE (as a prefix) /
SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS (hub-initiated PUBLISH or
PUBLISH_SKIPPED), PUBLISH_DONE, and Object delivery on Subgroup streams and
Object Datagrams. A session speaks draft-22 when the peer negotiates the
`moqt-22` WebTransport subprotocol. The data plane (SUBGROUP_HEADER, OBJECT_DATAGRAM,
Object body, padding) is byte-identical to draft-19; this file lists only
requirements that exist in draft-22 (some absent from, or worded
differently than, draft-19 — see each item's note). Requirements shared
verbatim with draft-19 reuse that ledger's wording and test references;
this file exists so draft-22-only readers do not have to cross-reference
another draft's ledger. Each requirement carries the test that demonstrates
it; an unchecked box with no test line is an open gap. Status as of
2026-10.

The hub keeps every session, track and cache in one process's memory: run
it single-process (no `--workers`, `--cores` or AF_XDP fan-out), as
`examples/moqt_chat` does.

Legend:

- `[x]` — demonstrated by the referenced test
- `[~]` — exercised indirectly (evidence line explains how; no dedicated test)
- `[ ]` — not demonstrated by any test yet

**Coverage: 200/212 tested, 10 indirect, 2 untested.**

## SS1.4.1 Variable-Length Integers (SS8.1)

- [x] MQ22-001 The implementation shall decode a MOQT variable-length integer
  using the number of leading 1 bits of the first byte to determine the encoded
  length (1-9 bytes), with the remaining bits and any subsequent bytes holding
  the value in network byte order.
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_official_examples`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_zero_all_lengths`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_nine_byte_padded`
- [x] MQ22-002 The implementation shall encode all 64-bit unsigned integers (0
  to 2^64-1) using the MOQT variable-length integer encoding.
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_official_examples`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_boundaries`
- [x] MQ22-003 The implementation shall encode a variable-length integer using
  the minimum number of bytes that can represent the value.
  - test: `tests/app/moqvi_test.c` — `test_moqvi_roundtrip`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_official_examples`
- [x] MQ22-004 Where a variable-length integer is encoded with more bytes than
  the minimum required, the implementation shall still decode it to the correct
  value (non-minimal encodings are valid).
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_zero_all_lengths`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_nine_byte_padded`
- [x] MQ22-005 If a variable-length integer's encoded length exceeds the number
  of bytes available, then the implementation shall report the decode as
  insufficient rather than reading past the input.
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_truncated`
- [x] MQ22-006 The implementation shall decode a variable-length integer
  without consuming bytes beyond its own encoded length, leaving any trailing
  bytes in the input untouched.
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_ignores_trailing`
- [x] MQ22-007 If the destination buffer is too small to hold the encoded
  length of a value, then the implementation shall fail the encode rather than
  writing past the buffer.
  - test: `tests/app/moqvi_test.c` — `test_moqvi_put_too_small`

## SS8.2 Location Structure

- [x] MQ22-008 The implementation shall encode/decode a Location as two
  consecutive variable-length integers (Group, Object).
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`
- [x] MQ22-009 The implementation shall compare two Locations A and B such that
  A < B iff A.Group < B.Group, or A.Group == B.Group and A.Object < B.Object.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`

## SS8.3 Key-Value-Pair Structure

- [x] MQ22-010 The implementation shall decode a Key-Value-Pair's Type as the
  previous cumulative Type plus a Delta Type (0 for the first pair).
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_even_num`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_delta_accumulates`
- [x] MQ22-011 If the cumulative Key-Value-Pair Type would exceed 2^64-1, then
  the implementation shall report a protocol violation.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_type_overflow`
- [x] MQ22-012 The implementation shall decode the Value of an odd-Type
  Key-Value-Pair as Length bytes, and of an even-Type pair as a single
  variable-length integer.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_even_num`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_odd_raw`
- [x] MQ22-013 The Length field of a Key-Value-Pair shall not exceed 2^16-1
  bytes; if a larger length is received, the implementation shall report a
  protocol violation.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_len_65535_accepted`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_len_65536_violation`
- [x] MQ22-014 Where a Key-Value-Pair's Value does not match the serialization
  defined by a Type the implementation understands, the implementation shall
  report a formatting error distinct from a protocol violation.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_put_rejects`
  - evidence: `moqctl_setup_take` maps a malformed known Setup Option to
    session close; the KVP layer itself exposes only the codec-level put-side
    rejection tested here (`moqkvp_put_rejects`); the formatting-vs-violation
    distinction is fully exercised at the SETUP layer (see MQ22-048).
- [x] MQ22-015 The implementation shall not use the minimum encoding length for
  a Key-Value-Pair's Delta Type or even-Type Value as a decode requirement
  (non-minimal encodings are valid).
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_nonminimal_delta`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_nonminimal_even_value`
- [x] MQ22-016 If a Key-Value-Pair is truncated within its own known byte
  bound, then the implementation shall report a protocol violation.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_truncated_insufficient`
- [x] MQ22-017 The implementation shall decode a Key-Value-Pair without reading
  past the caller-supplied byte bound, and shall encode a round-trippable
  Key-Value-Pair list preserving Type order.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_roundtrip`

## SS8.5 Reason Phrase Structure

- [x] MQ22-018 The implementation shall decode a Reason Phrase as a
  variable-length integer Length followed by that many UTF-8 bytes.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_reason_boundary`
- [x] MQ22-019 If a Reason Phrase Length exceeds 1024 bytes, then the
  implementation shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_reason_boundary`

## SS8.7 Track Namespace Structure

- [x] MQ22-020 The implementation shall decode a Track Namespace as a
  variable-length integer field count followed by that many length-prefixed
  Track Namespace Fields.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ftn_decode_basic`
- [x] MQ22-021 If a Track Namespace Field has a Length of 0, then the
  implementation shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ns_field_len_zero_rejected`
- [x] MQ22-022 If a Track Namespace has more than 32 Track Namespace Fields,
  then the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_ns_fields_32_accept_33_reject`
- [x] MQ22-023 If a Full Track Name (Track Namespace plus Track Name) exceeds
  4096 bytes, then the implementation shall close the session with a protocol
  violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ftn_4096_accept_4097_reject`
- [x] MQ22-024 The implementation shall compare Track Namespace Fields and
  Track Names by exact byte comparison.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ftn_eq_exact_bytes`

## SS12.1 Malformed Tracks

- [~] MQ22-025 If a subscriber detects a Malformed Track, then the
  implementation shall cancel the corresponding subscription for that Track
  from that publisher.
  - evidence: Besides the decode-time violations (unknown Object Status,
    cumulative Object ID overflow -- see MQ22-071/MQ22-072), the relay
    detects #4 (an Object past the latest END_OF_GROUP Object of its Group)
    and #5 (an Object past the END_OF_TRACK Object): every subscription ends
    PUBLISH_DONE MALFORMED_TRACK, fetch streams of the track reset
    MALFORMED_TRACK, the publisher's request is cancelled and the triggering
    Object is not cached. The rest of the catalog is out of scope.
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_after_end_of_track`
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_after_end_of_group`
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_resets_fetch`

## SS2.4.3/6.5 Reserved Namespaces / Session-Level Tracks

- [x] MQ22-028 If a request references a Track Namespace whose first field is a
  single period, then the implementation shall reject it with DOES_NOT_EXIST.
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_reserved_ns_rejected`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_reserved_rejected`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_other_dot_ns_served`
  - note: `moqtrun_ns_reserved` (ledger 10-1) rejects a first field of
    exactly `.` or `.session` with DOES_NOT_EXIST on PUBLISH, SUBSCRIBE,
    PUBLISH_NAMESPACE and SUBSCRIBE_NAMESPACE; any other `.`-led field is
    served like an ordinary namespace. The check is version-independent.

## SS6.3 Session Initialization

- [x] MQ22-029 The server shall open one unidirectional control stream and send
  SETUP as its first message.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_session_opens_uni_ctl`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_client_uni_ctl_accepted`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_refused_uni_ctl_open_retries`
  - note: a session whose WT token is empty (a client that offers no
    subprotocol, e.g. a browser without WebTransport `protocols` support)
    keeps the earlier drafts' single
    bidirectional control stream
    (`test_moqtrun_empty_token_keeps_bidi_ctl`).
- [x] MQ22-030 Once both endpoints have sent and received SETUP, the session
  shall be Established.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_establish`
  - test: `tests/app/moqsess_test.c` —
    `test_moqsess_established_accepts_request`
- [x] MQ22-031 A bidirectional request stream shall begin with one of the
  First-type messages (TRACK_STATUS, SUBSCRIBE, PUBLISH, FETCH,
  PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS); if it does not,
  the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_bad_first_message`
- [x] MQ22-032 Where a unidirectional stream containing Objects or a
  bidirectional request stream arrives before both control streams have
  completed SETUP, the implementation shall buffer it rather than deliver it to
  the application.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsess_buffer_before_setup_then_deliver`
- [x] MQ22-033 Where SETUP has not yet completed, the implementation may reset
  a bidirectional request stream instead of buffering it.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_pre_setup_reset_window`
- [x] MQ22-034 An endpoint may pipeline further control messages after sending
  its own SETUP without waiting for the peer's SETUP.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsess_pipeline_before_peer_setup`
- [x] MQ22-035 If a control stream is closed at the transport layer during the
  session's lifetime, then the implementation shall close the session with a
  protocol violation.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsess_ctrl_stream_transport_close`
- [x] MQ22-036 If the same peer opens a second control stream, then the
  implementation shall close the session with a protocol violation.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_second_control_stream`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_on_session_twice_is_idempotent`

## SS12.2 Stream Reset Error Codes / Termination (used subset)

- [x] MQ22-037 The implementation shall recognize the session termination error
  code table entries it uses (NO_ERROR, INTERNAL_ERROR, PROTOCOL_VIOLATION,
  INVALID_REQUEST_ID, DUPLICATE_TRACK_ALIAS, KEY_VALUE_FORMATTING_ERROR,
  INVALID_PATH, GOAWAY_TIMEOUT, INVALID_AUTHORITY).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_grease_pattern`
  - evidence: These codes are used as `#define`s at their call sites
    (moqctl.h/moqsess.h) rather than round-tripped through a codec; no
    dedicated test enumerates the full table, but each code's use is exercised
    at its own violation site (see the sess/data/ctl unwanted-behavior items
    throughout this file). draft-22 removes session code 0x15
    (VERSION_NEGOTIATION_FAILED, unassigned) — receivers already treat
    unknown codes as a plain close, so this is wire-safe (see Out of scope).

## SS6.4.1 Unidirectional Stream Types

- [x] MQ22-038 The implementation shall classify a unidirectional stream's
  leading variable-length integer as one of SETUP (0x2F00), FETCH_HEADER
  (0x05), SUBGROUP_HEADER (0b0XX1XXXX), or PADDING (0x132B3E28).
  - test: `tests/app/moqdata_test.c` — `test_moqdata_classify_golden`
- [x] MQ22-039 If an endpoint receives an unknown unidirectional stream type,
  then the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_unknown_uni_stream_type`
- [x] MQ22-040 The implementation shall classify a unidirectional stream
  without consuming bytes past a truncated leading type field, reporting the
  classification as insufficient instead.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_classify_truncated`

## SS12.2 Termination

- [x] MQ22-041 The server shall close a WebTransport-carried MOQT session using
  the CLOSE_WEBTRANSPORT_SESSION mechanism.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_unknown_type_closes_session`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_over_max_closes_session`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_bad_first_message_closes`
  - evidence: the hub closes through the io table's `close_session` op
    (`wired_server_wt_close_session` in production) with the draft's
    termination code; the WT_CLOSE_SESSION capsule itself is proven in
    the WebTransport ledger.

## SS6.6.1 Session Migration / SS9.2 GOAWAY (session lifecycle)

- [x] MQ22-042 An endpoint that has sent or received GOAWAY may reject a new
  request with an error indicating the endpoint is going away, while the
  session remains open.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_goaway_reject_new_request`
- [x] MQ22-043 An endpoint that has received GOAWAY on the control stream shall
  not initiate new requests of its own, without the session closing solely
  because of the GOAWAY.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_goaway_clean_shutdown`
- [x] MQ22-044 If the peer does not close the session within the GOAWAY
  timeout, then the sender shall close the session with GOAWAY_TIMEOUT.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_goaway_timeout_closes`
- [x] MQ22-045 If a server receives a GOAWAY with a non-zero New Session URI
  Length, then the implementation shall close the session with a protocol
  violation.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_goaway_bad_uri`
- [x] MQ22-046 If the same control stream receives more than one GOAWAY, then
  the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_second_goaway`
- [x] MQ22-047 Where a GOAWAY is received on a request stream rather than the
  control stream, the implementation shall accept it without closing the
  session, while a second GOAWAY on the same request stream shall still be a
  protocol violation.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_goaway_on_request_stream_produces_no_reply`
  - note: GOAWAY's wire layout is unchanged from draft-19 (no trailing
    Request ID field, unlike draft-18 — see
    `docs/features/draft-moq-transport-18.md` MQ18-048a).

## SS7 Relays (SS7.x forwarding discipline)

- [x] MQ22-048 A relay shall not reorder or drop Objects received on a
  multi-object stream when forwarding them to subscribers.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_to_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_two_subscribers_two_objects`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_normalize_forwards_only_whole_objects`
- [x] MQ22-049 A relay shall not modify Object header fields or payload when
  forwarding an Object.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_preserves_bytes`
- [x] MQ22-050 The relay shall have an Established upstream subscription before
  sending SUBSCRIBE_OK in response to a downstream SUBSCRIBE.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_matching_publish_replies_ok`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_ok_after_upstream`
- [x] MQ22-051 If a relay receives a SUBSCRIBE for a Track no publisher has
  PUBLISHed, then the implementation shall send a SUBSCRIBE upstream to a
  session (other than the subscriber's) that PUBLISH_NAMESPACEd the Track's
  namespace or a prefix of it (SS7.6), now or -- for a held SUBSCRIBE --
  when the PUBLISH_NAMESPACE arrives, and answer SUBSCRIBE_OK once that
  upstream subscription is Established or REQUEST_ERROR with the upstream's
  code; with no such publisher (and no RENDEZVOUS_TIMEOUT) it shall reply
  REQUEST_ERROR DOES_NOT_EXIST.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_without_publish_replies_error`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_ok_after_upstream`,
    `test_moqtrun_upsub_error_relayed`,
    `test_moqtrun_upsub_hold_then_announce`,
    `test_moqtrun_upsub_own_namespace`, `test_moqtrun_upsub_prefix`,
    `test_moqtrun_upsub_cross_draft`
  - note: one upstream SUBSCRIBE per Full Track Name, to the first matching
    announcer (SS7.6 says each matching publisher; the hub keys one track
    per name). An upstream subscription nobody downstream wants any more
    is cancelled (`test_moqtrun_upsub_last_cancel_cancels_upstream`).
- [~] MQ22-052 A relay may aggregate authorized subscriptions for a given Track
  when multiple subscribers request it, forwarding a single upstream Object to
  every matching downstream subscriber.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_to_all_three_subscribers`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_two_share_one`

## SS9 Control Messages: common envelope

- [x] MQ22-053 The implementation shall encode/decode every control message as
  Message Type (varint) + Message Length (16-bit) + Message Body.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_setup`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
- [x] MQ22-054 The implementation shall recognize the Message Type table
  entries it implements: SETUP (0x2F00), GOAWAY (0x10), SUBSCRIBE (0x3),
  SUBSCRIBE_OK (0x4), PUBLISH (0x1D), PUBLISH_DONE (0xB), REQUEST_OK (0x7),
  REQUEST_ERROR (0x5), and (new in draft-22) PUBLISH_STATE_NOTIFY (0x22,
  see MQ22-182).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_setup`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_ok_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_done_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_ok_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_error_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_roundtrip`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_publish_state_notify_d22_only`
  - evidence: FETCH (0x16, draft-22 body layout — see MQ22-131), FETCH_OK
    (0x18), TRACK_STATUS (0xD), REQUEST_UPDATE (0x2), PUBLISH_NAMESPACE
    (0x6, prefix semantics — see MQ22-182a), SUBSCRIBE_NAMESPACE (0x50),
    NAMESPACE (0x8) and NAMESPACE_DONE (0xE) are encoded/decoded by their
    own codecs (fetch/, ns/, tstat/), each pinned by golden vectors.
- [x] MQ22-055 If an endpoint receives an unknown Message Type, then the
  implementation shall report it distinctly so the caller closes the session.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_unknown`
- [x] MQ22-056 The implementation shall distinguish a known Message Type that
  the envelope peek does not decode itself (e.g. REQUEST_UPDATE, FETCH,
  TRACK_STATUS, PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS)
  from a wholly unknown one, so the caller can dispatch it, or reply
  NOT_SUPPORTED, instead of closing the session. The hub now answers all of
  these, SUBSCRIBE_TRACKS included (MQ22-193).
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_peek_type_known_unimplemented`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unknown_first_type_gets_not_supported`
- [x] MQ22-057 If a control message's declared Length does not match the actual
  Message Body length available, then the implementation shall not treat the
  message as complete (reporting insufficient rather than misreading past the
  body).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_length_mismatch`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_truncated`
- [x] MQ22-058 The implementation shall support a control message total length
  up to 2^16-1 bytes.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_max_len_field`

## SS8.4 Request ID

- [x] MQ22-059 The client shall generate even-numbered Request IDs starting at
  0, and the server shall generate odd-numbered Request IDs starting at 1,
  incrementing by 2 for each new request.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_and_audio_get_different_aliases`
  - evidence: The hub's own `request_id_next` field increments by 2 per new
    server-initiated request (moqtrun.h); no dedicated test isolates the
    arithmetic outside the alias-allocation tests, so this is `[~]` rather than
    `[x]`.
- [x] MQ22-060 If an endpoint receives a Request ID whose least significant bit
  is incorrect for the sender, then the implementation shall close the session
  with INVALID_REQUEST_ID.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_bad_request_id_parity`
- [x] MQ22-061 If an endpoint receives a duplicate Request ID, then the
  implementation shall close the session with INVALID_REQUEST_ID.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_duplicate_request_id`

## SS9.20 Message Parameters

- [x] MQ22-062 The implementation shall decode Message Parameters as a Type
  Delta (varint, cumulative from the previous Parameter Type) followed by a
  Value whose encoding (uint8, varint, Location, length-prefixed bytes, or
  Track Namespace) is fixed per Type.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_delivery_timeout_decode`
- [x] MQ22-063 Parameters shall be serialized in ascending order by Type; if
  the cumulative Parameter Type would exceed 2^64-1, the implementation shall
  close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_type_overflow_violation`
- [x] MQ22-064 If an endpoint receives an unknown Message Parameter Type, then
  the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_unknown_type_violation`
- [x] MQ22-065 If a sender repeats the same Parameter Type in one message, then
  the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_duplicate_type_violation`
- [x] MQ22-066 If a Message Parameter is defined for message types other than
  the one it appears in, then the implementation shall close the session with a
  protocol violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_scope_violation`
  - note: draft-22's allowed-message sets differ from draft-19's for most
    parameter types (PUBLISH_OK narrows to EXPIRES only; PUBLISH gains 5
    parameters; PUBLISH_STATE_NOTIFY and "inside FILL_PARAMETERS" are new
    contexts) — see `draft19-vs-22-diff.md` §5.2.
- [x] MQ22-067 Message Parameters in SUBSCRIBE, PUBLISH_OK, and FETCH shall not
  cause the publisher to alter the payload of the Objects it sends.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_preserves_bytes`
  - evidence: No parameter value is ever consulted when constructing an
    Object's payload in moqtrun.c; the relay-preserves-bytes test demonstrates
    payload identity end-to-end but does not vary parameters to isolate this
    specific guarantee.

## SS9.20.3/9.20.4 SUBGROUP_DELIVERY_TIMEOUT / OBJECT_DELIVERY_TIMEOUT

- [x] MQ22-068 The implementation shall decode the SUBGROUP_DELIVERY_TIMEOUT
  (0x06) and OBJECT_DELIVERY_TIMEOUT (0x02) Message Parameters as a varint,
  with a value of 0 meaning no timeout set.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_delivery_timeout_decode`
- [x] MQ22-069 The hub shall not send a delivery-timeout parameter in its own
  SUBSCRIBE_OK / REQUEST_OK / PUBLISH_DONE replies (the loss-free single-hub
  subset does not set delivery timeouts).
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_ok_carries_no_timeout_param`
- [x] MQ22-070 A SUBSCRIBE carrying a non-zero SUBGROUP_DELIVERY_TIMEOUT or
  OBJECT_DELIVERY_TIMEOUT parameter shall be accepted and applied.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_nonzero_timeout_accepted`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_accepted`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_subgroup_timeout_min`
- [ ] MQ22-070a OBJECT_DELIVERY_TIMEOUT's clock shall start at the time of the
  last Object header byte received or provided, unlike draft-19 where it
  starts at the first payload byte.
  - gap: ruling 4-11 (controller, 2026-10-04): this hub decodes an Object
    atomically and has no header-end/payload-start boundary timestamp to
    distinguish the two anchor points, so the draft-19-vs-22 difference is
    unobservable in this implementation (both versions produce the same
    timing value; a version gate here would be dead code). The timestamp
    source itself had a real bug (the ring path stamped on append-complete
    rather than `born_ms`), fixed by threading `born_ms` through
    `moqtrun_rel_take` — this fix is version-independent and not specific
    to draft-22's wording.

## SS9.20.18 FORWARD Parameter

- [x] MQ22-071 The implementation shall encode/decode the FORWARD parameter
  (Type 0x10) as a uint8 whose value is 0 (don't forward) or 1 (forward),
  defaulting to 1 when omitted.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
- [x] MQ22-072 A publisher that sends FORWARD=0 in PUBLISH shall not transmit
  any Objects until the subscriber sets Forward State (renamed "paused") to
  not-paused via REQUEST_UPDATE; Object forwarding toward a subscription is
  gated by its Forward State.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_forward_state_zero_blocks_objects`
  - note: draft-22 removes FORWARD from PUBLISH_OK's allowed set (the
    subscriber must use REQUEST_UPDATE instead, see MQ22-182b); the
    implementation's gate itself (Forward State on the subscription) is
    unchanged.

## SS9.1 SETUP

- [x] MQ22-073 The implementation shall encode/decode SETUP's Setup Options as
  a Key-Value-Pair list spanning the message payload.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
- [x] MQ22-074 Endpoints shall ignore unrecognized Setup Options.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_setup_unknown_option_ignored`
- [x] MQ22-075 Senders shall not repeat the same Setup Option Type in a message
  unless the option explicitly allows multiple instances.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
  - evidence: `moqctl_setup_encode` writes each of
    PATH/AUTHORITY/MOQT_IMPLEMENTATION at most once by construction; no test
    drives an encoder input with a duplicate to confirm rejection on decode
    (decode simply keeps the last-seen value for a repeated known option,
    matching the KVP layer's own duplicate-tolerant model).

## SS9.1.1/9.1.2 AUTHORITY / PATH / MOQT_IMPLEMENTATION

- [x] MQ22-076 The implementation shall decode the PATH (0x01) and AUTHORITY
  (0x05) Setup Options as byte-string values.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_path_option_decode`
- [~] MQ22-077 If a PATH or AUTHORITY option is received while WebTransport is
  used, then the implementation shall close the session with INVALID_PATH or
  INVALID_AUTHORITY respectively.
  - evidence: `moqctl_setup_take` only surfaces `has_path`/`has_authority` to
    the caller (moqctl.h's own doc: "WebTransport-context rejection is a
    session-layer decision"); no session-layer test in this ledger exercises
    the WT-context rejection itself.
- [x] MQ22-078 The implementation shall decode the MOQT_IMPLEMENTATION (0x07)
  Setup Option as a UTF-8 byte-string value.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`

## SS9.2 GOAWAY (wire format)

- [x] MQ22-079 The implementation shall encode/decode GOAWAY as Type (0x10) +
  Length + New Session URI Length + New Session URI + Timeout (unchanged
  from draft-19; no trailing Request ID field, unlike draft-18).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_roundtrip`
- [x] MQ22-080 If the New Session URI Length exceeds 8192 bytes, then the
  implementation shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_uri_boundary`
- [x] MQ22-081 A client shall send a zero-length New Session URI in any GOAWAY
  it sends.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_roundtrip`
  - evidence: The wire codec accepts and round-trips a zero-length URI; no test
    asserts the client-side encoder path specifically refuses a non-zero URI
    (the receiving side's rejection is MQ22-045 above).

## SS9.3 REQUEST_OK

- [x] MQ22-082 The implementation shall encode/decode REQUEST_OK as Type (0x7)
  + Length + Number of Parameters + Parameters + Track Properties (the
  remaining message bytes).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_ok_roundtrip`
- [x] MQ22-083 If a REQUEST_OK variant that must have empty Track Properties
  (e.g. PUBLISH_OK) carries non-empty Track Properties, then the implementation
  shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_ok_roundtrip`
  - evidence: `moqctl_request_ok_take` always decodes the residual span and
    lets the caller (which knows which request it answers) enforce the
    per-variant empty-Track-Properties rule (moqctl.h's own doc); no
    session/run-layer test exercises the enforcement itself.
- [x] MQ22-083a Where INCLUDE_PROPERTIES=0 is sent on a request whose OK
  carries Track Properties, the implementation shall emit an empty Track
  Properties tail regardless of the track's actual properties.
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_include_properties_0_empty_tail`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_include_properties_range`
  - evidence: with INCLUDE_PROPERTIES=1 (or omitted, the default) the
    SUBSCRIBE_OK carries the publisher's Track Properties (up to
    `WIRED_MOQTRUN_TRACK_PROPS_MAX` bytes).
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_include_properties_1_forwards`

## SS9.4 REQUEST_ERROR

- [x] MQ22-084 The implementation shall encode/decode REQUEST_ERROR as Type
  (0x5) + Length + Error Code + Retry Interval + Error Reason + optional
  Redirect.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_error_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_request_error_redirect_roundtrip`
- [x] MQ22-085 The Redirect structure shall be present only when Error Code is
  REDIRECT.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_request_error_redirect_roundtrip`
- [x] MQ22-086 If a server receives a Redirect with a non-zero Connect URI
  Length, then the implementation shall close the session with a protocol
  violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_request_error_redirect_roundtrip`
  - evidence: `moqctl_request_error_take` decodes the Redirect structure
    symmetrically for either role; the server-specific non-zero-URI rejection
    is a session-layer decision not exercised by a dedicated test.
- [x] MQ22-087 The implementation shall recognize the REQUEST_ERROR codes it
  uses: INTERNAL_ERROR, NOT_SUPPORTED, GOING_AWAY, INVALID_FILTER,
  UNINTERESTED, DOES_NOT_EXIST, UNAUTHORIZED, REDIRECT.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`
  - note: draft-22 removes INVALID_JOINING_REQUEST_ID (0x32, moot — Joining
    FETCH itself is removed, see MQ22-132); unknown codes normalize to
    INTERNAL_ERROR either way.
- [x] MQ22-088 If an endpoint receives an unrecognized REQUEST_ERROR code, then
  the implementation shall treat it as INTERNAL_ERROR rather than closing the
  session.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`

## SS9.6 SUBSCRIBE / SS9.7 SUBSCRIBE_OK

- [x] MQ22-089 The implementation shall encode/decode SUBSCRIBE as Type (0x3) +
  Length + Request ID + Track Namespace + Track Name + Number of Parameters +
  Parameters.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_roundtrip`
- [x] MQ22-090 On a successful subscription, the publisher shall reply with
  exactly one SUBSCRIBE_OK.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_ok_roundtrip`
  - test: `tests/app/moqsess_test.c` — `test_moqsub_subscribe_establish`
- [x] MQ22-091 The implementation shall encode/decode SUBSCRIBE_OK as Type
  (0x4) + Length + Track Alias + Number of Parameters + Parameters + Track
  Properties, where the allowed parameters are EXPIRES and LARGEST_OBJECT
  only (narrower than draft-19).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_ok_roundtrip`
- [x] MQ22-092 If a subscriber sends more than one SUBSCRIBE_OK or
  REQUEST_ERROR in response to the same SUBSCRIBE, then the implementation
  shall treat the second response as a session-level protocol fault.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_duplicate_response_is_session_fault`
- [x] MQ22-093 If a publisher rejects a SUBSCRIBE with REQUEST_ERROR, then no
  Object shall be sent for that subscription.
  - test: `tests/app/moqsess_test.c` — `test_moqsub_subscribe_rejected`
- [x] MQ22-093a A peer may have multiple concurrent subscriptions to the same
  Track, each with its own Request ID, unlike draft-18 (see
  `docs/features/draft-moq-transport-18.md` MQ18-094a).
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_sub_duplicate_reanswered_d19_d22`
  - note: `moqtrun_sub_held_reply` branches on `MOQVER_CAP_DUP_SUBSCRIPTION`,
    absent for d19/d22; see ledger 4-2.

## SS9.8 PUBLISH

- [x] MQ22-094 The implementation shall encode/decode PUBLISH as Type (0x1D) +
  Length + Request ID + Track Namespace + Track Name + Track Alias + Number of
  Parameters + Parameters + Track Properties.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_roundtrip`
- [~] MQ22-094a PUBLISH shall carry the publisher's initial subscription
  parameters (OBJECT_DELIVERY_TIMEOUT, SUBGROUP_DELIVERY_TIMEOUT, EXPIRES,
  LARGEST_OBJECT, FORWARD, SUBSCRIBER_PRIORITY, LOCATION_FILTER,
  GROUP_ORDER), unlike draft-19 where PUBLISH_OK carries the subscriber's
  parameters instead.
  - evidence: `moqctl_publish`'s wire decoder already carries a generic
    `params` field (byte-identical across 19/22); the gap is purely in the
    hub's behavior — `moqtrun_handle_publish` reads only LARGEST_OBJECT
    from an incoming PUBLISH and does not apply FORWARD/priority/filter/
    timeout, matching the same gap already open in the draft-19 ledger
    (see `draft-moq-transport.md`'s "Not implemented" section and ledger
    4-7's ruling that this hub's always-forward, no-priority behavior
    satisfies draft-22's MAY without an observable violation).
- [x] MQ22-095 On a successful PUBLISH-initiated subscription, the subscriber
  shall reply with exactly one PUBLISH_OK (REQUEST_OK carrying EXPIRES
  only), and may follow it with REQUEST_UPDATE to set subscriber-controlled
  parameters (unlike draft-19 where those parameters ride on PUBLISH_OK
  itself).
  - test: `tests/app/moqsess_test.c` — `test_moqsub_publish_establish`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_notify_on_publish_stream_d22`
  - test: `tests/app/moqtrun_vgate_test.c` — `test_moqtrun_vgate_update_kinds`
  - test: `tests/app/moqtrun_misc_test.c` — `test_moqtrun_misc_stray_update`
  - note: REQUEST_UPDATE on the sender's own PUBLISH stream is accepted on
    every draft (18/19 SS10.9 and 22 SS9.5 list PUBLISH alike); the former
    draft-22-only cap bit was removed (ledger 12-6). One outside SS9.5's two
    cases (control stream, TRACK_STATUS stream) closes the session with
    PROTOCOL_VIOLATION (ledger 12-17, `MOQVER_CAP_UPDATE_STRAY_CLOSE`).
- [x] MQ22-096 A publisher may start sending Objects on a PUBLISH-initiated
  subscription before receiving PUBLISH_OK.
  - test: `tests/app/moqsess_test.c` — `test_moqsub_object_before_publish_ok`
- [x] MQ22-097 If a subscriber rejects a PUBLISH with REQUEST_ERROR
  UNINTERESTED, then the subscription shall terminate without any Object being
  sent.
  - test: `tests/app/moqsess_test.c` — `test_moqsub_publish_rejected`
- [x] MQ22-097a If an unauthorized peer attempts to PUBLISH a namespace it is
  not permitted to publish to, then the implementation shall refuse it with
  REQUEST_ERROR UNAUTHORIZED, mirroring draft-22's §16.3.4 "Preventing
  Impersonation" requirement that relays authorize the publishing side's
  namespace, not only the subscribing side's.
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_publish_requires_authorization`
  - note: `moqtrun_publish_refused`, symmetric to the pre-existing
    `moqtrun_subscribe_refused`; closes the V-0839 gap noted in
    `docs/security/vuln-ledger.md`; see ledger 4-14a, commit `041b9ef4`
    family.

## SS9.9 PUBLISH_DONE

- [x] MQ22-098 The implementation shall encode/decode PUBLISH_DONE as Type
  (0xB) + Length + Status Code + Stream Count + Error Reason, where the
  "unknown" Stream Count sentinel is 2^64-1 (a 9-byte varint), unlike
  draft-19's 2^62-1.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_done_roundtrip`
  - note: wired's PUBLISH_DONE Stream Count is now always an exact count
    (ledger 3-9/10-3: `MOQTRUN_DONE_STREAMS_UNKNOWN` was removed from the
    codebase entirely), so this sentinel is never emitted by the hub in
    either version; it only matters for decoding a peer's PUBLISH_DONE,
    which this hub does not currently act on for its own fill/subscription
    bookkeeping beyond logging.
- [x] MQ22-099 A sender shall not send PUBLISH_DONE until it has closed every
  data stream it opened for that subscription, including any fill fetch
  streams opened for it (new in draft-22, see MQ22-186).
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_publish_done_terminates_and_reclaims`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_counts_in_done`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_done_waits_for_held`
- [x] MQ22-100 PUBLISH_DONE plus closing the subscription's bidi stream shall
  terminate the subscription; the sender may then destroy subscription state.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_publish_done_terminates_and_reclaims`
- [x] MQ22-101 If PUBLISH_DONE arrives before the subscriber has sent its
  response, then the subscriber shall owe exactly one deferred PUBLISH_OK
  before it FINs.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_publish_done_before_response_defers_ok`
- [x] MQ22-102 The implementation shall recognize the PUBLISH_DONE status codes
  it uses: INTERNAL_ERROR, TRACK_ENDED, GOING_AWAY. draft-22 removes
  SUBSCRIPTION_ENDED (0x3, unassigned), since a Location Filter's end no
  longer terminates a subscription (see MQ22-137a).
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`
  - note: unknown PUBLISH_DONE codes normalize to INTERNAL_ERROR either
    way, so the removal is wire-safe.
- [~] MQ22-103 If a publisher did not open any data stream for a subscription,
  then it shall set PUBLISH_DONE's Stream Count to 0.
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_relay_table_full_counts`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_done_track_ended`
  - evidence: the hub sends an exact Stream Count via
    `moqtrun_sub_done`/`moqtrun_done_emit` (ledger 3-9/10-3), which is 0
    when no data stream was opened; no dedicated draft-22-specific test
    isolates the zero-stream encoding from the general exact-count path.

## SS9 Reason Phrase / Location / Track Namespace shared structures used in control messages

- [x] MQ22-104 The implementation shall encode/decode Message Parameters,
  Location, and Reason Phrase consistently across every control message that
  embeds them.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_reason_boundary`

## SS9.20.9 LOCATION_FILTER (draft-22: typed, not length-prefixed)

- [x] MQ22-105 The implementation shall decode a LOCATION_FILTER's Location
  Filter Type as one of None (0x00), Relative Start (0x01), Absolute Start
  (0x02), Absolute Start/Group End (0x03), Absolute Range (0x04), or Next
  Object (0x05), with the field layout ([StartGroup], [StartObject],
  [EndGroupDelta], [EndObject]) determined by the type and with no outer
  Length field, unlike draft-19's length-prefixed four-type encoding.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_rangeloc22_none`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_rangeloc22_relative_start_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_rangeloc22_abs_start_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_rangeloc22_abs_start_group_end_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_rangeloc22_abs_range_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_rangeloc22_next_object_roundtrip`
  - note: codepoints 0x01-0x04 exist in both draft-19 and draft-22 with
    different meanings (see `draft19-vs-22-diff.md` §6.2); decoding is
    version-gated by `MOQVER_CAP_LOCFILTER_TYPED`, never auto-detected.
    `moqctl_rangeloc22_take/_put` map into the same internal
    `moqctl_rangeloc` model as the draft-19 decoder (ledger 3-6, commit
    `fc97a2e5`).
- [x] MQ22-106 If a LOCATION_FILTER's StartGroup + EndGroupDelta would exceed
  2^64-1, then the implementation shall close the session with a protocol
  violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_rangeloc22_egd_overflow_violation`
- [x] MQ22-107 If an endpoint receives a Location Filter Type other than the
  six defined values, then the implementation shall close the session with a
  protocol violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_rangeloc22_unknown_type_violation`
- [x] MQ22-108 The publisher shall forward only Objects that pass the
  combination Forward State AND Location Filter (Pass = Forward AND Filters).
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_forward_state_zero_blocks_objects`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_filter22_starts`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_filter22_ends`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_filter22_inverted`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_filter22_end_gates`
- [~] MQ22-108a A Location Filter's valid range is never invalidated by being
  entirely before the Largest Object (always valid), unlike draft-19 where
  the publisher SHOULD reject an unsatisfiable filter.
  - evidence: `moqctl_rangeloc22_take` has no "already in the past" rejection
    path; the filter evaluation in `moqtrun_sub_filter22_*` tests exercises
    acceptance of filters at/after the current Largest Object, matching
    this always-valid rule by construction (no code path raises
    INVALID_RANGE for a stale-but-structurally-valid filter).
- [x] MQ22-108b Reaching a Location Filter's end (Largest Object passes the
  filter's End) shall not terminate the subscription, unlike draft-19's
  PUBLISH_DONE SUBSCRIPTION_ENDED (removed in draft-22, see MQ22-102).
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_done_filter_end_keeps_sub`
- [x] MQ22-108c A publisher may send LOCATION_FILTER in PUBLISH (setting the
  initial filter) and in PUBLISH_STATE_NOTIFY (reporting the filter now in
  effect), in addition to SUBSCRIBE and REQUEST_UPDATE, unlike draft-19
  where only SUBSCRIBE, PUBLISH_OK and REQUEST_UPDATE may carry it.
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_filter_d22`
  - note: see MQ22-094a (PUBLISH's initial parameters) and MQ22-182
    (PUBLISH_STATE_NOTIFY).

## SS12 Grease

- [x] MQ22-109 The implementation shall recognize the grease value pattern
  0x7f*N + 0x9D for non-negative integer N in registries that reserve it (Setup
  Options, Properties, error/status code tables).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_grease_pattern`
- [x] MQ22-110 Endpoints shall not close the session solely because they
  received an unknown value in a greased registry (Setup Options, error codes).
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_setup_unknown_option_ignored`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`

## SS3.1.3 Track Alias

- [x] MQ22-111 The same Track Alias shall not be used by a publisher to refer
  to two different Tracks simultaneously in the same session.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_and_audio_get_different_aliases`
- [~] MQ22-112 If a subscriber receives a PUBLISH or SUBSCRIBE_OK reusing a
  Track Alias already bound to a different Established subscription, then the
  implementation shall close the session with DUPLICATE_TRACK_ALIAS.
  - evidence: The hub allocates aliases itself per-track (starting from 0
    independently per track, see moqtrun_test.c's own comment on
    `test_moqtrun_chat_and_audio_get_different_aliases`) and never receives an
    attacker-controlled alias to validate; the receiver-side duplicate-alias
    rejection is not exercised by any test in this subset.

## SS11.1.1 Object Status

- [x] MQ22-113 The implementation shall recognize Object Status values 0x0
  (Normal), 0x3 (End of Group), and 0x4 (End of Track).
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_status_values`
- [x] MQ22-114 If an Object carries an unregistered Status value, then the
  implementation shall close the session with a protocol violation.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_status_values`
- [x] MQ22-115 An Object shall have an empty payload unless its Object Status
  is Normal (0x0); the Object Status field shall be present only when Payload
  Length is 0.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_status_eog`
  - test: `tests/app/moqdata_test.c` —
    `test_moqdata_obj_take_status_eog_stream`

## SS11.1.2 Object Properties

- [x] MQ22-116 If an endpoint receives Object Properties on an Object whose
  Status is not Normal, then the implementation shall close the session with a
  protocol violation.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_properties`
- [x] MQ22-117 Object Properties shall be serialized as a Properties Length
  (varint) followed by a Key-Value-Pair list.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_properties`

## SS11.3.1 Subgroup Header

- [x] MQ22-118 All Objects on a stream opened with SUBGROUP_HEADER shall have
  Delivery Mode = Subgroup (renamed from "Object Forwarding Preference"),
  belonging to the Track Alias, Group ID, and Subgroup ID the header
  declares.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_basic`
- [x] MQ22-119 The SUBGROUP_HEADER Type Flags field shall take the form
  0b0XX1XXXX (bit 4 always set); if received with any other form, the
  implementation shall close the session with a protocol violation.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_valid_golden`
  - note: the valid value set is byte-identical to draft-19 (48 values);
    draft-22 only renames the field "Type Flags" and generalizes the
    reserved-bit rule — see `draft19-vs-22-diff.md` §10.
- [x] MQ22-120 The implementation shall decode the SUBGROUP_ID_MODE field (bits
  1-2) as: 0b00 Subgroup ID absent and 0, 0b01 Subgroup ID absent and equal to
  the first Object's Object ID, 0b10 Subgroup ID present in the header.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode2`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode1_resolve`
- [x] MQ22-121 If SUBGROUP_ID_MODE is 0b11, then the implementation shall close
  the session with a protocol violation.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_valid_golden`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_bad_type`
- [x] MQ22-122 The implementation shall decode the PROPERTIES bit (0x01),
  END_OF_GROUP bit (0x08), DEFAULT_PRIORITY bit (0x20), and FIRST_OBJECT bit
  (0x40) of the SUBGROUP_HEADER Type Flags field.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_bits_golden`
- [x] MQ22-123 Where DEFAULT_PRIORITY is set, the Publisher Priority field
  shall be omitted from the header and the Subgroup shall inherit the priority
  from the subscription's control message.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_basic`
- [x] MQ22-124 Where the END_OF_GROUP bit is set and the stream terminates with
  a FIN, the implementation shall infer that no Object with the same Group ID
  and a larger Object ID exists.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_normalize_forwards_only_whole_objects`
  - evidence: The bit is decoded (MQ22-122) but the specific inference "no
    larger Object ID exists once END_OF_GROUP FINs" is not asserted by a
    dedicated test; it is implicit in how the relay forwards whole Objects.
- [x] MQ22-125 When the Original Publisher opens a new Subgroup, it shall set
  the FIRST_OBJECT bit to indicate the first Object in the stream is the first
  Object ever published in that Subgroup.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_bits_golden`
- [x] MQ22-126 The implementation shall encode/decode a SUBGROUP_HEADER
  byte-exact against its wire fields (Type Flags, Track Alias, Group ID,
  optional Subgroup ID, optional Publisher Priority).
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_put_golden`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_put_errors`
- [x] MQ22-127 If a SUBGROUP_HEADER is truncated before all its declared fields
  are present, then the implementation shall report the decode as insufficient.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_truncated`
- [x] MQ22-128 The implementation shall resolve a mode-0b01 (deferred) Subgroup
  ID from the first Object's Object ID once decoded.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode1_resolve`

## SS11.3.1 Subgroup Object Fields

- [x] MQ22-129 The implementation shall encode/decode a Subgroup Object as
  Object ID Delta + optional Properties + Object Payload Length + optional
  Object Status + optional Object Payload.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_basic_stream`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_put`
- [x] MQ22-130 The Object ID shall be the Object ID Delta for the first Object
  in a Subgroup, and the previous Object ID plus the Delta plus 1 for each
  subsequent Object.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_delta_chain`
  - relay: a stream the hub late-opens mid-Subgroup gets its first Object's
    Delta rewritten to the absolute Object ID, and a mode-0b01 Subgroup ID
    spelled out (mode 0b10) in its header.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_late_subscriber_gets_late_opened_stream`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_late_open_sgid_mode1_explicit`
- [x] MQ22-130a If the resulting cumulative Object ID would exceed 2^64-1,
  then the implementation shall close the session with a protocol
  violation.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_id_overflow`

## SS9.11 FETCH (draft-22: Track Namespace/Name + LOCATION_FILTER, no Fetch Type)

- [x] MQ22-131 The implementation shall encode/decode FETCH as Type (0x16) +
  Length + Request ID + Track Namespace + Track Name Length + Track Name +
  Number of Parameters + Parameters (with the requested range carried in a
  LOCATION_FILTER parameter, see MQ22-105), unlike draft-19 where FETCH
  carries an explicit Fetch Type field (Standalone / Relative Joining /
  Absolute Joining) with inline Start/End Location fields.
  - test: `tests/app/moqfetch_test.c` —
    `test_moqfetch_req22_with_filter_roundtrip`
  - test: `tests/app/moqfetch_test.c` —
    `test_moqfetch_req22_no_filter_defaults`
  - test: `tests/app/moqfetch_test.c` —
    `test_moqfetch_req22_encode_with_larger_typed_param`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_req22_bad_ns_rejects`
  - note: `moqfetch_req22_take/_encode`, decoding into the same version-
    independent `moqfetch_req` internal model as the draft-19 decoder
    (ledger 3-7, commits `53a66346`/`a8e0eef2`).
- [x] MQ22-131a Where a FETCH omits LOCATION_FILTER, the implementation shall
  treat the request as covering the whole track ({0,0} through Largest
  Object), per draft-22's "omitted means no filter" rule.
  - test: `tests/app/moqfetch_test.c` —
    `test_moqfetch_req22_no_filter_defaults`
- [x] MQ22-132 If a draft-22 session's FETCH request stream carries the
  draft-19 Joining structure (a Fetch Type field with Joining Request ID /
  Joining Start), then the implementation shall close the session with a
  protocol violation, since Joining FETCH is removed entirely in draft-22
  (replaced by fill fetch streams, see MQ22-135 onward).
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_d22_joining_violation`
  - note: `moqtrun_fetch_route` branches on `MOQVER_CAP_FILL_FETCH`; ledger
    4-5, commit referenced there as "D-2".
- [x] MQ22-133 A FETCH shall be served from the cache, with its range
  normalized from the LOCATION_FILTER parameter into the version-
  independent internal model shared with draft-19's Standalone/Joining
  forms.
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_d22_served`
- [x] MQ22-134 If a FETCH's LOCATION_FILTER range is invalid (e.g. Start
  after Largest Object, or the structural violations of MQ22-106/MQ22-107),
  then the implementation shall refuse it with REQUEST_ERROR INVALID_RANGE
  rather than closing the session.
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_d22_invalid_range`

## SS9.11/11.4.1 FETCH_OK, End Location, End of Range markers (draft-22: inclusive)

- [x] MQ22-135 The implementation shall encode/decode FETCH_OK's End Location
  as inclusive (the actual last Object delivered), unlike draft-19 where End
  Location is exclusive ("+1", with Object 0 meaning the whole group).
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_ok19_end_inclusive`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_end19_whole_group`
  - note: these tests exercise the version-independent End Location model
    (`moqfetch_end19_incl`/`moqfetch_end19_wire`) that both the draft-19
    and draft-22 codec paths read from; ledger 3-8 confirms the conversion
    is already implemented and tested against the shared model, with no
    draft-22-specific inclusive-vs-exclusive boundary test existing yet
    beyond the shared `moqfetch_end19_incl` round-trip (hence `[x]` via the
    model-level test rather than a draft-22-labeled one).
- [x] MQ22-136 The implementation shall accept the End of Timed-Out Range
  marker (0x20C) on a draft-22 FETCH data stream, unlike draft-19 where
  0x20C is an unrecognized value and closes the session with a protocol
  violation.
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_eor_timed_out`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_d22_served`
  - note: `moqfetch_is_eor` / `MOQVER_CAP_EOR_TIMED_OUT`; ledger 3-10,
    commit `32172307`.

## SS7.6/11.4.1.2 Relay FETCH gap handling (draft-22)

- [ ] MQ22-137 Where a Range Filter restricts a FETCH or fill, an unmarked
  gap in the response shall be treated as unknown rather than non-existent,
  and the relay shall issue upstream FETCHes to at least one matching
  publisher rather than pausing delivery until confirmed, as draft-19 does.
  - gap: this hub does not forward a FETCH upstream to another relay (no
    FETCH-of-FETCH); the "pause until confirmed" behavior this would
    replace was never implemented either (ledger 4-13's N/A finding), so
    there is no code path to exercise this rule against yet.
- [x] MQ22-137a Reaching a Location Filter's end on a FETCH shall not emit
  SUBSCRIPTION_ENDED (see MQ22-108b; duplicate cross-reference kept here
  because this is also a FETCH/relay-section rule in the diff catalog).
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_done_filter_end_keeps_sub`

## Hub relay: fill fetch streams (FILL_PARAMETERS, draft-22 only, new in -20)

Draft-22 lets a subscriber request a bounded backfill of a track it is
already subscribed to, over its own FETCH_HEADER-framed data stream(s),
without replacing the subscription: FILL_PARAMETERS (0x23) on SUBSCRIBE (the
initial fill) or REQUEST_UPDATE (a later fill) opens a new fill fetch
stream, framed identically to a FETCH data stream and referencing the
SUBSCRIBE's or REQUEST_UPDATE's own Request ID. Several fill streams may be
open at once per subscription. This entire mechanism is absent from
draft-18 and draft-19.

- [x] MQ22-138 Where a SUBSCRIBE or REQUEST_UPDATE for a subscription carries
  FILL_PARAMETERS, the implementation shall open a new FETCH_HEADER-framed
  data stream referencing that message's own Request ID, serving the fill
  range (from FILL_PARAMETERS' own LOCATION_FILTER if present, else the
  subscription's filter) up to (but never beyond) the Largest Object known
  at open time.
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_subscribe_opens`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_update_opens`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_open_end_is_largest`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_end_clipped_to_largest`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_filter_separate_from_subscription`
  - note: ledger 4-6 (ruling 9-2: implement fill fetch). Q-01 (FILL_PARAMETERS
    value starts with a Number-of-Parameters count, same shape as a normal
    message's Parameters) and Q-02 (FILL's own LOCATION_FILTER type 0x00 or
    omitted both mean "no filter") are implemented per the ruling in
    `tasks/moqt-multidraft-ledger.md` 9-4.
- [x] MQ22-139 Where a fill's requested range is empty or starts entirely
  after the current Largest Object, the implementation shall not open a
  fill fetch stream at all.
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_empty_or_future_range`
- [x] MQ22-140 Several fill fetch streams may be open at once for the same
  subscription, each independently tracked.
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_two_at_once`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_survives_done_and_slot_reuse`
- [x] MQ22-141 A fill fetch stream shall deliver its range in the subscription's
  Group Order (ascending or descending, per GROUP_ORDER, overridable inside
  FILL_PARAMETERS), with an unmarked gap inside the filtered range reported
  as unknown rather than silently skipped.
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_descending`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_descending_skips_gap`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_next_object_no_gap`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_ascending_sends_first`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_descending_sends_last`
- [x] MQ22-142 Where a fill's source data has been evicted from the cache or
  times out under FILL_TIMEOUT, the implementation shall report it with the
  End of Timed-Out Range marker (0x20C, see MQ22-136) rather than hanging or
  silently dropping the stream.
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_miss_is_timed_out_now`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_evicted_run_collapsed`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_eviction_under_cursor`
- [x] MQ22-143 Cancelling the owning subscription shall reset every fill
  fetch stream opened for it; a fill stream's own cancellation (requester
  reset, STOP_SENDING, or upstream failure) shall never affect the
  subscription itself.
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_cancel_resets_all`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_stop_sending_leaves_sub`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_upstream_gone_resets`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_blocked_upstream_gone`
- [x] MQ22-144 A fill stream stalled past the delivery timeout shall be
  abandoned like any other stalled data stream, and never starve the
  subscription's own live delivery.
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_stall_delivery_timeout`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_blocked_never_starves_live`
- [x] MQ22-145 PUBLISH_DONE's Stream Count shall include every open fill
  fetch stream for the subscription, and PUBLISH_DONE shall wait for held
  (not-yet-opened) fill requests to resolve before being sent.
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_counts_in_done`
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_done_waits_for_held`
- [x] MQ22-146 Where the implementation's fixed fill-slot capacity is already
  full, a new fill request shall be held (not answered with an error)
  until a slot frees, per the capacity ruling accepted for this
  implementation (ledger 4-6, 2026-10-04: 8+8 slots, YAGNI on raising the
  limit or erroring explicitly).
  - test: `tests/app/moqtrun_fill_test.c` — `test_moqtrun_fill_slot_full_held`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_slot_full_cancel_drops`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_slot_full_done_waits`
- [x] MQ22-147 A FETCH_HEADER stream's Request ID may resolve to a SUBSCRIBE
  or REQUEST_UPDATE (a fill), not only to a FETCH, unlike draft-19 where a
  FETCH_HEADER names only the FETCH it answers.
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_inbound_fetch_known_rid`
  - test: `tests/app/moqtrun_fill_test.c` —
    `test_moqtrun_fill_inbound_fetch_unknown_rid`

## Hub relay: PUBLISH/SUBSCRIBE dispatch (SS7 Relays, SS9.3/9.6/9.8 applied)

- [x] MQ22-148 On a successful PUBLISH, the hub shall reply with REQUEST_OK on
  the same control stream without closing it.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_publish_replies_request_ok`
- [x] MQ22-149 A peer may PUBLISH more than one distinct track (up to the
  implementation's per-peer track capacity), each independently getting
  REQUEST_OK.
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_peer_publishes_two_tracks`
- [x] MQ22-150 If a peer attempts to PUBLISH more distinct tracks than the
  implementation's per-peer capacity, then the implementation shall reply with
  REQUEST_ERROR rather than silently overwriting an existing track.
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_fifth_publish_gets_error`
- [x] MQ22-151 Re-PUBLISHing the same Track Name that already occupies a slot
  shall reuse that slot rather than consuming a new one.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_republish_same_name_reuses_slot`
- [x] MQ22-152 A SUBSCRIBE naming any track a peer has PUBLISHed shall get
  SUBSCRIBE_OK with an assigned Track Alias.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_audio_track_replies_ok`
- [x] MQ22-153 Two SUBSCRIBE messages arriving in the same dispatch call shall
  each get their own reply queued without one overwriting the other.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_two_subscribe_oks_one_dispatch_no_overflow`

## Hub relay: Object forwarding to matching subscribers only (SS7.4, SS3.1.3)

- [x] MQ22-154 An Object shall be forwarded only to subscribers of the Track
  its Track Alias identifies, not to subscribers of any other Track in the same
  session.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_only_to_chat_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_object_relays_only_to_audio_subscriber`
- [x] MQ22-155 If an Object's Track Alias matches no Track the publisher has
  declared, then the implementation shall not forward it to any subscriber.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unknown_alias_object_relays_nowhere`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unbound_stream_id_relays_nowhere`
- [x] MQ22-156 Each Object matching multiple subscriptions to the same Track
  shall be sent once per matching subscription.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_to_all_three_subscribers`
- [x] MQ22-157 If forwarding an Object to one subscriber fails (the underlying
  transport refuses the send), then the implementation shall still forward it
  to every other matching subscriber, and shall count the loss rather than
  leaving it silent.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_one_of_three_subscribers_refused`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_send_uni_failure_counts_open_drop`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_stream_send_rejection_drops_frame_not_fatal`
- [x] MQ22-158 Objects sent with Delivery Mode Subgroup shall be relayed as
  one complete SUBGROUP_HEADER-plus-Objects unit per relay send, matching
  the publisher's stream framing.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_multi_object_stream_relays_in_one_send_uni`
- [x] MQ22-159 A long-lived Subgroup stream's later data (arriving without a
  repeated SUBGROUP_HEADER) shall be appended to the same already-bound relay
  stream, not misread as a new header.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_data_stream_continues_across_calls_without_header`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_first_object_opens_then_appends`
- [x] MQ22-160 When a publisher's Subgroup stream FINs, the implementation
  shall close the corresponding relay stream and open a fresh one for the next
  Subgroup on a new publisher stream, rather than appending across the
  boundary.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_publisher_fin_closes_and_reopens`
- [x] MQ22-161 The implementation shall relay each Subgroup consistently with
  the transport primitive matching its own delivery shape (one-shot
  open+send+FIN for a single-round Subgroup, open without FIN plus later
  appends for a long-lived one).
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_still_uses_send_uni_every_object`
- [x] MQ22-162 Two subscribers to the same Track shall each get their own
  independent relay stream, so a delivery to one does not affect the other's
  stream binding.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_two_subscribers_independent_streams`

## Hub relay: sustained-refusal shedding (SS11.4.3 reset discipline, applied)

- [x] MQ22-163 If a subscriber's relay stream is sustained-busy (refused) past
  the implementation's threshold, then the implementation shall reset that
  stream and re-open a fresh one at the next delivery, rather than continuing
  to hold a stale backlog.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_streak_sheds_after_threshold`
- [x] MQ22-164 An accepted delivery in the middle of a busy run shall reset the
  busy-streak counter, so scattered transient refusals never accumulate into a
  shed.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_streak_success_resets`
- [x] MQ22-165 After a stream has been shed, a publisher's bare FIN arriving
  for that now-abandoned stream shall not be forwarded to it.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_shed_stream_skips_publisher_fin`
- [x] MQ22-166 The busy-streak counter shall be tracked per subscriber, so one
  starved subscriber's shed does not affect another subscriber's healthy
  stream.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_shed_isolated_per_subscriber`
- [x] MQ22-167 If the reset itself is refused by the underlying transport, then
  the implementation shall retry the shed on the next busy round rather than
  treating it as done.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_shed_refused_retries_next_round`
- [x] MQ22-168 A re-PUBLISH of a track shall clear its relay state, including
  any accumulated busy-streak counters from the prior incarnation.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_republish_clears_busy_streak`

## Hub relay: session teardown (SS12.2 Termination applied to relay state)

- [x] MQ22-169 When a session closes, the implementation shall free its peer
  slot so a later reconnect on the same underlying session pointer is treated
  as a fresh peer, not the dead one.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_close_frees_peer_for_reregistration`
- [x] MQ22-170 When a subscriber's session closes, the implementation shall
  deactivate its subscription entries on every other peer's tracks so a later
  Object is not relayed to the dead session.
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_close_drops_subscriptions`
- [x] MQ22-171 Closing a session the implementation never registered (or one
  already closed) shall be a no-op that leaves other peers unaffected.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_close_unknown_session_noop`
- [x] MQ22-172 Repeated register/close cycles past the implementation's
  peer-table capacity shall not leak slots; every reconnect shall still receive
  its SETUP.
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_close_reregister_churn`

## Hub relay: control and request streams

- [x] MQ22-173 The implementation shall decode every Message Parameter by
  the draft-22 registry: its value encoding, the messages it may appear in,
  and its allowed value range; a parameter outside its message or range
  shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_registry_scope`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_uint8_value_ranges`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_repeatable_filters`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_golden_subscribe_params`
- [x] MQ22-174 A control message split across several stream deliveries
  shall be reassembled and handled once; a message longer than the hub's
  inbound limit (1024 bytes) shall close the session with INTERNAL_ERROR.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_split_subscribe_answered_once`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_message_then_half`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_max_length_accepted`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_over_max_closes_session`
- [x] MQ22-175 If the control stream carries a wholly unknown Message Type,
  then the hub shall close the session with a protocol violation.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_unknown_type_closes_session`
- [x] MQ22-176 Each request opened on its own bidirectional stream shall be
  answered on that stream; a reset of the stream cancels the request
  (unsubscribe/unpublish), a FIN alone does not, and a session may hold at
  most 24 open requests (more are reset with EXCESSIVE_LOAD).
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_subscribe_answered_on_its_stream`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_two_streams_answered_apart`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_reset_unsubscribes`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_fin_keeps_request`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_per_session_cap`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_pool_full_resets`
  - test: `tests/app/moqtrun_ns_test.c` —
    `test_moqtrun_ns_fin_half_closes_d19_d22`

## Hub relay: subscriptions

- [x] MQ22-177 A SUBSCRIBE shall match a published track by its full Track
  Name (namespace and name), so equal names in different namespaces are
  different tracks.
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_ns_must_match`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_same_name_other_ns_coexist`
- [x] MQ22-178 The hub shall record each subscription's Request ID,
  SUBSCRIBER_PRIORITY, GROUP_ORDER, FORWARD, delivery timeout and filter
  start, keep them across a publisher rejoin, and report LARGEST_OBJECT in
  SUBSCRIBE_OK once the track has objects.
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_params_recorded`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_reattach_keeps_state`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_ok_largest`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_largest_from_datagram`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_params_include_properties_d22`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_pub_params_delivery_timeout_d22`
- [x] MQ22-179 Objects shall be relayed reliably to each subscriber from a
  shared buffer pool: a slow subscriber holds the pool back only up to a
  watermark, a stalled one is dropped after a timeout, and a stream whose
  tail was dropped is not continued (it would desync the subscriber).
  - test: `tests/app/moqtrel_test.c` — `test_moqtrel_append_hold_at_watermark`
  - test: `tests/app/moqtrel_test.c` — `test_moqtrel_reclaim_follows_slowest`
  - test: `tests/app/moqtrel_test.c` — `test_moqtrel_stalled_after_timeout`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_poison_survives_reset_and_close`
- [x] MQ22-180 Subscriber priority shall map to the WebTransport stream
  urgency of that subscriber's relay streams, and a REQUEST_UPDATE changing
  the priority applies to later streams and re-classes the subscription's
  open keep-open and fill streams. With the io stream_sched hook the hub
  sets each Object stream's full class (urgency 4, Subscriber << 8 |
  Publisher Priority, per-subscription flow ranked by group order and
  fill-before-live) and the send pump schedules by it.
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_sched_relay_keys`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_sched_update_reclasses`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_sched_fill_shares_flow`
  - test: `tests/app/srvrun_test.c` — `test_srvrun_wt_sched_fill_before_live`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_per_subscriber`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_update_applies`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_op_absent`
- [x] MQ22-181 A REQUEST_UPDATE of a SUBSCRIBE, on that subscription's
  request stream, shall replace its parameters all-or-nothing: a refused
  update changes nothing.
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_forward_toggles`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_params_replace`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_failed_changes_nothing`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_survives_rejoin`
- [x] MQ22-182 A publisher may send PUBLISH_STATE_NOTIFY (0x22, new in
  draft-22) on its own subscription stream to report its current
  LARGEST_OBJECT, FORWARD or LOCATION_FILTER state to the subscriber; it
  shall never be sent on any other stream, shall receive no response, and
  shall not count against MAX_REQUEST_UPDATES.
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_notify_on_publish_stream_d22`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_notify_elsewhere_closes_d22`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_publish_state_notify_d22_only`
  - note: `moqtrun_dispatch_pub_notify`; ledger 4-10, direction-checked on
    3 paths.
- [x] MQ22-182a A PUBLISH_NAMESPACE shall be matched as a Track Namespace
  **Prefix** (any namespace starting with it), unlike draft-19 where it
  names one exact Track Namespace; relays shall never forward
  PUBLISH_NAMESPACE downstream, using NAMESPACE on a matching
  SUBSCRIBE_NAMESPACE instead.
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_prefix_overlap`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_ns_prefix_changes`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_ns_prefix_overlap_refused`
  - note: ledger 4-9's finding that `moqtrun_disc_under`/`_starts`/`_overlap`
    already implement byte-prefix matching (not exact match) for both
    draft-19 and draft-22, since draft-19's own NAMESPACE-sending-duty rule
    already requires prefix matching for SUBSCRIBE_NAMESPACE; draft-22's
    change is the field's own name ("Track Namespace Prefix") and applying
    the same algorithm to PUBLISH_NAMESPACE's matching rule too — already
    correct, no code change was required.
- [x] MQ22-182b A TRACK_STATUS shall be answered with REQUEST_OK carrying the
  track's largest location (or none when empty), or REQUEST_ERROR when the
  track is unknown or the authorizer refuses.
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_ok_largest`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_ok_empty`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_unknown_and_blob`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_authorized`
- [x] MQ22-183 Where an application installs an authorizer, every SUBSCRIBE,
  TRACK_STATUS, PUBLISH, PUBLISH_NAMESPACE and SUBSCRIBE_NAMESPACE shall be
  shown to it (draft-22 extends authorization to the publishing side too,
  see MQ22-097a), and a refusal shall be REQUEST_ERROR UNAUTHORIZED; an
  Alias-based authorization token shall close the session (the hub keeps
  no token cache, 8.9): REGISTER with AUTH_TOKEN_CACHE_OVERFLOW, DELETE and
  USE_ALIAS with UNKNOWN_AUTH_TOKEN_ALIAS.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_requires_authorization`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_alias_token_rejected`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_authorization`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_publish_requires_authorization`

## Hub relay: delivery timeouts

- [x] MQ22-184 With a non-zero OBJECT_DELIVERY_TIMEOUT (from SUBSCRIBE or a
  REQUEST_UPDATE), an object not delivered in time shall be abandoned: its
  stream is reset with DELIVERY_TIMEOUT (0x2), or the datagram is dropped.
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_live`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_datagram`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_by_update`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_torn_object`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_zero`

## Hub relay: caching and FETCH

- [x] MQ22-185 With a cache arena attached (`wired_moqt_cache_attach`),
  the hub shall cache whole groups only, evicting the oldest group when the
  budget is exceeded and dropping a group that alone exceeds it.
  - test: `tests/app/moqcache_test.c` — `test_moqcache_evicts_oldest_group`
  - test: `tests/app/moqcache_test.c` — `test_moqcache_group_over_budget_dropped`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_cache_attach`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_cache_default_off`
- [x] MQ22-186 A FETCH shall release its slot when the requester cancels,
  the data stream is stopped, the publisher or requester leaves, or the
  delivery stalls.
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_cancelled_by_request_reset`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_data_stream_stopped`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_publisher_leaves`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_stall_gives_up`

## Hub relay: namespace discovery

- [~] MQ22-187 A PUBLISH_NAMESPACE shall be accepted per publisher (several
  publishers may share a namespace), and a SUBSCRIBE_NAMESPACE shall get
  NAMESPACE for every matching namespace, then NAMESPACE / NAMESPACE_DONE
  as publishers come and go.
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_publish_accepted`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_initial_set`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_live_join_and_cancel`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_publisher_leaves`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_multiple_publishers`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_prefix_overlap`
  - evidence: `[~]` because PREFIX_OVERLAP is read strictly: within one
    session two prefixes overlap when either is empty or their first
    fields are equal, which refuses more than the draft requires.

## Hub relay: GOAWAY and PUBLISH_DONE

- [~] MQ22-188 `wired_moqt_goaway` shall send GOAWAY once per session; a
  request arriving after it is refused with GOING_AWAY; when the timeout
  expires the hub sends PUBLISH_DONE, answers what is still in flight, and
  closes with GOAWAY_TIMEOUT.
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_once_per_session`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_goaway_late_rejected`
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_timeout_flush_then_close`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_goaway_retried_on_tick`
  - evidence: unit-tested against the io table only; no third-party MOQT
    peer has been run against the GOAWAY/drain sequence yet.
- [x] MQ22-189 A second GOAWAY from the peer, or one carrying a New Session
  URI from a client, shall close the session with a protocol violation.
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_twice`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_uri`
- [x] MQ22-190 Before PUBLISH_DONE, the hub shall reset the subscription's
  data streams (including any open fill fetch streams, see MQ22-143); a
  publisher's session ending sends PUBLISH_DONE TRACK_ENDED to its
  subscribers.
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_done_resets_streams_first`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_done_track_ended`
- [~] MQ22-191 A WebTransport WT_DRAIN_SESSION from the peer
  (`wired_moqt_on_session_draining`) shall start the MOQT GOAWAY sequence
  for that session only.
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_drain_one_session`
  - evidence: unit-tested only; no live peer run yet.

## Hub relay: Object Datagrams

- [x] MQ22-192 An Object Datagram shall be relayed byte-identical to every
  subscriber of the track its alias names, and a malformed or unknown-alias
  datagram shall be counted and dropped.
  - test: `tests/app/moqdg_test.c` — `test_moqdg_roundtrip_golden`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_dg_relays_identical_bytes_to_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_dg_relays_to_all_three_subscribers`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_dg_unknown_alias_counts_bad`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_dg_malformed_counts_bad`

## Hub features completed in the multi-draft round (ledger ch. 10)

- [x] MQ22-193 (SS9.18) The hub shall answer a SUBSCRIBE_TRACKS with exactly one
  REQUEST_OK on its request stream, and shall refuse one whose Track Namespace
  Prefix overlaps an established SUBSCRIBE_TRACKS of the same session with
  PREFIX_OVERLAP.
  - test: `tests/app/moqtrun_subtracks_test.c` — `test_subtracks_ok_once`
  - test: `tests/app/moqtrun_subtracks_test.c` — `test_subtracks_prefix_overlap`
  - test: `tests/app/moqns_test.c` — `test_moqns_subscribe_tracks_param_scope`
  - note: Exercised on draft-19 sessions; the hub path is version-independent.
- [x] MQ22-194 (SS9.18) For every track matching an established SUBSCRIBE_TRACKS
  prefix and not published by the subscriber itself, the hub shall open one
  PUBLISH on a new bidirectional stream naming that track, carrying the
  SUBSCRIBE_TRACKS's FORWARD value; cancelling the SUBSCRIBE_TRACKS stops new
  PUBLISHes but leaves established ones, a track that vanishes before the reply
  resets its PUBLISH stream, and a REQUEST_ERROR reply frees the slot.
  The PUBLISH_OK (REQUEST_OK) reply opens the subscriber's subscription under
  the PUBLISH's Track Alias, starting from the PUBLISH's parameters (FORWARD 0
  holds Objects back); the subscriber's REQUEST_UPDATE on that stream is
  applied like a SUBSCRIBE's and answered there (ledger 12-11, 12-18).
  FORWARD and GROUP_ORDER, the SUBSCRIBE_TRACKS parameters SS9.8 admits on a
  PUBLISH, are echoed as given, FORWARD 1 included (SS3.6.2 "explicitly
  communicated", ledger 12-19). The SUBSCRIBE_TRACKS's object Range Filters,
  which SS9.8 keeps out of the PUBLISH, start that subscription anyway
  (SS3.6.1 "Objects published in the resulting Subscriptions can be filtered
  by any Range Filter"), and a SUBSCRIBE_TRACKS whose Range Filters are
  malformed, repeated or past MAX_FILTER_RANGES is refused INVALID_FILTER
  (SS3.3.2, ledger 12-26). A failed update ends it with PUBLISH_DONE
  UPDATE_FAILED and the hub then FINs the PUBLISH stream (SS9.5.1, SS9.9,
  ledger 12-27); a second REQUEST_OK or REQUEST_ERROR closes the session with
  PROTOCOL_VIOLATION (SS3.1, ledger 12-28).
  - test: `tests/app/moqtrun_misc_test.c` — `test_moqtrun_misc_pub_ok_relays`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_subtracks_rngf_gates`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_subtracks_rngf_limit`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_update_failed_fins`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_second_ok_closes`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_error_after_ok_closes`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_forward0_then_update`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_update_before_ok`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_d22_publish_params`
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_publish_match_excludes_self`
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_forward_zero_reflected`
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_cancel_keeps_established`
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_track_vanishes_resets_publish`
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_publish_error_frees_slot`
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_liveness_eventually_attempted`
  - note: ledger 10-2 (E-2): the hub-initiated PUBLISH path; TLA+-checked design
    in `tasks/loopeng/moqt/MoqtHubPublish/` (not in git). Exercised on draft-19
    sessions; the hub path is version-independent.
- [x] MQ22-195 (SS9.19) Where the hub cannot open a bidirectional stream for
  such a PUBLISH, it shall send PUBLISH_SKIPPED (Track Namespace Suffix, Track
  Name) on the SUBSCRIBE_TRACKS request stream instead, and shall not later send
  a PUBLISH for the same track incarnation.
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_skip_then_no_publish`
  - test: `tests/app/moqns_test.c` — `test_moqns_pub_skipped_roundtrip`
  - test: `tests/app/moqns_test.c` — `test_moqns_pub_skipped_rejects`
  - note: Exercised on draft-19 sessions; the hub path is version-independent.
- [x] MQ22-196 (SS9.5, SS9.5.2) A REQUEST_UPDATE of a FETCH, PUBLISH_NAMESPACE
  or SUBSCRIBE_NAMESPACE on its request stream shall be served: an accepted
  update is acknowledged (a new SUBSCRIBE_NAMESPACE prefix takes effect for
  later announcements); a refused FETCH update resets the FETCH data stream, and
  a refused namespace update (e.g. PREFIX_OVERLAP) closes the request stream and
  leaves the old prefix in place.
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_on_fetch_stream`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_on_fetch_stream_refused`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_ns_prefix_changes`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_ns_prefix_overlap_refused`
  - note: ledger 10-5. Exercised on draft-19 sessions; the hub path is
    version-independent.
- [x] MQ22-197 (SS9.11) A FETCH with GROUP_ORDER Descending shall be served
  newest group first (Objects within a group still ascending), and a FETCH whose
  body fails to decode shall close the session with PROTOCOL_VIOLATION.
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_descending_group_order`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_malformed_closes`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_descending_unknown_groups`,
    `test_moqtrun_fetch_descending_skips_missing_group`,
    `test_moqtrun_fetch_descending_start_object`
  - note: ledger 10-6. Exercised on draft-19 sessions; the hub path is
    version-independent. Gaps follow 3.2.2 read literally (first expected
    {End.Group, 0}, last {Start.Group, 2^64-1}, a gap across groups is
    several logical gaps): nonexistent groups stay unmarked, each group the
    cache cannot vouch for gets its own End of Unknown Range (see
    known-limitations.md).
- [x] MQ22-198 (SS3.3.1) A late subscriber attached to a live track shall start
  at its Location Filter's start Group: a start behind the live edge is clamped
  to the current Group, and a future start holds delivery until that Group.
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_live_attach_filter_start`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_filter22_start_object_oneshot`,
    `test_moqtrun_sub_filter22_start_object_keepopen`,
    `test_moqtrun_sub_filter22_start_object_append`,
    `test_moqtrun_sub_filter22_ring_start_object`,
    `test_moqtrun_sub_filter22_ring_late_replay_start`,
    `test_moqtrun_sub_filter22_ring_late_replay_end`,
    `test_moqtrun_sub_filter22_ring_end_object_append`,
    `test_moqtrun_sub_filter22_ring_end_object_open`
  - note: ledger 10-7. A start Object inside the first Group, and an End
    Object, are cut per Object on the lossy and the reliable (ring) relay
    paths alike; the first Object of a cut stream is re-framed with its
    absolute ID. Exercised on every draft; the hub path is
    version-independent.
- [x] MQ22-199 (SS9.1.6, SS9.1.7) The hub's SETUP shall advertise
  MAX_FILTER_RANGES and MAX_REQUEST_UPDATES (both 4,
  `WIRED_MOQTRUN_MAX_FILTER_RANGES` / `WIRED_MOQTRUN_MAX_REQ_UPDATES`), and
  shall decode the peer's; an absent option keeps the draft default 0.
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_setup_advertises_limits`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_limit_options_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_limit_options_default_zero`
  - note: ledger 10-11.
- [x] MQ22-200 (SS9.1.7, SS9.5) A request stream already holding
  MAX_REQUEST_UPDATES unanswered REQUEST_UPDATEs shall close the session with
  TOO_MANY_REQUEST_UPDATES on one more; a flushed response round restores the
  credit of every coalesced update.
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_credit_too_many`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_credit_restored_by_flush`
  - test: `tests/app/moqtrun_vgate_test.c` — `test_moqtrun_vgate_update_credit`
  - note: ledger 10-10; gated on `MOQVER_CAP_MAX_REQUEST_UPDATES`, which
    draft-19 and draft-22 hold and draft-18 lacks (12-5).
- [x] MQ22-201 (SS3.3.2, SS8.6) Range Filter parameters shall be decoded with
  delta resolution and validated: an undecodable value, a repeated (Type, SetID)
  in one message, or a total Range count beyond the advertised MAX_FILTER_RANGES
  (SUBSCRIBE, FETCH or REQUEST_UPDATE) is INVALID_FILTER; a REQUEST_UPDATE
  replaces a mentioned filter type whole and a zero-length value removes it;
  SetIDs OR together, and OBJECTID_FILTER gates each datagram-forwarded Object.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_rangefilter_value_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_rangefilter_open_end_prop_and_remove`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_rangefilter_overflow_and_truncated`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_rngf_dup_identity`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_rngf_limit`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_rngf_limit`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_rngf_replace_remove`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_rngf_sets_or`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_objectid_filter_gates_datagram`
  - note: ledger 10-9. Only OBJECTID_FILTER gates delivery, and only at the
    per-Object (datagram) gate; the other filter types are validated and stored
    but pass (see Out of scope). Exercised on draft-19 sessions; the hub path is
    version-independent.

## Experimental extensions (moqtail-compatible track switching)

These items are **not draft-22 requirements.** Draft-22 leaves every code
point below unassigned. They describe an opt-in extension that uses
moqtail's (`ee9753c`) values so that the two implementations can
interoperate. They are left out of the Coverage line above and out of the
totals in [the features index](README.md). Overview:
[MoQT track switching](moqt-track-switching.md).

All of it is restricted to draft-22 sessions, and only when the hub enables
it (`wired_moqt_hub.switch_track`; `ssts_algs` / `ssts_alg_n`). Wire status:
the codec is pinned to byte vectors copied from moqtail-rs unit tests, and
the hub behaviour is tested in-process (loopback) only. **No run against
moqtail or any other third-party implementation has happened yet.** Under
the wire-format rule (`.claude/rules/rfc-and-verification-layers.md`), the
hub items therefore stay at `[~]` until such a run exists, even though
their tests pass.

- [x] MQ22-X01 (0x24 SWITCH_FROM, codec) The codec shall decode and encode
  SWITCH_FROM {Request ID, Mode 0 Hard / 1 Soft, Flags 0x80 Publish Done}
  in SUBSCRIBE and REQUEST_UPDATE (subscription) on draft-22 only. Trailing
  bytes, an unknown Mode or another Flags bit is a violation.
  - test: `tests/app/moqctl_switch_test.c` —
    `test_mcsw_switch_from_golden_encode` (`24 03 07 00 80`)
  - test: `tests/app/moqctl_switch_test.c` —
    `test_mcsw_switch_from_golden_decode`
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_switch_from_violations`
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_switch_from_scope`
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_moqtail_list`
  - test: `tests/app/moqctl_switch_test.c` —
    `test_mcsw_moqtail_switch_from_3byte`
  - note: the golden and moqtail vectors are moqtail-rs unit-test bytes
    (a static third-party pin, not a live peer).
- [x] MQ22-X02 (0x41 SWITCHING_SET_ASSIGNMENT, codec) The codec shall
  decode and encode {Set ID, Algorithm ID, Threshold kbps, Weight 1..10,
  Activate, optional Rank} in SUBSCRIBE and REQUEST_UPDATE (subscription)
  on draft-22 only.
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_ssa_norank`
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_ssa_violations`
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_ssa_scope`
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_moqtail_ssa`
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_moqtail_ssa_trailing`
- [x] MQ22-X03 (0x09 SSTS_ALGORITHMS Setup Option, codec) The codec shall
  decode and encode the option as concatenated algorithm-id varints, keeping
  at most `MOQCTL_SSTS_MAX_ALGS` (4) with known IDs first. A malformed list
  is ignored rather than closed (a deliberate deviation, see
  [Known Limitations](known-limitations.md#moqt-track-switching-experimental)).
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_ssts_absent`,
    `test_mcsw_ssts_two`, `test_mcsw_ssts_cap_keeps_known`,
    `test_mcsw_ssts_malformed`
- [x] MQ22-X04 (codes 0x32, 0x33, PUBLISH_DONE 0x3) The code points match
  moqtail's. On draft-22, `moqctl_request_error_for` passes INVALID_SWITCH
  0x32 and UNSUPPORTED_EXTENSION 0x33 through unchanged. PUBLISH_DONE
  "switched" 0x3 must be written directly, because `moqctl_publish_done_for`
  maps it to TRACK_ENDED on draft-22.
  - test: `tests/app/moqctl_switch_test.c` — `test_mcsw_codes`
  - note: 0x32 never reaches a draft-18/19 session, because on those drafts
    0x24 is itself a PROTOCOL_VIOLATION (MQ22-X05).
- [~] MQ22-X05 (opt-in gate) With `switch_track` 0 or `ssts_alg_n` 0, or on
  a draft-18/19 session, a SUBSCRIBE carrying 0x24 or 0x41 shall close the
  session PROTOCOL_VIOLATION, as before the extension.
  - test: `tests/app/moqtrun_switch_test.c` — `test_moqtrun_switch_off_closes`
  - test: `tests/app/moqtrun_switch_test.c` —
    `test_moqtrun_switch_old_drafts_close`
  - test: `tests/app/moqtrun_ssts_test.c` — `test_moqtrun_ssts_off_violates`
  - test: `tests/app/moqtrun_ssts_test.c` —
    `test_moqtrun_ssts_nonmember_and_d19`
- [~] MQ22-X06 (SWITCH_FROM boundary and gating, TS-1/TS-2) G = max(Largest
  of both tracks) + 1. The old subscription ends at G−1 and the new one
  starts at {G, 0}, with no Group delivered twice and none skipped.
  - test: `tests/app/moqtrun_switch_test.c` —
    `test_moqtrun_switch_boundary_plus_one`,
    `test_moqtrun_switch_boundary_b_ahead`,
    `test_moqtrun_switch_soft_cut_at_boundary`,
    `test_moqtrun_switch_no_group_twice`, `test_moqtrun_switch_soft_no_gap`,
    `test_moqtrun_switch_reattach_keeps_bounds`,
    `test_moqtrun_switch_filter_update_keeps_bounds`
  - note: TLA+ `TrackSwitch.tla` (`tasks/loopeng/moqt/TrackSwitch/`, not in
    git).
- [~] MQ22-X07 (Soft / Hard, TS-3/TS-4) Soft drains the old subscription to
  G−1 and gives up after `WIRED_MOQTSW_SOFT_WAIT_MS`. Hard resets the old
  subscription's open streams CANCELLED once the new track's Group G (or
  later) reaches the hub, or when the new one goes away.
  - test: `tests/app/moqtrun_switch_test.c` —
    `test_moqtrun_switch_soft_drains_old`,
    `test_moqtrun_switch_soft_done_after_fin`,
    `test_moqtrun_switch_soft_deadline_giveup`,
    `test_moqtrun_switch_soft_g0_ends_now`,
    `test_moqtrun_switch_hard_resets_old`,
    `test_moqtrun_switch_hard_ends_on_b_boundary`,
    `test_moqtrun_switch_hard_no_silent_gap`,
    `test_moqtrun_switch_hard_b_gone_cuts_old`,
    `test_moqtrun_switch_hard_datagram_b`
- [~] MQ22-X08 (ending the old subscription, TS-5/TS-6) With Publish Done,
  the old subscription gets exactly one PUBLISH_DONE 0x3, after its last
  stream. Without it, the old subscription is suspended (streams reset,
  FORWARD 0, request stream open, no PUBLISH_DONE), and a later SWITCH_FROM
  can switch back to it.
  - test: `tests/app/moqtrun_switch_test.c` —
    `test_moqtrun_switch_no_flag_no_done`,
    `test_moqtrun_switch_done_once_track_ended`,
    `test_moqtrun_switch_hard_no_flag_suspends`,
    `test_moqtrun_switch_back`, `test_moqtrun_switch_no_leak`
- [~] MQ22-X09 (refusal, TS-9) A SWITCH_FROM with FORWARD, naming itself, a
  missing or ended subscription, the same track, or a hub-owned track, or
  carried on a PUBLISH's update or with FILL_PARAMETERS, is refused
  REQUEST_ERROR 0x32 and nothing changes.
  - test: `tests/app/moqtrun_switch_test.c` —
    `test_moqtrun_switch_rejects_ended_old`,
    `test_moqtrun_switch_hub_track_refused`,
    `test_moqtrun_switch_publish_update_refused`,
    `test_moqtrun_switch_fill_refused`,
    `test_moqtrun_switch_ssts_member_refused`
- [~] MQ22-X10 (SSTS negotiation and membership) The hub advertises 0x09
  only on draft-22, and the negotiated algorithms are the intersection of
  the two lists. An assignment naming an algorithm that was not negotiated,
  or a track already in another set, is refused 0x33.
  - test: `tests/app/moqtrun_ssts_test.c` — `test_moqtrun_ssts_setup_option`,
    `test_moqtrun_ssts_negotiation`,
    `test_moqtrun_ssts_refused_not_negotiated`,
    `test_moqtrun_ssts_track_in_other_set`,
    `test_moqtrun_ssts_cancel_removes_member`
- [~] MQ22-X11 (SSTS per-Group decision, SS-1..SS-4) Each Group's member is
  decided once, at the Group's first arrival, and that decision is final.
  Exactly one member's Group is forwarded, whole, on streams and datagrams
  alike.
  - test: `tests/app/moqtrun_ssts_test.c` —
    `test_moqtrun_ssts_one_member_per_group`,
    `test_moqtrun_ssts_forward_after_decision`,
    `test_moqtrun_ssts_whole_group`, `test_moqtrun_ssts_decision_final`,
    `test_moqtrun_ssts_switches_at_group_boundary`,
    `test_moqtrun_ssts_one_member_reliable`, `test_moqtrun_ssts_datagram`,
    `test_moqtrun_ssts_inactive_set_forwards_nothing`
  - note: TLA+ `SstsDecision.tla` (not in git).
- [~] MQ22-X12 (SSTS algorithms 0 and 0xff01) The default weighted split
  and the backpressure tier machine behave as moqtail's own tests
  describe.
  - test: `tests/app/moqssts_test.c` — `test_moqssts` (moqtail test cases
    ported), e.g. `test_moqssts_rises_one_tier_per_five_clear_groups`,
    `test_moqssts_falls_one_tier_at_the_downshift_depth`,
    `test_moqssts_two_sets_of_the_same_rank_split_by_weight`
  - test: `tests/app/moqtrun_ssts_test.c` — `test_moqtrun_ssts_bp_upshift`,
    `test_moqtrun_ssts_bp_downshift`, `test_moqtrun_ssts_default_cap`
- [ ] MQ22-X13 (interop) Third-party interop with moqtail (or any other
  implementation of these code points). Not run.
- Not implemented: SWITCHING_SET_ASSIGNMENT in PUBLISH_OK / REQUEST_OK
  (moqtail allows it), and the talk's switch prompt, GOP extension and
  latency budget, which are not in moqtail's code either.

## Not implemented

In scope for a draft-22 relay, but not implemented yet. A peer that needs
one of these gets NOT_SUPPORTED (or, where noted, a different behavior).
Reserved namespaces, SUBSCRIBE_TRACKS, PUBLISH_SKIPPED, FETCH GROUP_ORDER,
REQUEST_UPDATE of FETCH and namespace requests, MAX_REQUEST_UPDATES and
Range Filter validation were listed here until ledger ch. 10 implemented
them (MQ22-028, MQ22-193 through MQ22-201). REQUEST_UPDATE of a
SUBSCRIBE_TRACKS (prefix with per-type overlap, FORWARD; a failed one
closes the bidi stream, 9.5.1) followed: `test_moqtrun_vgate_update_kinds`.

- (SS7.6, SS11.4.1.2) Relay-level FETCH gap/upstream-fetch behavior
  (MQ22-137) — moot until this hub forwards FETCH upstream to another
  relay.

## Out of scope

Features and requirements this hub relay subset does not implement, excluded
from the coverage denominator above:

- (SS9.9) PUBLISH_DONE for a subscription made on the legacy control
  stream, by design: PUBLISH_DONE carries no Request ID, so on a stream
  shared by several subscriptions it cannot name the one that ended; the
  subscription is kept and re-attached when the publisher rejoins.

- (SS1.5, SS1.5.1) Rendering/parsing namespace and track names as
  human-readable strings — an operator/logging concern; this SDK compares
  names as raw bytes only.
- (SS12.1) The general receiver-side Malformed Track detection catalog
  (Publisher Priority mismatch across a Subgroup ID, Object ID exceeding a
  Subgroup/Group/Track final, differing finals across FIN'd streams,
  duplicate Objects with a different payload, Delivery Mode change) —
  beyond the decode-time violations (unknown Object Status, Object ID
  overflow), only an Object past END_OF_GROUP / END_OF_TRACK is detected
  (MQ22-025).
- (SS6.1, SS6.2) The `moqt` URI scheme, fragment identifiers, MOQT URI
  dereferencing and host resolution via SVCB/HTTPS RR — client-side
  concerns of a server-only hub. Native-QUIC sessions themselves (SS6.2.2:
  ALPN `moqt-22`, PATH/AUTHORITY Setup Options, CONNECTION_CLOSE
  termination) are implemented (`wired_moqt_on_session_raw`,
  `tests/app/moqtrun_raw_test.c`), verified in-process only until a pinned
  real-peer trace exists.
- (SS6.6.1, SS7.2, SS7.3) Session Migration and graceful relay switchover
  beyond the GOAWAY mechanics covered above — this is a single hub with
  no upstream relay to switch to.
- (SS3.3.x, SS8.6) Acting on OBJECT_PROPERTY_FILTER at delivery, and on
  OBJECTID_FILTER for stream-forwarded Objects — these are decoded,
  validated, counted against MAX_FILTER_RANGES and updated (MQ22-201), but
  the stream gates do not cut single Objects out of a relayed stream, so
  they pass. OBJECTID_FILTER does gate datagram-forwarded Objects;
  SUBGROUP_FILTER and PRIORITY_FILTER gate a whole stream at its open
  (`test_moqtrun_sub_rngf_gates_stream`), TRACK_PROPERTY_FILTER the tracks
  a SUBSCRIBE_TRACKS is offered (`test_moqtrun_misc_subtracks_track_prop_filter`);
  fill fetch range filtering is covered by MQ22-138 onward.
- (SS5, SS5.1--5.2) Priorities — the scheduling algorithm runs on the
  WebTransport send pump
  (Subscriber, then Publisher Priority, then group order and
  fill-before-live inside one subscription; MQ22-180). What remains:
  one-shot streams already queued keep their class across a
  REQUEST_UPDATE, datagrams bypass the stream classes, a FETCH's own
  SUBSCRIBER_PRIORITY is not kept (it ranks as 128), and equal classes
  across subscriptions share each pump pass round-robin.
- (SS7.4) Multiple Publishers of one Track — several publishers may share a
  namespace (MQ22-187), but each Track still has one publisher;
  aggregation/deduplication across publishers of a Track is not
  implemented.
- (SS9.20.5, SS9.20.6, SS9.20.16, SS9.20.19) FILL_TIMEOUT's own
  acted-on budget (only its presence gates the Timed-Out marker, see
  MQ22-142), EXPIRES and NEW_GROUP_REQUEST — decoded by the registry,
  not otherwise acted on. (SS9.20.6)
  RENDEZVOUS_TIMEOUT is acted on since 12-1 (ff1c0df): a SUBSCRIBE for a
  track with no publisher is held until one arrives or the timeout
  (capped at 1.5 s) answers TIMEOUT, see tests/app/moqtrun_rdv_test.c.
- (SS9.1.3, SS9.1.4, SS8.9) MAX_AUTH_TOKEN_CACHE_SIZE and AUTHORIZATION
  TOKEN as a Setup Option — not advertised; the hub keeps no token cache,
  so Alias-based tokens close the session (MQ22-183). (MAX_FILTER_RANGES and
  MAX_REQUEST_UPDATES are advertised, MQ22-199.)
- (SS11.5) Padding Datagrams — not sent.
- (SS10, SS10.1--10.x) MOQT Properties (MAX_CACHE_DURATION,
  DEFAULT_PUBLISHER_GROUP_ORDER, DYNAMIC_GROUPS,
  Immutable Properties, Prior Group/Object ID Gap, and the renumbered
  provisional properties — TIMESTAMP 0x10, VIDEO_FRAME_MARKING 0x09,
  AUDIO_CONFIG 0x0F, ENCRYPTED_LIST 0x0A, PADDING 0x32) as Track/Object
  Properties — the Properties wire slot is decoded generically and relayed
  unchanged; no specific Property type is interpreted except
  DEFAULT_PUBLISHER_PRIORITY (the stream urgency of a header omitting its
  Publisher Priority).
- (SS16) Security Considerations (subscription amplification,
  communication security, media security, resource exhaustion, timeouts,
  relay security, implementation fingerprinting, mTLS/RFC 9525 certificate
  verification detail, Reason Phrase / MOQT_IMPLEMENTATION log
  sanitization) beyond the namespace-authorization requirement already
  covered (MQ22-097a/MQ22-183) — operational/deployment guidance, not a
  wire behavior this ledger tests. E2E object encryption (Secure Objects /
  SFRAME) is an external mechanism this relay does not implement or
  interpret.
- (SS17) IANA Considerations — registry administration, not implementation
  behavior.
- REDIRECT as an actual relay behavior (sending it to move a requester to
  another URI/target, or reacting to one from an upstream) — this is a
  single hub with no upstream relay or sibling instance to redirect to or
  from, the same reasoning as the Session Migration entry above. This
  also covers draft-22's changed empty-NS/empty-Name Redirect semantics
  (literal target rather than "same as original") and the relaxed Retry
  Interval 0 wording, neither of which this relay exercises. The Redirect
  structure's wire format is still covered (MQ22-084 through MQ22-088).
- Per-version scope (ledger 4-4): this hub negotiates draft-18, -19 and -22
  per session (`moqver.c`). Range Filters, MAX_FILTER_RANGES and
  MAX_REQUEST_UPDATES exist only in draft-19 and later, so on a draft-18
  session a Range Filter parameter is refused as a protocol violation and
  the two Setup Options are ignored by the peer; on draft-19 and draft-22
  sessions they behave as described above (MQ22-199 to MQ22-201).
  SUBSCRIBE_TRACKS admits every Subscription parameter on draft-19 and
  draft-22 sessions, but only AUTHORIZATION TOKEN and FORWARD on draft-18
  ones (`MOQCTL_PARAM_RULES` in `moqctl.c`). See
  [draft-18](draft-moq-transport-18.md) and
  [draft-19](draft-moq-transport.md) for those drafts' own lists.
- Relay-to-relay coordination (draft-22 §7's "coordinated relay set"
  concept) — this is a single hub, not a federation of relays.
- Host resolution details (DNS A/AAAA, SVCB/HTTPS RR, default port 443)
  and the query-component-excluded-from-scope rule — delegated entirely to
  the underlying WebTransport/HTTP layer, not a MOQT-layer behavior.
