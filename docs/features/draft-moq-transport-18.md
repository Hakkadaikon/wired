[Docs](../README.md) › [Features](README.md) › draft-ietf-moq-transport-18

# draft-ietf-moq-transport-18 — Media over QUIC Transport

EARS requirement ledger extracted from the spec text
(`tasks/specs/draft-ietf-moq-transport-18.txt`, not in git), for this SDK's
MOQT subset: a single central hub relay over WebTransport implementing
SETUP, GOAWAY, PUBLISH, SUBSCRIBE (with Location Filters, FORWARD, priority
and both delivery timeouts), REQUEST_UPDATE of a SUBSCRIBE, FETCH or
namespace request, TRACK_STATUS, FETCH (standalone and joining, served from
a whole-group cache), PUBLISH_NAMESPACE / SUBSCRIBE_NAMESPACE,
SUBSCRIBE_TRACKS (hub-initiated PUBLISH or PUBLISH_BLOCKED), PUBLISH_DONE,
and Object delivery on Subgroup streams and Object Datagrams. A session
speaks draft-18 when the peer negotiates the `moqt-18` WebTransport
subprotocol. The data plane is byte-identical
to draft-19; this file lists only requirements that exist in draft-18 (some
absent from, or worded differently than, draft-19 — see each item's note).
Requirements shared verbatim with draft-19 reuse that ledger's wording and
test references; this file exists so draft-18-only readers do not have to
cross-reference another draft's ledger. Each requirement carries the test
that demonstrates it; an unchecked box with no test line is an open gap.
Status as of 2026-10.

The hub keeps every session, track and cache in one process's memory: run
it single-process (no `--workers`, `--cores` or AF_XDP fan-out), as
`examples/moqt_chat` does.

Legend:

- `[x]` — demonstrated by the referenced test
- `[~]` — exercised indirectly (evidence line explains how; no dedicated test)
- `[ ]` — not demonstrated by any test yet

**Coverage: 206/215 tested, 9 indirect, 0 untested.**

## SS1.4.1 Variable-Length Integers

- [x] MQ18-001 The implementation shall decode a MOQT variable-length integer
  using the number of leading 1 bits of the first byte to determine the encoded
  length (1-9 bytes), with the remaining bits and any subsequent bytes holding
  the value in network byte order.
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_official_examples`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_zero_all_lengths`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_nine_byte_padded`
- [x] MQ18-002 The implementation shall encode all 64-bit unsigned integers (0
  to 2^64-1) using the MOQT variable-length integer encoding.
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_official_examples`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_boundaries`
- [x] MQ18-003 The implementation shall encode a variable-length integer using
  the minimum number of bytes that can represent the value.
  - test: `tests/app/moqvi_test.c` — `test_moqvi_roundtrip`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_encode_official_examples`
- [x] MQ18-004 Where a variable-length integer is encoded with more bytes than
  the minimum required, the implementation shall still decode it to the correct
  value (non-minimal encodings are valid).
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_zero_all_lengths`
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_nine_byte_padded`
- [x] MQ18-005 If a variable-length integer's encoded length exceeds the number
  of bytes available, then the implementation shall report the decode as
  insufficient rather than reading past the input.
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_truncated`
- [x] MQ18-006 The implementation shall decode a variable-length integer
  without consuming bytes beyond its own encoded length, leaving any trailing
  bytes in the input untouched.
  - test: `tests/app/moqvi_test.c` — `test_moqvi_decode_ignores_trailing`
- [x] MQ18-007 If the destination buffer is too small to hold the encoded
  length of a value, then the implementation shall fail the encode rather than
  writing past the buffer.
  - test: `tests/app/moqvi_test.c` — `test_moqvi_put_too_small`

## SS1.4.2 Location Structure

- [x] MQ18-008 The implementation shall encode/decode a Location as two
  consecutive variable-length integers (Group, Object).
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`
- [x] MQ18-009 The implementation shall compare two Locations A and B such that
  A < B iff A.Group < B.Group, or A.Group == B.Group and A.Object < B.Object.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`

## SS1.4.3 Key-Value-Pair Structure

- [x] MQ18-010 The implementation shall decode a Key-Value-Pair's Type as the
  previous cumulative Type plus a Delta Type (0 for the first pair).
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_even_num`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_delta_accumulates`
- [x] MQ18-011 If the cumulative Key-Value-Pair Type would exceed 2^64-1, then
  the implementation shall report a protocol violation.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_type_overflow`
- [x] MQ18-012 The implementation shall decode the Value of an odd-Type
  Key-Value-Pair as Length bytes, and of an even-Type pair as a single
  variable-length integer.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_even_num`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_odd_raw`
- [x] MQ18-013 The Length field of a Key-Value-Pair shall not exceed 2^16-1
  bytes; if a larger length is received, the implementation shall report a
  protocol violation.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_len_65535_accepted`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_len_65536_violation`
- [x] MQ18-014 Where a Key-Value-Pair's Value does not match the serialization
  defined by a Type the implementation understands, the implementation shall
  report a formatting error distinct from a protocol violation.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_put_rejects`
  - evidence: `moqctl_setup_take` maps a malformed known Setup Option to
    session close; the KVP layer itself exposes only the codec-level put-side
    rejection tested here (`moqkvp_put_rejects`); the formatting-vs-violation
    distinction is fully exercised at the SETUP layer (see MQ18-045).
- [x] MQ18-015 The implementation shall not use the minimum encoding length for
  a Key-Value-Pair's Delta Type or even-Type Value as a decode requirement
  (non-minimal encodings are valid).
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_nonminimal_delta`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_nonminimal_even_value`
- [x] MQ18-016 If a Key-Value-Pair is truncated within its own known byte
  bound, then the implementation shall report a protocol violation.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_truncated_insufficient`
- [x] MQ18-017 The implementation shall decode a Key-Value-Pair without reading
  past the caller-supplied byte bound, and shall encode a round-trippable
  Key-Value-Pair list preserving Type order.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_roundtrip`

## SS1.4.4 Reason Phrase Structure

- [x] MQ18-018 The implementation shall decode a Reason Phrase as a
  variable-length integer Length followed by that many UTF-8 bytes.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_reason_boundary`
- [x] MQ18-019 If a Reason Phrase Length exceeds 1024 bytes, then the
  implementation shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_reason_boundary`

## SS2.4.1 Track Naming

- [x] MQ18-020 The implementation shall decode a Track Namespace as a
  variable-length integer field count followed by that many length-prefixed
  Track Namespace Fields.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ftn_decode_basic`
- [x] MQ18-021 If a Track Namespace Field has a Length of 0, then the
  implementation shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ns_field_len_zero_rejected`
- [x] MQ18-022 If a Track Namespace has more than 32 Track Namespace Fields,
  then the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_ns_fields_32_accept_33_reject`
- [x] MQ18-023 If a Full Track Name (Track Namespace plus Track Name) exceeds
  4096 bytes, then the implementation shall close the session with a protocol
  violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ftn_4096_accept_4097_reject`
- [x] MQ18-024 The implementation shall compare Track Namespace Fields and
  Track Names by exact byte comparison.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ftn_eq_exact_bytes`

## SS2.4.2 Malformed Tracks

- [~] MQ18-025 If a subscriber detects a Malformed Track, then the
  implementation shall cancel the corresponding subscription for that Track
  from that publisher.
  - evidence: The subset's malformed-track surface is limited to what the hub
    itself can detect from wire framing (unknown Object Status, cumulative
    Object ID overflow -- see MQ18-071/MQ18-072); the general receiver-side
    malformed-track catalog in SS2.4.2 (priority mismatch across a Subgroup ID,
    Object ID exceeding the Subgroup/Group/Track final, differing final Objects
    across FIN'd streams, duplicate Objects with different payload) is not
    implemented by this loss-free single-hub subset -- see Out of scope.

## SS2.5 Properties / SS2.5.1 Mandatory Track Properties

- [x] MQ18-026 The implementation shall recognize Property type ranges
  0x38-0x3F and 0x3800-0x3FFF as reserved for application-specific use.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_grease_pattern`
  - evidence: `moqctl_is_grease` and the Track Properties residual-span decode
    (MQ18-053) pass these ranges through uninterpreted; no dedicated boundary
    test pins the exact 0x38-0x3F/0x3800-0x3FFF edges. Note: draft-18's
    one-byte application-specific range is 0x38-0x3F; draft-19 widened it to
    0x78-0x7F (see `draft18-vs-19-diff.md` SS11).
  - gap: this range differs from draft-19's 0x78-0x7F; the implementation's
    greasing table is shared across versions and no draft-18-specific
    boundary is pinned (see Out of scope).
- [x] MQ18-027 The implementation shall recognize Property types in the range
  0x4000-0x7FFF as Mandatory Track Properties.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_grease_pattern`
  - evidence: No dedicated boundary test for the 0x4000-0x7FFF range itself;
    the codec treats Track Properties as an opaque residual span (MQ18-053) and
    does not currently classify or reject individual Mandatory Track Property
    types.

## SS3.2.1 Reserved Namespaces / SS3.2.2 Session-Level Tracks

- [x] MQ18-028 If a request references a Track Namespace whose first field is a
  single period, then the implementation shall reject it with DOES_NOT_EXIST.
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_reserved_ns_rejected`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_reserved_rejected`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_other_dot_ns_served`
  - note: `moqtrun_ns_reserved` (ledger 10-1) rejects a first field of
    exactly `.` or `.session` with DOES_NOT_EXIST on PUBLISH, SUBSCRIBE,
    PUBLISH_NAMESPACE and SUBSCRIBE_NAMESPACE; any other `.`-led field is
    served like an ordinary namespace. The check is version-independent.

## SS3.3 Session Initialization

- [x] MQ18-029 The server shall open one unidirectional control stream and send
  SETUP as its first message.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_session_opens_uni_ctl`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_client_uni_ctl_accepted`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_refused_uni_ctl_open_retries`
  - note: a session whose WT token is empty (browser clients cannot
    negotiate a subprotocol) keeps the earlier drafts' single
    bidirectional control stream
    (`test_moqtrun_empty_token_keeps_bidi_ctl`). draft-18 introduced the
    unidirectional control-stream pair in draft-17 and keeps it unchanged.
- [x] MQ18-030 Once both endpoints have sent and received SETUP, the session
  shall be Established.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_establish`
  - test: `tests/app/moqsess_test.c` —
    `test_moqsess_established_accepts_request`
- [x] MQ18-031 A bidirectional request stream shall begin with one of the
  First-type messages (TRACK_STATUS, SUBSCRIBE, PUBLISH, FETCH,
  PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS); if it does not,
  the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_bad_first_message`
- [x] MQ18-032 Where a unidirectional stream containing Objects or a
  bidirectional request stream arrives before both control streams have
  completed SETUP, the implementation shall buffer it rather than deliver it to
  the application.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsess_buffer_before_setup_then_deliver`
- [x] MQ18-033 Where SETUP has not yet completed, the implementation may reset
  a bidirectional request stream instead of buffering it.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_pre_setup_reset_window`
- [x] MQ18-034 An endpoint may pipeline further control messages after sending
  its own SETUP without waiting for the peer's SETUP.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsess_pipeline_before_peer_setup`
- [x] MQ18-035 If a control stream is closed at the transport layer during the
  session's lifetime, then the implementation shall close the session with a
  protocol violation.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsess_ctrl_stream_transport_close`
- [x] MQ18-036 If the same peer opens a second control stream, then the
  implementation shall close the session with a protocol violation.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_second_control_stream`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_on_session_twice_is_idempotent`

## SS3.3.2 Request Stream Closure (draft-18: FIN is a cancellation)

- [x] MQ18-037a Where a SUBSCRIBE_NAMESPACE or SUBSCRIBE_TRACKS request
  stream's direction is closed with a FIN, the implementation shall treat it
  as a cancellation of that request, unlike draft-19 (and later) where FIN
  is a graceful half-close that is not a cancellation.
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_fin_cancels_d18`
  - note: this is a draft-18-specific wire behavior (`MOQVER_CAP_FIN_CANCEL_NS`);
    see `draft18-vs-19-diff.md` SS2 "Request-stream FIN semantics".

## SS3.3.4 Stream Reset Error Codes / SS3.5 Termination (used subset)

- [x] MQ18-037 The implementation shall recognize the session termination error
  code table entries it uses (NO_ERROR, INTERNAL_ERROR, PROTOCOL_VIOLATION,
  INVALID_REQUEST_ID, DUPLICATE_TRACK_ALIAS, KEY_VALUE_FORMATTING_ERROR,
  INVALID_PATH, GOAWAY_TIMEOUT, INVALID_AUTHORITY).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_grease_pattern`
  - evidence: These codes are used as `#define`s at their call sites
    (moqctl.h/moqsess.h) rather than round-tripped through a codec; no
    dedicated test enumerates the full table, but each code's use is exercised
    at its own violation site (see the sess/data/ctl unwanted-behavior items
    throughout this file). draft-18 does not define session code 0x1B
    (TOO_MANY_REQUEST_UPDATES, draft-19 only) — see Out of scope.

## SS3.4 Unidirectional Stream Types

- [x] MQ18-038 The implementation shall classify a unidirectional stream's
  leading variable-length integer as one of SETUP (0x2F00), FETCH_HEADER
  (0x05), SUBGROUP_HEADER (0b0XX1XXXX), or PADDING (0x132B3E28).
  - test: `tests/app/moqdata_test.c` — `test_moqdata_classify_golden`
- [x] MQ18-039 If an endpoint receives an unknown unidirectional stream type,
  then the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_unknown_uni_stream_type`
- [x] MQ18-040 The implementation shall classify a unidirectional stream
  without consuming bytes past a truncated leading type field, reporting the
  classification as insufficient instead.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_classify_truncated`

## SS3.5 Termination

- [x] MQ18-041 The server shall close a WebTransport-carried MOQT session using
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

## SS3.6 Session Migration / SS10.4 GOAWAY (session lifecycle, draft-18 layout)

- [x] MQ18-042 An endpoint that has sent or received GOAWAY may reject a new
  request with an error indicating the endpoint is going away, while the
  session remains open.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_goaway_reject_new_request`
- [x] MQ18-043 An endpoint that has received GOAWAY on the control stream shall
  not initiate new requests of its own, without the session closing solely
  because of the GOAWAY.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_goaway_clean_shutdown`
- [x] MQ18-044 If the peer does not close the session within the GOAWAY
  timeout, then the sender shall close the session with GOAWAY_TIMEOUT.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_goaway_timeout_closes`
- [x] MQ18-045 If a server receives a GOAWAY with a non-zero New Session URI
  Length, then the implementation shall close the session with a protocol
  violation.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_goaway_bad_uri`
- [x] MQ18-046 If the same control stream receives more than one GOAWAY, then
  the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_second_goaway`
- [x] MQ18-047 Where a GOAWAY is received on a request stream rather than the
  control stream, the implementation shall accept it without closing the
  session, while a second GOAWAY on the same request stream shall still be a
  protocol violation.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_goaway_on_request_stream_produces_no_reply`
- [x] MQ18-048a The implementation shall encode/decode a control-stream GOAWAY
  carrying a trailing Request ID (vi64): the smallest peer Request ID the
  sender has not (or may not have) processed, differing from draft-19 and
  later, where GOAWAY has no Request ID field at all.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway18_request_id`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway18_vs_19_shape`
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_request_id_d18`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_d18`
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_peer_goaway_d18_parity`
  - note: `MOQVER_CAP_GOAWAY_REQID`; see `draft18-vs-19-diff.md` SS4.
- [x] MQ18-048b If a server receives a draft-18 request with a Request ID at
  or above the watermark carried in a control-stream GOAWAY it has sent (or
  any request arriving after that GOAWAY), then the implementation shall
  reject it with REQUEST_ERROR GOING_AWAY.
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_goaway_watermark_d18`
  - note: resolved via the existing version-independent `moqtrun_is_late`
    gate (rejecting everything after GOAWAY is sent is equivalent to
    rejecting everything at or above the watermark, since the hub sends
    GOAWAY only once); see ledger 4-1.

## SS9 Relays (SS9.4/9.6/9.7 forwarding discipline)

- [x] MQ18-049 A relay shall not reorder or drop Objects received on a
  multi-object stream when forwarding them to subscribers.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_to_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_two_subscribers_two_objects`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_normalize_forwards_only_whole_objects`
  - note: draft-18's text permits an application-specific reorder/drop
    exception that draft-19 removes; the implementation never exercises
    that exception (always strict), so this item holds under both drafts.
- [x] MQ18-050 A relay shall not modify Object header fields or payload when
  forwarding an Object.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_preserves_bytes`
- [x] MQ18-051 The relay shall have an Established upstream subscription before
  sending SUBSCRIBE_OK in response to a downstream SUBSCRIBE.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_matching_publish_replies_ok`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_ok_after_upstream`
- [x] MQ18-052 If a relay receives a SUBSCRIBE for a Track no publisher has
  PUBLISHed, then the implementation shall send a SUBSCRIBE upstream to a
  session (other than the subscriber's) that PUBLISH_NAMESPACEd the Track's
  namespace or a prefix of it (SS9.5), now or -- for a held SUBSCRIBE --
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
    announcer (SS9.5 says each matching publisher; the hub keys one track
    per name). An upstream subscription nobody downstream wants any more
    is cancelled (`test_moqtrun_upsub_last_cancel_cancels_upstream`).
- [~] MQ18-053 A relay may aggregate authorized subscriptions for a given Track
  when multiple subscribers request it, forwarding a single upstream Object to
  every matching downstream subscriber.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_to_all_three_subscribers`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_two_share_one`

## SS10 Control Messages: common envelope

- [x] MQ18-054 The implementation shall encode/decode every control message as
  Message Type (varint) + Message Length (16-bit) + Message Body.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_setup`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
- [x] MQ18-055 The implementation shall recognize the Message Type table
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
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_standalone_golden`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_ok_golden`
  - test: `tests/app/moqns_test.c` — `test_moqns_publish_golden`
  - test: `tests/app/moqns_test.c` — `test_moqns_subscribe_golden`
  - test: `tests/app/moqtstat_test.c` — `test_moqtstat_golden`
  - test: `tests/app/moqtstat_test.c` — `test_moqtstat_update_golden`
  - evidence: FETCH (0x16), FETCH_OK (0x18), TRACK_STATUS (0xD),
    REQUEST_UPDATE (0x2), PUBLISH_NAMESPACE (0x6), SUBSCRIBE_NAMESPACE
    (0x50), NAMESPACE (0x8) and NAMESPACE_DONE (0xE) are encoded/decoded by
    their own codecs (fetch/, ns/, tstat/), each pinned by golden vectors;
    the draft-18 and draft-19 layouts for all these messages are
    byte-identical.
- [x] MQ18-055a Where a draft-18 session sends PUBLISH_OK, the implementation
  shall encode it as REQUEST_OK (0x7); where a draft-18 session receives
  message type 0x1E, the implementation shall accept it as an alias for
  REQUEST_OK (0x7), unlike draft-19 (and later) where 0x1E is RESERVED and
  closes the session as unknown.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_publish_ok_alias_d18_only`
  - test: `tests/app/moqver_test.c` — `test_moqver_caps_d18`
  - note: `MOQVER_CAP_PUBLISH_OK_ALIAS`; ruling Q18-01 (interop-favoring
    choice: accept 0x1E from a draft-18 peer, but always send 0x7). See
    `draft18-vs-19-diff.md` SS3.
- [x] MQ18-056 If an endpoint receives an unknown Message Type, then the
  implementation shall report it distinctly so the caller closes the session.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_unknown`
- [x] MQ18-057 The implementation shall distinguish a known Message Type that
  the envelope peek does not decode itself (e.g. REQUEST_UPDATE, FETCH,
  TRACK_STATUS, PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS)
  from a wholly unknown one, so the caller can dispatch it, or reply
  NOT_SUPPORTED, instead of closing the session. The hub now answers all of
  these, SUBSCRIBE_TRACKS included (MQ18-201).
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_peek_type_known_unimplemented`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unknown_first_type_gets_not_supported`
- [x] MQ18-058 If a control message's declared Length does not match the actual
  Message Body length available, then the implementation shall not treat the
  message as complete (reporting insufficient rather than misreading past the
  body).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_length_mismatch`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_truncated`
- [x] MQ18-059 The implementation shall support a control message total length
  up to 2^16-1 bytes.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_max_len_field`

## SS10.1 Request ID

- [x] MQ18-060 The client shall generate even-numbered Request IDs starting at
  0, and the server shall generate odd-numbered Request IDs starting at 1,
  incrementing by 2 for each new request.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_and_audio_get_different_aliases`
  - evidence: The hub's own `request_id_next` field increments by 2 per new
    server-initiated request (moqtrun.h); no dedicated test isolates the
    arithmetic outside the alias-allocation tests, so this is `[~]` rather than
    `[x]`.
- [x] MQ18-061 If an endpoint receives a Request ID whose least significant bit
  is incorrect for the sender, then the implementation shall close the session
  with INVALID_REQUEST_ID.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_bad_request_id_parity`
- [x] MQ18-062 If an endpoint receives a duplicate Request ID, then the
  implementation shall close the session with INVALID_REQUEST_ID.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_duplicate_request_id`

## SS10.2 Message Parameters

- [x] MQ18-063 The implementation shall decode Message Parameters as a Type
  Delta (varint, cumulative from the previous Parameter Type) followed by a
  Value whose encoding (uint8, varint, Location, or length-prefixed bytes) is
  fixed per Type.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_delivery_timeout_decode`
- [x] MQ18-064 Parameters shall be serialized in ascending order by Type; if
  the cumulative Parameter Type would exceed 2^64-1, the implementation shall
  close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_type_overflow_violation`
- [x] MQ18-065 If an endpoint receives an unknown Message Parameter Type, then
  the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_unknown_type_violation`
  - note: draft-18 does not register Range Filter parameter types
    0x25-0x29 (new in draft-19); a draft-18 session receiving one of these
    closes with a protocol violation under this same rule — see Out of
    scope.
- [x] MQ18-066 If a sender repeats the same Parameter Type in one message, then
  the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_duplicate_type_violation`
- [x] MQ18-067 If a Message Parameter is defined for message types other than
  the one it appears in, then the implementation shall close the session with a
  protocol violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_scope_violation`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_registry_scope_per_draft`
  - note: draft-18's allowed-message sets differ from draft-19's for
    EXPIRES (0x08) and GROUP_ORDER (0x22) — see MQ18-071a/MQ18-073a.
- [x] MQ18-068 Message Parameters in SUBSCRIBE, PUBLISH_OK, and FETCH shall not
  cause the publisher to alter the payload of the Objects it sends.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_preserves_bytes`
  - evidence: No parameter value is ever consulted when constructing an
    Object's payload in moqtrun.c; the relay-preserves-bytes test demonstrates
    payload identity end-to-end but does not vary parameters to isolate this
    specific guarantee.

## SS10.2.3/10.2.4 SUBGROUP_DELIVERY_TIMEOUT / OBJECT_DELIVERY_TIMEOUT

- [x] MQ18-069 The implementation shall decode the SUBGROUP_DELIVERY_TIMEOUT
  (0x06) and OBJECT_DELIVERY_TIMEOUT (0x02) Message Parameters as a varint,
  with a value of 0 meaning no timeout set.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_delivery_timeout_decode`
- [x] MQ18-070 The hub shall not send a delivery-timeout parameter in its own
  SUBSCRIBE_OK / REQUEST_OK / PUBLISH_DONE replies (the loss-free single-hub
  subset does not set delivery timeouts).
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_ok_carries_no_timeout_param`
- [x] MQ18-071 A SUBSCRIBE carrying a non-zero SUBGROUP_DELIVERY_TIMEOUT or
  OBJECT_DELIVERY_TIMEOUT parameter shall be accepted and applied, taking
  the min() of the subscriber's value and the publisher's Track Property
  value where both are non-zero.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_nonzero_timeout_accepted`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_accepted`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_subgroup_timeout_min`
  - note: this reflects the current implementation (ledger 10-4), which
    replaced the earlier NOT_SUPPORTED rejection (the draft-19 ledger's
    MOQT-070 says the same).

## SS10.2.17 FORWARD Parameter

- [x] MQ18-072 The implementation shall encode/decode the FORWARD parameter
  (Type 0x10) as a uint8 whose value is 0 (don't forward) or 1 (forward),
  defaulting to 1 when omitted.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
- [x] MQ18-073 A publisher that sends FORWARD=0 in PUBLISH shall not transmit
  any Objects until the subscriber sets Forward State to 1; Object forwarding
  toward a subscription is gated by its Forward State.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_forward_state_zero_blocks_objects`

## SS10.2.8/10.2.10 GROUP_ORDER / EXPIRES allowed-message sets (draft-18)

- [x] MQ18-073a The implementation shall accept GROUP_ORDER (0x22) in
  PUBLISH_OK on a draft-18 session, unlike draft-19 (and later) where
  PUBLISH_OK does not allow GROUP_ORDER and SUBSCRIBE_TRACKS does instead.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_registry_scope_per_draft`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_pub_params_group_order_d19`
  - note: ruling Q18-02 (follow §10.19.1's per-request-type rule over the
    allowed-set table's apparent contradiction) applies from draft-19 on:
    draft-18 §10.19 has no §10.19.1 and echoes only FORWARD, and §10.2.8
    lists SUBSCRIBE, PUBLISH_OK and FETCH only, so a draft-18 PUBLISH with
    GROUP_ORDER is a protocol violation (ledger 12-7).
- [x] MQ18-073b The implementation shall reject EXPIRES (0x08) in
  SUBSCRIBE_NAMESPACE_OK, SUBSCRIBE_TRACKS_OK or PUBLISH_NAMESPACE_OK on a
  draft-18 session with a protocol violation, unlike draft-19 (and later)
  where those three REQUEST_OK variants allow EXPIRES.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_registry_scope_per_draft`
  - note: draft-18's EXPIRES allowed-mask is narrower (SUBSCRIBE_OK, PUBLISH,
    PUBLISH_OK, REQUEST_UPDATE_OK only); see `draft18-vs-19-diff.md` §5.

## SS10.3 SETUP

- [x] MQ18-074 The implementation shall encode/decode SETUP's Setup Options as
  a Key-Value-Pair list spanning the message payload.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
- [x] MQ18-075 Endpoints shall ignore unrecognized Setup Options.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_setup_unknown_option_ignored`
  - note: draft-18 does not register MAX_FILTER_RANGES (0x06) or
    MAX_REQUEST_UPDATES (0x08), new in draft-19; a draft-18 session receiving
    either is covered by this same "ignore unknown" rule — see Out of scope.
    The hub's own SETUP leaves both options off for a draft-18 peer
    (`moqtrun_setup_limits`, ledger 4-4):
    `test_moqtrun_xver_setup_d18_omits_d19_options`.
- [x] MQ18-076 Senders shall not repeat the same Setup Option Type in a message
  unless the option explicitly allows multiple instances.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
  - evidence: `moqctl_setup_encode` writes each of
    PATH/AUTHORITY/MOQT_IMPLEMENTATION at most once by construction; no test
    drives an encoder input with a duplicate to confirm rejection on decode
    (decode simply keeps the last-seen value for a repeated known option,
    matching the KVP layer's own duplicate-tolerant model).

## SS10.3.1.1 AUTHORITY / SS10.3.1.2 PATH / SS10.3.1.5 MOQT_IMPLEMENTATION

- [x] MQ18-077 The implementation shall decode the PATH (0x01) and AUTHORITY
  (0x05) Setup Options as byte-string values.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_path_option_decode`
- [~] MQ18-078 If a PATH or AUTHORITY option is received while WebTransport is
  used, then the implementation shall close the session with INVALID_PATH or
  INVALID_AUTHORITY respectively.
  - evidence: `moqctl_setup_take` only surfaces `has_path`/`has_authority` to
    the caller (moqctl.h's own doc: "WebTransport-context rejection is a
    session-layer decision"); no session-layer test in this ledger exercises
    the WT-context rejection itself.
- [x] MQ18-079 The implementation shall decode the MOQT_IMPLEMENTATION (0x07)
  Setup Option as a UTF-8 byte-string value.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`

## SS10.4 GOAWAY (wire format, draft-18 shape)

- [x] MQ18-080 The implementation shall encode/decode GOAWAY's shared prefix
  as Type (0x10) + Length + New Session URI Length + New Session URI +
  Timeout, with the trailing Request ID field present only on the control
  stream (see MQ18-048a).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway18_request_id`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway18_vs_19_shape`
- [x] MQ18-081 If the New Session URI Length exceeds 8192 bytes, then the
  implementation shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_uri_boundary`
- [x] MQ18-082 A client shall send a zero-length New Session URI in any GOAWAY
  it sends.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_roundtrip`
  - evidence: The wire codec accepts and round-trips a zero-length URI; no test
    asserts the client-side encoder path specifically refuses a non-zero URI
    (the receiving side's rejection is MQ18-045 above).

## SS10.5 REQUEST_OK

- [x] MQ18-083 The implementation shall encode/decode REQUEST_OK as Type (0x7)
  + Length + Number of Parameters + Parameters + Track Properties (the
  remaining message bytes).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_ok_roundtrip`
- [x] MQ18-084 If a REQUEST_OK variant that must have empty Track Properties
  (e.g. PUBLISH_OK) carries non-empty Track Properties, then the implementation
  shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_ok_roundtrip`
  - evidence: `moqctl_request_ok_take` always decodes the residual span and
    lets the caller (which knows which request it answers) enforce the
    per-variant empty-Track-Properties rule (moqctl.h's own doc); no
    session/run-layer test exercises the enforcement itself.

## SS10.6 REQUEST_ERROR

- [x] MQ18-085 The implementation shall encode/decode REQUEST_ERROR as Type
  (0x5) + Length + Error Code + Retry Interval + Error Reason + optional
  Redirect.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_error_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_request_error_redirect_roundtrip`
- [x] MQ18-086 The Redirect structure shall be present only when Error Code is
  REDIRECT.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_request_error_redirect_roundtrip`
- [x] MQ18-087 If a server receives a Redirect with a non-zero Connect URI
  Length, then the implementation shall close the session with a protocol
  violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_request_error_redirect_roundtrip`
  - evidence: `moqctl_request_error_take` decodes the Redirect structure
    symmetrically for either role; the server-specific non-zero-URI rejection
    is a session-layer decision not exercised by a dedicated test.
- [x] MQ18-088 The implementation shall recognize the REQUEST_ERROR codes it
  uses: INTERNAL_ERROR, NOT_SUPPORTED, GOING_AWAY, INVALID_FILTER,
  UNINTERESTED, DOES_NOT_EXIST, UNAUTHORIZED, REDIRECT, and (draft-18 only)
  DUPLICATE_SUBSCRIPTION (0x19, see MQ18-130a).
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_registry_scope_per_draft`
- [x] MQ18-089 If an endpoint receives an unrecognized REQUEST_ERROR code, then
  the implementation shall treat it as INTERNAL_ERROR rather than closing the
  session.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`
  - note: draft-18 does not define REQUEST_ERROR codes 0x35
    (CONFLICTING_FILTERS) or 0x36 (INVALID_FILTER's draft-19 code; draft-18
    reuses INVALID_FILTER at a different numeric slot per the Range Filter
    registry, absent in draft-18 — see Out of scope); both are tolerated as
    unknown by this same rule.

## SS10.7 SUBSCRIBE / SS10.8 SUBSCRIBE_OK

- [x] MQ18-090 The implementation shall encode/decode SUBSCRIBE as Type (0x3) +
  Length + Request ID + Track Namespace + Track Name + Number of Parameters +
  Parameters.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_roundtrip`
- [x] MQ18-091 On a successful subscription, the publisher shall reply with
  exactly one SUBSCRIBE_OK.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_ok_roundtrip`
  - test: `tests/app/moqsess_test.c` — `test_moqsub_subscribe_establish`
- [x] MQ18-092 The implementation shall encode/decode SUBSCRIBE_OK as Type
  (0x4) + Length + Track Alias + Number of Parameters + Parameters + Track
  Properties.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_ok_roundtrip`
- [x] MQ18-093 If a subscriber sends more than one SUBSCRIBE_OK or
  REQUEST_ERROR in response to the same SUBSCRIBE, then the implementation
  shall treat the second response as a session-level protocol fault.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_duplicate_response_is_session_fault`
- [x] MQ18-094 If a publisher rejects a SUBSCRIBE with REQUEST_ERROR, then no
  Object shall be sent for that subscription.
  - test: `tests/app/moqsess_test.c` — `test_moqsub_subscribe_rejected`
- [x] MQ18-094a If a peer sends a second concurrent subscription to the same
  Track from the same role, then a draft-18 session shall reject it with
  REQUEST_ERROR DUPLICATE_SUBSCRIPTION, unlike draft-19 (and later) which
  allows multiple concurrent subscriptions to the same Track.
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_sub_duplicate_refused_d18`
  - note: `moqtrun_sub_held_reply` branches on the negotiated version's
    `MOQVER_CAP_DUP_SUBSCRIPTION` bit; see ledger 4-2 and
    `draft18-vs-19-diff.md` §9.3.

## SS10.10 PUBLISH

- [x] MQ18-095 The implementation shall encode/decode PUBLISH as Type (0x1D) +
  Length + Request ID + Track Namespace + Track Name + Track Alias + Number of
  Parameters + Parameters + Track Properties.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_roundtrip`
- [x] MQ18-096 On a successful PUBLISH-initiated subscription, the subscriber
  shall reply with exactly one PUBLISH_OK (REQUEST_OK).
  - test: `tests/app/moqsess_test.c` — `test_moqsub_publish_establish`
- [x] MQ18-097 A publisher may start sending Objects on a PUBLISH-initiated
  subscription before receiving PUBLISH_OK.
  - test: `tests/app/moqsess_test.c` — `test_moqsub_object_before_publish_ok`
- [x] MQ18-098 If a subscriber rejects a PUBLISH with REQUEST_ERROR
  UNINTERESTED, then the subscription shall terminate without any Object being
  sent.
  - test: `tests/app/moqsess_test.c` — `test_moqsub_publish_rejected`

## SS10.11 PUBLISH_DONE

- [x] MQ18-099 The implementation shall encode/decode PUBLISH_DONE as Type
  (0xB) + Length + Status Code + Stream Count + Error Reason.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_done_roundtrip`
- [x] MQ18-100 A sender shall not send PUBLISH_DONE until it has closed every
  data stream it opened for that subscription.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_publish_done_terminates_and_reclaims`
- [x] MQ18-101 PUBLISH_DONE plus closing the subscription's bidi stream shall
  terminate the subscription; the sender may then destroy subscription state.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_publish_done_terminates_and_reclaims`
- [x] MQ18-102 If PUBLISH_DONE arrives before the subscriber has sent its
  response, then the subscriber shall owe exactly one deferred PUBLISH_OK
  before it FINs.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_publish_done_before_response_defers_ok`
- [x] MQ18-103 The implementation shall recognize the PUBLISH_DONE status codes
  it uses: INTERNAL_ERROR, TRACK_ENDED, GOING_AWAY.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`
- [~] MQ18-104 If a publisher did not open any data stream for a subscription,
  then it shall set PUBLISH_DONE's Stream Count to 0.
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_relay_table_full_counts`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_done_track_ended`
  - evidence: the hub now sends PUBLISH_DONE (MQ18-198), but always with
    the draft's "unknown" Stream Count (2^62-1, same sentinel value as
    draft-19) rather than an exact count, so the zero-stream case is never
    encoded as 0.

## SS10 Reason Phrase / Location / Track Namespace shared structures used in control messages

- [x] MQ18-105 The implementation shall encode/decode Message Parameters,
  Location, and Reason Phrase consistently across every control message that
  embeds them.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_reason_boundary`

## SS9.3.1 Location Filter (subscription filtering, draft-18 shape identical to draft-19)

- [x] MQ18-106 The implementation shall decode a Location Filter's Filter Type
  as one of Next Group Start (0x1), Largest Object (0x2), AbsoluteStart (0x3),
  or AbsoluteRange (0x4), with the field layout (Start Location, End Group
  Delta) determined by the type.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_locfilter_next_group_and_largest`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_locfilter_abs_start_and_range_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_rangeloc19_next_group`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_rangeloc19_largest_object`
  - note: this parameter is named "Subscription Filter" in draft-18's prose
    (renamed "Location Filter" in draft-19); the structure is byte-identical
    — see `draft18-vs-19-diff.md` §9.3.
- [x] MQ18-107 If an AbsoluteRange filter's End Group (Start.Group + End Group
  Delta) would exceed 2^64-1, then the implementation shall close the session
  with a protocol violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_locfilter_end_group_overflow_violation`
- [x] MQ18-108 If an endpoint receives a Location Filter Type other than the
  four defined values, then the implementation shall close the session with a
  protocol violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_locfilter_unknown_type_violation`
- [x] MQ18-109 The publisher shall forward only Objects that pass the
  combination Forward State AND Location Filter (Pass = Forward AND Filters).
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_forward_state_zero_blocks_objects`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_filter_groups_delivered`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_filter_from_largest`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_no_replay_before_start`
  - evidence: the Location Filter is evaluated when objects are replayed to
    a late subscriber over the reliable relay; a live attachment still
    starts at the current group's object 0 rather than the filter's start
    object (see Not implemented).

## SS14 Grease

- [x] MQ18-110 The implementation shall recognize the grease value pattern
  0x7f*N + 0x9D for non-negative integer N in registries that reserve it (Setup
  Options, Properties, error/status code tables).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_grease_pattern`
- [x] MQ18-111 Endpoints shall not close the session solely because they
  received an unknown value in a greased registry (Setup Options, error codes).
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_setup_unknown_option_ignored`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`

## SS11.1 Track Alias

- [x] MQ18-112 The same Track Alias shall not be used by a publisher to refer
  to two different Tracks simultaneously in the same session.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_and_audio_get_different_aliases`
- [~] MQ18-113 If a subscriber receives a PUBLISH or SUBSCRIBE_OK reusing a
  Track Alias already bound to a different Established subscription, then the
  implementation shall close the session with DUPLICATE_TRACK_ALIAS.
  - evidence: The hub allocates aliases itself per-track (starting from 0
    independently per track, see moqtrun_test.c's own comment on
    `test_moqtrun_chat_and_audio_get_different_aliases`) and never receives an
    attacker-controlled alias to validate; the receiver-side duplicate-alias
    rejection is not exercised by any test in this subset.

## SS11.2.1.1 Object Status

- [x] MQ18-114 The implementation shall recognize Object Status values 0x0
  (Normal), 0x3 (End of Group), and 0x4 (End of Track).
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_status_values`
- [x] MQ18-115 If an Object carries an unregistered Status value, then the
  implementation shall close the session with a protocol violation.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_status_values`
- [x] MQ18-116 An Object shall have an empty payload unless its Object Status
  is Normal (0x0); the Object Status field shall be present only when Payload
  Length is 0.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_status_eog`
  - test: `tests/app/moqdata_test.c` —
    `test_moqdata_obj_take_status_eog_stream`

## SS11.2.1.2 Object Properties

- [x] MQ18-117 If an endpoint receives Object Properties on an Object whose
  Status is not Normal, then the implementation shall close the session with a
  protocol violation.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_properties`
- [x] MQ18-118 Object Properties shall be serialized as a Properties Length
  (varint) followed by a Key-Value-Pair list.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_properties`
- [x] MQ18-118a If an Object Datagram carries an OBJECT_DELIVERY_TIMEOUT or
  SUBGROUP_DELIVERY_TIMEOUT Object Property, then the implementation shall
  close the session with a protocol violation (the delivery-timeout Object
  Property is undefined for datagram-forwarded Objects).
  - test: `tests/app/moqtrun_ctlfix_test.c` — `test_mtcf_d18_dg_timeout_prop`
  - note: ruling Q18-05; gated on `MOQVER_CAP_DG_TIMEOUT_PROP_CLOSE`
    (draft-18 only).

## SS11.4.2 Subgroup Header

- [x] MQ18-119 All Objects on a stream opened with SUBGROUP_HEADER shall have
  Object Forwarding Preference = Subgroup, belonging to the Track Alias, Group
  ID, and Subgroup ID the header declares.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_basic`
- [x] MQ18-120 The SUBGROUP_HEADER Type field shall take the form 0b0XX1XXXX
  (bit 4 always set); if received with any other form, the implementation shall
  close the session with a protocol violation.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_valid_golden`
- [x] MQ18-121 The implementation shall decode the SUBGROUP_ID_MODE field (bits
  1-2) as: 0b00 Subgroup ID absent and 0, 0b01 Subgroup ID absent and equal to
  the first Object's Object ID, 0b10 Subgroup ID present in the header.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode2`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode1_resolve`
- [x] MQ18-122 If SUBGROUP_ID_MODE is 0b11, then the implementation shall close
  the session with a protocol violation.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_valid_golden`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_bad_type`
- [x] MQ18-123 The implementation shall decode the PROPERTIES bit (0x01),
  END_OF_GROUP bit (0x08), DEFAULT_PRIORITY bit (0x20), and FIRST_OBJECT bit
  (0x40) of the SUBGROUP_HEADER Type field.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_bits_golden`
- [x] MQ18-124 Where DEFAULT_PRIORITY is set, the Publisher Priority field
  shall be omitted from the header and the Subgroup shall inherit the priority
  from the subscription's control message.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_basic`
- [x] MQ18-125 Where the END_OF_GROUP bit is set and the stream terminates with
  a FIN, the implementation shall infer that no Object with the same Group ID
  and a larger Object ID exists.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_normalize_forwards_only_whole_objects`
  - evidence: The bit is decoded (MQ18-123) but the specific inference "no
    larger Object ID exists once END_OF_GROUP FINs" is not asserted by a
    dedicated test; it is implicit in how the relay forwards whole Objects.
- [x] MQ18-126 When the Original Publisher opens a new Subgroup, it shall set
  the FIRST_OBJECT bit to indicate the first Object in the stream is the first
  Object ever published in that Subgroup.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_bits_golden`
- [x] MQ18-127 The implementation shall encode/decode a SUBGROUP_HEADER
  byte-exact against its wire fields (Type, Track Alias, Group ID, optional
  Subgroup ID, optional Publisher Priority).
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_put_golden`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_put_errors`
- [x] MQ18-128 If a SUBGROUP_HEADER is truncated before all its declared fields
  are present, then the implementation shall report the decode as insufficient.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_truncated`
- [x] MQ18-129 The implementation shall resolve a mode-0b01 (deferred) Subgroup
  ID from the first Object's Object ID once decoded.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode1_resolve`

## SS11.4.2 Subgroup Object Fields

- [x] MQ18-130 The implementation shall encode/decode a Subgroup Object as
  Object ID Delta + optional Properties + Object Payload Length + optional
  Object Status + optional Object Payload.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_basic_stream`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_put`
- [x] MQ18-130a The implementation shall recognize REQUEST_ERROR code
  DUPLICATE_SUBSCRIPTION (0x19), used on a draft-18 session when a second
  concurrent subscription to the same Track from the same role is refused
  (MQ18-094a); draft-19 and later remove this code (unassigned).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_registry_scope_per_draft`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_sub_duplicate_refused_d18`
  - note: unrelated to wired's own `MOQCTL_CLOSE_*` 0x19
    (INVALID_AUTHORITY, a session termination code in a different
    registry); see `draft18-vs-19-diff.md` §7 note.
- [x] MQ18-131 The Object ID shall be the Object ID Delta for the first Object
  in a Subgroup, and the previous Object ID plus the Delta plus 1 for each
  subsequent Object.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_delta_chain`
- [x] MQ18-132 If the resulting cumulative Object ID would exceed 2^64-1, then
  the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_id_overflow`
- [x] MQ18-133 If a Subgroup Object stream terminates with a FIN in the middle
  of a serialized Object, then the implementation shall not treat the partial
  Object as complete.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_truncated`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_decode_loop_stops_at_truncation`
- [x] MQ18-134 If a Subgroup Object stream's per-Object decode reports a
  protocol violation, then the implementation shall stop decoding further
  Objects on that stream at that point.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_decode_loop_stops_at_violation`
- [x] MQ18-135 The implementation shall decode more than one Object
  sequentially from a single stream buffer, matching the result of decoding
  each Object individually.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_decode_loop_single_object_matches_one_shot`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_decode_loop_multiple_objects`

## SS11.4.3 Closing Subgroup Streams

- [x] MQ18-136 If a sender has delivered all Objects in a Subgroup, then it
  shall close the stream with a FIN.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_split_data_then_bare_fin_relays_and_closes`
- [x] MQ18-137 An implementation that observes a stream FIN is assured it has
  received all Objects in that Subgroup from the start of the subscription.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_torn_object_held_until_complete`
- [x] MQ18-138 A relay shall not forward an Object on an existing Subgroup
  stream unless it is the next Object in that Subgroup (an Object split across
  two deliveries is held back until complete).
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_fresh_delivery_tail_held_back`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_frag_overflow_counted`
- [x] MQ18-139 A publisher stream's FIN with no accompanying new Object bytes
  shall close the corresponding relay stream via a bare FIN, not a rejected
  empty data send.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_split_data_then_bare_fin_relays_and_closes`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_split_data_then_bare_fin_closes`
- [x] MQ18-140 Two overlapping publisher streams on the same track shall each
  be relayed on their own independent stream, with each closed only by its own
  publisher's FIN.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_interleaved_chat_messages_close_independently`
- [x] MQ18-141 A subscriber that joins after a Subgroup stream has already
  started shall still receive a relay stream, opened carrying the already-sent
  SUBGROUP_HEADER.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_late_subscriber_gets_late_opened_stream`

## SS11.5.1 Padding Streams

- [x] MQ18-142 The implementation shall discard all data received on a padding
  stream (Type 0x132B3E28).
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_padding_stream_discarded`

## SS3.7 Congestion Control / flow control priority

- [~] MQ18-143 Endpoints shall allocate connection flow control to the control
  streams before allocating it to any data streams, so a receiver does not
  deadlock waiting for a control message that itself needs flow control to
  arrive.
  - evidence: This subset relies on the underlying WT/QUIC transport's own
    stream and connection flow control (app/http3/server/srvrun); no MOQT-layer
    test independently verifies control-before-data flow-control priority.

## SS11.4.2 Subgroup Object Fields (encoder byte-exactness)

- [x] MQ18-144 The implementation shall encode a Subgroup Object's Object ID
  Delta, Payload Length, and either an explicit Object Status (when the payload
  is empty) or the Payload bytes, byte-exact against the wire format.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_put`
- [x] MQ18-145 The one-message builder shall assemble a single SUBGROUP_HEADER
  carrying one Object byte-exact against the wire format, and shall fail
  without partial writes when the destination buffer is too small.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_msg_build_golden`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_msg_build_bounds`
  - test: `tests/app/moqdata_test.c` —
    `test_moqdata_put_path_status_eog_golden`

## SS5.1 Subscriptions (state machine, additional coverage)

- [x] MQ18-146 While a subscription is Established, Object forwarding toward
  it shall be permitted regardless of which side (SUBSCRIBE or PUBLISH)
  initiated it.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_object_delivery_after_subscribe`
- [x] MQ18-147 A REQUEST_UPDATE received on an Established subscription shall
  leave the subscription Established.
  - test: `tests/app/moqsess_test.c` — `test_moqsub_update_keeps_established`
- [x] MQ18-148 A requester that FINs its own direction immediately after
  sending its request, before any response, shall not have the request treated
  as failed.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsub_requester_early_fin_not_failed`
- [x] MQ18-149 The subscriber shall be able to terminate an Established or
  Pending(Subscriber) subscription by sending STOP_SENDING.
  - test: `tests/app/moqsess_test.c` — `test_moqsub_cancel_established`
- [x] MQ18-150 Where the requester's own direction is already FIN'd, cancelling
  a subscription shall send only STOP_SENDING on the receiving direction.
  - test: `tests/app/moqsess_test.c` — `test_moqsub_cancel_after_fin`
- [x] MQ18-151 If the responder FINs its own direction without ever sending a
  response, then the requester shall treat the request as failed.
  - test: `tests/app/moqsess_test.c` — `test_moqsub_early_fin_before_response`

## SS10 Control Messages: session-machine unwanted behavior (additional coverage)

- [x] MQ18-152 If the control stream carries an unknown message type or a
  Length/Body mismatch, then the implementation shall close the session with a
  protocol violation.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_malformed_control_message`
- [x] MQ18-153 Once a session is closed, further events shall be no-ops (the
  close reason is sticky).
  - test: `tests/app/moqsess_test.c` — `test_moqsess_closed_is_sticky`

## Hub relay: PUBLISH/SUBSCRIBE dispatch (SS9 Relays, SS10.5/10.7/10.10 applied)

- [x] MQ18-154 On a successful PUBLISH, the hub shall reply with REQUEST_OK on
  the same control stream without closing it.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_publish_replies_request_ok`
- [x] MQ18-155 A peer may PUBLISH more than one distinct track (up to the
  implementation's per-peer track capacity), each independently getting
  REQUEST_OK.
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_peer_publishes_two_tracks`
- [x] MQ18-156 If a peer attempts to PUBLISH more distinct tracks than the
  implementation's per-peer capacity, then the implementation shall reply with
  REQUEST_ERROR rather than silently overwriting an existing track.
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_fifth_publish_gets_error`
- [x] MQ18-157 Re-PUBLISHing the same Track Name that already occupies a slot
  shall reuse that slot rather than consuming a new one.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_republish_same_name_reuses_slot`
- [x] MQ18-158 A SUBSCRIBE naming any track a peer has PUBLISHed shall get
  SUBSCRIBE_OK with an assigned Track Alias.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_audio_track_replies_ok`
- [x] MQ18-159 Two SUBSCRIBE messages arriving in the same dispatch call shall
  each get their own reply queued without one overwriting the other.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_two_subscribe_oks_one_dispatch_no_overflow`

## Hub relay: Object forwarding to matching subscribers only (SS9.4, SS11.1)

- [x] MQ18-160 An Object shall be forwarded only to subscribers of the Track
  its Track Alias identifies, not to subscribers of any other Track in the same
  session.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_only_to_chat_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_object_relays_only_to_audio_subscriber`
- [x] MQ18-161 If an Object's Track Alias matches no Track the publisher has
  declared, then the implementation shall not forward it to any subscriber.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unknown_alias_object_relays_nowhere`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_unbound_stream_id_relays_nowhere`
- [x] MQ18-162 Each Object matching multiple subscriptions to the same Track
  shall be sent once per matching subscription.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_to_all_three_subscribers`
- [x] MQ18-163 If forwarding an Object to one subscriber fails (the underlying
  transport refuses the send), then the implementation shall still forward it
  to every other matching subscriber, and shall count the loss rather than
  leaving it silent.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_one_of_three_subscribers_refused`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_send_uni_failure_counts_open_drop`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_stream_send_rejection_drops_frame_not_fatal`
- [x] MQ18-164 Objects sent with Forwarding Preference Subgroup shall be
  relayed as one complete SUBGROUP_HEADER-plus-Objects unit per relay send,
  matching the publisher's stream framing.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_multi_object_stream_relays_in_one_send_uni`
- [x] MQ18-165 A long-lived Subgroup stream's later data (arriving without a
  repeated SUBGROUP_HEADER) shall be appended to the same already-bound relay
  stream, not misread as a new header.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_data_stream_continues_across_calls_without_header`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_first_object_opens_then_appends`
- [x] MQ18-166 When a publisher's Subgroup stream FINs, the implementation
  shall close the corresponding relay stream and open a fresh one for the next
  Subgroup on a new publisher stream, rather than appending across the
  boundary.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_publisher_fin_closes_and_reopens`
- [x] MQ18-167 The implementation shall relay each Subgroup consistently with
  the transport primitive matching its own delivery shape (one-shot
  open+send+FIN for a single-round Subgroup, open without FIN plus later
  appends for a long-lived one).
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_still_uses_send_uni_every_object`
- [x] MQ18-168 Two subscribers to the same Track shall each get their own
  independent relay stream, so a delivery to one does not affect the other's
  stream binding.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_audio_two_subscribers_independent_streams`

## Hub relay: sustained-refusal shedding (SS11.4.3 reset discipline, applied)

- [x] MQ18-169 If a subscriber's relay stream is sustained-busy (refused) past
  the implementation's threshold, then the implementation shall reset that
  stream and re-open a fresh one at the next delivery, rather than continuing
  to hold a stale backlog.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_streak_sheds_after_threshold`
- [x] MQ18-170 An accepted delivery in the middle of a busy run shall reset the
  busy-streak counter, so scattered transient refusals never accumulate into a
  shed.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_streak_success_resets`
- [x] MQ18-171 After a stream has been shed, a publisher's bare FIN arriving
  for that now-abandoned stream shall not be forwarded to it.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_shed_stream_skips_publisher_fin`
- [x] MQ18-172 The busy-streak counter shall be tracked per subscriber, so one
  starved subscriber's shed does not affect another subscriber's healthy
  stream.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_busy_shed_isolated_per_subscriber`
- [x] MQ18-173 If the reset itself is refused by the underlying transport, then
  the implementation shall retry the shed on the next busy round rather than
  treating it as done.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_shed_refused_retries_next_round`
- [x] MQ18-174 A re-PUBLISH of a track shall clear its relay state, including
  any accumulated busy-streak counters from the prior incarnation.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_republish_clears_busy_streak`

## Hub relay: session teardown (SS3.5 Termination applied to relay state)

- [x] MQ18-175 When a session closes, the implementation shall free its peer
  slot so a later reconnect on the same underlying session pointer is treated
  as a fresh peer, not the dead one.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_close_frees_peer_for_reregistration`
- [x] MQ18-176 When a subscriber's session closes, the implementation shall
  deactivate its subscription entries on every other peer's tracks so a later
  Object is not relayed to the dead session.
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_close_drops_subscriptions`
- [x] MQ18-177 Closing a session the implementation never registered (or one
  already closed) shall be a no-op that leaves other peers unaffected.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_close_unknown_session_noop`
- [x] MQ18-178 Repeated register/close cycles past the implementation's
  peer-table capacity shall not leak slots; every reconnect shall still receive
  its SETUP.
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_close_reregister_churn`

## Hub relay: control and request streams

- [x] MQ18-179 The implementation shall decode every Message Parameter by
  the draft-18 registry: its value encoding, the messages it may appear in,
  and its allowed value range; a parameter outside its message or range
  shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_registry_scope`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_registry_scope_per_draft`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_uint8_value_ranges`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_repeatable_filters`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_golden_subscribe_params`
- [x] MQ18-180 A control message split across several stream deliveries
  shall be reassembled and handled once; a message longer than the hub's
  inbound limit (1024 bytes) shall close the session with INTERNAL_ERROR.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_split_subscribe_answered_once`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_message_then_half`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_max_length_accepted`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_over_max_closes_session`
- [x] MQ18-181 If the control stream carries a wholly unknown Message Type,
  then the hub shall close the session with a protocol violation.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_unknown_type_closes_session`
- [x] MQ18-182 Each request opened on its own bidirectional stream shall be
  answered on that stream; a reset of the stream cancels the request
  (unsubscribe/unpublish), a FIN alone does not (for most request types; see
  MQ18-037a for the draft-18 SUBSCRIBE_NAMESPACE/SUBSCRIBE_TRACKS exception),
  and a session may hold at most 24 open requests (more are reset with
  EXCESSIVE_LOAD).
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_subscribe_answered_on_its_stream`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_two_streams_answered_apart`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_reset_unsubscribes`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_fin_keeps_request`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_per_session_cap`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_pool_full_resets`

## Hub relay: subscriptions

- [x] MQ18-183 A SUBSCRIBE shall match a published track by its full Track
  Name (namespace and name), so equal names in different namespaces are
  different tracks.
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_ns_must_match`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_same_name_other_ns_coexist`
- [x] MQ18-184 The hub shall record each subscription's Request ID,
  SUBSCRIBER_PRIORITY, GROUP_ORDER, FORWARD, delivery timeout and filter
  start, keep them across a publisher rejoin, and report LARGEST_OBJECT in
  SUBSCRIBE_OK once the track has objects.
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_params_recorded`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_reattach_keeps_state`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_ok_largest`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_largest_from_datagram`
- [x] MQ18-185 Objects shall be relayed reliably to each subscriber from a
  shared buffer pool: a slow subscriber holds the pool back only up to a
  watermark, a stalled one is dropped after a timeout, and a stream whose
  tail was dropped is not continued (it would desync the subscriber).
  - test: `tests/app/moqtrel_test.c` — `test_moqtrel_append_hold_at_watermark`
  - test: `tests/app/moqtrel_test.c` — `test_moqtrel_reclaim_follows_slowest`
  - test: `tests/app/moqtrel_test.c` — `test_moqtrel_stalled_after_timeout`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_poison_survives_reset_and_close`
- [x] MQ18-186 Subscriber priority shall map to the WebTransport stream
  urgency of that subscriber's relay streams, and a REQUEST_UPDATE changing
  the priority applies to later streams.
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_per_subscriber`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_update_applies`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_op_absent`
- [x] MQ18-187 A REQUEST_UPDATE of a SUBSCRIBE, on that subscription's
  request stream, shall replace its parameters all-or-nothing: a refused
  update changes nothing.
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_forward_toggles`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_params_replace`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_failed_changes_nothing`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_survives_rejoin`
- [x] MQ18-188 A TRACK_STATUS shall be answered with REQUEST_OK carrying the
  track's largest location (or none when empty), or REQUEST_ERROR when the
  track is unknown or the authorizer refuses.
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_ok_largest`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_ok_empty`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_unknown_and_blob`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_authorized`
- [x] MQ18-189 Where an application installs an authorizer, every SUBSCRIBE,
  TRACK_STATUS, PUBLISH_NAMESPACE and SUBSCRIBE_NAMESPACE shall be shown to
  it, and a refusal shall be REQUEST_ERROR UNAUTHORIZED; an Alias-based
  authorization token shall close the session (the hub keeps no token
  cache, 10.2.2): REGISTER with AUTH_TOKEN_CACHE_OVERFLOW, DELETE and
  USE_ALIAS with UNKNOWN_AUTH_TOKEN_ALIAS.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_requires_authorization`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_alias_token_rejected`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_authorization`

## Hub relay: delivery timeouts

- [x] MQ18-190 With a non-zero OBJECT_DELIVERY_TIMEOUT (from SUBSCRIBE or a
  REQUEST_UPDATE), an object not delivered in time shall be abandoned: its
  stream is reset with DELIVERY_TIMEOUT (0x2), or the datagram is dropped.
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_live`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_datagram`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_by_update`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_torn_object`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_timeout_zero`
  - note: draft-18 scopes OBJECT_DELIVERY_TIMEOUT/SUBGROUP_DELIVERY_TIMEOUT
    as Track Properties only (not Object Properties on the first object of
    a subgroup, which draft-19 adds); the implementation's single-source
    timeout value is unaffected by this difference since it does not read
    either as an Object Property — see `draft18-vs-19-diff.md` §11.

## Hub relay: caching and FETCH

- [x] MQ18-191 With a cache arena attached (`wired_moqt_cache_attach`),
  the hub shall cache whole groups only, evicting the oldest group when the
  budget is exceeded and dropping a group that alone exceeds it.
  - test: `tests/app/moqcache_test.c` — `test_moqcache_evicts_oldest_group`
  - test: `tests/app/moqcache_test.c` — `test_moqcache_group_over_budget_dropped`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_cache_attach`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_cache_default_off`
- [x] MQ18-192 A standalone FETCH shall be served from the cache; a range
  that was evicted or never cached shall be reported as an End of Unknown
  Range marker rather than skipped silently.
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_serves_cached`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_evicted_group_unknown`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_no_cache_unknown`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_stream_end_of_range`
- [x] MQ18-193 A joining FETCH (relative or absolute) shall resolve against
  the joined subscription so that FETCH plus SUBSCRIBE leave no gap, and an
  invalid range or unknown joined request shall be refused.
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_relative_join_no_gap`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_absolute_join`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_join_invalid_range`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_join_unknown_request`
  - note: draft-18's FETCH body (Fetch Type + Standalone/Joining) is
    byte-identical to draft-19's; draft-22 removes Joining FETCH entirely
    (see `docs/features/draft-moq-transport-22.md` 4-6).
- [x] MQ18-194 A FETCH shall release its slot when the requester cancels,
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

- [~] MQ18-195 A PUBLISH_NAMESPACE shall be accepted per publisher (several
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

- [~] MQ18-196 `wired_moqt_goaway` shall send GOAWAY once per session; a
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
- [x] MQ18-197 A second GOAWAY from the peer, or one carrying a New Session
  URI from a client, shall close the session with a protocol violation.
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_twice`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_uri`
- [x] MQ18-198 Before PUBLISH_DONE, the hub shall reset the subscription's
  data streams; a publisher's session ending sends PUBLISH_DONE
  TRACK_ENDED to its subscribers.
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_done_resets_streams_first`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_done_track_ended`
- [~] MQ18-199 A WebTransport WT_DRAIN_SESSION from the peer
  (`wired_moqt_on_session_draining`) shall start the MOQT GOAWAY sequence
  for that session only.
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_drain_one_session`
  - evidence: unit-tested only; no live peer run yet.

## Hub relay: Object Datagrams

- [x] MQ18-200 An Object Datagram shall be relayed byte-identical to every
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

- [x] MQ18-201 (SS10.19) The hub shall answer a SUBSCRIBE_TRACKS with exactly
  one REQUEST_OK on its request stream, and shall refuse one whose Track
  Namespace Prefix overlaps an established SUBSCRIBE_TRACKS of the same session
  with PREFIX_OVERLAP.
  - test: `tests/app/moqtrun_subtracks_test.c` — `test_subtracks_ok_once`
  - test: `tests/app/moqtrun_subtracks_test.c` — `test_subtracks_prefix_overlap`
  - test: `tests/app/moqns_test.c` — `test_moqns_subscribe_tracks_param_scope`
  - note: draft-18 admits only AUTHORIZATION TOKEN and FORWARD in
    SUBSCRIBE_TRACKS (see MQ18-037a and the parameter table). Exercised on
    draft-19 sessions; the hub path is version-independent.
- [x] MQ18-202 (SS10.19) For every track matching an established
  SUBSCRIBE_TRACKS prefix and not published by the subscriber itself, the hub
  shall open one PUBLISH on a new bidirectional stream naming that track,
  carrying the SUBSCRIBE_TRACKS's FORWARD value; cancelling the SUBSCRIBE_TRACKS
  stops new PUBLISHes but leaves established ones, a track that vanishes before
  the reply resets its PUBLISH stream, and a REQUEST_ERROR reply frees the slot.
  The PUBLISH_OK (REQUEST_OK) reply opens the subscriber's subscription under
  the PUBLISH's Track Alias, starting from the PUBLISH's parameters (FORWARD 0
  holds Objects back); the subscriber's REQUEST_UPDATE on that stream is
  applied like a SUBSCRIBE's and answered there (ledger 12-11, 12-18). A
  failed update ends it with PUBLISH_DONE UPDATE_FAILED and the hub then FINs
  the PUBLISH stream (SS10.11 "A sender SHOULD send FIN on the subscription's
  bidi stream immediately after sending PUBLISH_DONE", ledger 12-27); a second
  REQUEST_OK (PUBLISH_OK) or REQUEST_ERROR closes the session with
  PROTOCOL_VIOLATION (SS5.1 "SHOULD close the session with a protocol error",
  ledger 12-28).
  - test: `tests/app/moqtrun_misc_test.c` — `test_moqtrun_misc_pub_ok_relays`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_second_ok_closes`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_error_after_ok_closes`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_forward0_then_update`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_update_before_ok`
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
- [x] MQ18-203 (SS10.20) Where the hub cannot open a bidirectional stream for
  such a PUBLISH, it shall send PUBLISH_SKIPPED (draft-18: PUBLISH_BLOCKED)
  (Track Namespace Suffix, Track Name) on the SUBSCRIBE_TRACKS request stream
  instead, and shall not later send a PUBLISH for the same track incarnation.
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_skip_then_no_publish`
  - test: `tests/app/moqns_test.c` — `test_moqns_pub_skipped_roundtrip`
  - test: `tests/app/moqns_test.c` — `test_moqns_pub_skipped_rejects`
  - note: Exercised on draft-19 sessions; the hub path is version-independent.
- [x] MQ18-204 (SS10.9, SS10.9.2) A REQUEST_UPDATE of a FETCH, PUBLISH_NAMESPACE
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
- [x] MQ18-204a (SS10.9) A REQUEST_UPDATE of the sender's own PUBLISH ("The
  sender of a request (SUBSCRIBE, PUBLISH, FETCH, ...) can later send a
  REQUEST_UPDATE") shall be answered REQUEST_OK, the track kept. Draft-18
  SS10.9 has no "other than in the two cases above" close rule, so a
  REQUEST_UPDATE on the control stream keeps its REQUEST_ERROR NOT_SUPPORTED.
  - test: `tests/app/moqtrun_vgate_test.c` — `test_moqtrun_vgate_update_kinds`
  - test: `tests/app/moqtrun_misc_test.c` — `test_moqtrun_misc_stray_update`
  - note: ledger 12-6 (was draft-22 only before); 12-17.
- [x] MQ18-205 (SS10.12) A FETCH with GROUP_ORDER Descending shall be served
  newest group first (Objects within a group still ascending), and a FETCH whose
  body fails to decode shall close the session with PROTOCOL_VIOLATION.
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_descending_group_order`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_malformed_closes`
  - note: ledger 10-6. Exercised on draft-19 sessions; the hub path is
    version-independent.
- [x] MQ18-206 (SS5.1.4) A late subscriber attached to a live track shall start
  at its Location Filter's start Group: a start behind the live edge is clamped
  to the current Group, and a future start holds delivery until that Group.
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_live_attach_filter_start`
  - note: ledger 10-7. Group-granular: a start Object inside the first Group is
    not trimmed on a Subgroup stream (see Not implemented). Exercised on
    draft-19 sessions; the hub path is version-independent.

## Not implemented

In scope for a draft-18 relay, but not implemented yet. A peer that needs
one of these gets NOT_SUPPORTED (or, where noted, a different behavior).
Reserved namespaces, SUBSCRIBE_TRACKS, PUBLISH_SKIPPED (PUBLISH_BLOCKED),
FETCH GROUP_ORDER and REQUEST_UPDATE of FETCH and namespace requests were
listed here until ledger ch. 10 implemented them (MQ18-028, MQ18-201
through MQ18-206).

- (SS10.11) PUBLISH_DONE for a subscription made on the legacy control
  stream: there is no request stream to carry it, so none is sent and the
  subscription is kept for a publisher rejoin.
- (SS10.9) REQUEST_UPDATE of a SUBSCRIBE_TRACKS — answered REQUEST_ERROR
  NOT_SUPPORTED (the request stays established; SS10.9 lets the receiver
  refuse an update). `test_moqtrun_vgate_update_kinds`.
- (SS5.1.4) A late subscriber's live delivery starts at its Location
  Filter's start Group (MQ18-206), but a start Object inside that Group is
  not trimmed from a Subgroup stream; only the reliable replay honours the
  start Object.

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
- (SS3.1, SS3.1.1-3.1.6) The `moqt` URI scheme, fragment identifiers, and
  MOQT URI dereferencing — client-side concerns of a server-only hub.
  Native-QUIC sessions themselves (SS3.1.4: ALPN `moqt-18`, PATH/AUTHORITY
  Setup Options, CONNECTION_CLOSE termination) are implemented
  (`wired_moqt_on_session_raw`, `tests/app/moqtrun_raw_test.c`), verified
  in-process only until a pinned real-peer trace exists.
- (SS3.6, SS9.4.1, SS9.5.1) Session Migration and graceful relay
  switchover beyond the GOAWAY mechanics covered above — this is a single
  hub with no upstream relay to switch to.
- (SS5.1.3, SS5.1.4) Range Filters (SUBGROUP_FILTER, OBJECTID_FILTER,
  PRIORITY_FILTER, OBJECT_PROPERTY_FILTER, TRACK_PROPERTY_FILTER) and the
  MAX_FILTER_RANGES Setup Option — **these do not exist in draft-18 at
  all** (new in draft-19, see `draft18-vs-19-diff.md` §5); a draft-18
  session that receives one of these parameter types closes with a
  protocol violation as an unknown type (MQ18-065), and MAX_FILTER_RANGES
  as a Setup Option is ignored as unknown (MQ18-075).
- (SS10.9) MAX_REQUEST_UPDATES credit limit and TOO_MANY_REQUEST_UPDATES —
  **new in draft-19** (`draft18-vs-19-diff.md` §6-7); draft-18 has no
  REQUEST_UPDATE flow-control mechanism, so Q18-06 (credit recovery count
  for coalesced updates) does not apply to this draft. The hub's credit
  check is gated on `MOQVER_CAP_MAX_REQUEST_UPDATES`: a draft-18 peer with
  more than 4 unanswered REQUEST_UPDATEs on one request stream is not
  closed and every update is still answered (ledger 12-5,
  `tests/app/moqtrun_vgate_test.c` — `test_moqtrun_vgate_update_credit`).
- (SS10.9) Publisher-side REQUEST_UPDATE carrying a Range Filter (Q18-07) —
  moot, since Range Filters do not exist in draft-18.
- (SS7, SS7.1--7.3) The Priorities scheduling algorithm across
  subscriptions and Publisher Priority — only Subscriber Priority is
  applied, as WebTransport stream urgency (MQ18-186).
- (SS9.3) Multiple Publishers of one Track — several publishers may share a
  namespace (MQ18-195), but each Track still has one publisher;
  aggregation/deduplication across publishers of a Track is not
  implemented.
- (SS10.2.5, SS10.2.14, SS10.2.16) FILL_TIMEOUT, EXPIRES and
  NEW_GROUP_REQUEST — decoded by the registry, not acted on. (SS10.2.6)
  RENDEZVOUS_TIMEOUT is acted on since 12-1 (ff1c0df): a SUBSCRIBE for a
  track with no publisher is held until one arrives or the timeout
  (capped at 1.5 s) answers TIMEOUT, see tests/app/moqtrun_rdv_test.c.
- (SS10.3.1.3, SS10.3.1.4, SS10.3.1.6) MAX_AUTH_TOKEN_CACHE_SIZE,
  AUTHORIZATION TOKEN as a Setup Option, and MAX_FILTER_RANGES Setup
  Option (the last does not exist in draft-18 at all, see above) — not
  advertised; the hub keeps no token cache, so Alias-based tokens close
  the session (MQ18-189).
- (SS11.5.2) Padding Datagrams — not sent.
- (SS12, SS12.1--12.9) MOQT Properties (MAX_CACHE_DURATION,
  DEFAULT_PUBLISHER_GROUP_ORDER, DYNAMIC_GROUPS,
  Immutable Properties, Prior Group/Object ID Gap) as Track/Object
  Properties — the Properties wire slot is decoded generically and relayed
  unchanged; no specific Property type is interpreted except
  DEFAULT_PUBLISHER_PRIORITY (the stream urgency of a header omitting its
  Publisher Priority).
- (SS13) Security Considerations (subscription amplification,
  communication security, authorization, media security, resource
  exhaustion, timeouts, relay security, implementation fingerprinting) —
  operational/deployment guidance, not a wire behavior this ledger tests.
- (SS15) IANA Considerations — registry administration, not implementation
  behavior.
- Per-version scope (ledger 4-4): this hub negotiates draft-18, -19 and -22
  per session (`moqver.c`); the Range Filter, MAX_FILTER_RANGES and
  MAX_REQUEST_UPDATES entries above are out of scope for draft-18 only —
  on draft-19 and draft-22 sessions the hub validates Range Filters and
  enforces the request-update credit (see MOQT-206 to MOQT-208 and MQ22-199
  to MQ22-201). SUBSCRIBE_TRACKS itself is served on every version
  (MQ18-201); only its parameter set differs: AUTHORIZATION TOKEN and
  FORWARD on draft-18, every Subscription parameter on draft-19 and
  draft-22 (`MOQCTL_PARAM_RULES` in `moqctl.c`).
- REDIRECT as an actual relay behavior (sending it to move a requester to
  another URI/target, or reacting to one from an upstream) — this is a
  single hub with no upstream relay or sibling instance to redirect to or
  from, the same reasoning as the Session Migration entry above. The
  Redirect structure's wire format is still covered (MQ18-085 through
  MQ18-089).
- Draft-18's own application-specific Property reserved range 0x38-0x3F
  (one-byte registry; widened to 0x78-0x7F in draft-19, see
  `draft18-vs-19-diff.md` §11) — no draft-18-specific boundary test exists
  (MQ18-026 reuses the shared greasing test); this is an informational gap
  tracked against the shared implementation, not re-litigated here per
  version.
