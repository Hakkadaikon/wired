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

**Coverage: 213/248 tested, 29 indirect, 6 untested.**

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
- [x] MQ18-014 (§1.4.3) If a Key-Value-Pair's Value does not match the
  serialization defined by a Type the implementation understands, then the
  implementation shall close the session with KEY_VALUE_FORMATTING_ERROR,
  distinct from a protocol violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_auth_token_malformed_kvfmt`
- [x] MQ18-015 The implementation shall not use the minimum encoding length for
  a Key-Value-Pair's Delta Type or even-Type Value as a decode requirement
  (non-minimal encodings are valid).
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_nonminimal_delta`
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_nonminimal_even_value`
- [x] MQ18-016 (§1.4.3) If a Key-Value-Pair is truncated within its own known
  byte bound, then the implementation shall report it as insufficient
  without reading past the bound.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_take_truncated_insufficient`
- [x] MQ18-017 The implementation shall decode a Key-Value-Pair without reading
  past the caller-supplied byte bound, and shall encode a round-trippable
  Key-Value-Pair list preserving Type order.
  - test: `tests/app/moqkvp_test.c` — `test_moqkvp_roundtrip`

## SS1.4.4 Reason Phrase Structure

- [x] MQ18-018 The implementation shall decode a Reason Phrase as a
  variable-length integer Length followed by that many UTF-8 bytes.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_reason_boundary`
- [~] MQ18-019 (§1.4.4) If a Reason Phrase Length exceeds 1024 bytes, then the
  implementation shall close the session with a protocol violation.
  - evidence: the codec reports the violation
    (`test_moqctl_reason_boundary`); the hub closes PROTOCOL_VIOLATION on a request or SETUP
    that fails to decode (`test_moqtrun_fillfix_malformed_subscribe`,
    `test_moqtrun_setup_malformed_closes`), but no hub test sends this
    trigger.
## SS2.4.1 Track Naming

- [x] MQ18-020 The implementation shall decode a Track Namespace as a
  variable-length integer field count followed by that many length-prefixed
  Track Namespace Fields.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ftn_decode_basic`
- [~] MQ18-021 (§2.4.1) If a Track Namespace Field has a Length of 0, then the
  implementation shall close the session with a protocol violation.
  - evidence: the codec reports the violation
    (`test_moqctl_ns_field_len_zero_rejected`); the hub closes PROTOCOL_VIOLATION on a request or SETUP
    that fails to decode (`test_moqtrun_fillfix_malformed_subscribe`,
    `test_moqtrun_setup_malformed_closes`), but no hub test sends this
    trigger.
- [~] MQ18-022 (§2.4.1) If a Track Namespace has more than 32 Track Namespace
  Fields, then the implementation shall close the session with a protocol
  violation.
  - evidence: the codec reports the violation
    (`test_moqctl_ns_fields_32_accept_33_reject`); the hub closes PROTOCOL_VIOLATION on a request or SETUP
    that fails to decode (`test_moqtrun_fillfix_malformed_subscribe`,
    `test_moqtrun_setup_malformed_closes`), but no hub test sends this
    trigger.
- [~] MQ18-023 (§2.4.1) If a Full Track Name (Track Namespace plus Track Name)
  exceeds 4096 bytes, then the implementation shall close the session with a
  protocol violation.
  - evidence: the codec reports the violation
    (`test_moqctl_ftn_4096_accept_4097_reject`); the hub closes PROTOCOL_VIOLATION on a request or SETUP
    that fails to decode (`test_moqtrun_fillfix_malformed_subscribe`,
    `test_moqtrun_setup_malformed_closes`), but no hub test sends this
    trigger.
- [x] MQ18-024 The implementation shall compare Track Namespace Fields and
  Track Names by exact byte comparison.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_ftn_eq_exact_bytes`

## SS2.4.2 Malformed Tracks

- [x] MQ18-025 (§2.4.2) If the hub detects a Malformed Track (of the
  conditions MQ18-207 lists), then it shall cancel its subscription or
  fetches for that Track from that publisher.
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_after_end_of_track`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_malformed_past_end`
  - note: the general receiver-side catalog (Publisher Priority change
    within a Subgroup ID, Object past a Subgroup's final, differing finals,
    Forwarding Preference change) is not checked -- see Out of scope.
- [x] MQ18-207 (§2.4.2, §9.1) If the hub, as a relay, detects a Malformed
  Track -- an Object past the track's END_OF_TRACK or past a Group's
  END_OF_GROUP, or an upstream FETCH Object past FETCH_OK's End Of Track or
  conflicting with a cached Object's payload -- then it shall at once end
  the downstream subscriptions with PUBLISH_DONE MALFORMED_TRACK, reset its
  fetch streams of that track with MALFORMED_TRACK, and not cache the
  triggering Object.
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_after_end_of_track`
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_after_end_of_group`
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_resets_fetch`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_malformed_past_end`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_malformed_conflict`
  - note: the PUBLISH_DONE scenarios run on every draft; the upstream FETCH
    ones on draft-22 sessions (the check is version-independent).

## SS2.5 Properties / SS2.5.1 Mandatory Track Properties

- [~] MQ18-026 (§2.5) The relay shall forward Properties whose types fall in
  the application-specific ranges 0x38-0x3F and 0x3800-0x3FFF unchanged,
  without interpreting them.
  - evidence: no Property type in these ranges is read by the hub
    (`moqtrun_tprop` skips unknown types), Track Properties are
    forwarded as received (MQ18-208) and Object Properties ride the relayed
    Object bytes (`test_moqtrun_object_relay_preserves_bytes`); no test
    sends a property of these ranges.
  - note: draft-18 §15.8 lists 0x78-0x7F as the one-byte application range,
    contradicting §2.5's 0x38-0x3F; draft-19 settles on 0x78-0x7F (see
    `draft18-vs-19-diff.md` SS11).
- [x] MQ18-027 (§2.5.1) If a PUBLISH or an upstream SUBSCRIBE_OK carries a
  Mandatory Track Property (type 0x4000-0x7FFF) the hub does not understand,
  then the hub shall not process or forward that track: it shall refuse the
  PUBLISH with REQUEST_ERROR UNSUPPORTED_EXTENSION, or cancel the upstream
  subscription and send REQUEST_ERROR UNSUPPORTED_EXTENSION to its pending
  downstream subscribers.
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_publish_mandatory_refused`
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_ok_mandatory_refused`
- [~] MQ18-208 (§2.5, §9.6) When relaying a track, the hub shall forward the
  publisher's Track Properties, unknown ones included, unchanged in
  SUBSCRIBE_OK, a later PUBLISH of the track replacing (never merging with)
  the kept set.
  - evidence: `test_moqtrun_sub_include_properties_1_forwards` asserts the
    PUBLISH's properties in a later SUBSCRIBE_OK (its parameterless
    subscriber runs on every draft); replacement is by construction
    (`moqtrun_track_keep_props`), untested.
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_props_long_forwarded`
  - note: a block longer than `WIRED_MOQTRUN_TRACK_PROPS_MAX` (96 bytes)
    refuses the track INTERNAL_ERROR instead of being forwarded empty.
- [x] MQ18-220 (§9.6, §10.14) The hub shall include the track's Track
  Properties in every hub-initiated PUBLISH, TRACK_STATUS REQUEST_OK and
  FETCH_OK it sends for a relayed track.
  - test: `tests/app/moqtrun_subtracks_test.c` — `test_subtracks_publish_carries_props`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_ok_props`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_ok_props`
- [x] MQ18-209 (§2.5.1) If an upstream FETCH_OK carries a Mandatory Track
  Property the hub does not understand, then the hub shall cancel that
  upstream FETCH and answer the downstream FETCH with REQUEST_ERROR
  UNSUPPORTED_EXTENSION if it is still unanswered, or reset its fetch
  stream if data already went out.
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_mandatory`
  - note: run on draft-22 sessions; the check is version-independent.
- [x] MQ18-239 (§12.5, §12.6) If a Track Property DEFAULT_PUBLISHER_GROUP_ORDER
  outside 1-2 or DYNAMIC_GROUPS above 1 is received, then the implementation
  shall close the session with PROTOCOL_VIOLATION.
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_props_bad_values_close`
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_ok_bad_prop_closes`
- [x] MQ18-224 (§12.7) When the hub reads a Property's value (e.g.
  DEFAULT_PUBLISHER_PRIORITY, SUBGROUP_DELIVERY_TIMEOUT), it shall search
  both the mutable properties and the contents of Immutable Properties.
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_props_immutable`

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
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_client_uni_ctl_accepted`
- [x] MQ18-031 (§3.3) A bidirectional request stream shall begin with one of
  the First-type messages (TRACK_STATUS, SUBSCRIBE, PUBLISH, FETCH,
  PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS); if it does not,
  the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_bad_first_message_closes`
- [x] MQ18-032 Where a unidirectional stream containing Objects or a
  bidirectional request stream arrives before both control streams have
  completed SETUP, the implementation shall buffer it rather than deliver it to
  the application.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsess_buffer_before_setup_then_deliver`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_requests_held_until_established`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_object_stream_held_until_established`
- [x] MQ18-033 (§3.3) Where SETUP has not yet completed, the implementation
  may reset a bidirectional request stream instead of buffering it.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_token_unbufferable_request_reset`
- [~] MQ18-034 (§10.3) An endpoint may pipeline further control messages after
  sending its own SETUP without waiting for the peer's SETUP.
  - evidence: the session machine admits the half-open state
    (`test_moqsess_pipeline_before_peer_setup`), and a request that arrives
    before SETUP completes is held, then answered
    (`test_moqtrun_token_requests_held_until_established`); no test sends a
    control message pipelined ahead of the peer's SETUP.
- [x] MQ18-035 If a control stream is closed at the transport layer during the
  session's lifetime, then the implementation shall close the session with a
  protocol violation.
  - test: `tests/app/moqsess_test.c` —
    `test_moqsess_ctrl_stream_transport_close`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_fin_violates`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_ctl_reset_violates`
- [x] MQ18-036 (§3.3) If the same peer opens a second control stream, then the
  implementation shall close the session with a protocol violation.
  - test: `tests/app/moqsess_test.c` — `test_moqsess_second_control_stream`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_second_ctl_stream_violates`
- [x] MQ18-210 (§3.3.2, §10.14) When the hub rejects a request with
  REQUEST_ERROR, it shall FIN its side of the request stream after the
  answer.
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_refusal_fins_and_frees`

## SS6.1 Request Stream Closure (draft-18: FIN is a cancellation)

- [x] MQ18-037a (§6.1) Where a SUBSCRIBE_NAMESPACE request stream's direction
  is closed with a FIN, the implementation shall treat it as a cancellation
  of that request, unlike draft-19 (and later) where FIN is a graceful
  half-close that is not a cancellation.
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_fin_cancels_d18`
  - note: this is a draft-18-specific wire behavior (`MOQVER_CAP_FIN_CANCEL_NS`);
    see `draft18-vs-19-diff.md` SS2 "Request-stream FIN semantics".
- [~] MQ18-211 (§6.1) Where a SUBSCRIBE_TRACKS request stream's direction is
  closed with a FIN, the implementation shall treat it as a cancellation of
  that request.
  - evidence: `moqtrun_req_fin_kind` names SUBSCRIBE_TRACKS beside
    SUBSCRIBE_NAMESPACE under the same `MOQVER_CAP_FIN_CANCEL_NS` gate whose
    SUBSCRIBE_NAMESPACE half `test_moqtrun_ns_fin_cancels_d18` asserts; no
    draft-18 SUBSCRIBE_TRACKS FIN test exists.

## SS3.3.3 Stream Reset Error Codes / SS3.5 Termination (used subset)

- [~] MQ18-037 (§3.5) The implementation shall use the session termination
  error codes of the draft-18 table for the conditions it detects (NO_ERROR,
  INTERNAL_ERROR, PROTOCOL_VIOLATION, INVALID_REQUEST_ID,
  KEY_VALUE_FORMATTING_ERROR, INVALID_PATH, MALFORMED_PATH, GOAWAY_TIMEOUT,
  AUTH_TOKEN_CACHE_OVERFLOW, UNKNOWN_AUTH_TOKEN_ALIAS, INVALID_AUTHORITY,
  MALFORMED_AUTHORITY).
  - evidence: these codes are `#define`s at their call sites
    (moqctl.h/moqsess.h/moqraw.h/moqtrun_types.h) rather than round-tripped
    through a codec; no test enumerates the table, but each code is
    asserted at its own violation site (the unwanted-behavior items of this
    file). DUPLICATE_TRACK_ALIAS is raised at MQ18-113. draft-18 does
    not define session code 0x1B (TOO_MANY_REQUEST_UPDATES, draft-19 only)
    -- see Out of scope.

## SS3.4 Unidirectional Stream Types

- [x] MQ18-038 The implementation shall classify a unidirectional stream's
  leading variable-length integer as one of SETUP (0x2F00), FETCH_HEADER
  (0x05), SUBGROUP_HEADER (0b0XX1XXXX), or PADDING (0x132B3E28).
  - test: `tests/app/moqdata_test.c` — `test_moqdata_classify_golden`
- [x] MQ18-039 (§3.4) If an endpoint receives an unknown unidirectional stream
  type, then the implementation shall close the session with a protocol
  violation.
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_unknown_uni_closes`
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_padding_stream_kept`
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

- [x] MQ18-042 (§10.4) An endpoint that has sent or received GOAWAY may reject
  a new request with an error indicating the endpoint is going away, while
  the session remains open.
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_goaway_late_rejected`
- [x] MQ18-043 (§10.4) An endpoint that has received GOAWAY on the control
  stream shall not initiate new requests of its own, without the session
  closing solely because of the GOAWAY.
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_upsub_skips_goaway`
- [x] MQ18-044 (§3.6, §10.4) If the peer does not close the session within the
  GOAWAY timeout, then the sender shall close the session with
  GOAWAY_TIMEOUT.
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_goaway_timeout_flush_then_close`
- [x] MQ18-045 (§10.4) If a server receives a GOAWAY with a non-zero New
  Session URI Length, then the implementation shall close the session with a
  protocol violation.
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_uri`
- [x] MQ18-046 (§10.4) If the same control stream receives more than one
  GOAWAY, then the implementation shall close the session with a protocol
  violation.
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_peer_goaway_twice`
- [x] MQ18-047 (§10.4) Where a GOAWAY is received on a request stream rather
  than the control stream, the implementation shall accept it without
  closing the session, while a second GOAWAY on the same request stream
  shall still be a protocol violation.
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_second_goaway_closes`
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
  - note: the upstream SUBSCRIBE carries no parameters, so FORWARD is 1 and
    no downstream SUBSCRIBER_PRIORITY, GROUP_ORDER or delivery timeout is
    forwarded (§7.3, §9.2, §10.2.3/10.2.4). An upstream subscription nobody
    downstream wants any more is cancelled
    (`test_moqtrun_upsub_last_cancel_cancels_upstream`).
  - gap: one upstream SUBSCRIBE per Full Track Name, to the first matching
    announcer; §9.5 requires one to each matching publisher (the hub keys
    one track per name, see MQ18-223).
- [x] MQ18-228 (§10.2.6) Where a SUBSCRIBE for a track with no publisher
  carries a non-zero RENDEZVOUS_TIMEOUT, the hub shall hold it, answer
  SUBSCRIBE_OK once a publisher appears, and REQUEST_ERROR TIMEOUT at the
  (capped) deadline; with the parameter absent or 0 it shall answer
  REQUEST_ERROR DOES_NOT_EXIST at once.
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s2_timeout`
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s3_zero_is_dne`
  - test: `tests/app/moqtrun_rdv_test.c` — `test_moqtrun_rdv_s4_resolve`
- [~] MQ18-229 (§10.2.13) Where a downstream SUBSCRIBE or REQUEST_UPDATE
  carries NEW_GROUP_REQUEST, the hub shall include it in its upstream
  SUBSCRIBE, or send it upstream in a REQUEST_UPDATE for an Established
  subscription (value 0 or above the Largest Group, the track supporting
  dynamic Groups, none outstanding).
  - evidence: `moqtrun_ngr_upstream` copies a waiter's value into the
    upstream SUBSCRIBE (`test_moqtrun_upsub_ngr_in_subscribe`);
    `moqtrun_ngr_relay` sends REQUEST_UPDATE on the hub's own upstream
    SUBSCRIBE stream under the three conditions, outstanding until the
    Largest Group moves (`test_moqtrun_upsub_ngr_update`).
  - gap: a track Established by the publisher's own PUBLISH gets no
    REQUEST_UPDATE (its reply would arrive on the PUBLISH stream, which has
    no parser for it).
- [x] MQ18-053 (§9.4, §9.5) A relay may aggregate authorized subscriptions for
  a given Track when multiple subscribers request it, answering a SUBSCRIBE
  for a Track with an Established upstream subscription with SUBSCRIBE_OK and
  forwarding a single upstream Object to every matching downstream
  subscriber.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_object_relays_to_all_three_subscribers`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_two_share_one`
- [ ] MQ18-223 (§9.3) The relay shall handle Objects for the same Track from
  multiple publishers, forwarding them to matching Established
  subscriptions, and should deduplicate them.
  - gap: several publishers may share a namespace (MQ18-195), but each
    Track has one publisher; a second PUBLISH of a held name is refused
    (MQ18-156).

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
  - note: FETCH (0x16), FETCH_OK (0x18), TRACK_STATUS (0xD),
    REQUEST_UPDATE (0x2), PUBLISH_NAMESPACE (0x6), SUBSCRIBE_NAMESPACE
    (0x50), NAMESPACE (0x8) and NAMESPACE_DONE (0xE) are encoded/decoded by
    their own codecs (fetch/, ns/, tstat/), each pinned by golden vectors
    decoded as draft-19; the draft-18 and draft-19 layouts of these
    messages are byte-identical.
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
- [x] MQ18-059 (§10) The implementation shall read a control message's Length
  as a 16-bit field, so no message body exceeds 2^16-1 bytes; a Length of
  65535 waits for the full body rather than failing.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_max_len_field`
  - note: the hub's own inbound cap is lower (1024 bytes, MQ18-180).

## SS10.1 Request ID

- [~] MQ18-060 (§10.1) The server shall generate odd-numbered Request IDs
  starting at 1, incrementing by 2 for each new request.
  - evidence: the hub's upstream SUBSCRIBE and FETCH carry odd, distinct
    Request IDs (`test_moqtrun_upsub_ok_after_upstream`,
    `test_moqtrun_upfetch_two_not_shared`); the start at 1 and the step of 2
    (`request_id_next`) are not pinned by a test. The client's even half is
    client behavior.
- [x] MQ18-061 (§10.1) If an endpoint receives a Request ID whose least
  significant bit is incorrect for the sender, then the implementation shall
  close the session with INVALID_REQUEST_ID.
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_parity_closes`
- [x] MQ18-062 (§10.1) If an endpoint receives a duplicate Request ID, then the
  implementation shall close the session with INVALID_REQUEST_ID.
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_duplicate_closes`
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_out_of_order_ok`
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_rid_window_slides`

## SS10.2 Message Parameters

- [x] MQ18-063 The implementation shall decode Message Parameters as a Type
  Delta (varint, cumulative from the previous Parameter Type) followed by a
  Value whose encoding (uint8, varint, Location, or length-prefixed bytes) is
  fixed per Type.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_delivery_timeout_decode`
- [~] MQ18-064 (§10.2) Parameters shall be serialized in ascending order by
  Type; if the cumulative Parameter Type would exceed 2^64-1, the
  implementation shall close the session with a protocol violation.
  - evidence: the codec reports the violation
    (`test_moqctl_params_type_overflow_violation`); the hub closes PROTOCOL_VIOLATION on a request or SETUP
    that fails to decode (`test_moqtrun_fillfix_malformed_subscribe`,
    `test_moqtrun_setup_malformed_closes`), but no hub test sends this
    trigger.
- [x] MQ18-065 If an endpoint receives an unknown Message Parameter Type, then
  the implementation shall close the session with a protocol violation.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_unknown_type_violation`
  - note: draft-18 does not register Range Filter parameter types
    0x25-0x29 (new in draft-19); a draft-18 session receiving one of these
    closes with a protocol violation under this same rule — see Out of
    scope.
  - test: `tests/app/moqtrun_fillfix_test.c` —
    `test_moqtrun_fillfix_malformed_subscribe`
- [~] MQ18-066 (§10.2) If a sender repeats the same Parameter Type in one
  message, then the implementation shall close the session with a protocol
  violation.
  - evidence: the codec reports the violation
    (`test_moqctl_params_duplicate_type_violation`); the hub closes PROTOCOL_VIOLATION on a request or SETUP
    that fails to decode (`test_moqtrun_fillfix_malformed_subscribe`,
    `test_moqtrun_setup_malformed_closes`), but no hub test sends this
    trigger.
- [x] MQ18-067 If a Message Parameter is defined for message types other than
  the one it appears in, then the implementation shall close the session with a
  protocol violation.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_scope_violation`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_registry_scope_per_draft`
  - note: draft-18's allowed-message sets differ from draft-19's for
    EXPIRES (0x08) and GROUP_ORDER (0x22) — see MQ18-073a/MQ18-073b.
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_bad_and_control`
- [~] MQ18-068 (§10.2) Message Parameters in SUBSCRIBE, PUBLISH_OK, and FETCH
  shall not cause the publisher to alter the payload of the Objects it sends.
  - evidence: no parameter value is consulted when the hub builds or relays
    an Object (moqtrun.c); `test_moqtrun_object_relay_preserves_bytes` shows
    payload identity end-to-end, but with a parameterless SUBSCRIBE.

## SS10.2.3/10.2.4 SUBGROUP_DELIVERY_TIMEOUT / OBJECT_DELIVERY_TIMEOUT

- [x] MQ18-069 The implementation shall decode the SUBGROUP_DELIVERY_TIMEOUT
  (0x06) and OBJECT_DELIVERY_TIMEOUT (0x02) Message Parameters as a varint,
  with a value of 0 meaning no timeout set.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_params_delivery_timeout_decode`
- [x] MQ18-070 (§10.2.1, §10.2.3, §10.2.4) The hub shall not send a
  delivery-timeout parameter in SUBSCRIBE_OK, a message outside those
  parameters' allowed set.
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

## SS10.2.12 FORWARD Parameter

- [x] MQ18-072 The implementation shall encode/decode the FORWARD parameter
  (Type 0x10) as a uint8 whose value is 0 (don't forward) or 1 (forward),
  defaulting to 1 when omitted.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_uint8_value_ranges`
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_sub_params_absent`
- [x] MQ18-073 (§5.1, §10.10) A publisher that sends FORWARD=0 in PUBLISH shall
  not transmit any Objects until the subscriber sets Forward State to 1;
  Object forwarding toward a subscription is gated by its Forward State.
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_forward0_then_update`

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
    `test_moqtrun_xver_setup_d18_omits_d19_options`. Duplicates of unknown
    options are dropped too (`test_moqraw_unknown`).
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_unknown_options_ignored`
- [~] MQ18-076 (§10.3) Senders shall not repeat the same Setup Option Type in a
  message unless the option explicitly allows multiple instances.
  - evidence: `moqctl_setup_encode` writes each of
    PATH/AUTHORITY/MOQT_IMPLEMENTATION at most once by construction
    (`test_moqctl_setup_roundtrip` round-trips one of each); no test drives
    a duplicate.

## SS10.3.1.1 AUTHORITY / SS10.3.1.2 PATH / SS10.3.1.5 MOQT_IMPLEMENTATION

- [x] MQ18-077 The implementation shall decode the PATH (0x01) and AUTHORITY
  (0x05) Setup Options as byte-string values.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_path_option_decode`
  - test: `tests/app/moqtrun_raw_test.c` —
    `test_moqtrun_raw_path_authority_established`
- [x] MQ18-078 (§10.3.1.1, §10.3.1.2) If a PATH or AUTHORITY option is received
  while WebTransport is used, then the implementation shall close the
  session with INVALID_PATH or INVALID_AUTHORITY respectively.
  - test: `tests/app/moqraw_test.c` — `test_moqraw_wt`
  - test: `tests/app/moqtrun_raw_test.c` —
    `test_moqtrun_raw_same_setup_on_wt_closes`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_path_closes_invalid_path`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_authority_closes_invalid_authority`
- [x] MQ18-231 (§10.3.1.1, §10.3.1.2) On a native-QUIC session, if a PATH or
  AUTHORITY option does not conform to the URI rules, then the server shall
  close the session with MALFORMED_PATH or MALFORMED_AUTHORITY; if the
  application's policy does not support the path or authority, then it
  shall close with INVALID_PATH or INVALID_AUTHORITY.
  - test: `tests/app/moqraw_test.c` — `test_moqraw_path`
  - test: `tests/app/moqraw_test.c` — `test_moqraw_authority`
  - test: `tests/app/moqraw_test.c` — `test_moqraw_hook`
- [x] MQ18-079 (§10.3.1.5) The implementation shall decode the
  MOQT_IMPLEMENTATION (0x07) Setup Option as a UTF-8 byte-string value.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_setup_roundtrip`
- [x] MQ18-232 (§10.3.1.5, §13.8) The server should send a
  MOQT_IMPLEMENTATION Setup Option, limited to the implementation name and
  major version, unless configured not to.
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_setup_sends_implementation`
- [x] MQ18-226 (§10.2.2, §10.3.1.4) If a client SETUP carries an AUTHORIZATION
  TOKEN Setup Option with Alias Type DELETE or USE_ALIAS, then the server
  shall close the session with PROTOCOL_VIOLATION; a REGISTER that exceeds
  its MAX_AUTH_TOKEN_CACHE_SIZE shall be treated as USE_VALUE, not a session
  failure.
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_setup_token_alias`

## SS10.4 GOAWAY (wire format, draft-18 shape)

- [x] MQ18-080 The implementation shall encode/decode GOAWAY's shared prefix
  as Type (0x10) + Length + New Session URI Length + New Session URI +
  Timeout, with the trailing Request ID field present only on the control
  stream (see MQ18-048a).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway_roundtrip`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway18_request_id`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_goaway18_vs_19_shape`
- [~] MQ18-081 (§10.4) If the New Session URI Length exceeds 8192 bytes, then
  the implementation shall close the session with a protocol violation.
  - evidence: the codec reports the violation
    (`test_moqctl_goaway_uri_boundary`); the hub closes PROTOCOL_VIOLATION on a request or SETUP
    that fails to decode (`test_moqtrun_fillfix_malformed_subscribe`,
    `test_moqtrun_setup_malformed_closes`), but no hub test sends this
    trigger.
## SS10.5 REQUEST_OK

- [x] MQ18-083 The implementation shall encode/decode REQUEST_OK as Type (0x7)
  + Length + Number of Parameters + Parameters + Track Properties (the
  remaining message bytes).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_ok_roundtrip`
- [x] MQ18-084 (§10.5) If a PUBLISH_OK, REQUEST_UPDATE_OK,
  SUBSCRIBE_NAMESPACE_OK or PUBLISH_NAMESPACE_OK carries non-empty Track
  Properties, then the implementation shall close the session with a protocol
  violation.
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_publish_ok_props_closes`
  - evidence: PUBLISH_OK is the only one of these the hub can receive: it
    sends no REQUEST_UPDATE, SUBSCRIBE_NAMESPACE or PUBLISH_NAMESPACE.

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
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_error_roundtrip`
- [x] MQ18-087 (§10.6.1) If the server receives a Redirect with a non-zero
  Connect URI Length, or a Redirect with a non-empty Track Name for a
  namespace-scoped request, then the implementation shall close the session
  with a protocol violation.
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_publish_error_redirect_closes`
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_redirect_uri_closes`
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_error_redirect_uri_closes`
  - evidence: the hub sends no namespace-scoped request, so the Track Name
    rule has no REQUEST_ERROR to apply to.
- [x] MQ18-088 (§10.6.2, §15.10.2) The implementation shall use the draft-18
  REQUEST_ERROR codes: INTERNAL_ERROR, UNAUTHORIZED, TIMEOUT, NOT_SUPPORTED,
  GOING_AWAY, EXCESSIVE_LOAD, UNSUPPORTED_EXTENSION, DUPLICATE_SUBSCRIPTION,
  REDIRECT, DOES_NOT_EXIST, INVALID_RANGE, UNINTERESTED, PREFIX_OVERLAP and
  INVALID_JOINING_REQUEST_ID, spelling a code another draft defines
  differently in draft-18's terms (e.g. INVALID_FILTER as INVALID_RANGE).
  - test: `tests/app/moqctl_test.c` — `test_moqctl_request_error_for_draft`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`
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
- [x] MQ18-091 (§5.1, §10.7) On a successful subscription, the publisher shall
  reply with exactly one SUBSCRIBE_OK.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_ok_roundtrip`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_split_subscribe_answered_once`
- [x] MQ18-092 The implementation shall encode/decode SUBSCRIBE_OK as Type
  (0x4) + Length + Track Alias + Number of Parameters + Parameters + Track
  Properties.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_subscribe_ok_roundtrip`
- [x] MQ18-093 (§5.1) If the hub receives more than one response
  (PUBLISH_OK or REQUEST_ERROR) to a request it sent, then the
  implementation shall close the session with a protocol violation.
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_second_ok_closes`
  - test: `tests/app/moqtrun_misc_test.c` —
    `test_moqtrun_misc_pub_error_after_ok_closes`
  - note: shown for the hub-initiated PUBLISH; a second SUBSCRIBE_OK from an
    upstream publisher is not tested.
- [x] MQ18-094 (§5.1.1) If a publisher rejects a SUBSCRIBE with REQUEST_ERROR,
  then no Object shall be sent for that subscription.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_requires_authorization`
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
- [x] MQ18-096 (§5.1) On a successful PUBLISH-initiated subscription, the
  subscriber shall reply with exactly one PUBLISH_OK (REQUEST_OK).
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_publish_replies_request_ok`
- [~] MQ18-097 (§5.1) A publisher may start sending Objects on a
  PUBLISH-initiated subscription before receiving PUBLISH_OK.
  - evidence: the hub as subscriber accepts Objects that arrive before its
    own answer is processed (upstream: `test_moqtrun_upsub_stream_before_ok`);
    the hub as PUBLISH sender waits for PUBLISH_OK
    (`test_moqtrun_misc_pub_ok_relays`).
- [x] MQ18-098 (§5.1.1, §10.10) If a subscriber rejects a PUBLISH with
  REQUEST_ERROR UNINTERESTED, then the subscription shall terminate without
  any Object being sent.
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_publish_error_frees_slot`

## SS10.11 PUBLISH_DONE

- [x] MQ18-099 The implementation shall encode/decode PUBLISH_DONE as Type
  (0xB) + Length + Status Code + Stream Count + Error Reason.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_publish_done_roundtrip`
- [x] MQ18-100 (§5.1.1, §10.11) A sender shall not send PUBLISH_DONE until it
  has closed every data stream it opened for that subscription.
  - test: `tests/app/moqtrun_drain_test.c` —
    `test_moqtrun_done_resets_streams_first`
- [x] MQ18-101 (§10.11) PUBLISH_DONE plus closing the subscription's bidi
  stream shall terminate the subscription; the sender may then destroy
  subscription state.
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_done_track_ended`
  - test: `tests/app/moqtrun_upsub_test.c` —
    `test_moqtrun_upsub_publish_done_relayed`
- [~] MQ18-102 (§10.11) If PUBLISH_DONE arrives before the subscriber has sent
  its response, then the subscriber shall owe exactly one deferred
  PUBLISH_OK before it FINs.
  - evidence: only the unwired `moqsub` model shows it
    (`test_moqsub_publish_done_before_response_defers_ok`); the hub answers a
    PUBLISH synchronously, so the race does not arise.
- [x] MQ18-103 (§10.11) The implementation shall use the draft-18
  PUBLISH_DONE status codes for the endings it signals: INTERNAL_ERROR,
  TRACK_ENDED, SUBSCRIPTION_ENDED, GOING_AWAY, UPDATE_FAILED and
  MALFORMED_TRACK.
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_done_track_ended`
  - test: `tests/app/moqtrun_done_test.c` —
    `test_moqtrun_pubdone_malformed_after_end_of_track`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_unknown_error_normalizes_to_internal`
- [x] MQ18-104 (§10.11) The publisher shall set PUBLISH_DONE's Stream Count to
  the exact number of data streams it opened for the subscription (0 when it
  opened none), or to 2^62-1 when it cannot count them.
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_done_track_ended`

## SS10 Reason Phrase / Location / Track Namespace shared structures used in control messages

- [x] MQ18-105 The implementation shall encode/decode Message Parameters,
  Location, and Reason Phrase consistently across every control message that
  embeds them.
  - test: `tests/app/moqctl_test.c` — `test_moqctl_params_forward_roundtrip`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_location_roundtrip_and_order`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_reason_boundary`

## SS5.1.2 / SS10.2.9 Subscription Filter

- [x] MQ18-106 (§5.1.2) The implementation shall decode a Subscription
  Filter's Filter Type as one of Next Group Start (0x1), Largest Object
  (0x2), AbsoluteStart (0x3), or AbsoluteRange (0x4), with the field layout
  (Start Location, End Group Delta) determined by the type.
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_locfilter_next_group_and_largest`
  - test: `tests/app/moqctl_test.c` —
    `test_moqctl_locfilter_abs_start_and_range_roundtrip`
  - note: draft-18 calls it "Subscription Filter" (renamed "Location
    Filter" in draft-19); the structure is byte-identical -- see
    `draft18-vs-19-diff.md` §9.3.
- [~] MQ18-107 (§5.1.2) If an AbsoluteRange filter's End Group (Start.Group +
  End Group Delta) would exceed 2^64-1, then the implementation shall close
  the session with a protocol violation.
  - evidence: the codec reports the violation
    (`test_moqctl_locfilter_end_group_overflow_violation`); the hub closes PROTOCOL_VIOLATION on a request or SETUP
    that fails to decode (`test_moqtrun_fillfix_malformed_subscribe`,
    `test_moqtrun_setup_malformed_closes`), but no hub test sends this
    trigger.
- [~] MQ18-108 (§5.1.2) If an endpoint receives a Subscription Filter Type
  other than the four defined values, then the implementation shall close
  the session with a protocol violation.
  - evidence: the codec reports the violation
    (`test_moqctl_locfilter_unknown_type_violation`); the hub closes PROTOCOL_VIOLATION on a request or SETUP
    that fails to decode (`test_moqtrun_fillfix_malformed_subscribe`,
    `test_moqtrun_setup_malformed_closes`), but no hub test sends this
    trigger.
- [x] MQ18-109 The publisher shall forward only Objects that pass the
  combination Forward State AND Location Filter (Pass = Forward AND Filters).
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_forward_toggles`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_filter_groups_delivered`
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_filter_from_largest`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_no_replay_before_start`
  - note: the filter is evaluated when objects are replayed to a late
    subscriber over the reliable relay, and Objects of the start Group below
    the start Object are cut on every relay path.

- [x] MQ18-217 (§5.1.2) If the hub cannot satisfy a Subscription Filter, or
  the filter's entire End Group has already been published, then it should
  reply REQUEST_ERROR INVALID_RANGE.
  - evidence: `moqtrun_filter_past` refuses an AbsoluteRange whose End Group
    precedes the track's Largest Group; `test_moqtrun_sub_range_past_invalid`
    (one ending at the Largest Group is accepted).

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
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_setup_unknown_options_ignored`
## SS11.1 Track Alias

- [x] MQ18-112 The same Track Alias shall not be used by a publisher to refer
  to two different Tracks simultaneously in the same session.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_chat_and_audio_get_different_aliases`
- [x] MQ18-113 (§11.1) If a subscriber receives a PUBLISH or SUBSCRIBE_OK
  reusing a Track Alias already bound to a different Established
  subscription, then the implementation shall close the session with
  DUPLICATE_TRACK_ALIAS.
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_publish_dup_alias_closes`
  - test: `tests/app/moqtrun_upsub_test.c` — `test_moqtrun_upsub_dup_alias_closes`

## SS11.2.1.1 Object Status

- [x] MQ18-114 The implementation shall recognize Object Status values 0x0
  (Normal), 0x3 (End of Group), and 0x4 (End of Track).
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_status_values`
- [x] MQ18-115 (§11.2.1.1) If an Object carries an unregistered Status value,
  then the implementation should close the session with a protocol
  violation.
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_object_violations`
- [x] MQ18-116 An Object shall have an empty payload unless its Object Status
  is Normal (0x0); the Object Status field shall be present only when Payload
  Length is 0.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_status_eog`
  - test: `tests/app/moqdata_test.c` —
    `test_moqdata_obj_take_status_eog_stream`

## SS11.2.1.2 Object Properties

- [x] MQ18-117 (§11.2.1.2) If an endpoint receives Object Properties on an
  Object whose Status is not Normal, then the implementation shall close the
  session with a protocol violation.
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_object_violations`
- [x] MQ18-118 Object Properties shall be serialized as a Properties Length
  (varint) followed by a Key-Value-Pair list.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_properties`
- [x] MQ18-118a (§12.1, §12.2, §15.8) If an Object Datagram carries an
  OBJECT_DELIVERY_TIMEOUT or SUBGROUP_DELIVERY_TIMEOUT Object Property, then
  the implementation shall close the session with a protocol violation
  (draft-18 registers both as Track-scope properties only).
  - test: `tests/app/moqtrun_ctlfix_test.c` — `test_mtcf_d18_dg_timeout_prop`
  - note: ruling Q18-05; gated on `MOQVER_CAP_DG_TIMEOUT_PROP_CLOSE`
    (draft-18 only). No draft-18 sentence prescribes the close; the ruling
    reads the Track-only scope as making the Object Property invalid.

## SS11.4.2 Subgroup Header

- [x] MQ18-119 All Objects on a stream opened with SUBGROUP_HEADER shall have
  Object Forwarding Preference = Subgroup, belonging to the Track Alias, Group
  ID, and Subgroup ID the header declares.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_basic`
- [x] MQ18-120 (§11.4.2) The SUBGROUP_HEADER Type field shall take the form
  0b0XX1XXXX (bit 4 always set); if received with any other form, the
  implementation shall close the session with a protocol violation.
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_unknown_uni_closes`
- [x] MQ18-121 The implementation shall decode the SUBGROUP_ID_MODE field (bits
  1-2) as: 0b00 Subgroup ID absent and 0, 0b01 Subgroup ID absent and equal to
  the first Object's Object ID, 0b10 Subgroup ID present in the header.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode2`
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_mode1_resolve`
- [x] MQ18-122 (§11.4.2) If SUBGROUP_ID_MODE is 0b11, then the implementation
  shall close the session with a protocol violation.
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_mode3_closes`
- [x] MQ18-123 The implementation shall decode the PROPERTIES bit (0x01),
  END_OF_GROUP bit (0x08), DEFAULT_PRIORITY bit (0x20), and FIRST_OBJECT bit
  (0x40) of the SUBGROUP_HEADER Type field.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_type_bits_golden`
- [x] MQ18-124 Where DEFAULT_PRIORITY is set, the Publisher Priority field
  shall be omitted from the header and the Subgroup shall inherit the priority
  from the subscription's control message.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_subhdr_take_basic`
  - test: `tests/app/moqtrun_drain_test.c` — `test_moqtrun_prio_track_default`
- [~] MQ18-125 (§11.4.2) Where the END_OF_GROUP bit is set and the stream
  terminates with a FIN, the implementation shall infer that no Object with
  the same Group ID and a larger Object ID exists.
  - evidence: the bit is decoded (MQ18-123) and relayed in the header bytes;
    no test asserts the inference.
- [x] MQ18-126 (§2.2, §11.4.2) When the hub, as Original Publisher of its own
  tracks (`wired_moqt_publish_blob` / `_live`), opens a new Subgroup, it
  shall set the FIRST_OBJECT bit.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_msg_build_golden`
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
- [x] MQ18-132 (§11.4.2) If the resulting cumulative Object ID would exceed
  2^64-1, then the implementation shall close the session with a protocol
  violation.
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_subgroup_object_violations`
- [x] MQ18-133 If a Subgroup Object stream terminates with a FIN in the middle
  of a serialized Object, then the implementation shall not treat the partial
  Object as complete.
  - test: `tests/app/moqdata_test.c` — `test_moqdata_obj_take_truncated`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_decode_loop_stops_at_truncation`
  - gap: §11.4 says the session SHOULD then be closed with
    PROTOCOL_VIOLATION; the hub discards the torn tail instead
    (`test_moqtrun_fresh_oneshot_no_object_discarded`).
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
- [~] MQ18-137 (§11.4.3) An implementation that observes a stream FIN is
  assured it has received all Objects in that Subgroup from the start of the
  subscription.
  - evidence: the hub forwards a FIN only after the Objects before it
    (`test_moqtrun_torn_object_held_until_complete` shows the reassembly);
    no test asserts the guarantee itself.
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
- [ ] MQ18-235 (§11.4.3) When a subscriber sends STOP_SENDING on a relay
  Subgroup stream, the hub should reset that stream and should not open a
  new stream for further Objects of that Subgroup.
  - gap: no test sends STOP_SENDING on a relay stream.
- [x] MQ18-140 Two overlapping publisher streams on the same track shall each
  be relayed on their own independent stream, with each closed only by its own
  publisher's FIN.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_interleaved_chat_messages_close_independently`
- [x] MQ18-141 (§2.2, §11.4.2) A subscriber that joins after a Subgroup stream
  has already started shall still receive a relay stream, opened with that
  stream's SUBGROUP_HEADER with FIRST_OBJECT cleared (the stream no longer
  begins at the Subgroup's first Object); a stream that does begin there
  keeps the bit as received.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_late_subscriber_gets_late_opened_stream`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_preserves_bytes`

## SS11.5.1 Padding Streams

- [x] MQ18-142 The implementation shall discard all data received on a padding
  stream (Type 0x132B3E28).
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_padding_stream_discarded`

## SS11.4.4 Fetch Header and Fetch Object Fields

- [x] MQ18-236 (§11.4.4, §11.4.4.1, §11.4.4.2) The implementation shall
  encode/decode a FETCH_HEADER (0x5, Request ID) and its Fetch Object Fields:
  Serialization Flags with the Subgroup modes, the Object ID / Group ID
  Delta, Priority and Properties flags, the Datagram flag (0x40, the two
  low bits ignored), group-order-aware Group ID deltas, and End of
  Non-Existent / Unknown Range markers.
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_hdr`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_stream_golden`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_group_order`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_datagram_lsbs`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_stream_end_of_range`
- [x] MQ18-237 (§11.4.4, §11.4.4.1, §11.4.4.2) If a Fetch Object uses a
  Serialization Flags value of 128 or more other than an End of Range
  marker, the first Object lacks the Group or Object ID Delta or references
  a prior field, a prior Subgroup or Priority is referenced with no prior
  Object after an End of Range, or a computed Group ID or Object ID leaves
  0..2^64-1, then the implementation shall report a protocol violation.
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_flags_reject`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_overflow`
  - test: `tests/app/moqfetch_test.c` — `test_moqfetch_obj_after_eor_reject`

## SS11.4.2 Flow control for the control streams

- [~] MQ18-143 (§11.4.2) Endpoints shall allocate connection flow control to the control
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

- [x] MQ18-146 (§5.1) While a subscription is Established, Object forwarding
  toward it shall be permitted regardless of which side (SUBSCRIBE or
  PUBLISH) initiated it.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_object_relay_to_subscriber`
  - test: `tests/app/moqtrun_misc_test.c` — `test_moqtrun_misc_pub_ok_relays`
- [x] MQ18-147 (§5.1) A REQUEST_UPDATE received on an Established
  subscription shall leave the subscription Established.
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_forward_toggles`
- [x] MQ18-148 (§3.3.2) A requester that FINs its own direction immediately
  after sending its request, before any response, shall not have the request
  treated as failed.
  - test: `tests/app/moqtrun_sub_test.c` — `test_moqtrun_req_fin_keeps_request`
- [x] MQ18-149 (§5.1, §3.3.2) The subscriber shall be able to terminate an
  Established subscription by cancelling its request stream.
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_req_reset_unsubscribes`
- [~] MQ18-150 (§3.3.2) Where the requester's own direction is already FIN'd,
  cancelling a subscription shall send only STOP_SENDING on the receiving
  direction.
  - evidence: only the unwired `moqsub` model shows it
    (`test_moqsub_cancel_after_fin`); the hub, cancelling its upstream
    SUBSCRIBE, sends RESET_STREAM and STOP_SENDING
    (`test_moqtrun_upsub_last_cancel_cancels_upstream`).
- [x] MQ18-151 (§3.3.2) If the responder FINs its own direction without ever
  sending a response, then the requester shall treat the request as failed.
  - evidence: `moqtrun_up_rx` / `moqtrun_upf_rx` take the FIN and fail an
    unanswered upstream SUBSCRIBE / FETCH as a REQUEST_ERROR would;
    `test_moqtrun_upsub_fin_unanswered_fails` and
    `test_moqtrun_upfetch_fin_unanswered` FIN before the response and see the
    downstream requester refused, the hub's side FINned, the slot freed.
- [x] MQ18-212 (§5.1) The publisher shall save as the subscription's Joining
  Location the Largest Location it communicates in SUBSCRIBE_OK, PUBLISH,
  or the REQUEST_OK of a REQUEST_UPDATE that changes the Forward State from
  0 to 1.
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_forward_toggles`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_rejoin_reresolves_start`
- [x] MQ18-213 (§5.1) If the hub receives a SUBSCRIBE for a Track for which it
  has a subscription to that peer in Pending (publisher) state (a
  hub-initiated PUBLISH not yet answered), then it shall refuse it with
  REQUEST_ERROR DUPLICATE_SUBSCRIPTION.
  - evidence: `moqtrun_fresh_refusal` (`moqtrun_pub_crossing`);
    `test_subtracks_subscribe_crosses_publish` subscribes while the hub's
    SUBSCRIBE_TRACKS PUBLISH is unanswered and sees DUPLICATE_SUBSCRIPTION on
    draft-18, a subscription on later drafts.
- [x] MQ18-214 (§5.1) If the hub receives a PUBLISH for a Track for which its
  own upstream SUBSCRIBE to that peer is still Pending (subscriber), then it
  shall terminate its own subscription before sending PUBLISH_OK.
  - evidence: `moqtrun_up_crossed` cancels the Pending upstream SUBSCRIBE in
    `moqtrun_publish_checked` before PUBLISH_OK is queued;
    `test_moqtrun_upsub_publish_crosses` asserts the reset precedes the
    PUBLISH_OK and the waiter rides the PUBLISH.
- [x] MQ18-215 (§5.1.1) When a subscriber cancels a subscription, the hub
  shall reset every open data stream of that subscription.
  - evidence: `moqtrun_req_cancel` resets the subscription's relay streams
    (`moqtrun_cancel_peer_subs`) before dropping it;
    `test_moqtrun_req_reset_resets_data_streams` asserts the open Subgroup
    stream toward the subscriber is reset.
- [ ] MQ18-216 (§5.1) A publisher should begin sending incomplete Objects as
  they become available.
  - gap: the hub holds an Object split across deliveries until it is
    complete (MQ18-138, `test_moqtrun_fresh_delivery_tail_held_back`).
- [ ] MQ18-218 (§5.1) Where a peer SUBSCRIBEs to a Track it publishes itself,
  the hub shall serve it like any other subscription, forwarding the
  published Objects back.
  - gap: no test; a publisher re-PUBLISHing a name it had subscribed to is
    deliberately not attached to its own track
    (`test_moqtrun_publisher_is_not_reattached_to_own_track`).

## SS10 Control Messages: session-machine unwanted behavior (additional coverage)

- [x] MQ18-152 (§10) If the control stream carries an unknown message type or
  a Length/Body mismatch, then the implementation shall close the session
  with a protocol violation.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_unknown_type_closes_session`
  - test: `tests/app/moqctl_test.c` — `test_moqctl_peek_type_length_mismatch`
- [x] MQ18-153 (§3.5) Once a session is closed, further events shall be
  no-ops (the close reason is sticky).
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_ctl_unknown_type_closes_session`
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
  - test: `tests/app/moqtrun_test.c` —
    `test_moqt_reliable_relay_sheds_stalled_sub`
- [x] MQ18-186 Subscriber priority shall map to the WebTransport stream
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
- [x] MQ18-187 (§10.9) A REQUEST_UPDATE of a SUBSCRIBE, on that subscription's
  request stream, shall replace its parameters all-or-nothing: absent
  parameters keep their value, and a refused update changes nothing.
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_forward_toggles`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_params_replace`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_upd_failed_changes_nothing`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_upd_survives_rejoin`
- [~] MQ18-230 (§10.9.1) When a REQUEST_UPDATE of a subscription fails, the
  hub shall also terminate the subscription with PUBLISH_DONE UPDATE_FAILED
  and FIN its request stream.
  - evidence: `moqtrun_update_sub_apply` sends REQUEST_ERROR then
    PUBLISH_DONE UPDATE_FAILED; the tests assert REQUEST_ERROR and the FIN
    only (`test_moqtrun_upd_failed_changes_nothing`; for a hub-initiated
    PUBLISH, `test_moqtrun_misc_pub_update_failed_fins`, which runs on
    draft-19/22 only).
- [x] MQ18-188 A TRACK_STATUS shall be answered with REQUEST_OK carrying the
  track's largest location (or none when empty), or REQUEST_ERROR when the
  track is unknown or the authorizer refuses.
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_ok_largest`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_ok_empty`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_unknown_and_blob`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_authorized`
- [x] MQ18-189 (§9.4, §9.5, §10.2.2, §13) Where an application installs an
  authorizer, every PUBLISH, SUBSCRIBE, TRACK_STATUS, PUBLISH_NAMESPACE and
  SUBSCRIBE_NAMESPACE shall be shown to it, and a refusal shall be
  REQUEST_ERROR UNAUTHORIZED; an Alias-based authorization token shall close
  the session (the hub keeps no token cache, 10.2.2): REGISTER with
  AUTH_TOKEN_CACHE_OVERFLOW, DELETE and USE_ALIAS with
  UNKNOWN_AUTH_TOKEN_ALIAS.
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_requires_authorization`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_subscribe_alias_token_rejected`
  - test: `tests/app/moqtrun_upd_test.c` —
    `test_moqtrun_publish_requires_authorization`
  - test: `tests/app/moqtrun_upd_test.c` — `test_moqtrun_tstat_authorized`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_authorization`
  - note: SUBSCRIBE_TRACKS goes through the same namespace check
    (`moqtrun_disc_verdict`) but has no test of its own.

## Hub relay: delivery timeouts

- [x] MQ18-190 (§8) With a non-zero OBJECT_DELIVERY_TIMEOUT (from SUBSCRIBE or
  a REQUEST_UPDATE), an object not delivered in time shall be abandoned: its
  stream is reset with DELIVERY_TIMEOUT (0x2) and no new stream is opened
  for the rest of its Subgroup; a datagram is relayed on arrival, so it
  never outlives the timeout.
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

- [ ] MQ18-221 (§8) With a non-zero SUBGROUP_DELIVERY_TIMEOUT, the hub shall
  start a timer when a Subgroup's FIN arrives from upstream and reset the
  relay stream if it has not reached "all data committed" when the timer
  expires.
  - gap: the hub applies the min'ed subgroup timeout as a delivery-age bound
    (`test_moqtrun_sub_subgroup_timeout_gates_delivery`); there is no
    post-FIN timer.

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
- [x] MQ18-193 (§10.12.2) A joining FETCH (relative or absolute) shall resolve
  against the joined subscription's Joining Location so that FETCH plus
  SUBSCRIBE leave no gap; it shall be refused INVALID_RANGE when the
  subscription has Forward State 0, nothing was published, or the start lies
  past the Joining Location, and INVALID_JOINING_REQUEST_ID when the Request
  ID names no subscription of the session.
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_relative_join_no_gap`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_absolute_join`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_join_invalid_range`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_join_forward_off`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_join_unknown_request`
  - note: draft-18's FETCH body (Fetch Type + Standalone/Joining) is
    byte-identical to draft-19's; draft-22 removes Joining FETCH entirely
    (see `docs/features/draft-moq-transport-22.md` 4-6).
  - gap: no test covers a Joining FETCH of a subscription still Pending
    (subscriber), which §10.12.2 says is buffered until it is established.
- [x] MQ18-233 (§10.12.3, §10.13) A Standalone FETCH shall be refused
  INVALID_RANGE when nothing was published, its Start lies past the Largest
  Object, or its End precedes its Start, DOES_NOT_EXIST when no one
  publishes the track; an End past the Largest Object shall be cut to
  {Largest.Group, Largest.Object + 1} in FETCH_OK.
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_nothing_published`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_range_against_largest`
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_end_before_start`
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_unknown_track`
- [x] MQ18-219 (§5.2, §9.4, §9.5, §10.12.3, §10.13) When a FETCH needs Objects
  the hub neither holds nor knows to be absent, the hub shall send one FETCH
  upstream to the track's publisher or a covering announcer, relay the
  upstream Objects in place, withhold FETCH_OK until the End Location is
  known, close an upstream session whose FETCH_OK End precedes the Start
  with PROTOCOL_VIOLATION, and on cancellation send RESET_STREAM and
  STOP_SENDING on the upstream request stream.
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_gap_to_owner`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_no_track_waits_ok`
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_bad_end`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_requester_gone`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_upstream_draft`
  - note: the requester runs draft-22 in these tests; the upstream FETCH is
    spelled in the upstream session's own draft, draft-18 included
    (`test_moqtrun_upfetch_upstream_draft`).
- [x] MQ18-227 (§10.2.5) The hub shall bound the time it waits on upstream
  FETCHes by the FETCH's FILL_TIMEOUT (an implementation default when
  absent), then report what is still missing as an unknown range; with
  FILL_TIMEOUT 0 it shall ask nothing upstream.
  - test: `tests/app/moqtrun_upfetch_test.c` — `test_moqtrun_upfetch_budget`
  - test: `tests/app/moqtrun_upfetch_test.c` —
    `test_moqtrun_upfetch_fill_timeout_zero`
  - note: draft-18 has no End of Timed-Out Range marker; toward such a
    draft the gap is End of Unknown Range (the budget test's draft-19 leg).
- [~] MQ18-222 (§9.1) Where the hub has recorded an Object as not existing,
  it should neither cache nor forward that Object if it arrives later.
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_late_nonexistent_not_cached`
  - gap: the record is the cache (a closed Group's Location it serves as
    nonexistent); caching and datagram Objects are gated, but a Subgroup
    stream's late Object is still forwarded with the stream's bytes.
- [x] MQ18-238 (§12.3) Where a track carries MAX_CACHE_DURATION, the hub shall
  not start forwarding an Object later than that many milliseconds after
  its first byte was received.
  - test: `tests/app/moqtrun_fetch_test.c` — `test_moqtrun_fetch_max_cache_duration`
  - note: "received" is the last `wired_moqt_tick` clock before the Object
    arrived, never later than its first byte, so Objects only expire early;
    a cached group with one expired Object becomes unknown whole (the cache
    never holds a partial group). Driven with the draft-18/19 FETCH body.
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
  - test: `tests/app/moqtrun_fetch_test.c` —
    `test_moqtrun_fetch_requester_leaves`

## Hub relay: namespace discovery

- [x] MQ18-195 A PUBLISH_NAMESPACE shall be accepted per publisher (several
  publishers may share a namespace), and a SUBSCRIBE_NAMESPACE shall get
  NAMESPACE for every matching namespace, then NAMESPACE / NAMESPACE_DONE
  as publishers come and go.
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_publish_accepted`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_initial_set`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_live_join_and_cancel`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_publisher_leaves`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_multiple_publishers`
  - test: `tests/app/moqtrun_ns_test.c` — `test_moqtrun_ns_prefix_overlap`
  - note: within one session two prefixes overlap when either is empty or
    their first fields are equal -- §10.18's "shares a common prefix" read
    literally, so (chat, room1) and (chat, room2) overlap.

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

- [x] MQ18-200 (§11.3) An Object Datagram shall be relayed byte-identical to
  every subscriber of the track its alias names, and a datagram with an
  unknown alias may be dropped (counted).
  - test: `tests/app/moqdg_test.c` — `test_moqdg_roundtrip_golden`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_dg_relays_identical_bytes_to_subscriber`
  - test: `tests/app/moqtrun_test.c` —
    `test_moqtrun_dg_relays_to_all_three_subscribers`
  - test: `tests/app/moqtrun_test.c` — `test_moqtrun_dg_unknown_alias_counts_bad`
- [x] MQ18-234 (§11, §11.3.1) If a datagram has an unknown or invalid Type
  (outside 0b00X0XXXX, or STATUS with END_OF_GROUP), the PROPERTIES bit with a
  Properties Length of 0, or Properties on a non-Normal Object Status, then
  the server shall close the session with PROTOCOL_VIOLATION.
  - test: `tests/app/moqtrun_sess_test.c` — `test_mtss_datagram_invalid_closes`
- [~] MQ18-240 (§11.5.2) The server shall discard all data received in a
  padding datagram (type 0x132B3E29).
  - evidence: the datagram codec has no padding type, so the hub drops it as
    undecodable like any malformed datagram
    (`test_moqtrun_dg_malformed_counts_bad`); no test sends the padding type.

## Hub features completed in the multi-draft round (ledger ch. 10)

- [x] MQ18-201 (SS10.19) The hub shall answer a SUBSCRIBE_TRACKS with exactly
  one REQUEST_OK on its request stream, and shall refuse one whose Track
  Namespace Prefix overlaps an established SUBSCRIBE_TRACKS of the same session
  with PREFIX_OVERLAP.
  - test: `tests/app/moqtrun_subtracks_test.c` — `test_subtracks_ok_once`
  - test: `tests/app/moqtrun_subtracks_test.c` — `test_subtracks_prefix_overlap`
  - test: `tests/app/moqtrun_ctlfix_test.c` —
    `test_mtcf_d18_subtracks_range_filter`
  - note: draft-18 admits only AUTHORIZATION TOKEN and FORWARD in
    SUBSCRIBE_TRACKS (see the parameter table); the subtracks scenarios run
    on every draft, draft-18 included.
- [x] MQ18-202 (SS10.19) For every track matching an established
  SUBSCRIBE_TRACKS prefix and not published by the subscriber itself, the hub
  shall open one PUBLISH on a new bidirectional stream naming that track,
  carrying the SUBSCRIBE_TRACKS's FORWARD value; cancelling the SUBSCRIBE_TRACKS
  stops new PUBLISHes but leaves established ones, a track that vanishes before
  the reply resets its PUBLISH stream, and a REQUEST_ERROR reply frees the slot.
  The PUBLISH_OK (REQUEST_OK) reply opens the subscriber's subscription under
  the PUBLISH's Track Alias, starting from the PUBLISH's parameters (FORWARD 0
  holds Objects back); the subscriber's REQUEST_UPDATE on that stream is
  applied like a SUBSCRIBE's and answered there (ledger 12-11, 12-18; a
  failed update is MQ18-230); a second REQUEST_OK (PUBLISH_OK) or
  REQUEST_ERROR closes the session with PROTOCOL_VIOLATION (SS5.1 "SHOULD
  close the session with a protocol error", ledger 12-28).
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
    in `tasks/loopeng/moqt/MoqtHubPublish/` (not in git). The scenarios run on
    every draft, draft-18 included.
- [x] MQ18-225 (§9.5) Where the hub holds a downstream SUBSCRIBE awaiting a
  publisher for a track and that subscriber also has a matching
  SUBSCRIBE_TRACKS, an arriving PUBLISH shall complete the held SUBSCRIBE and
  shall not also be forwarded to that subscriber as a hub-initiated PUBLISH.
  - test: `tests/app/moqtrun_rdv_test.c` —
    `test_moqtrun_rdv_s12_subtracks_skips_held`
- [x] MQ18-203 (SS10.20) Where the hub cannot open a bidirectional stream for
  such a PUBLISH, it shall send PUBLISH_SKIPPED (draft-18: PUBLISH_BLOCKED)
  (Track Namespace Suffix, Track Name) on the SUBSCRIBE_TRACKS request stream
  instead, and shall not later send a PUBLISH for the same track incarnation.
  - test: `tests/app/moqtrun_subtracks_test.c` —
    `test_subtracks_skip_then_no_publish`
  - test: `tests/app/moqns_test.c` — `test_moqns_pub_skipped_roundtrip`
  - test: `tests/app/moqns_test.c` — `test_moqns_pub_skipped_rejects`
  - note: the subtracks scenarios run on every draft, draft-18 included.
- [~] MQ18-204 (SS10.9, SS10.9.1, SS10.9.2) A REQUEST_UPDATE of a FETCH,
  PUBLISH_NAMESPACE or SUBSCRIBE_NAMESPACE on its request stream shall be
  served: an accepted update is acknowledged (a new SUBSCRIBE_NAMESPACE
  prefix takes effect for later announcements); a refused FETCH update
  resets the FETCH data stream, and a refused namespace update (e.g.
  PREFIX_OVERLAP) closes the request stream and leaves the old prefix in
  place.
  - evidence: an accepted FETCH update (`test_moqtrun_upd_on_fetch_stream`),
    a SUBSCRIBE_NAMESPACE prefix change
    (`test_moqtrun_upd_ns_prefix_changes`) and a PREFIX_OVERLAP refusal that
    FINs the stream (`test_moqtrun_upd_ns_prefix_overlap_refused`) are
    asserted; a PUBLISH_NAMESPACE update, the FETCH data-stream reset on a
    refused update (`test_moqtrun_upd_on_fetch_stream_refused` asserts a
    session close instead) and the kept old prefix are not.
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
  - note: ledger 10-6. These scenarios run on every draft with the
    draft-18/19 FETCH body, draft-18 included. The malformed FETCH carries
    an unknown Fetch Type (§10.12).
- [x] MQ18-206 (SS5.1.4) A late subscriber attached to a live track shall start
  at its Location Filter's start Group: a start behind the live edge is clamped
  to the current Group, and a future start holds delivery until that Group.
  - test: `tests/app/moqtrun_sub_test.c` —
    `test_moqtrun_sub_live_attach_filter_start`
  - note: ledger 10-7. A start Object inside the first Group is cut per
    Object on a Subgroup stream (`test_moqtrun_sub_filter22_start_object_*`,
    `test_moqtrun_sub_filter22_ring_*`). The scenario runs on every draft,
    draft-18 included.

## Not implemented

In scope for a draft-18 relay, but not implemented yet. A peer that needs
one of these gets NOT_SUPPORTED (or, where noted, a different behavior).
Reserved namespaces, SUBSCRIBE_TRACKS, PUBLISH_SKIPPED (PUBLISH_BLOCKED),
FETCH GROUP_ORDER and REQUEST_UPDATE of FETCH and namespace requests were
listed here until ledger ch. 10 implemented them (MQ18-028, MQ18-201
through MQ18-206).

Nothing beyond the `[ ]` items above, each of which carries its `gap:`.

## Out of scope

Features and requirements this hub relay subset does not implement, excluded
from the coverage denominator above:

- (SS10.11) PUBLISH_DONE for a subscription made on the legacy control
  stream, by design: PUBLISH_DONE carries no Request ID, so on a stream
  shared by several subscriptions it cannot name the one that ended; the
  subscription is kept and re-attached when the publisher rejoins.

- (SS1.5, SS1.5.1) Rendering/parsing namespace and track names as
  human-readable strings — an operator/logging concern; this SDK compares
  names as raw bytes only.
- (SS2.4.2, SS12.7-12.9) The rest of the receiver-side Malformed Track
  catalog (Publisher Priority mismatch across a Subgroup ID, Object ID past
  a Subgroup's final, differing finals across FIN'd streams, Forwarding
  Preference change, nested Immutable Properties, Prior Group/Object ID Gap
  violations) — the spec lists conditions "when detected"; the hub detects
  an Object past END_OF_GROUP / END_OF_TRACK and an upstream FETCH Object
  conflicting with the cache (MQ18-207).
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
- (SS7, SS7.1--7.3) Priorities — the scheduling algorithm runs on the
  WebTransport send pump
  (Subscriber, then Publisher Priority, then group order and
  fill-before-live inside one subscription; MQ18-186). What remains:
  one-shot streams already queued keep their class across a
  REQUEST_UPDATE, datagrams bypass the stream classes, a FETCH's own
  SUBSCRIBER_PRIORITY is not kept (it ranks as 128), and equal classes
  across subscriptions share each pump pass round-robin.
- (SS10.2.10) EXPIRES — decoded by the registry, not acted on (the value is
  advisory). FILL_TIMEOUT, RENDEZVOUS_TIMEOUT and NEW_GROUP_REQUEST are
  items MQ18-227, MQ18-228 and MQ18-229.
- (SS10.3.1.3, SS10.3.1.4) MAX_AUTH_TOKEN_CACHE_SIZE and AUTHORIZATION TOKEN
  as Setup Options the hub sends — not advertised; the hub keeps no token
  cache, so Alias-based tokens close the session (MQ18-189). Receiving the
  AUTHORIZATION TOKEN option is MQ18-226.
- (SS11.5.2) Padding Datagrams — not sent.
- (SS12.5-12.9) The scheduling semantics of DEFAULT_PUBLISHER_GROUP_ORDER
  and DYNAMIC_GROUPS, and Prior Group/Object ID Gap — the Properties wire
  slot is relayed unchanged; the hub reads DEFAULT_PUBLISHER_PRIORITY,
  SUBGROUP_DELIVERY_TIMEOUT and MAX_CACHE_DURATION (inside Immutable
  Properties too) and validates the group-order / dynamic-groups ranges.
  The MUSTs a relay owes these properties are items MQ18-224, MQ18-238 and
  MQ18-239.
- (SS5.1.3.1, SS10.2.13) Dynamically starting new Groups on the hub's own
  tracks — they do not declare DYNAMIC_GROUPS.
- (SS10.4) A client's zero-length New Session URI and its use of the URI —
  client rules (MQ18-082 removed; the server-side check is MQ18-045).
- (SS10.4, SS3.6) Sending GOAWAY on a request stream and the SHOULD to
  reset that stream afterwards, re-issuing a request after a request-stream
  GOAWAY, and SS3.6's "send GOAWAY downstream before unsubscribing
  upstream" — the hub sends GOAWAY on the control stream only and its drain
  never unsubscribes upstream first.
- (SS10.11, SS10.18, SS10.19) Subscriber-side rules for requests the hub
  never sends or never waits on: the first-message checks and
  NAMESPACE_DONE-before-NAMESPACE close of a SUBSCRIBE_NAMESPACE /
  SUBSCRIBE_TRACKS requester, the post-PUBLISH_DONE timer and STOP_SENDING
  cleanup, and PUBLISH_NAMESPACE's duplicate-answer close (the hub sends no
  PUBLISH_NAMESPACE).
- (SS10.2.2) Token sender rules (register only for re-use, USE_ALIAS /
  DELETE ordering), expired-token retention, and MALFORMED_AUTH_TOKEN —
  the hub sends no tokens, keeps no cache, and leaves token validity to
  the application's authorizer (UNAUTHORIZED, MQ18-189).
- (SS8, SS11.4.3) Checking delivery timeouts before a transport
  retransmission and RESET_STREAM_AT's reliable_size — the QUIC stack gives
  the MOQT layer no retransmission hook, and the hub resets with
  RESET_STREAM only.
- (SS10.2.13, SS10.6.2, SS10.10) Subscriber obligations of NEW_GROUP_REQUEST,
  Retry Interval pacing, and refusing an unwanted PUBLISH with UNINTERESTED
  — the hub never sends NEW_GROUP_REQUEST, never retries a refused request,
  and accepts every authorized PUBLISH it has room for (MQ18-156).
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
