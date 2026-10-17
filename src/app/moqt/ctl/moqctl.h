#ifndef MOQCTL_H
#define MOQCTL_H

#include "app/moqt/ctl/moqctl_loc.h"

/** @file
 * draft-ietf-moq-transport-19 SS10 Control Messages: common envelope
 * (Type + 16-bit Length + Body), Message Parameters (SS10.2), Location
 * (SS1.4.2), Track Namespace/Name (SS1.5), Reason Phrase (SS1.4.4), and the
 * eight message codecs this SDK subset implements: SETUP, SUBSCRIBE,
 * SUBSCRIBE_OK, PUBLISH, REQUEST_OK, REQUEST_ERROR, PUBLISH_DONE, GOAWAY.
 *
 * Every decode returns one of the five outcomes below. INSUFFICIENT means
 * "not enough bytes yet, may become valid" (a session-layer concern, not a
 * close reason). VIOLATION means the bytes are illegal per spec and the
 * caller closes with PROTOCOL_VIOLATION (or a message-specific code noted
 * on the call). UNKNOWN_TYPE / KNOWN_UNIMPLEMENTED are returned only by
 * moqctl_peek_type, so the session layer can tell "must close" apart
 * from "must reply NOT_SUPPORTED".
 *
 * Ownership: every wired_span a take fills (names, reasons, URIs, token
 * values, raw parameter bytes, track_properties) is a view into the
 * caller's input buffer and is valid only while that buffer is. Every
 * wired_span an encode reads is caller-owned and only read during the
 * call. Encoders return 1 on success and 0 when buf runs out.
 */

/** One fixed 8-bit field (uint8 parameter values, Publisher Priority,
 * End Of Track). take: MOQCTL_OK or INSUFFICIENT; put: 1 ok, 0 no room. */
int moqctl_param_take_uint8(wired_span buf, usz* at, u64* out);
/** Writes the low 8 bits of v as one byte at *at; 1 ok, 0 no room. */
int moqctl_param_put_uint8(wired_mspan buf, usz* at, u64 v);

/** Exact byte comparison (SS1.5): 1 if equal, 0 otherwise. */
int moqctl_ftn_eq(const moqctl_ftn* a, const moqctl_ftn* b);

/** draft-ietf-moq-transport-19 SS1.4.4 Reason Phrase: Length + UTF-8 bytes,
 * length capped at MOQCTL_MAX_REASON_LEN.
 *
 * Design constraint (draft-22's "Logging of Untrusted String Fields",
 * carried into every draft as sender-controlled text): this field and
 * MOQT_IMPLEMENTATION (MOQCTL_OPT_MOQT_IMPLEMENTATION) are untrusted bytes.
 * Neither is logged or rendered anywhere in this hub today, so there is no
 * sanitize-before-log call to add yet -- but the first call site that logs
 * or displays either one MUST sanitize it first (e.g. escape bytes outside
 * printable ASCII) to avoid log/terminal-escape injection, through one
 * shared sanitizer, not a copy per call site. */
typedef wired_span moqctl_reason;

/** Decodes a Reason Phrase as a view into buf. MOQCTL_OK, INSUFFICIENT,
 * or VIOLATION when Length exceeds MOQCTL_MAX_REASON_LEN. */
int moqctl_reason_take(wired_span buf, usz* off, moqctl_reason* out);
/** Encodes reason as Length + bytes; 1 ok, 0 when buf runs out. The
 * caller keeps reason within MOQCTL_MAX_REASON_LEN. */
int moqctl_reason_put(wired_mspan buf, usz* off, moqctl_reason reason);

/** draft-ietf-moq-transport-19 SS10.2.2 Token structure: Alias Type
 * selects which of the optional fields are present (MOQCTL_TOKEN_*);
 * absent fields are left zero / empty. value is a view into the decoded
 * message, valid only as long as that buffer is. */
typedef struct {
  /** Alias Type, one of MOQCTL_TOKEN_*. */
  u64 alias_type;
  /** Token Alias; present for DELETE / REGISTER / USE_ALIAS. */
  u64 alias;
  /** Token Type (registry value); present for REGISTER / USE_VALUE. */
  u64 token_type;
  /** Opaque Token Value (view); present for REGISTER / USE_VALUE. */
  wired_span value;
} moqctl_token;

/** SWITCH_FROM value (moqtail): activate this subscription and stop the
 * one with request_id. Encode fails (0) when mode is not Hard/Soft. */
typedef struct {
  /** Request ID of the subscription being switched away from. */
  u64 request_id;
  /** MOQCTL_SWITCH_HARD / MOQCTL_SWITCH_SOFT. */
  u8 mode;
  /** Flags bit 0x80: end the old subscription with PUBLISH_DONE. */
  u8 publish_done;
} moqctl_switchfrom;

/** SWITCHING_SET_ASSIGNMENT value (moqtail SSTS): puts the subscription
 * into switching set set_id. Encode fails (0) when weight is not 1..10. */
typedef struct {
  /** Switching set the subscription joins (subscriber-chosen ID). */
  u64 set_id;
  /** Selection algorithm, one of MOQCTL_SSTS_ALG_*. */
  u64 algorithm_id;
  /** Estimated bandwidth in kbit/s at or above which this member is
   * eligible for selection. */
  u64 threshold_kbps;
  /** Member weight, 1..10. */
  u64 weight;
  /** Member count at which the set becomes active; 0 never activates. */
  u64 activate;
  /** Set rank: active sets of equal rank are switched together; valid
   * iff has_rank, 0 otherwise. */
  u8 rank;
  /** 1 when the optional trailing Rank byte was present on the wire. */
  u8 has_rank;
} moqctl_ssa;

/** draft-ietf-moq-transport-19 SS10.2 Message Parameter: Type Delta +
 * Value. Decoded absolute type + encoding-tagged value. */
typedef struct {
  /** Absolute Parameter Type (MOQCTL_PARAM_*), Type Delta resolved. */
  u64 type;
  /** Value encoding, one of MOQCTL_PENC_*; selects the field below. */
  int enc;
  /** Value for MOQCTL_PENC_UINT8 (0..255). */
  u64 u8v;
  /** Value for MOQCTL_PENC_VARINT. */
  u64 vi;
  /** Value for MOQCTL_PENC_LOCATION. */
  moqctl_loc loc;
  /** View for MOQCTL_PENC_BYTES / NS, and MOQCTL_PENC_TOKEN's raw Token
   * bytes (what encode re-emits). */
  wired_span bytes;
  /** Decoded Token for MOQCTL_PENC_TOKEN. */
  moqctl_token token;
  /** draft-19 Location Filter for MOQCTL_PENC_LOCFILTER. */
  moqctl_locfilter lf;
  /** PENC_LOCFILTER/RANGELOC22: 0 for draft-22 Type 0x00 (None). */
  int has_filter;
  /** Version-neutral filter for PENC_LOCFILTER / PENC_RANGELOC22. */
  moqctl_rangeloc rl;
  /** Decoded value for MOQCTL_PENC_SWITCHFROM. */
  moqctl_switchfrom sw;
  /** Decoded value for MOQCTL_PENC_SSA. */
  moqctl_ssa ssa;
} moqctl_param;

/** A decoded/to-encode Message Parameter list. */
typedef struct {
  /** Parameters in wire order, i.e. ascending type. */
  moqctl_param items[MOQCTL_MAX_PARAMS];
  /** Number of items used, 0..MOQCTL_MAX_PARAMS. */
  usz n;
} moqctl_params;

/** Decodes count-prefixed Message Parameters. ctx is the MOQCTL_PCTX_*
 * set the list may appear in (SS10.2.1 Parameter Scope): a Type is legal
 * when its own set shares a bit with ctx. VIOLATION on: cumulative Type
 * overflow, unknown Type, duplicate Type, a known Type outside ctx, or a
 * known Type's Value not matching its defined encoding (mapped by the caller to
 * KEY_VALUE_FORMATTING_ERROR rather than PROTOCOL_VIOLATION -- see
 * moqctl_params_take's return contract below). */
#define MOQCTL_PARAMS_KVFMT (-4)
/** ver (MOQVER_*, a valid id) picks the draft's parameter table: each
 * Type's allowed contexts, whether it exists at all, and, under draft-22,
 * LOCATION_FILTER's unprefixed encoding (moqctl_rangeloc22_take, into
 * moqctl_param.rl/has_filter). Every message take below that carries
 * Parameters takes the same ver. */
int moqctl_params_take(
    int ver, wired_span buf, usz* off, u32 ctx, moqctl_params* out);
/** Encodes params as count + Type Delta/Value pairs, each value per its
 * enc. 1 ok; 0 when buf runs out or items are not in ascending type
 * order (a Type Delta cannot be negative). */
int moqctl_params_put(wired_mspan buf, usz* off, const moqctl_params* params);

/** First item of Type type in params, or 0 when absent (the draft
 * default then applies, e.g. SUBSCRIBER_PRIORITY 128, SS10.2.7). */
const moqctl_param* moqctl_params_find(const moqctl_params* params, u64 type);

/** draft-ietf-moq-transport-19 SS10.4 SETUP: Setup Options are a KVP list
 * (unknown options ignored on decode -- not surfaced here). PATH/AUTHORITY
 * are surfaced explicitly since WebTransport-context rejection is a
 * session-layer decision. */
typedef struct {
  /** 1 when the PATH option was present. */
  int has_path;
  /** PATH option value (view): the MOQT URI path on raw QUIC. */
  wired_span path;
  /** 1 when the AUTHORITY option was present. */
  int has_authority;
  /** AUTHORITY option value (view). */
  wired_span authority;
  /** 1 when the MOQT_IMPLEMENTATION option was present. */
  int has_implementation;
  /** MOQT_IMPLEMENTATION value (view); untrusted text, see
   * moqctl_reason. */
  wired_span implementation;
  /** MAX_FILTER_RANGES (SS10.4): Ranges the sender accepts concurrently
   * across one request's Range filter parameters; the draft default 0
   * means none. 0 is never encoded (it IS the default). */
  u64 max_filter_ranges;
  /** MAX_REQUEST_UPDATES (SS10.4): outstanding REQUEST_UPDATEs the
   * sender accepts per request stream; the draft default 0 means no
   * limit. 0 is never encoded. */
  u64 max_request_updates;
  /** SSTS_ALGORITHMS (experimental, moqtail): has_ssts when the option was
   * present and well-formed (a malformed list is ignored like an unknown
   * option). ssts_algs holds the known ids (MOQCTL_SSTS_ALG_*) in wire
   * order, then unknown ids in wire order, MOQCTL_SSTS_MAX_ALGS at most,
   * so a re-encode may reorder or drop ids. Present with ssts_alg_n 0 is
   * an empty list, encoded as such. */
  u64 ssts_algs[MOQCTL_SSTS_MAX_ALGS];
  /** Number of ids used in ssts_algs. */
  u8 ssts_alg_n;
  /** 1 when a well-formed SSTS_ALGORITHMS option is present. */
  u8 has_ssts;
} moqctl_setup;

/** Decodes a SETUP Message Body: every byte from *off to the end of buf
 * is the Setup Options list. MOQCTL_OK, VIOLATION on a malformed
 * Key-Value-Pair, or MOQCTL_PARAMS_KVFMT on an SSTS_ALGORITHMS value
 * ending mid-varint (KEY_VALUE_FORMATTING_ERROR). */
int moqctl_setup_take(wired_span buf, usz* off, moqctl_setup* out);
/** Encodes s's present options as a SETUP Message Body, in ascending
 * option order; 1 ok, 0 when buf runs out. */
int moqctl_setup_encode(wired_mspan buf, usz* off, const moqctl_setup* s);

/** draft-ietf-moq-transport-19 SS10.6 SUBSCRIBE. */
typedef struct {
  /** Request ID the sender allocated for this subscription. */
  u64 request_id;
  /** Full Track Name subscribed to. */
  moqctl_ftn name;
  /** Parameters (SUBSCRIBE context). */
  moqctl_params params;
} moqctl_subscribe;

/** Decodes a SUBSCRIBE Message Body; ver as in moqctl_params_take. */
int moqctl_subscribe_take(
    int ver, wired_span buf, usz* off, moqctl_subscribe* out);
/** Encodes m as a SUBSCRIBE Message Body; 1 ok, 0 when buf runs out. */
int moqctl_subscribe_encode(
    wired_mspan buf, usz* off, const moqctl_subscribe* m);

/** draft-ietf-moq-transport-19 SS10.7 SUBSCRIBE_OK. track_properties is
 * the residual span (this codec does not parse Properties -- data-layer
 * scope). */
typedef struct {
  /** Track Alias the publisher assigned; data streams carry it in place
   * of the Full Track Name. */
  u64 track_alias;
  /** Parameters (SUBSCRIBE_OK context). */
  moqctl_params params;
  /** Unparsed Track Properties: the rest of the body (view). */
  wired_span track_properties;
} moqctl_subscribe_ok;

/** Decodes a SUBSCRIBE_OK Message Body to its end (*off = buf.n). */
int moqctl_subscribe_ok_take(
    int ver, wired_span buf, usz* off, moqctl_subscribe_ok* out);
/** Encodes m as a SUBSCRIBE_OK Message Body; 1 ok, 0 when buf runs
 * out. */
int moqctl_subscribe_ok_encode(
    wired_mspan buf, usz* off, const moqctl_subscribe_ok* m);

/** draft-ietf-moq-transport-19 SS10.9 PUBLISH. */
typedef struct {
  /** Request ID the publisher allocated for this PUBLISH. */
  u64 request_id;
  /** Full Track Name offered. */
  moqctl_ftn name;
  /** Track Alias the publisher assigned for the data streams. */
  u64 track_alias;
  /** Parameters (PUBLISH context). */
  moqctl_params params;
  /** Unparsed Track Properties: the rest of the body (view). */
  wired_span track_properties;
} moqctl_publish;

/** Decodes a PUBLISH Message Body to its end (*off = buf.n). */
int moqctl_publish_take(int ver, wired_span buf, usz* off, moqctl_publish* out);
/** Encodes m as a PUBLISH Message Body; 1 ok, 0 when buf runs out. */
int moqctl_publish_encode(wired_mspan buf, usz* off, const moqctl_publish* m);

/** draft-ietf-moq-transport-19 SS10.5 REQUEST_OK. Parameters are
 * checked against MOQCTL_PCTX_REQUEST_OK_ANY, the union of every OK's
 * scope. Non-empty track_properties is only legal for the TRACK_STATUS_OK
 * variant; this codec always decodes the residual bytes and lets the caller
 * (which knows which request it answers) enforce SS10.5's "MUST be empty for
 * PUBLISH_OK etc." rule. */
typedef struct {
  /** Parameters (MOQCTL_PCTX_REQUEST_OK_ANY context). */
  moqctl_params params;
  /** Unparsed Track Properties: the rest of the body (view). */
  wired_span track_properties;
} moqctl_request_ok;

/** Decodes a REQUEST_OK Message Body to its end (*off = buf.n). */
int moqctl_request_ok_take(
    int ver, wired_span buf, usz* off, moqctl_request_ok* out);
/** Encodes m as a REQUEST_OK Message Body; 1 ok, 0 when buf runs out. */
int moqctl_request_ok_encode(
    wired_mspan buf, usz* off, const moqctl_request_ok* m);

/** draft-ietf-moq-transport-19 SS10.8 REQUEST_ERROR redirect (SS10.8.1). */
typedef struct {
  /** URI of the session to retry the request on (view). */
  wired_span connect_uri;
  /** Track Namespace to request instead. */
  moqctl_ns track_namespace;
  /** Track Name to request instead (view). */
  wired_span track_name;
} moqctl_redirect;

/** draft-ietf-moq-transport-19 SS10.8 REQUEST_ERROR. has_redirect is only
 * legal when error_code == MOQCTL_ERR_REDIRECT (checked on
 * encode/decode: a Redirect present with any other code, or absent with
 * REDIRECT, is a VIOLATION since it desyncs Length from Body). */
typedef struct {
  /** Error Code (MOQCTL_ERR_*); normalize received codes with
   * moqctl_known_request_error. */
  u64 error_code;
  /** Retry Interval: 0 means do not retry, otherwise the minimum wait
   * before retrying in milliseconds plus one. */
  u64 retry_interval;
  /** Reason Phrase (view, untrusted). */
  moqctl_reason reason;
  /** 1 when redirect is present (error_code == MOQCTL_ERR_REDIRECT). */
  int has_redirect;
  /** Redirect target; valid iff has_redirect. */
  moqctl_redirect redirect;
} moqctl_request_error;

/** Decodes a REQUEST_ERROR Message Body (Redirect read iff the code is
 * REDIRECT). */
int moqctl_request_error_take(
    wired_span buf, usz* off, moqctl_request_error* out);
/** Encodes m as a REQUEST_ERROR Message Body; 1 ok, 0 when buf runs
 * out. */
int moqctl_request_error_encode(
    wired_mspan buf, usz* off, const moqctl_request_error* m);

/** draft-ietf-moq-transport-19 SS10.10 PUBLISH_DONE. */
typedef struct {
  /** Status Code (MOQCTL_DONE_*); normalize received codes with
   * moqctl_known_publish_done. */
  u64 status_code;
  /** Number of data streams the publisher opened for the subscription,
   * so the subscriber knows when all of them have arrived. */
  u64 stream_count;
  /** Reason Phrase (view, untrusted). */
  moqctl_reason reason;
} moqctl_publish_done;

/** Decodes a PUBLISH_DONE Message Body. */
int moqctl_publish_done_take(
    wired_span buf, usz* off, moqctl_publish_done* out);
/** Encodes m as a PUBLISH_DONE Message Body; 1 ok, 0 when buf runs
 * out. */
int moqctl_publish_done_encode(
    wired_mspan buf, usz* off, const moqctl_publish_done* m);

/** draft-ietf-moq-transport-19 SS10.3 GOAWAY. */
typedef struct {
  /** URI to reconnect to (view), at most MOQCTL_MAX_URI_LEN bytes;
   * empty means reuse the current URI. */
  wired_span new_session_uri;
  /** Milliseconds after which the sender may close the session. */
  u64 timeout;
  /** draft-18 control-stream GOAWAY only (moqctl_goaway18_*): the smallest
   * peer Request ID not (or maybe not) processed. */
  u64 request_id;
} moqctl_goaway;

/** Decodes a GOAWAY Message Body (draft-19/22 form, no Request ID).
 * VIOLATION when the URI exceeds MOQCTL_MAX_URI_LEN. */
int moqctl_goaway_take(wired_span buf, usz* off, moqctl_goaway* out);
/** Encodes m's URI and timeout as a GOAWAY Message Body; 1 ok, 0 when
 * buf runs out. */
int moqctl_goaway_encode(wired_mspan buf, usz* off, const moqctl_goaway* m);

/** draft-18 SS10.4 GOAWAY on the control stream: the fields above plus a
 * trailing Request ID. A GOAWAY on a request stream has none in any draft
 * and uses moqctl_goaway_take/_encode. */
int moqctl_goaway18_take(wired_span buf, usz* off, moqctl_goaway* out);
/** Encoding counterpart of moqctl_goaway18_take (appends request_id). */
int moqctl_goaway18_encode(wired_mspan buf, usz* off, const moqctl_goaway* m);

/** Common envelope: reads Type (vi64) + Length (16-bit BE) at *off,
 * without consuming past MOQCTL_OK's Type+Length header. On
 * MOQCTL_OK, *type_out is the Message Type, *body is the Message
 * Body view (exactly Length bytes, already bounds-checked against buf),
 * and *off has advanced past Type+Length+Body (the whole message).
 * MOQCTL_INSUFFICIENT: header or body not fully in buf yet (*off
 * untouched). MOQCTL_UNKNOWN_TYPE: Type is not in the SS10 table.
 * MOQCTL_KNOWN_UNIMPLEMENTED: Type is a known-but-unimplemented ID
 * (REQUEST_UPDATE/FETCH/FETCH_OK/TRACK_STATUS/PUBLISH_NAMESPACE/
 * SUBSCRIBE_NAMESPACE/SUBSCRIBE_TRACKS/NAMESPACE/NAMESPACE_DONE/
 * PUBLISH_SKIPPED). Both still fill *type_out / *body and advance *off
 * past the whole message, exactly like MOQCTL_OK, so the caller can
 * answer or skip it and go on with the next one. */
int moqctl_peek_type(wired_span buf, usz* off, u64* type_out, wired_span* body);

/** Re-classifies a moqctl_peek_type result for draft ver (MOQVER_*): a
 * Type unknown to the draft-19 table that ver does define gets ver's
 * classification, and *type is rewritten to the Type it stands for
 * (draft-18 0x1E -> REQUEST_OK). Every other peek passes through. */
int moqctl_type_ver(int ver, int peek, u64* type);

/** Reads only Type + Length at *at (no body check): MOQCTL_OK advances *at
 * past them; on MOQCTL_INSUFFICIENT *len is unset and *at may have moved. */
int moqctl_peek_header(wired_span buf, usz* at, u64* type, u16* len);

/** Whole-body decode verdict: r is a take's result after reading from the
 * start of a Message Body, off where it stopped. INSUFFICIENT (truncated
 * inside the Length) and OK with bytes left over are both a Length
 * mismatch, so VIOLATION (SS10); any other r passes through. */
int moqctl_body_end(int r, usz off, wired_span body);

#endif
