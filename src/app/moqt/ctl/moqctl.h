#ifndef MOQCTL_H
#define MOQCTL_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

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
 */

#define MOQCTL_OK 1
#define MOQCTL_INSUFFICIENT 0
#define MOQCTL_VIOLATION (-1)

/* Message Type IDs this codec knows how to decode/encode (SS10 table). */
#define MOQCTL_T_SETUP 0x2F00ULL
#define MOQCTL_T_GOAWAY 0x10ULL
#define MOQCTL_T_SUBSCRIBE 0x3ULL
#define MOQCTL_T_SUBSCRIBE_OK 0x4ULL
#define MOQCTL_T_REQUEST_ERROR 0x5ULL
#define MOQCTL_T_REQUEST_OK 0x7ULL
#define MOQCTL_T_PUBLISH_DONE 0xBULL
#define MOQCTL_T_PUBLISH 0x1DULL

/** moqctl_peek_type results (in addition to MOQCTL_OK). */
#define MOQCTL_UNKNOWN_TYPE (-2)
#define MOQCTL_KNOWN_UNIMPLEMENTED (-3)

/* Wire limits (draft-ietf-moq-transport-19). */
#define MOQCTL_MAX_MSG_LEN 0xFFFF  /* SS10: 2^16-1 */
#define MOQCTL_MAX_REASON_LEN 1024 /* SS1.4.4 */
#define MOQCTL_MAX_URI_LEN 8192    /* SS10.3 GOAWAY */
#define MOQCTL_MAX_NS_FIELDS 32    /* SS1.5 */
#define MOQCTL_MAX_FTN_LEN 4096    /* SS1.5 */
#define MOQCTL_MAX_PARAMS 64       /* implementation bound */

/** REQUEST_ERROR error codes actually used by this subset (SS17.3). */
#define MOQCTL_ERR_INTERNAL_ERROR 0x0ULL
#define MOQCTL_ERR_NOT_SUPPORTED 0x3ULL
#define MOQCTL_ERR_GOING_AWAY 0x6ULL
#define MOQCTL_ERR_DOES_NOT_EXIST 0x10ULL
#define MOQCTL_ERR_INVALID_RANGE 0x11ULL
#define MOQCTL_ERR_UNINTERESTED 0x20ULL
#define MOQCTL_ERR_UNAUTHORIZED 0x1ULL
#define MOQCTL_ERR_INVALID_FILTER 0x36ULL
#define MOQCTL_ERR_REDIRECT 0x34ULL

/** PUBLISH_DONE status codes actually used by this subset (SS17.4). */
#define MOQCTL_DONE_INTERNAL_ERROR 0x0ULL
#define MOQCTL_DONE_TRACK_ENDED 0x2ULL
#define MOQCTL_DONE_GOING_AWAY 0x4ULL

/** Session-level termination codes referenced by this codec (SS17.1). */
#define MOQCTL_CLOSE_INVALID_AUTHORITY 0x19ULL
#define MOQCTL_CLOSE_INVALID_PATH 0x8ULL
#define MOQCTL_CLOSE_KVFMT_ERROR 0x6ULL

/** Setup Option types (SS10.1.1). */
#define MOQCTL_OPT_PATH 0x1ULL
#define MOQCTL_OPT_AUTHORITY 0x5ULL
#define MOQCTL_OPT_MOQT_IMPLEMENTATION 0x7ULL

/** Message Parameter types this subset encodes/decodes. */
#define MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT 0x02ULL
#define MOQCTL_PARAM_SUBGROUP_DELIVERY_TIMEOUT 0x06ULL
#define MOQCTL_PARAM_FORWARD 0x10ULL

/** Message Parameter value encodings (SS10.2). */
#define MOQCTL_PENC_UINT8 0
#define MOQCTL_PENC_VARINT 1
#define MOQCTL_PENC_LOCATION 2
#define MOQCTL_PENC_BYTES 3

/** Location Filter types (SS9.3.1). */
#define MOQCTL_FILTER_NEXT_GROUP 0x1ULL
#define MOQCTL_FILTER_LARGEST 0x2ULL
#define MOQCTL_FILTER_ABS_START 0x3ULL
#define MOQCTL_FILTER_ABS_RANGE 0x4ULL

/** grease pattern (SS17.6): 0x7f*N + 0x9D. */
int moqctl_is_grease(u64 v);

/** Unknown-error-code-is-INTERNAL_ERROR normalization (SS17.6). Pass any
 * decoded error/status code through this before acting on it. */
u64 moqctl_known_request_error(u64 code);
u64 moqctl_known_publish_done(u64 code);

/** draft-ietf-moq-transport-19 SS1.4.2 Location: two consecutive varints. */
typedef struct {
  u64 group;
  u64 object;
} moqctl_loc;

/** Location A < Location B: (A.Group, A.Object) lexicographic. */
int moqctl_loc_less(moqctl_loc a, moqctl_loc b);

int moqctl_loc_take(wired_span buf, usz* off, moqctl_loc* out);
int moqctl_loc_put(wired_mspan buf, usz* off, moqctl_loc loc);

/** draft-ietf-moq-transport-19 SS9.3.1 Location Filter. */
typedef struct {
  u64        type; /* QUIC_MOQCTL_FILTER_* */
  moqctl_loc start;
  u64        end_group_delta; /* only when type == ABS_RANGE */
} moqctl_locfilter;

/** Returns MOQCTL_OK / INSUFFICIENT / VIOLATION (unknown type, or
 * AbsoluteRange End Group overflowing 2^64-1). */
int moqctl_locfilter_take(wired_span buf, usz* off, moqctl_locfilter* out);
int moqctl_locfilter_put(wired_mspan buf, usz* off, const moqctl_locfilter* f);

/** draft-ietf-moq-transport-19 SS1.5 Track Namespace: up to
 * MOQCTL_MAX_NS_FIELDS fields, each a byte-string view into the
 * decode input (or caller-owned storage on encode). */
typedef struct {
  wired_span fields[MOQCTL_MAX_NS_FIELDS];
  usz        n;
} moqctl_ns;

/** Full Track Name: Track Namespace + Track Name (may be empty). */
typedef struct {
  moqctl_ns  ns;
  wired_span name;
} moqctl_ftn;

/** VIOLATION on: a field of length 0, >32 fields, or total (namespace +
 * name) bytes > MOQCTL_MAX_FTN_LEN. */
int moqctl_ftn_take(wired_span buf, usz* off, moqctl_ftn* out);
int moqctl_ftn_put(wired_mspan buf, usz* off, const moqctl_ftn* f);

/** Track Namespace alone (no Track Name): same VIOLATION rules as the
 * namespace half of moqctl_ftn_take (field length 0, >32 fields).
 * Exposed separately for contexts that decode a bare Track Namespace. */
int moqctl_ns_take(wired_span buf, usz* off, moqctl_ns* out);

/** Exact byte comparison (SS1.5): 1 if equal, 0 otherwise. */
int moqctl_ftn_eq(const moqctl_ftn* a, const moqctl_ftn* b);

/** draft-ietf-moq-transport-19 SS1.4.4 Reason Phrase: Length + UTF-8 bytes,
 * length capped at MOQCTL_MAX_REASON_LEN. */
typedef wired_span moqctl_reason;

int moqctl_reason_take(wired_span buf, usz* off, moqctl_reason* out);
int moqctl_reason_put(wired_mspan buf, usz* off, moqctl_reason reason);

/** draft-ietf-moq-transport-19 SS10.2 Message Parameter: Type Delta +
 * Value. Decoded absolute type + encoding-tagged value. */
typedef struct {
  u64        type;
  int        enc;   /* QUIC_MOQCTL_PENC_* */
  u64        u8v;   /* PENC_UINT8 */
  u64        vi;    /* PENC_VARINT */
  moqctl_loc loc;   /* PENC_LOCATION */
  wired_span bytes; /* PENC_BYTES */
} moqctl_param;

/** A decoded/to-encode Message Parameter list. msg_type selects which
 * types are legal in this list (SS10.2 Parameter Scope) and which
 * encoding each known type uses. */
typedef struct {
  moqctl_param items[MOQCTL_MAX_PARAMS];
  usz          n;
} moqctl_params;

/** Decodes count-prefixed Message Parameters. VIOLATION on: cumulative
 * Type overflow, unknown Type, duplicate Type, a known Type appearing in
 * a msg_type where it is not permitted, or a known Type's Value not
 * matching its defined encoding (mapped by the caller to
 * KEY_VALUE_FORMATTING_ERROR rather than PROTOCOL_VIOLATION -- see
 * moqctl_params_take's return contract below). */
#define MOQCTL_PARAMS_KVFMT (-4)
int moqctl_params_take(
    wired_span buf, usz* off, u64 msg_type, moqctl_params* out);
int moqctl_params_put(wired_mspan buf, usz* off, const moqctl_params* params);

/** draft-ietf-moq-transport-19 SS10.4 SETUP: Setup Options are a KVP list
 * (unknown options ignored on decode -- not surfaced here). PATH/AUTHORITY
 * are surfaced explicitly since WebTransport-context rejection is a
 * session-layer decision. */
typedef struct {
  int        has_path;
  wired_span path;
  int        has_authority;
  wired_span authority;
  int        has_implementation;
  wired_span implementation;
} moqctl_setup;

int moqctl_setup_take(wired_span buf, usz* off, moqctl_setup* out);
int moqctl_setup_encode(wired_mspan buf, usz* off, const moqctl_setup* s);

/** draft-ietf-moq-transport-19 SS10.6 SUBSCRIBE. */
typedef struct {
  u64           request_id;
  moqctl_ftn    name;
  moqctl_params params;
} moqctl_subscribe;

int moqctl_subscribe_take(wired_span buf, usz* off, moqctl_subscribe* out);
int moqctl_subscribe_encode(
    wired_mspan buf, usz* off, const moqctl_subscribe* m);

/** draft-ietf-moq-transport-19 SS10.7 SUBSCRIBE_OK. track_properties is
 * the residual span (this codec does not parse Properties -- data-layer
 * scope). */
typedef struct {
  u64           track_alias;
  moqctl_params params;
  wired_span    track_properties;
} moqctl_subscribe_ok;

int moqctl_subscribe_ok_take(
    wired_span buf, usz* off, moqctl_subscribe_ok* out);
int moqctl_subscribe_ok_encode(
    wired_mspan buf, usz* off, const moqctl_subscribe_ok* m);

/** draft-ietf-moq-transport-19 SS10.9 PUBLISH. */
typedef struct {
  u64           request_id;
  moqctl_ftn    name;
  u64           track_alias;
  moqctl_params params;
  wired_span    track_properties;
} moqctl_publish;

int moqctl_publish_take(wired_span buf, usz* off, moqctl_publish* out);
int moqctl_publish_encode(wired_mspan buf, usz* off, const moqctl_publish* m);

/** draft-ietf-moq-transport-19 SS10.5 REQUEST_OK. Non-empty
 * track_properties is only legal for the TRACK_STATUS_OK variant; this
 * codec always decodes the residual bytes and lets the caller (which
 * knows which request it answers) enforce SS10.5's "MUST be empty for
 * PUBLISH_OK etc." rule. */
typedef struct {
  moqctl_params params;
  wired_span    track_properties;
} moqctl_request_ok;

int moqctl_request_ok_take(wired_span buf, usz* off, moqctl_request_ok* out);
int moqctl_request_ok_encode(
    wired_mspan buf, usz* off, const moqctl_request_ok* m);

/** draft-ietf-moq-transport-19 SS10.8 REQUEST_ERROR redirect (SS10.8.1). */
typedef struct {
  wired_span connect_uri;
  moqctl_ns  track_namespace;
  wired_span track_name;
} moqctl_redirect;

/** draft-ietf-moq-transport-19 SS10.8 REQUEST_ERROR. has_redirect is only
 * legal when error_code == MOQCTL_ERR_REDIRECT (checked on
 * encode/decode: a Redirect present with any other code, or absent with
 * REDIRECT, is a VIOLATION since it desyncs Length from Body). */
typedef struct {
  u64             error_code;
  u64             retry_interval;
  moqctl_reason   reason;
  int             has_redirect;
  moqctl_redirect redirect;
} moqctl_request_error;

int moqctl_request_error_take(
    wired_span buf, usz* off, moqctl_request_error* out);
int moqctl_request_error_encode(
    wired_mspan buf, usz* off, const moqctl_request_error* m);

/** draft-ietf-moq-transport-19 SS10.10 PUBLISH_DONE. */
typedef struct {
  u64           status_code;
  u64           stream_count;
  moqctl_reason reason;
} moqctl_publish_done;

int moqctl_publish_done_take(
    wired_span buf, usz* off, moqctl_publish_done* out);
int moqctl_publish_done_encode(
    wired_mspan buf, usz* off, const moqctl_publish_done* m);

/** draft-ietf-moq-transport-19 SS10.3 GOAWAY. */
typedef struct {
  wired_span new_session_uri;
  u64        timeout;
} moqctl_goaway;

int moqctl_goaway_take(wired_span buf, usz* off, moqctl_goaway* out);
int moqctl_goaway_encode(wired_mspan buf, usz* off, const moqctl_goaway* m);

/** Common envelope: reads Type (vi64) + Length (16-bit BE) at *off,
 * without consuming past MOQCTL_OK's Type+Length header. On
 * MOQCTL_OK, *type_out is the Message Type, *body is the Message
 * Body view (exactly Length bytes, already bounds-checked against buf),
 * and *off has advanced past Type+Length+Body (the whole message).
 * MOQCTL_INSUFFICIENT: header or body not fully in buf yet.
 * MOQCTL_UNKNOWN_TYPE: Type is not in the SS10 table (caller
 * closes). MOQCTL_KNOWN_UNIMPLEMENTED: Type is a known-but-
 * unimplemented ID (REQUEST_UPDATE/FETCH/TRACK_STATUS/PUBLISH_NAMESPACE/
 * SUBSCRIBE_NAMESPACE/SUBSCRIBE_TRACKS/NAMESPACE/NAMESPACE_DONE/
 * PUBLISH_SKIPPED); caller replies NOT_SUPPORTED rather than closing. */
int moqctl_peek_type(wired_span buf, usz* off, u64* type_out, wired_span* body);

#endif
