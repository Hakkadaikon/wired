#ifndef APP_MOQT_CTL_MOQCTL_LOC_H
#define APP_MOQT_CTL_MOQCTL_LOC_H

#include "app/moqt/ver/moqver.h"
#include "common/bytes/span/span.h"
#include "common/bytes/varint/varint.h"
#include "common/platform/sys/syscall.h"

/** Decode outcome: the item was decoded and *off advanced past it. */
#define MOQCTL_OK 1
/** Decode outcome: buf ends before the item does; *off is untouched and
 * the same call may succeed once more bytes arrive. */
#define MOQCTL_INSUFFICIENT 0
/** Decode outcome: the bytes break the draft's encoding rules; the caller
 * closes the session with PROTOCOL_VIOLATION (SS17.1). */
#define MOQCTL_VIOLATION (-1)

/* Message Type IDs this codec knows how to decode/encode (SS10 table). */
/** SETUP (SS10.4): the single Setup message each endpoint sends first on
 * its control stream. */
#define MOQCTL_T_SETUP 0x2F00ULL
/** GOAWAY (SS10.3): the sender asks the peer to migrate to a new
 * session. */
#define MOQCTL_T_GOAWAY 0x10ULL
/** SUBSCRIBE (SS10.6): subscriber requests a Track's Objects. */
#define MOQCTL_T_SUBSCRIBE 0x3ULL
/** SUBSCRIBE_OK (SS10.7): publisher accepts a SUBSCRIBE and assigns the
 * Track Alias. */
#define MOQCTL_T_SUBSCRIBE_OK 0x4ULL
/** REQUEST_ERROR (SS10.8): rejects any request, with an error code. */
#define MOQCTL_T_REQUEST_ERROR 0x5ULL
/** REQUEST_OK (SS10.5): generic acceptance of a request other than
 * SUBSCRIBE / FETCH. */
#define MOQCTL_T_REQUEST_OK 0x7ULL
/** PUBLISH_DONE (SS10.10): publisher ends a subscription. */
#define MOQCTL_T_PUBLISH_DONE 0xBULL
/** PUBLISH (SS10.9): publisher offers a Track to the subscriber. */
#define MOQCTL_T_PUBLISH 0x1DULL
/** PUBLISH_SKIPPED: known but not implemented; moqctl_peek_type returns
 * MOQCTL_KNOWN_UNIMPLEMENTED for it. */
#define MOQCTL_T_PUBLISH_SKIPPED 0xFULL
/** SUBSCRIBE_TRACKS: known but not implemented; moqctl_peek_type returns
 * MOQCTL_KNOWN_UNIMPLEMENTED for it. */
#define MOQCTL_T_SUBSCRIBE_TRACKS 0x51ULL
/** draft-18 SS10 table's PUBLISH_OK row (a REQUEST_OK alias per its
 * SS10.5); reserved in draft-19/22. */
#define MOQCTL_T_PUBLISH_OK18 0x1EULL
/** draft-22 SS9.10; unknown in draft-18/19. */
#define MOQCTL_T_PUBLISH_STATE_NOTIFY 0x22ULL

/** moqctl_peek_type results (in addition to MOQCTL_OK). */
#define MOQCTL_UNKNOWN_TYPE (-2)
/** moqctl_peek_type: Type is in the SS10 table but this subset has no
 * codec for it; the session answers NOT_SUPPORTED instead of closing. */
#define MOQCTL_KNOWN_UNIMPLEMENTED (-3)

/* Wire limits (draft-ietf-moq-transport-18/19/22: the same in all three;
 * draft-19 sections). */
/** Largest Message Body in bytes (SS10): the 16-bit Length field's
 * maximum, 2^16-1. */
#define MOQCTL_MAX_MSG_LEN 0xFFFF
/** Largest Reason Phrase in bytes (SS1.4.4); a longer one is a
 * VIOLATION. */
#define MOQCTL_MAX_REASON_LEN 1024
/** Largest GOAWAY New Session URI in bytes (SS10.3); a longer one is a
 * VIOLATION. */
#define MOQCTL_MAX_URI_LEN 8192
/** Most Track Namespace fields (SS1.5); more is a VIOLATION. */
#define MOQCTL_MAX_NS_FIELDS 32
/** Largest Full Track Name in bytes, namespace fields plus Track Name
 * (SS1.5); also the bound for a bare Track Namespace. */
#define MOQCTL_MAX_FTN_LEN 4096
/** Most Message Parameters one list holds: an implementation bound (no
 * draft limit); a longer list is a VIOLATION. */
#define MOQCTL_MAX_PARAMS 64

/** REQUEST_ERROR error codes actually used by this subset (SS17.3). */
#define MOQCTL_ERR_INTERNAL_ERROR 0x0ULL
/** NOT_SUPPORTED: the request type or a feature it needs is not
 * implemented here (the answer to MOQCTL_KNOWN_UNIMPLEMENTED). */
#define MOQCTL_ERR_NOT_SUPPORTED 0x3ULL
/** GOING_AWAY: the request arrived after this endpoint sent GOAWAY. */
#define MOQCTL_ERR_GOING_AWAY 0x6ULL
/** DOES_NOT_EXIST: no such Track / Track Namespace. */
#define MOQCTL_ERR_DOES_NOT_EXIST 0x10ULL
/** INVALID_RANGE: the requested Location range cannot be served (also
 * draft-18's code for an unsatisfiable filter). */
#define MOQCTL_ERR_INVALID_RANGE 0x11ULL
/** UNINTERESTED: the receiver does not want the offered Track. */
#define MOQCTL_ERR_UNINTERESTED 0x20ULL
/** UNAUTHORIZED: the request's authorization was refused. */
#define MOQCTL_ERR_UNAUTHORIZED 0x1ULL
/** MALFORMED_AUTH_TOKEN: an AUTHORIZATION TOKEN could not be parsed. */
#define MOQCTL_ERR_MALFORMED_AUTH_TOKEN 0x4ULL
/** INVALID_FILTER: a Range Filter parameter is unusable (delta overflow,
 * too many Ranges); not defined in draft-18. */
#define MOQCTL_ERR_INVALID_FILTER 0x36ULL
/** REDIRECT: retry elsewhere; the REQUEST_ERROR then carries a Redirect
 * (moqctl_redirect). */
#define MOQCTL_ERR_REDIRECT 0x34ULL
/** PREFIX_OVERLAP: a namespace prefix overlaps one already in use. */
#define MOQCTL_ERR_PREFIX_OVERLAP 0x30ULL
/** Codes that exist in only some drafts (moqctl_request_error_for). */
#define MOQCTL_ERR_EXCESSIVE_LOAD 0x9ULL
/** DUPLICATE_SUBSCRIPTION: draft-18 only; mapped to INTERNAL_ERROR on
 * later drafts, which allow several subscriptions per Track. */
#define MOQCTL_ERR_DUPLICATE_SUBSCRIPTION 0x19ULL
/** INVALID_JOINING_REQUEST_ID: a joining FETCH named an unknown request
 * (draft-18/19). */
#define MOQCTL_ERR_INVALID_JOINING_REQUEST_ID 0x32ULL
/** CONFLICTING_FILTERS: filters too costly to aggregate; not in draft-18,
 * where it is sent as EXCESSIVE_LOAD. */
#define MOQCTL_ERR_CONFLICTING_FILTERS 0x35ULL
/** moqtail-compatible INVALID_SWITCH (a bad SWITCH_FROM): 0x32 is
 * unassigned in draft-22 but is INVALID_JOINING_REQUEST_ID in draft-18/19,
 * so its meaning is per draft and it is sent only on a draft-22 session
 * that accepted a SWITCH_FROM. */
#define MOQCTL_ERR_INVALID_SWITCH 0x32ULL
/** UNSUPPORTED_EXTENSION: a standard code in draft-18/19/22 (22 SS12.3
 * Table 20; 18/19 SS10.6); SSTS also uses it for an un-negotiated
 * algorithm or a track already in another switching set. */
#define MOQCTL_ERR_UNSUPPORTED_EXTENSION 0x33ULL

/** PUBLISH_DONE status codes actually used by this subset (SS17.4). */
#define MOQCTL_DONE_INTERNAL_ERROR 0x0ULL
/** TRACK_ENDED: the publisher has no more Objects for the Track. */
#define MOQCTL_DONE_TRACK_ENDED 0x2ULL
/** GOING_AWAY: the publisher is migrating away (after GOAWAY). */
#define MOQCTL_DONE_GOING_AWAY 0x4ULL
/** UPDATE_FAILED: a REQUEST_UPDATE to the subscription could not be
 * applied. */
#define MOQCTL_DONE_UPDATE_FAILED 0x8ULL
/** Not in draft-22 (moqctl_publish_done_for). */
#define MOQCTL_DONE_SUBSCRIPTION_ENDED 0x3ULL
/** PUBLISH_DONE MALFORMED_TRACK (draft-18/19/22, 0x12 in each): a relay
 * detected the track violates MOQT (draft-22 12.1). */
#define MOQCTL_DONE_MALFORMED_TRACK 0x12ULL
/** draft-22 only, moqtail-compatible: "switched away from" (SWITCH_FROM
 * with Publish Done). Same wire value as draft-18/19 SUBSCRIPTION_ENDED,
 * which moqctl_publish_done_for maps to TRACK_ENDED on draft-22, so the
 * sender writes this code directly and never passes it through
 * moqctl_publish_done_for. */
#define MOQCTL_DONE_SWITCHED 0x3ULL

/** Session-level termination codes referenced by this codec (SS17.1). */
#define MOQCTL_CLOSE_INVALID_AUTHORITY 0x19ULL
/** INVALID_PATH: SETUP's PATH option is malformed or must be absent
 * (WebTransport). */
#define MOQCTL_CLOSE_INVALID_PATH 0x8ULL
/** KEY_VALUE_FORMATTING_ERROR: a Key-Value-Pair or Message Parameter
 * value does not match its encoding (moqctl_params_take's
 * MOQCTL_PARAMS_KVFMT). */
#define MOQCTL_CLOSE_KVFMT_ERROR 0x6ULL

/** Setup Option types (SS10.1.1). */
#define MOQCTL_OPT_PATH 0x1ULL
/** AUTHORITY option: the server authority on a raw-QUIC session (odd
 * type: Length-prefixed bytes). */
#define MOQCTL_OPT_AUTHORITY 0x5ULL
/** MAX_FILTER_RANGES option (even type: one varint), see
 * moqctl_setup.max_filter_ranges. */
#define MOQCTL_OPT_MAX_FILTER_RANGES 0x6ULL
/** MOQT_IMPLEMENTATION option: free-form, untrusted implementation name
 * (odd type: Length-prefixed bytes). */
#define MOQCTL_OPT_MOQT_IMPLEMENTATION 0x7ULL
/** MAX_REQUEST_UPDATES option (even type: one varint), see
 * moqctl_setup.max_request_updates. */
#define MOQCTL_OPT_MAX_REQUEST_UPDATES 0x8ULL
/** moqtail-compatible SSTS_ALGORITHMS (experimental, odd: Length + the
 * concatenated varint algorithm ids, no count). */
#define MOQCTL_OPT_SSTS_ALGORITHMS 0x9ULL

/** SSTS algorithm ids (moqtail): 0 bandwidth-weighted default, 0xff01
 * active-stream-depth backpressure. */
#define MOQCTL_SSTS_ALG_DEFAULT 0x0ULL
/** SSTS algorithm id 0xff01: switch on active-stream-depth backpressure
 * instead of bandwidth weight. */
#define MOQCTL_SSTS_ALG_BACKPRESSURE 0xff01ULL
/** Algorithm ids one decoded SSTS_ALGORITHMS option keeps. Known ids
 * (MOQCTL_SSTS_ALG_*) are kept first, then unknown ones in wire order
 * while room is left; the rest are parsed and dropped. */
#define MOQCTL_SSTS_MAX_ALGS 4

/** Message Parameter types (draft-ietf-moq-transport-19 15.7 Table 13). */
#define MOQCTL_PARAM_AUTHORIZATION_TOKEN 0x03ULL
/** OBJECT_DELIVERY_TIMEOUT: varint, milliseconds an Object may take to
 * deliver before it is dropped. */
#define MOQCTL_PARAM_OBJECT_DELIVERY_TIMEOUT 0x02ULL
/** SUBGROUP_DELIVERY_TIMEOUT: varint, milliseconds before an unfinished
 * Subgroup stream is reset. */
#define MOQCTL_PARAM_SUBGROUP_DELIVERY_TIMEOUT 0x06ULL
/** FORWARD: uint8 0 or 1; 0 pauses Object delivery for the subscription,
 * 1 resumes it. */
#define MOQCTL_PARAM_FORWARD 0x10ULL
/** RENDEZVOUS_TIMEOUT: a timeout value (encoding unstated by the draft;
 * varint assumed). */
#define MOQCTL_PARAM_RENDEZVOUS_TIMEOUT 0x04ULL
/** EXPIRES: varint, milliseconds until the subscription / namespace
 * state expires. */
#define MOQCTL_PARAM_EXPIRES 0x08ULL
/** LARGEST_OBJECT: Location of the largest Object the publisher has. */
#define MOQCTL_PARAM_LARGEST_OBJECT 0x09ULL
/** FILL_TIMEOUT: a timeout value (encoding unstated by the draft;
 * varint assumed). */
#define MOQCTL_PARAM_FILL_TIMEOUT 0x0AULL
/** SUBSCRIBER_PRIORITY: uint8 0..255, lower is more urgent; absent means
 * 128 (SS10.2.7). */
#define MOQCTL_PARAM_SUBSCRIBER_PRIORITY 0x20ULL
/** LOCATION_FILTER: which Locations the subscription starts/ends at
 * (MOQCTL_PENC_LOCFILTER, or MOQCTL_PENC_RANGELOC22 under draft-22). */
#define MOQCTL_PARAM_LOCATION_FILTER 0x21ULL
/** GROUP_ORDER: uint8, 1 ascending / 2 descending Group delivery order;
 * any other value is a VIOLATION. */
#define MOQCTL_PARAM_GROUP_ORDER 0x22ULL
/** SUBGROUP_FILTER: Range Filter on Subgroup IDs (moqctl_rangefilter). */
#define MOQCTL_PARAM_SUBGROUP_FILTER 0x25ULL
/** OBJECTID_FILTER: Range Filter on Object IDs (moqctl_rangefilter). */
#define MOQCTL_PARAM_OBJECTID_FILTER 0x26ULL
/** PRIORITY_FILTER: Range Filter on Publisher Priority
 * (moqctl_rangefilter). */
#define MOQCTL_PARAM_PRIORITY_FILTER 0x27ULL
/** OBJECT_PROPERTY_FILTER: Range Filter on one Object Property's value,
 * prefixed by the Property Type (moqctl_rangefilter.prop_type). */
#define MOQCTL_PARAM_OBJECT_PROPERTY_FILTER 0x28ULL
/** TRACK_PROPERTY_FILTER: Range Filter on one Track Property's value,
 * prefixed by the Property Type (moqctl_rangefilter.prop_type). */
#define MOQCTL_PARAM_TRACK_PROPERTY_FILTER 0x29ULL
/** NEW_GROUP_REQUEST: varint; asks the publisher to start a new Group. */
#define MOQCTL_PARAM_NEW_GROUP_REQUEST 0x32ULL
/** TRACK_NAMESPACE_PREFIX: bare Track Namespace (MOQCTL_PENC_NS). */
#define MOQCTL_PARAM_TRACK_NAMESPACE_PREFIX 0x34ULL
/** draft-22 only (SS9.20.15, SS9.20.21). */
#define MOQCTL_PARAM_FILL_PARAMETERS 0x23ULL
/** INCLUDE_PROPERTIES: draft-22 only (SS9.20.21), uint8 0 or 1. */
#define MOQCTL_PARAM_INCLUDE_PROPERTIES 0x35ULL
/** moqtail-compatible track-switching extensions: draft-22 only, in
 * SUBSCRIBE and REQUEST_UPDATE (subscription); unknown in draft-18/19. */
#define MOQCTL_PARAM_SWITCH_FROM 0x24ULL
/** SWITCHING_SET_ASSIGNMENT: moqtail-compatible, draft-22 only; value
 * decoded into moqctl_param.ssa. */
#define MOQCTL_PARAM_SWITCHING_SET_ASSIGNMENT 0x41ULL

/** SWITCH_FROM Mode values; any other Mode is a VIOLATION. */
#define MOQCTL_SWITCH_HARD 0
/** SWITCH_FROM Mode Soft (moqtail): the counterpart of
 * MOQCTL_SWITCH_HARD; the session layer decides what each does. */
#define MOQCTL_SWITCH_SOFT 1

/** Message contexts a Message Parameter may appear in, one bit each
 * (draft-ietf-moq-transport-19 10.2.x "MAY appear in"). REQUEST_OK and
 * REQUEST_UPDATE are split by the request they answer / update, since
 * 10.2.x qualifies several entries ("REQUEST_UPDATE (for a
 * subscription)"). */
#define MOQCTL_PCTX_SUBSCRIBE 0x1u
/** Context bit: SUBSCRIBE_OK. */
#define MOQCTL_PCTX_SUBSCRIBE_OK 0x2u
/** Context bit: PUBLISH. */
#define MOQCTL_PCTX_PUBLISH 0x4u
/** Context bit: REQUEST_OK answering PUBLISH (draft-18 PUBLISH_OK). */
#define MOQCTL_PCTX_PUBLISH_OK 0x8u
/** Context bit: FETCH. */
#define MOQCTL_PCTX_FETCH 0x10u
/** Context bit: FETCH_OK. */
#define MOQCTL_PCTX_FETCH_OK 0x20u
/** Context bit: TRACK_STATUS. */
#define MOQCTL_PCTX_TRACK_STATUS 0x40u
/** Context bit: REQUEST_OK answering TRACK_STATUS. */
#define MOQCTL_PCTX_TRACK_STATUS_OK 0x80u
/** Context bit: PUBLISH_NAMESPACE. */
#define MOQCTL_PCTX_PUBLISH_NAMESPACE 0x100u
/** Context bit: REQUEST_OK answering PUBLISH_NAMESPACE. */
#define MOQCTL_PCTX_PUBLISH_NAMESPACE_OK 0x200u
/** Context bit: SUBSCRIBE_NAMESPACE. */
#define MOQCTL_PCTX_SUBSCRIBE_NAMESPACE 0x400u
/** Context bit: REQUEST_OK answering SUBSCRIBE_NAMESPACE. */
#define MOQCTL_PCTX_SUBSCRIBE_NAMESPACE_OK 0x800u
/** Context bit: SUBSCRIBE_TRACKS. */
#define MOQCTL_PCTX_SUBSCRIBE_TRACKS 0x1000u
/** Context bit: REQUEST_OK answering SUBSCRIBE_TRACKS. */
#define MOQCTL_PCTX_SUBSCRIBE_TRACKS_OK 0x2000u
/** Context bit: REQUEST_UPDATE of a subscription. */
#define MOQCTL_PCTX_UPDATE_SUBSCRIPTION 0x4000u
/** Context bit: REQUEST_UPDATE of a FETCH. */
#define MOQCTL_PCTX_UPDATE_FETCH 0x8000u
/** Context bit: REQUEST_UPDATE of a SUBSCRIBE_NAMESPACE. */
#define MOQCTL_PCTX_UPDATE_SUBSCRIBE_NAMESPACE 0x10000u
/** Context bit: REQUEST_UPDATE of a SUBSCRIBE_TRACKS. */
#define MOQCTL_PCTX_UPDATE_SUBSCRIBE_TRACKS 0x20000u
/** Context bit: REQUEST_UPDATE of a PUBLISH_NAMESPACE. */
#define MOQCTL_PCTX_UPDATE_PUBLISH_NAMESPACE 0x40000u
/** Context bit: REQUEST_OK answering a REQUEST_UPDATE. */
#define MOQCTL_PCTX_REQUEST_UPDATE_OK 0x80000u
/** Every OK a REQUEST_OK may stand for (SS10.5). */
#define MOQCTL_PCTX_REQUEST_OK_ANY                                         \
  (MOQCTL_PCTX_PUBLISH_OK | MOQCTL_PCTX_TRACK_STATUS_OK |                  \
   MOQCTL_PCTX_PUBLISH_NAMESPACE_OK | MOQCTL_PCTX_SUBSCRIBE_NAMESPACE_OK | \
   MOQCTL_PCTX_SUBSCRIBE_TRACKS_OK | MOQCTL_PCTX_REQUEST_UPDATE_OK)

/** Message Parameter value encodings (SS10.2). */
#define MOQCTL_PENC_UINT8 0
/** One varint value, decoded into moqctl_param.vi. */
#define MOQCTL_PENC_VARINT 1
/** A Location (two varints), decoded into moqctl_param.loc. */
#define MOQCTL_PENC_LOCATION 2
/** Length-prefixed opaque bytes, viewed by moqctl_param.bytes. */
#define MOQCTL_PENC_BYTES 3
/** Length-prefixed Token structure (SS10.2.2 Figure 5), decoded into
 * moqctl_param.token; an undecodable Token is MOQCTL_PARAMS_KVFMT. */
#define MOQCTL_PENC_TOKEN 4
/** Length-prefixed Location Filter (SS5.1.2), decoded into
 * moqctl_param.lf and, version-neutral, into moqctl_param.rl/has_filter;
 * one not exactly its Length is a VIOLATION. */
#define MOQCTL_PENC_LOCFILTER 5
/** Bare Track Namespace (SS2.4.1, no Length prefix): moqctl_param.bytes
 * spans its encoding, which encode re-emits as is. */
#define MOQCTL_PENC_NS 6
/** draft-22 LOCATION_FILTER (SS9.20.9): no Length prefix, decoded by
 * moqctl_rangeloc22_take into moqctl_param.rl/has_filter. Selected only by
 * moqctl_params_take under draft-22 only. */
#define MOQCTL_PENC_RANGELOC22 7
/** Length-prefixed SWITCH_FROM value into moqctl_param.sw; a value not
 * exactly RequestID + Mode + Flags, a Mode other than Hard/Soft or a Flags
 * bit other than 0x80 is a VIOLATION. */
#define MOQCTL_PENC_SWITCHFROM 8
/** Length-prefixed SWITCHING_SET_ASSIGNMENT value into moqctl_param.ssa;
 * a truncated value, Weight outside 1..10 or bytes after the optional Rank
 * is a VIOLATION. */
#define MOQCTL_PENC_SSA 9

/** AUTHORIZATION TOKEN Alias Types (SS10.2.2). Which fields follow the
 * Alias Type is fixed per code point: DELETE/USE_ALIAS carry only the
 * Alias, USE_VALUE only Type+Value, REGISTER all three. */
#define MOQCTL_TOKEN_DELETE 0x0ULL
/** REGISTER: store Token Type + Value under Alias for later USE_ALIAS. */
#define MOQCTL_TOKEN_REGISTER 0x1ULL
/** USE_ALIAS: authorize with the token registered under Alias. */
#define MOQCTL_TOKEN_USE_ALIAS 0x2ULL
/** USE_VALUE: authorize with the inline Token Type + Value, unstored. */
#define MOQCTL_TOKEN_USE_VALUE 0x3ULL

/** Location Filter types (SS9.3.1). */
#define MOQCTL_FILTER_NEXT_GROUP 0x1ULL
/** Largest Object: start right after the publisher's largest Object. */
#define MOQCTL_FILTER_LARGEST 0x2ULL
/** AbsoluteStart: start at an explicit Location, no end. */
#define MOQCTL_FILTER_ABS_START 0x3ULL
/** AbsoluteRange: start at an explicit Location, end at start group +
 * End Group Delta. */
#define MOQCTL_FILTER_ABS_RANGE 0x4ULL

/** grease pattern (SS17.6): 0x7f*N + 0x9D. */
int moqctl_is_grease(u64 v);

/** Unknown-error-code-is-INTERNAL_ERROR normalization (SS17.6). Pass any
 * decoded error/status code through this before acting on it. */
u64 moqctl_known_request_error(u64 code);
/** PUBLISH_DONE counterpart of moqctl_known_request_error: a status code
 * this subset does not act on becomes MOQCTL_DONE_INTERNAL_ERROR. */
u64 moqctl_known_publish_done(u64 code);

/** Send-side code for draft ver (MOQVER_*): a REQUEST_ERROR / PUBLISH_DONE
 * code that ver does not define becomes ver's nearest defined code; any
 * other code is returned as is. Receive side stays tolerant (above). */
u64 moqctl_request_error_for(int ver, u64 code);
/** PUBLISH_DONE counterpart of moqctl_request_error_for (draft-22 has no
 * SUBSCRIPTION_ENDED, so it becomes TRACK_ENDED there). */
u64 moqctl_publish_done_for(int ver, u64 code);

/** draft-ietf-moq-transport-19 SS1.4.2 Location: two consecutive varints. */
typedef struct {
  /** Group ID. */
  u64 group;
  /** Object ID within the Group. */
  u64 object;
} moqctl_loc;

/** Location {group, object}. */
static inline moqctl_loc moqctl_loc_of(u64 group, u64 object) {
  moqctl_loc l = {group, object};
  return l;
}

/** Location A < Location B: (A.Group, A.Object) lexicographic. */
int moqctl_loc_less(moqctl_loc a, moqctl_loc b);

/** The earlier of a and b. */
static inline moqctl_loc moqctl_loc_min(moqctl_loc a, moqctl_loc b) {
  return moqctl_loc_less(a, b) ? a : b;
}

/** The later of a and b. */
static inline moqctl_loc moqctl_loc_max(moqctl_loc a, moqctl_loc b) {
  return moqctl_loc_less(a, b) ? b : a;
}

/** The Location just before excl (excl > {0, 0}): the previous Group's
 * last possible Object when excl starts a Group. */
static inline moqctl_loc moqctl_loc_prev(moqctl_loc excl) {
  return excl.object ? moqctl_loc_of(excl.group, excl.object - 1)
                     : moqctl_loc_of(excl.group - 1, VARINT_MAX);
}

/** Decodes a Location at *off. MOQCTL_OK or INSUFFICIENT. */
int moqctl_loc_take(wired_span buf, usz* off, moqctl_loc* out);
/** Encodes loc as two varints at *off; 1 ok, 0 when buf runs out. */
int moqctl_loc_put(wired_mspan buf, usz* off, moqctl_loc loc);

/** draft-ietf-moq-transport-19 SS9.3.1 Location Filter. */
typedef struct {
  /** Filter Type, one of MOQCTL_FILTER_*. */
  u64 type;
  /** Start Location; on the wire only for ABS_START / ABS_RANGE. */
  moqctl_loc start;
  /** End Group minus start.group; on the wire only for ABS_RANGE. */
  u64 end_group_delta;
} moqctl_locfilter;

/** Returns MOQCTL_OK / INSUFFICIENT / VIOLATION (unknown type, or
 * AbsoluteRange End Group overflowing 2^64-1). */
int moqctl_locfilter_take(wired_span buf, usz* off, moqctl_locfilter* out);
/** Encodes f (Type, then the fields its Type carries); 1 ok, 0 when buf
 * runs out. */
int moqctl_locfilter_put(wired_mspan buf, usz* off, const moqctl_locfilter* f);

/** Version-neutral LOCATION_FILTER range model. Start kind: REL_GROUP is "N
 * groups back from Largest.Group" (draft-19 type 0x1 is always REL_GROUP with
 * n=0; draft-22 type 0x01 carries n explicitly); NEXT_OBJ is Largest.Object+1
 * in Largest.Group; ABS is an explicit {start_group,start_object}. */
typedef enum {
  MOQCTL_RSK_REL_GROUP,
  MOQCTL_RSK_NEXT_OBJ,
  MOQCTL_RSK_ABS
} moqctl_rsk;

/** End kind: UNBOUNDED (open-ended), GROUP (ends at the last Object of
 * end_group, no explicit end object), OBJ (ends at {end_group,end_object}
 * inclusive). */
typedef enum {
  MOQCTL_REK_UNBOUNDED,
  MOQCTL_REK_GROUP,
  MOQCTL_REK_OBJ
} moqctl_rek;

/** Version-neutral LOCATION_FILTER range. start_group doubles as the
 * relative "N groups back" count when sk == REL_GROUP (there is no
 * Largest.Group at decode time to resolve it against), and as the
 * absolute start group when sk == ABS. end_group is always absolute: the
 * draft-22 End Group Delta is resolved against start_group at decode time
 * and re-derived as a delta at encode time. */
typedef struct {
  /** How the start is expressed (moqctl_rsk). */
  moqctl_rsk sk;
  /** Absolute start Group (ABS) or groups-back count (REL_GROUP). */
  u64 start_group;
  /** Start Object ID; meaningful only when sk == ABS. */
  u64 start_object;
  /** How the end is expressed (moqctl_rek). */
  moqctl_rek ek;
  /** Absolute last Group; meaningful unless ek == UNBOUNDED. */
  u64 end_group;
  /** Last Object ID, inclusive; meaningful only when ek == OBJ. */
  u64 end_object;
} moqctl_rangeloc;

/** draft-19 LOCATION_FILTER value codec (SS5.1.2/SS10.2.9). Always decodes/
 * encodes a present filter -- draft-19 has no "present but empty" wire
 * form at this layer; absence is the caller's param-presence check.
 * Returns MOQCTL_OK / INSUFFICIENT / VIOLATION (unknown type, or
 * AbsoluteRange End Group overflowing 2^64-1). */
int moqctl_rangeloc19_take(wired_span buf, usz* off, moqctl_rangeloc* out);
/** Encodes r in draft-19's Location Filter form; 1 ok, 0 when buf runs
 * out. */
int moqctl_rangeloc19_put(wired_mspan buf, usz* off, const moqctl_rangeloc* r);

/** draft-22 LOCATION_FILTER value codec (SS9.20.9). *has_filter is set to 0
 * and *out zeroed when Location Filter Type is 0x00 (None) -- draft-19
 * has no such "present but empty" form.
 * Returns MOQCTL_OK / INSUFFICIENT / VIOLATION (unknown type >= 0x06, or
 * End Group Delta overflowing 2^64-1). */
int moqctl_rangeloc22_take(
    wired_span buf, usz* off, int* has_filter, moqctl_rangeloc* out);
/** Encodes r in draft-22's form, or Type 0x00 (None) when has_filter is
 * 0; 1 ok, 0 when buf runs out. */
int moqctl_rangeloc22_put(
    wired_mspan buf, usz* off, int has_filter, const moqctl_rangeloc* r);

/** Ranges one decoded Range Filter value holds (SS10.2.10-10.2.14); a
 * value with more marks the filter invalid -- the receiver's advertised
 * MAX_FILTER_RANGES (SS10.4) is at most this. */
#define MOQCTL_MAX_RANGES 4

/** One inclusive Range of a Range Filter (SS10.2.10): [start, end], or
 * [start, inf) when the final End was omitted. */
typedef struct {
  /** First matching value, absolute (deltas already resolved). */
  u64 start;
  /** Last matching value, inclusive; valid iff has_end. */
  u64 end;
  /** 0 when the final Range is open-ended. */
  int has_end;
} moqctl_range;

/** A decoded Range Filter parameter value (SS10.2.10-10.2.14): SetID,
 * the 0x28/0x29 Property Type, and the delta-resolved Ranges. remove
 * marks a zero-length value (the REQUEST_UPDATE delete); invalid marks
 * a delta summing past 2^64-1 or more than MOQCTL_MAX_RANGES Ranges --
 * both call for REQUEST_ERROR INVALID_FILTER at the message layer, not
 * a session close, so they decode OK and flag instead. */
typedef struct {
  /** SetID: the filter set this Range Filter belongs to. */
  u64 set_id;
  /** 1 for the Property filters (0x28/0x29), which carry prop_type. */
  int has_prop;
  /** Property Type the Ranges apply to; valid iff has_prop. */
  u64 prop_type;
  /** 1 for a zero-length value: delete this filter (REQUEST_UPDATE). */
  int remove;
  /** 1 when the value is unusable (see above): answer INVALID_FILTER. */
  int invalid;
  /** Ranges decoded into r, at most MOQCTL_MAX_RANGES. */
  usz n;
  /** The Ranges in wire order (each start is a delta past the previous
   * end, so they ascend). */
  moqctl_range r[MOQCTL_MAX_RANGES];
} moqctl_rangefilter;

/** Decodes a Range Filter parameter's value bytes (exactly its Length).
 * ptype (MOQCTL_PARAM_*_FILTER) selects the Property Type prefix. OK or
 * MOQCTL_PARAMS_KVFMT (truncated structure). */
int moqctl_rangefilter_take(
    u64 ptype, wired_span value, moqctl_rangefilter* out);

/** Encodes f as a Range Filter value (no parameter Type/Length around
 * it). 1 ok, 0 when buf runs out. */
int moqctl_rangefilter_put(
    wired_mspan buf, usz* off, u64 ptype, const moqctl_rangefilter* f);

/** draft-ietf-moq-transport-19 SS1.5 Track Namespace: up to
 * MOQCTL_MAX_NS_FIELDS fields, each a byte-string view into the
 * decode input (or caller-owned storage on encode). */
typedef struct {
  /** Namespace fields in order; each non-empty (views, not copies). */
  wired_span fields[MOQCTL_MAX_NS_FIELDS];
  /** Number of fields used, 0..MOQCTL_MAX_NS_FIELDS. */
  usz n;
} moqctl_ns;

/** Full Track Name: Track Namespace + Track Name (may be empty). */
typedef struct {
  /** Track Namespace. */
  moqctl_ns ns;
  /** Track Name bytes (view); may be empty. */
  wired_span name;
} moqctl_ftn;

/** VIOLATION on: a field of length 0, >32 fields, or total (namespace +
 * name) bytes > MOQCTL_MAX_FTN_LEN. */
int moqctl_ftn_take(wired_span buf, usz* off, moqctl_ftn* out);
/** Encodes f as Track Namespace then Track Name; 1 ok, 0 when buf runs
 * out. */
int moqctl_ftn_put(wired_mspan buf, usz* off, const moqctl_ftn* f);

/** Track Namespace alone (no Track Name): VIOLATION on a field of length
 * 0, >32 fields, or field lengths summing past MOQCTL_MAX_FTN_LEN.
 * Exposed separately for contexts that decode a bare Track Namespace. */
int moqctl_ns_take(wired_span buf, usz* off, moqctl_ns* out);
/** Encodes a bare Track Namespace (count + Length-prefixed fields);
 * 0 when buf runs out. */
int moqctl_ns_put(wired_mspan buf, usz* off, const moqctl_ns* ns);

/** Encodes a bare Track Namespace (field count + fields). Returns 1 ok,
 * 0 if buf is too small (*off may then have advanced). */
int moqctl_ns_put(wired_mspan buf, usz* off, const moqctl_ns* ns);

/** Sum of the Track Namespace Field Lengths (SS2.4.1 namespace length). */
usz moqctl_ns_bytelen(const moqctl_ns* ns);

/** Length (vi64) + that many bytes, as a view into buf (Track Name and
 * every other length-prefixed byte string). MOQCTL_OK or INSUFFICIENT;
 * on INSUFFICIENT *off may have advanced past the Length. */
int moqctl_name_take(wired_span buf, usz* off, wired_span* name);

/** Length (vi64) + bytes. Returns 1 ok, 0 if buf is too small (*off may
 * then have advanced). */
int moqctl_name_put(wired_mspan buf, usz* off, wired_span name);

#endif
