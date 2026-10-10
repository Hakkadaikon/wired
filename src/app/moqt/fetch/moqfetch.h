#ifndef MOQFETCH_H
#define MOQFETCH_H

#include "app/moqt/ctl/moqctl.h"

/** @file
 * draft-ietf-moq-transport-18/19/22 FETCH: the FETCH (19 10.12, 22 9.11)
 * and FETCH_OK (19 10.13, 22 9.12) control messages, and the fetch data
 * stream (19 11.4.4, 22 11.4): the FETCH_HEADER and the fetch Objects
 * with their Serialization Flags, including the End of Range markers
 * (19 11.4.4.2). Takes with a ver argument decode that draft's layout.
 *
 * Message takes decode one whole Message Body (the bytes moqctl_peek_type
 * framed) and return MOQCTL_OK, MOQCTL_VIOLATION (malformed, or a Length
 * mismatch -- see moqctl_body_end) or MOQCTL_PARAMS_KVFMT. Stream takes
 * return MOQCTL_OK / MOQCTL_INSUFFICIENT (need more stream bytes) /
 * MOQCTL_VIOLATION and leave *off (and the sequence) unchanged unless OK.
 * Encoders return 1 ok, 0 if buf is too small (*off may then have
 * advanced).
 */

/** Control message type of FETCH (19 10.12). */
#define MOQFETCH_T_FETCH 0x16ULL
/** Control message type of FETCH_OK (19 10.13). */
#define MOQFETCH_T_FETCH_OK 0x18ULL

/** REQUEST_ERROR code for a Joining Fetch naming no subscription of the
 * session (10.12.2; registry 15.11.2). */
#define MOQFETCH_ERR_INVALID_JOINING_REQUEST_ID \
  MOQCTL_ERR_INVALID_JOINING_REQUEST_ID

/** Fetch Type (10.12 Table 6); any other value is a VIOLATION. */
#define MOQFETCH_STANDALONE 0x1ULL
/** Joining Fetch whose Joining Start counts groups back from the joined
 * subscription's Largest Group (10.12.2). */
#define MOQFETCH_RELATIVE_JOINING 0x2ULL
/** Joining Fetch whose Joining Start is an absolute Group ID (10.12.2). */
#define MOQFETCH_ABSOLUTE_JOINING 0x3ULL

/** FETCH (10.12.3 Figure 15). track/start/end are set for a Standalone
 * Fetch (10.12.1), joining_request_id/joining_start for the two Joining
 * Fetches (10.12.2). End Location is "last Object + 1" (Object 0 = the
 * whole End Group); its ordering against Start is the publisher's check
 * (INVALID_RANGE), not a decode error. */
typedef struct {
  /** Request ID of this FETCH. */
  u64 request_id;
  /** Fetch Type: MOQFETCH_STANDALONE / _RELATIVE_JOINING /
   * _ABSOLUTE_JOINING. */
  u64 fetch_type;
  /** Track Namespace + Track Name (Standalone only); views into the
   * decoded body. */
  moqctl_ftn track;
  /** Start Location (Standalone only). */
  moqctl_loc start;
  /** End Location as on the wire: last Object + 1, Object 0 = whole End
   * Group (Standalone only). */
  moqctl_loc end;
  /** Request ID of the subscription joined (Joining Fetches only). */
  u64 joining_request_id;
  /** Joining Start: groups back from the joined Largest Group (Relative)
   * or an absolute Group ID (Absolute). */
  u64 joining_start;
  /** Message Parameters (FETCH scope). */
  moqctl_params params;
} moqfetch_fetch;

/** Decodes a FETCH body in draft ver's layout (standalone vs joining
 * fields chosen by Fetch Type). Same return contract as the file note.
 * @param ver MOQVER_* id of the session
 * @param body one whole Message Body
 * @param out decoded message; views point into body
 * @return MOQCTL_OK, MOQCTL_VIOLATION or MOQCTL_PARAMS_KVFMT */
int moqfetch_fetch_take(int ver, wired_span body, moqfetch_fetch* out);
/** Encodes m as a FETCH body (no type/length framing) at *off.
 * @param buf output buffer
 * @param off write offset, advanced past the body
 * @param m message to encode
 * @return 1 ok, 0 if buf is too small */
int moqfetch_fetch_encode(wired_mspan buf, usz* off, const moqfetch_fetch* m);

/** Version-neutral FETCH request, an upper set of draft-19's Standalone +
 * Joining split and draft-22's single Track Namespace/Name + LOCATION_FILTER
 * parameter form. is_joining is only ever set by a d19 Relative/Absolute
 * Joining Fetch (draft-22 has no Joining Fetch); track/range are then
 * unused -- the publisher resolves the range from the joined subscription,
 * which this layer does not have. fetch_type keeps d19's own Fetch Type
 * (needed to tell a Relative Joining's relative joining_start from an
 * Absolute Joining's absolute one, SS10.12.2.1); it is always
 * MOQFETCH_STANDALONE for a draft-22 request. */
typedef struct {
  /** Request ID of this FETCH. */
  u64 request_id;
  /** MOQFETCH_STANDALONE / _RELATIVE_JOINING / _ABSOLUTE_JOINING. */
  u64 fetch_type;
  /** 1 for a draft-19 Relative/Absolute Joining Fetch. */
  int is_joining;
  /** Request ID of the joined subscription; valid iff is_joining. */
  u64 joining_request_id;
  /** Joining Start (relative or absolute per fetch_type); valid iff
   * is_joining. */
  u64 joining_start;
  /** Track Namespace + Track Name (views into the decoded body); valid
   * iff !is_joining. */
  moqctl_ftn track;
  /** Requested Location range; valid iff !is_joining. */
  moqctl_rangeloc range;
  /** Message Parameters (FETCH scope). */
  moqctl_params params;
} moqfetch_req;

/** Decodes a draft-19 FETCH body (10.12) into the version-neutral model.
 * A Standalone Fetch's Start/End Location pair is normalized into range
 * (End Location's "+1, Object 0 = whole group" quirk resolved here); a
 * Joining Fetch leaves range zeroed. Same return contract as
 * moqfetch_fetch_take. */
int moqfetch_req19_take(int ver, wired_span body, moqfetch_req* out);

/** Encodes m as a draft-19 FETCH body. Returns 0 (nothing written) for a
 * Standalone range d19 cannot carry (ek UNBOUNDED or sk not ABS), else 0
 * only if buf is too small. */
int moqfetch_req19_encode(wired_mspan buf, usz* off, const moqfetch_req* m);

/** Decodes a draft-22 FETCH body (SS "FETCH"): Request ID, Track Namespace,
 * Track Name, then Parameters. is_joining is always 0. range is the
 * LOCATION_FILTER parameter (0x21) if present, else "fetch everything"
 * (sk=ABS, start_group=0, start_object=0, ek=UNBOUNDED) per SS9.20.9's "If
 * omitted from FETCH ..., the fetch ... is unfiltered". Same return
 * contract as moqfetch_fetch_take. */
int moqfetch_req22_take(wired_span body, moqfetch_req* out);
/** Encodes m as a draft-22 FETCH body; range goes out as a LOCATION_FILTER
 * parameter (SS9.20.9).
 * @param buf output buffer
 * @param off write offset, advanced past the body
 * @param m request to encode (joining fields are not carried)
 * @return 1 ok, 0 if buf is too small */
int moqfetch_req22_encode(wired_mspan buf, usz* off, const moqfetch_req* m);

/** draft-22 SS9.20.15 FILL_PARAMETERS value (Number of Parameters +
 * Parameters, the FETCH parameter scope), decoded into the fields a fill
 * fetch stream needs: the range (LOCATION_FILTER, SS9.20.9 -- type 0x00 or
 * a zero-length value mean "no filter", ruling Q-02; an absent parameter
 * in a non-empty value sets inherit, SS3.4), the Group Order
 * (GROUP_ORDER 0x2 = Descending) and FILL_TIMEOUT as a varint of
 * milliseconds. */
typedef struct {
  /** 1 iff the value carries parameters but no LOCATION_FILTER: the fill
   * range is the subscription's own Location filter (draft-22 SS3.4). */
  int inherit;
  /** 1 iff a LOCATION_FILTER with a range (type != 0x00) was carried. */
  int has_filter;
  /** The fill range; valid iff has_filter. */
  moqctl_rangeloc range;
  /** 1 iff GROUP_ORDER is Descending (0x2). */
  int descending;
  /** 1 iff FILL_TIMEOUT was carried. */
  int has_timeout;
  /** FILL_TIMEOUT in milliseconds; valid iff has_timeout. */
  u64 timeout_ms;
} moqfetch_fill;

/** Decodes a FILL_PARAMETERS value (a zero-length one is "no
 * parameters"). The Parameters must fill value exactly; same return
 * contract as moqfetch_fetch_take. */
int moqfetch_fill_take(wired_span value, moqfetch_fill* out);

/** Encodes f as a FILL_PARAMETERS value; a fill without a filter sends
 * LOCATION_FILTER type 0x00 (SS9.20.9 None), never an empty list.
 * Returns 1 ok, 0 if buf is too small (*off may then have advanced). */
int moqfetch_fill_put(wired_mspan buf, usz* off, const moqfetch_fill* f);

/** FETCH_OK (10.13 Figure 16). track_properties is the rest of the body. */
typedef struct {
  /** End Of Track byte: 1 when the track has ended and End Location is
   * its final Object, else 0. */
  u64 end_of_track;
  /** End Location: draft-19 wire form (last Object + 1) from
   * moqfetch_ok_take, inclusive in draft-22. */
  moqctl_loc end;
  /** Message Parameters (FETCH_OK scope). */
  moqctl_params params;
  /** Track Properties: the body bytes after Parameters (view into the
   * decoded body). */
  wired_span track_properties;
} moqfetch_ok;

/** Decodes a FETCH_OK body in draft ver's layout.
 * @param ver MOQVER_* id of the session
 * @param body one whole Message Body
 * @param out decoded message; views point into body
 * @return MOQCTL_OK, MOQCTL_VIOLATION or MOQCTL_PARAMS_KVFMT */
int moqfetch_ok_take(int ver, wired_span body, moqfetch_ok* out);
/** Encodes m as a FETCH_OK body with m->end written as is (draft-22
 * inclusive form; moqfetch_ok19_encode for draft-19).
 * @param buf output buffer
 * @param off write offset, advanced past the body
 * @param m message to encode
 * @return 1 ok, 0 if buf is too small */
int moqfetch_ok_encode(wired_mspan buf, usz* off, const moqfetch_ok* m);

/** Inclusive End Object meaning "through the last Object of the group" --
 * draft-19's End Location Object 0 (10.13) in the inclusive model. */
#define MOQFETCH_OBJ_GROUP_END (~0ULL)

/** draft-19 End Location (last Object + 1, Object 0 = whole group) to the
 * inclusive model and back (draft-22 SS9.12 is inclusive on the wire). */
moqctl_loc moqfetch_end19_incl(moqctl_loc wire);
/** Inverse of moqfetch_end19_incl: inclusive end to the draft-19 wire
 * End Location (MOQFETCH_OBJ_GROUP_END becomes Object 0). */
moqctl_loc moqfetch_end19_wire(moqctl_loc incl);

/** The inclusive end of a FETCH range r, in the same model: a whole end
 * group (MOQCTL_REK_GROUP) is Object MOQFETCH_OBJ_GROUP_END, an open end
 * is largest (draft-22 SS9.20.9: an omitted FETCH end is Largest Object). */
moqctl_loc moqfetch_req_end(const moqctl_rangeloc* r, moqctl_loc largest);

/** FETCH_OK encode with m->end held inclusive, converted to the draft-19
 * wire form (moqfetch_end19_wire). moqfetch_ok_encode is the draft-22
 * form (wire == model); a draft-19 decode applies moqfetch_end19_incl to
 * moqfetch_ok_take's end. */
int moqfetch_ok19_encode(wired_mspan buf, usz* off, const moqfetch_ok* m);

/** FETCH_HEADER (11.4.4 Figure 26): Type 0x5 then Request ID. A Type
 * other than 0x5 is a VIOLATION. */
int moqfetch_hdr_take(wired_span buf, usz* off, u64* request_id);
/** Writes FETCH_HEADER (Type 0x5, Request ID) at *off.
 * @param buf output buffer
 * @param off write offset, advanced past the header
 * @param request_id Request ID of the FETCH this stream answers
 * @return 1 ok, 0 if buf is too small */
int moqfetch_hdr_put(wired_mspan buf, usz* off, u64 request_id);

/** Serialization Flags (11.4.4.1 Tables 8/9, 11.4.4 Table 7). */
#define MOQFETCH_F_SUBGROUP_MASK 0x03ULL
/** Object ID Delta present; absent means prior Object ID + 1. */
#define MOQFETCH_F_OBJECT 0x04ULL
/** Group ID Delta present; absent means the prior Object's group. */
#define MOQFETCH_F_GROUP 0x08ULL
/** Publisher Priority present; absent means the prior Object's. */
#define MOQFETCH_F_PRIORITY 0x10ULL
/** Object Properties (Length + KVPs) present. */
#define MOQFETCH_F_PROPS 0x20ULL
/** Datagram-preference Object: no Subgroup ID, subgroup bits ignored. */
#define MOQFETCH_F_DATAGRAM 0x40ULL
/** End of Non-Existent Range marker (11.4.4.2). */
#define MOQFETCH_EOR_NONEXISTENT 0x8CULL
/** End of Unknown Range marker (11.4.4.2). */
#define MOQFETCH_EOR_UNKNOWN 0x10CULL
/** draft-22 SS11.4.1 End of Timed-Out Range; accepted only when
 * moqfetch_seq.eor_timed_out is set. */
#define MOQFETCH_EOR_TIMED_OUT 0x20CULL

/** The "prior Object" state threaded through one fetch stream. Zero it,
 * then set descending when the FETCH's GROUP_ORDER is Descending (0x2):
 * Group ID Deltas run the other way (11.4.4.1); set eor_timed_out on a
 * stream of a session whose draft has MOQVER_CAP_EOR_TIMED_OUT, so the
 * 0x20C marker is an End of Range rather than a VIOLATION. */
typedef struct {
  /** 1 iff Group ID Deltas count downward (GROUP_ORDER Descending). */
  int descending;
  /** 1 iff the 0x20C End of Timed-Out Range marker is accepted. */
  int eor_timed_out;
  /** 1 once a prior Object or End of Range set group/object. */
  int have_loc;
  /** 1 iff the last Object (not End of Range) carried a Subgroup ID. */
  int have_subgroup;
  /** 1 once a prior Object set priority. */
  int have_priority;
  /** Prior item's Group ID; valid iff have_loc. */
  u64 group;
  /** Prior item's Object ID; valid iff have_loc. */
  u64 object;
  /** Last Object's Subgroup ID; valid iff have_subgroup. */
  u64 subgroup;
  /** Last Object's Publisher Priority; valid iff have_priority. */
  u64 priority;
} moqfetch_seq;

/** One fetch Object or End of Range marker, with every field resolved to
 * its absolute value. flags is the wire Serialization Flags; an End of
 * Range has flags MOQFETCH_EOR_*, group/object = the range's last
 * Location (inclusive), no subgroup/priority/properties and an empty
 * payload. has_subgroup is 0 for a Datagram-preference Object (0x40). */
typedef struct {
  /** Serialization Flags (MOQFETCH_F_* bits, or MOQFETCH_EOR_*). */
  u64 flags;
  /** Absolute Group ID. */
  u64 group;
  /** Absolute Object ID. */
  u64 object;
  /** 1 iff the Object has a Subgroup ID (not Datagram-preference). */
  int has_subgroup;
  /** Subgroup ID; valid iff has_subgroup. */
  u64 subgroup;
  /** Publisher Priority (explicit or inherited from the prior Object). */
  u64 priority;
  /** 1 iff Object Properties were carried (MOQFETCH_F_PROPS). */
  int has_props;
  /** Object Properties' KVP bytes without the Length; view into the
   * stream buffer. */
  wired_span props;
  /** Object payload; view into the stream buffer. */
  wired_span payload;
} moqfetch_obj;

/** Decodes one fetch Object / End of Range and advances *seq. VIOLATION
 * on: Serialization Flags >= 128 other than the two End of Range values,
 * a first Object missing Group ID Delta or Object ID Delta, a flag
 * referencing a prior Subgroup/Priority that does not exist, a Group or
 * Object ID out of 0..2^64-1. An End of Range carries the absolute
 * Group ID and Object ID only (11.4.4.2). */
int moqfetch_obj_take(
    wired_span buf, usz* off, moqfetch_seq* seq, moqfetch_obj* out);

/** Encodes o with the wire fields o->flags selects (deltas computed from
 * *seq), then advances *seq exactly as moqfetch_obj_take would. The flags
 * must agree with seq (an omitted field must equal what the prior Object
 * implies); 0 also for an invalid flags value. */
int moqfetch_obj_put(
    wired_mspan buf, usz* off, moqfetch_seq* seq, const moqfetch_obj* o);

#endif
