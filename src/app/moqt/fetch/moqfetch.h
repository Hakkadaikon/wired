#ifndef MOQFETCH_H
#define MOQFETCH_H

#include "app/moqt/ctl/moqctl.h"

/** @file
 * draft-ietf-moq-transport-19 FETCH: the FETCH (10.12) and FETCH_OK
 * (10.13) control messages, and the fetch data stream (11.4.4): the
 * FETCH_HEADER and the fetch Objects with their Serialization Flags,
 * including the End of Range markers (11.4.4.2).
 *
 * Message takes decode one whole Message Body (the bytes moqctl_peek_type
 * framed) and return MOQCTL_OK, MOQCTL_VIOLATION (malformed, or a Length
 * mismatch -- see moqctl_body_end) or MOQCTL_PARAMS_KVFMT. Stream takes
 * return MOQCTL_OK / MOQCTL_INSUFFICIENT (need more stream bytes) /
 * MOQCTL_VIOLATION and leave *off (and the sequence) unchanged unless OK.
 * Encoders return 1 ok, 0 if buf is too small (*off may then have
 * advanced).
 */

#define MOQFETCH_T_FETCH 0x16ULL
#define MOQFETCH_T_FETCH_OK 0x18ULL

/** REQUEST_ERROR code for a Joining Fetch naming no subscription of the
 * session (10.12.2; registry 15.11.2). */
#define MOQFETCH_ERR_INVALID_JOINING_REQUEST_ID 0x32ULL

/** Fetch Type (10.12 Table 6); any other value is a VIOLATION. */
#define MOQFETCH_STANDALONE 0x1ULL
#define MOQFETCH_RELATIVE_JOINING 0x2ULL
#define MOQFETCH_ABSOLUTE_JOINING 0x3ULL

/** FETCH (10.12.3 Figure 15). track/start/end are set for a Standalone
 * Fetch (10.12.1), joining_request_id/joining_start for the two Joining
 * Fetches (10.12.2). End Location is "last Object + 1" (Object 0 = the
 * whole End Group); its ordering against Start is the publisher's check
 * (INVALID_RANGE), not a decode error. */
typedef struct {
  u64           request_id;
  u64           fetch_type;
  moqctl_ftn    track;
  moqctl_loc    start;
  moqctl_loc    end;
  u64           joining_request_id;
  u64           joining_start;
  moqctl_params params;
} moqfetch_fetch;

int moqfetch_fetch_take(wired_span body, moqfetch_fetch* out);
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
  u64             request_id;
  u64             fetch_type; /* MOQFETCH_STANDALONE/RELATIVE/ABSOLUTE */
  int             is_joining;
  u64             joining_request_id; /* valid iff is_joining */
  u64             joining_start;      /* valid iff is_joining */
  moqctl_ftn      track;              /* valid iff !is_joining */
  moqctl_rangeloc range;              /* valid iff !is_joining */
  moqctl_params   params;
} moqfetch_req;

/** Decodes a draft-19 FETCH body (10.12) into the version-neutral model.
 * A Standalone Fetch's Start/End Location pair is normalized into range
 * (End Location's "+1, Object 0 = whole group" quirk resolved here); a
 * Joining Fetch leaves range zeroed. Same return contract as
 * moqfetch_fetch_take. */
int moqfetch_req19_take(wired_span body, moqfetch_req* out);
int moqfetch_req19_encode(wired_mspan buf, usz* off, const moqfetch_req* m);

/** Decodes a draft-22 FETCH body (SS "FETCH"): Request ID, Track Namespace,
 * Track Name, then Parameters. is_joining is always 0. range is the
 * LOCATION_FILTER parameter (0x21) if present, else "fetch everything"
 * (sk=ABS, start_group=0, start_object=0, ek=UNBOUNDED) per SS9.20.9's "If
 * omitted from FETCH ..., the fetch ... is unfiltered". Same return
 * contract as moqfetch_fetch_take. */
int moqfetch_req22_take(wired_span body, moqfetch_req* out);
int moqfetch_req22_encode(wired_mspan buf, usz* off, const moqfetch_req* m);

/** FETCH_OK (10.13 Figure 16). track_properties is the rest of the body. */
typedef struct {
  u64           end_of_track;
  moqctl_loc    end;
  moqctl_params params;
  wired_span    track_properties;
} moqfetch_ok;

int moqfetch_ok_take(wired_span body, moqfetch_ok* out);
int moqfetch_ok_encode(wired_mspan buf, usz* off, const moqfetch_ok* m);

/** FETCH_HEADER (11.4.4 Figure 26): Type 0x5 then Request ID. A Type
 * other than 0x5 is a VIOLATION. */
int moqfetch_hdr_take(wired_span buf, usz* off, u64* request_id);
int moqfetch_hdr_put(wired_mspan buf, usz* off, u64 request_id);

/** Serialization Flags (11.4.4.1 Tables 8/9, 11.4.4 Table 7). */
#define MOQFETCH_F_SUBGROUP_MASK 0x03ULL
#define MOQFETCH_F_OBJECT 0x04ULL
#define MOQFETCH_F_GROUP 0x08ULL
#define MOQFETCH_F_PRIORITY 0x10ULL
#define MOQFETCH_F_PROPS 0x20ULL
#define MOQFETCH_F_DATAGRAM 0x40ULL
#define MOQFETCH_EOR_NONEXISTENT 0x8CULL
#define MOQFETCH_EOR_UNKNOWN 0x10CULL

/** The "prior Object" state threaded through one fetch stream. Zero it,
 * then set descending when the FETCH's GROUP_ORDER is Descending (0x2):
 * Group ID Deltas run the other way (11.4.4.1). */
typedef struct {
  int descending;
  int have_loc;
  int have_subgroup;
  int have_priority;
  u64 group;
  u64 object;
  u64 subgroup;
  u64 priority;
} moqfetch_seq;

/** One fetch Object or End of Range marker, with every field resolved to
 * its absolute value. flags is the wire Serialization Flags; an End of
 * Range has flags MOQFETCH_EOR_*, group/object = the range's last
 * Location (inclusive), no subgroup/priority/properties and an empty
 * payload. has_subgroup is 0 for a Datagram-preference Object (0x40). */
typedef struct {
  u64        flags;
  u64        group;
  u64        object;
  int        has_subgroup;
  u64        subgroup;
  u64        priority;
  int        has_props;
  wired_span props; /* Object Properties' KVP bytes (no Length) */
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
