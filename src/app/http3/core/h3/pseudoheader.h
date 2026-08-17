#ifndef H3_PSEUDOHEADER_H
#define H3_PSEUDOHEADER_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 4.3.1. Request and response control data is carried in
 * pseudo-header fields whose names begin with ':'. All pseudo-header fields
 * MUST appear before any regular field. A request uses :method, :scheme,
 * :authority, :path; a response uses :status. A field block that places a
 * pseudo-header after a regular field, repeats a pseudo-header, carries an
 * unknown pseudo-header, or omits a required one is malformed. */

/** RFC 9114 4.3.1: which pseudo-header (or none/unknown) a field name is. */
typedef enum {
  H3_PH_NONE = 0, /* a regular (non-pseudo) field */
  H3_PH_METHOD,
  H3_PH_SCHEME,
  H3_PH_AUTHORITY,
  H3_PH_PATH,
  H3_PH_PROTOCOL, /* RFC 9220 3: Extended CONNECT's :protocol */
  H3_PH_STATUS,
  H3_PH_UNKNOWN /* a name beginning with ':' that is not known */
} h3_ph_kind;

/* Classify a field name of len bytes. Returns the pseudo-header kind, or
 * H3_PH_NONE for a regular field, or H3_PH_UNKNOWN for an
 * unrecognised ':'-prefixed name. */
h3_ph_kind h3_ph_classify(const u8* name, usz len);

/** Accumulates the pseudo-headers of one field section, in receipt order. */
typedef struct {
  u8 seen;        /* bitmask of QUIC_H3_PH_* kinds that appeared */
  u8 saw_regular; /* a regular field has been seen */
  u8 ok;          /* 0 once any ordering/duplicate/unknown rule is broken */
} h3_ph_set;

void h3_ph_init(h3_ph_set* p);

/* Feed the next field name. Maintains p->ok: a pseudo-header after a regular
 * field, a duplicate pseudo-header, or an unknown pseudo-header clears it. */
void h3_ph_field(h3_ph_set* p, const u8* name, usz len);

/* Whether the accumulated pseudo-headers form a valid request / response:
 * p->ok held and the required set is present (request: :method :scheme :path;
 * response: :status). Returns 1 valid, 0 malformed. */
int h3_ph_request_ok(const h3_ph_set* p);
int h3_ph_response_ok(const h3_ph_set* p);

#endif
