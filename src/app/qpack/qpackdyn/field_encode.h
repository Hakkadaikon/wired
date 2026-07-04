#ifndef QUIC_QPACKDYN_FIELD_ENCODE_H
#define QUIC_QPACKDYN_FIELD_ENCODE_H

#include "common/bytes/span/span.h"

/* RFC 9204 4.5.2. Indexed Field Line referencing the dynamic table: pattern
 * 1Tiiiiii with T=0 (dynamic) and a 6-bit prefixed relative index. Returns
 * bytes written (also stored in out->len), or 0 if it does not fit. */
usz quic_qdyn_indexed_dynamic(u64 rel_index, quic_obuf* out);

#endif
