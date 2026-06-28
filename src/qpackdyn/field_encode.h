#ifndef QUIC_QPACKDYN_FIELD_ENCODE_H
#define QUIC_QPACKDYN_FIELD_ENCODE_H

#include "sys/syscall.h"

/* RFC 9204 4.5.2. Indexed Field Line referencing the dynamic table: pattern
 * 1Tiiiiii with T=0 (dynamic) and a 6-bit prefixed relative index. */
usz quic_qdyn_indexed_dynamic(u64 rel_index, u8 *out, usz cap, usz *out_len);

#endif
