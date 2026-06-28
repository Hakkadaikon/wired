#ifndef QUIC_RNG_CIDGEN_H
#define QUIC_RNG_CIDGEN_H

#include "sys/syscall.h"

/* Connection ID generation (RFC 9000 5.1). */

/* A connection ID is 1..20 bytes. */
int quic_cid_len_valid(u8 len);

/* Generate a len-byte random connection ID into cid.
   Returns 1 on success, 0 if len is out of range or RNG fails. */
int quic_cid_generate(u8 *cid, u8 len);

#endif
