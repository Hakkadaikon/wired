#ifndef QUIC_FRAME_NCID_CHECK_H
#define QUIC_FRAME_NCID_CHECK_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 19.15: NEW_CONNECTION_ID is malformed (FRAME_ENCODING_ERROR) if
 * Retire Prior To is greater than the Sequence Number, or the connection ID
 * length is outside 1..20. */

#define QUIC_NCID_CHECK_MIN_LEN 1
#define QUIC_NCID_CHECK_MAX_LEN 20

/* Returns 1 if retire_prior_to <= seq and 1 <= cid_len <= 20, else 0. */
int quic_ncid_check(u64 seq, u64 retire_prior_to, u8 cid_len);

#endif
