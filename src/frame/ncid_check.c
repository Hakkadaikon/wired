#include "frame/ncid_check.h"

/* RFC 9000 5.1.1: a connection ID is 1 to 20 bytes in QUIC v1. */
static int ncid_check_cid_len_ok(u8 cid_len)
{
    return cid_len >= QUIC_NCID_CHECK_MIN_LEN && cid_len <= QUIC_NCID_CHECK_MAX_LEN;
}

/* RFC 9000 19.15: Retire Prior To must not exceed the Sequence Number. */
int quic_ncid_check(u64 seq, u64 retire_prior_to, u8 cid_len)
{
    return retire_prior_to <= seq && ncid_check_cid_len_ok(cid_len);
}
