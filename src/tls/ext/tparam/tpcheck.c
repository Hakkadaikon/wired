#include "tls/ext/tparam/tpcheck.h"

/* Whether the first n bytes of a and b are equal. */
static int bytes_eq(const u8 *a, const u8 *b, usz n)
{
    for (usz i = 0; i < n; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

int quic_tparam_cid_match(const u8 *got, usz got_len, const u8 *expected, usz exp_len)
{
    if (got_len != exp_len) return 0;
    return bytes_eq(got, expected, got_len);
}

int quic_tparam_check_initial_scid(const u8 *got, usz got_len,
                                   const u8 *observed, usz observed_len)
{
    return quic_tparam_cid_match(got, got_len, observed, observed_len);
}

int quic_tparam_check_original_dcid(const u8 *got, usz got_len,
                                    const u8 *sent_dcid, usz sent_len)
{
    return quic_tparam_cid_match(got, got_len, sent_dcid, sent_len);
}

int quic_tparam_check_retry_scid(int did_retry, int has_param,
                                 const u8 *got, usz got_len,
                                 const u8 *retry_scid, usz retry_len)
{
    if (did_retry != has_param) return 0; /* present iff a Retry was processed */
    if (!did_retry) return 1;             /* both absent: nothing to match */
    return quic_tparam_cid_match(got, got_len, retry_scid, retry_len);
}
