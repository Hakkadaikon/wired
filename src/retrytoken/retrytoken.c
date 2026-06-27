#include "retrytoken/retrytoken.h"
#include "hash/hmac.h"
#include "util/ct.h"

#define QUIC_RETRYTOKEN_MSG 64 /* addr + odcid, both bounded small */

static void copy_bytes(u8 *dst, const u8 *src, usz len)
{
    for (usz i = 0; i < len; i++) dst[i] = src[i];
}

/* Concatenate addr and odcid into msg; returns the combined length, or 0 if
 * they do not fit. */
static usz build_msg(u8 *msg, const u8 *addr, usz addr_len,
                     const u8 *odcid, usz odcid_len)
{
    if (addr_len + odcid_len > QUIC_RETRYTOKEN_MSG) return 0;
    copy_bytes(msg, addr, addr_len);
    copy_bytes(msg + addr_len, odcid, odcid_len);
    return addr_len + odcid_len;
}

void quic_retrytoken_make(const u8 key[QUIC_RETRYTOKEN_KEY],
                          const u8 *addr, usz addr_len,
                          const u8 *odcid, usz odcid_len,
                          u8 token[QUIC_RETRYTOKEN_LEN])
{
    u8 msg[QUIC_RETRYTOKEN_MSG];
    usz n = build_msg(msg, addr, addr_len, odcid, odcid_len);
    quic_hmac_sha256(key, QUIC_RETRYTOKEN_KEY, msg, n, token);
}

int quic_retrytoken_verify(const u8 key[QUIC_RETRYTOKEN_KEY],
                           const u8 *addr, usz addr_len,
                           const u8 *odcid, usz odcid_len,
                           const u8 token[QUIC_RETRYTOKEN_LEN])
{
    u8 want[QUIC_RETRYTOKEN_LEN];
    quic_retrytoken_make(key, addr, addr_len, odcid, odcid_len, want);
    return quic_ct_diff32(want, token) == 0;
}
