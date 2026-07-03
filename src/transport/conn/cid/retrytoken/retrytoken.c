#include "transport/conn/cid/retrytoken/retrytoken.h"

#include "common/bytes/util/ct.h"
#include "crypto/symmetric/hash/hash/hmac.h"

#define QUIC_RETRYTOKEN_MSG 64 /* addr + odcid, both bounded small */

static void copy_bytes(u8 *dst, const u8 *src, usz len) {
  for (usz i = 0; i < len; i++) dst[i] = src[i];
}

/* Concatenate addr and odcid into msg; returns the combined length, or 0 if
 * they do not fit. */
static usz build_msg(u8 *msg, const quic_retrytoken_in *in) {
  if (in->addr.n + in->odcid.n > QUIC_RETRYTOKEN_MSG) return 0;
  copy_bytes(msg, in->addr.p, in->addr.n);
  copy_bytes(msg + in->addr.n, in->odcid.p, in->odcid.n);
  return in->addr.n + in->odcid.n;
}

void quic_retrytoken_make(
    const u8 key[QUIC_RETRYTOKEN_KEY],
    const quic_retrytoken_in *in,
    u8 token[QUIC_RETRYTOKEN_LEN]) {
  u8  msg[QUIC_RETRYTOKEN_MSG];
  usz n = build_msg(msg, in);
  quic_hmac_sha256(
      quic_span_of(key, QUIC_RETRYTOKEN_KEY), quic_span_of(msg, n), token);
}

int quic_retrytoken_verify(
    const u8 key[QUIC_RETRYTOKEN_KEY],
    const quic_retrytoken_in *in,
    const u8 token[QUIC_RETRYTOKEN_LEN]) {
  u8 want[QUIC_RETRYTOKEN_LEN];
  quic_retrytoken_make(key, in, want);
  return quic_ct_diff32(want, token) == 0;
}
