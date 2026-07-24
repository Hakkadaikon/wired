#include "transport/conn/cid/sreset/sreset.h"

#include "common/bytes/util/ct.h"
#include "common/bytes/util/num.h"
#include "crypto/symmetric/hash/hash/hmac.h"

void quic_sreset_token(
    const u8  key[QUIC_SRESET_KEY],
    const u8* cid,
    usz       cid_len,
    u8        token[QUIC_SRESET_TOKEN]) {
  u8 mac[QUIC_SHA256_DIGEST];
  quic_hmac_sha256(
      quic_span_of(key, QUIC_SRESET_KEY), quic_span_of(cid, cid_len), mac);
  for (usz i = 0; i < QUIC_SRESET_TOKEN; i++) token[i] = mac[i]; /* truncate */
}

int quic_sreset_detect(
    const u8* dgram, usz len, const u8 token[QUIC_SRESET_TOKEN]) {
  if (len < QUIC_SRESET_TOKEN) return 0; /* too short to carry a token */
  return quic_ct_diff16(dgram + len - QUIC_SRESET_TOKEN, token) == 0;
}

usz quic_sreset_size(usz trigger_len) {
  usz cap = trigger_len * 3;
  if (cap > 0) cap -= 1; /* strictly under 3x, not 3x itself */
  return quic_u64_max(cap, QUIC_SRESET_MIN);
}

int quic_sreset_build(
    const u8  key[QUIC_SRESET_KEY],
    const u8* cid,
    usz       cid_len,
    usz       trigger_len,
    int (*rand_fill)(u8* buf, usz len),
    u8*  out,
    usz  out_cap,
    usz* out_len) {
  if (out_cap < QUIC_SRESET_MIN) return 0;
  usz len = quic_u64_min(quic_sreset_size(trigger_len), out_cap);

  rand_fill(out, len);
  u8 token[QUIC_SRESET_TOKEN];
  quic_sreset_token(key, cid, cid_len, token);
  for (usz i = 0; i < QUIC_SRESET_TOKEN; i++)
    out[len - QUIC_SRESET_TOKEN + i] = token[i];
  *out_len = len;
  return 1;
}
