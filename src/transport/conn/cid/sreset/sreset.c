#include "transport/conn/cid/sreset/sreset.h"

#include "common/bytes/util/ct.h"
#include "common/bytes/util/num.h"
#include "crypto/symmetric/hash/hash/hmac.h"

void sreset_key_derive(const u8 secret[SRESET_KEY], u8 key[SRESET_KEY]) {
  static const u8 label[] = "stateless reset";
  hmac_sha256(
      wired_span_of(secret, SRESET_KEY), wired_span_of(label, sizeof label - 1),
      key);
}

void sreset_token(
    const u8  key[SRESET_KEY],
    const u8* cid,
    usz       cid_len,
    u8        token[SRESET_TOKEN]) {
  u8 mac[SHA256_DIGEST];
  hmac_sha256(wired_span_of(key, SRESET_KEY), wired_span_of(cid, cid_len), mac);
  for (usz i = 0; i < SRESET_TOKEN; i++) token[i] = mac[i]; /* truncate */
}

int sreset_detect(const u8* dgram, usz len, const u8 token[SRESET_TOKEN]) {
  if (len < SRESET_TOKEN) return 0; /* too short to carry a token */
  return ct_diff16(dgram + len - SRESET_TOKEN, token) == 0;
}

usz sreset_size(usz trigger_len) {
  usz cap = trigger_len * 3;
  if (cap > 0) cap -= 1; /* strictly under 3x, not 3x itself */
  return u64_max(cap, SRESET_MIN);
}

int sreset_build(
    const u8  key[SRESET_KEY],
    const u8* cid,
    usz       cid_len,
    usz       trigger_len,
    int (*rand_fill)(u8* buf, usz len),
    u8*  out,
    usz  out_cap,
    usz* out_len) {
  if (out_cap < SRESET_MIN) return 0;
  usz len = u64_min(sreset_size(trigger_len), out_cap);

  rand_fill(out, len);
  u8 token[SRESET_TOKEN];
  sreset_token(key, cid, cid_len, token);
  for (usz i = 0; i < SRESET_TOKEN; i++) out[len - SRESET_TOKEN + i] = token[i];
  *out_len = len;
  return 1;
}
