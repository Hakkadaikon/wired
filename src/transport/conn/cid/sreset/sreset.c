#include "transport/conn/cid/sreset/sreset.h"

#include "common/bytes/util/ct.h"
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
