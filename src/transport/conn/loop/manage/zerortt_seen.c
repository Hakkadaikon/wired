#include "transport/conn/loop/manage/zerortt_seen.h"

#include "common/bytes/util/ct.h"
#include "crypto/symmetric/hash/hash/sha256.h"

void quic_zerortt_seen_init(quic_zerortt_seen* s) {
  s->next  = 0;
  s->count = 0;
}

/* The index of an existing entry matching digest, or -1. */
static int zerortt_seen_find(const quic_zerortt_seen* s, const u8 digest[32]) {
  for (usz i = 0; i < s->count; i++)
    if (quic_ct_diff32(s->digest[i], digest) == 0) return (int)i;
  return -1;
}

/* Append digest at the ring's write cursor, growing count until CAP, then
 * wrapping and overwriting the oldest entry. */
static void zerortt_seen_record(quic_zerortt_seen* s, const u8 digest[32]) {
  usz i;
  for (i = 0; i < 32; i++) s->digest[s->next][i] = digest[i];
  s->next = (s->next + 1) % QUIC_ZERORTT_SEEN_CAP;
  if (s->count < QUIC_ZERORTT_SEEN_CAP) s->count++;
}

int quic_zerortt_seen_check(quic_zerortt_seen* s, quic_span identity) {
  u8 digest[32];
  quic_sha256(identity.p, identity.n, digest);
  if (zerortt_seen_find(s, digest) >= 0) return 0;
  zerortt_seen_record(s, digest);
  return 1;
}
