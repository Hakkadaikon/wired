#include "transport/conn/loop/manage/zerortt_seen.h"

#include "common/arch/arch.h"
#include "common/bytes/util/ct.h"
#include "crypto/symmetric/hash/hash/sha256.h"

void zerortt_seen_init(zerortt_seen* s) {
  s->next  = 0;
  s->count = 0;
  s->lock  = 0;
}

/* The index of an existing entry matching digest, or -1. */
static int zerortt_seen_find(const zerortt_seen* s, const u8 digest[32]) {
  for (usz i = 0; i < s->count; i++) {
    if (ct_diff32(s->digest[i], digest) == 0) {
      return (int)i;
    }
  }
  return -1;
}

/* Append digest at the ring's write cursor, growing count until CAP, then
 * wrapping and overwriting the oldest entry. */
static void zerortt_seen_record(zerortt_seen* s, const u8 digest[32]) {
  usz i;
  for (i = 0; i < 32; i++) {
    s->digest[s->next][i] = digest[i];
  }
  s->next = (s->next + 1) % ZERORTT_SEEN_CAP;
  if (s->count < ZERORTT_SEEN_CAP) {
    s->count++;
  }
}

/* ponytail: one spinlock over the whole table (a 0-RTT attempt is rare and
 * the critical section is one bounded scan); stripe it by digest byte if
 * 0-RTT contention ever shows up in a profile. */
static void zerortt_seen_lock(zerortt_seen* s) {
  while (__atomic_exchange_n(&s->lock, 1, __ATOMIC_ACQUIRE)) {
    wired_arch_pause();
  }
}

/* Find, and record on a miss. 1 on first use. Caller holds s->lock. */
static int zerortt_seen_find_or_record(zerortt_seen* s, const u8 digest[32]) {
  if (zerortt_seen_find(s, digest) >= 0) {
    return 0;
  }
  zerortt_seen_record(s, digest);
  return 1;
}

int zerortt_seen_check(zerortt_seen* s, wired_span identity) {
  u8  digest[32];
  int first;
  wired_sha256(identity.p, identity.n, digest);
  zerortt_seen_lock(s);
  first = zerortt_seen_find_or_record(s, digest);
  __atomic_store_n(&s->lock, 0, __ATOMIC_RELEASE);
  return first;
}
