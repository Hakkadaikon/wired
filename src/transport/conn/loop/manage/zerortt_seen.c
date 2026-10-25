#include "transport/conn/loop/manage/zerortt_seen.h"

#include "common/arch/arch.h"
#include "common/bytes/util/ct.h"
#include "common/platform/clock/clock.h"
#include "crypto/symmetric/hash/hash/sha256.h"

void zerortt_seen_init(zerortt_seen* s) {
  s->next    = 0;
  s->count   = 0;
  s->lock    = 0;
  s->started = 0;
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
static void zerortt_seen_record(zerortt_seen* s, const u8 digest[32], u64 now) {
  usz i;
  for (i = 0; i < 32; i++) {
    s->digest[s->next][i] = digest[i];
  }
  s->at[s->next] = now;
  s->next        = (s->next + 1) % ZERORTT_SEEN_CAP;
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

/* The ring is full and its oldest entry (next to be overwritten) could
 * still be replayed -- evicting it would let that replay through. */
static int zerortt_seen_full_live(const zerortt_seen* s, u64 now) {
  return s->count == ZERORTT_SEEN_CAP &&
         now < s->at[s->next] + ZERORTT_SEEN_LIVE_SECS;
}

/* Find, and record on a miss. 1 on first use; 0 on a replay or when there
 * is no room to record (RFC 8446 8.2: refuse rather than forget). Caller
 * holds s->lock. */
static int zerortt_seen_find_or_record(
    zerortt_seen* s, const u8 digest[32], u64 now) {
  if (zerortt_seen_find(s, digest) >= 0) {
    return 0;
  }
  if (zerortt_seen_full_live(s, now)) {
    return 0;
  }
  zerortt_seen_record(s, digest, now);
  return 1;
}

int zerortt_seen_check(zerortt_seen* s, wired_span identity) {
  return zerortt_seen_check_at(s, identity, wired_clock_epoch_secs());
}

int zerortt_seen_check_at(zerortt_seen* s, wired_span identity, u64 now_secs) {
  u8  digest[32];
  int first;
  wired_sha256(identity.p, identity.n, digest);
  zerortt_seen_lock(s);
  first = zerortt_seen_find_or_record(s, digest, now_secs);
  __atomic_store_n(&s->lock, 0, __ATOMIC_RELEASE);
  return first;
}

int zerortt_seen_starting(zerortt_seen* s, u64 now_secs) {
  u64 unset = 0;
  __atomic_compare_exchange_n(
      &s->started, &unset, now_secs, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
  return now_secs < __atomic_load_n(&s->started, __ATOMIC_ACQUIRE) +
                        ZERORTT_SEEN_LIVE_SECS;
}

void zerortt_seen_set_started(zerortt_seen* s, u64 secs) {
  __atomic_store_n(&s->started, secs, __ATOMIC_RELEASE);
}
