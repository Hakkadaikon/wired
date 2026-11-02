#include "transport/conn/loop/manage/zerortt_seen.h"

#include "common/arch/arch.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"
#include "common/platform/clock/clock.h"
#include "crypto/symmetric/hash/hash/sha256.h"

/* mmap(2) flags for a region fork(2) children keep sharing with the parent
 * (Linux <sys/mman.h>). */
#define ZERORTT_SEEN_PROT_RW 0x3
#define ZERORTT_SEEN_MAP_SHARED_ANON 0x21

void zerortt_seen_init(zerortt_seen* s) {
  s->next    = 0;
  s->count   = 0;
  s->lock    = 0;
  s->stuck   = 0;
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
 * 0-RTT contention ever shows up in a profile. The spin is bounded: a
 * worker killed while holding the lock (shared across fork) leaves it set
 * forever, so after ZERORTT_SEEN_SPIN tries give up (0) and the caller
 * refuses. */
static int zerortt_seen_spin(zerortt_seen* s) {
  for (u32 n = 0; n < ZERORTT_SEEN_SPIN; n++) {
    if (!__atomic_exchange_n(&s->lock, 1, __ATOMIC_ACQUIRE)) {
      return 1;
    }
    wired_arch_pause();
  }
  return 0;
}

/* One timeout marks s stuck for good, so a client resending Initials does
 * not stall the worker ZERORTT_SEEN_SPIN tries per check. shortcut: a
 * timeout under mere contention also disables s until restart; clear stuck
 * on a lease/owner check if that ever happens. */
static int zerortt_seen_lock(zerortt_seen* s) {
  if (__atomic_load_n(&s->stuck, __ATOMIC_ACQUIRE)) {
    return 0;
  }
  if (zerortt_seen_spin(s)) {
    return 1;
  }
  __atomic_store_n(&s->stuck, 1, __ATOMIC_RELEASE);
  return 0;
}

/* The ring is full and its oldest entry (next to be overwritten) could
 * still be replayed (recorded less than life seconds ago) -- evicting it
 * would let that replay through. */
static int zerortt_seen_full_live(const zerortt_seen* s, u64 now, u64 life) {
  return s->count == ZERORTT_SEEN_CAP && now < s->at[s->next] + life;
}

/* Find, and record on a miss. 1 on first use; 0 on a replay or when there
 * is no room to record (RFC 8446 8.2: refuse rather than forget). Caller
 * holds s->lock. */
static int zerortt_seen_find_or_record(
    zerortt_seen* s, const u8 digest[32], u64 now, u64 life) {
  if (zerortt_seen_find(s, digest) >= 0) {
    return 0;
  }
  if (zerortt_seen_full_live(s, now, life)) {
    return 0;
  }
  zerortt_seen_record(s, digest, now);
  return 1;
}

int zerortt_seen_check(zerortt_seen* s, wired_span identity) {
  return zerortt_seen_check_at(s, identity, wired_clock_epoch_secs());
}

int zerortt_seen_check_at(zerortt_seen* s, wired_span identity, u64 now_secs) {
  return zerortt_seen_check_live(s, identity, now_secs, ZERORTT_SEEN_LIVE_SECS);
}

int zerortt_seen_check_live(
    zerortt_seen* s, wired_span identity, u64 now_secs, u64 life_secs) {
  u8  digest[32];
  int first;
  wired_sha256(identity.p, identity.n, digest);
  if (!zerortt_seen_lock(s)) {
    return 0;
  }
  first = zerortt_seen_find_or_record(s, digest, now_secs, life_secs);
  __atomic_store_n(&s->lock, 0, __ATOMIC_RELEASE);
  return first;
}

void zerortt_seen_open(zerortt_seen* s, u64 now_secs) {
  u64 unset = 0;
  __atomic_compare_exchange_n(
      &s->started, &unset, now_secs, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

int zerortt_seen_pre_start(zerortt_seen* s, u64 issued_at, u64 now_secs) {
  u64 started;
  zerortt_seen_open(s, now_secs);
  started = __atomic_load_n(&s->started, __ATOMIC_ACQUIRE);
  return issued_at < started && now_secs < started + ZERORTT_SEEN_LIVE_SECS;
}

void zerortt_seen_set_started(zerortt_seen* s, u64 secs) {
  __atomic_store_n(&s->started, secs, __ATOMIC_RELEASE);
}

int zerortt_seen_share(zerortt_seen** tab, const zerortt_seen* local) {
  i64 p;
  if (*tab != local) {
    return 1;
  }
  p = wired_arch_mmap(
      0, sizeof(zerortt_seen), ZERORTT_SEEN_PROT_RW,
      ZERORTT_SEEN_MAP_SHARED_ANON, -1, 0);
  if (p < 0) {
    return 0;
  }
  bytes_memcpy((void*)p, local, sizeof(zerortt_seen));
  *tab = (zerortt_seen*)p;
  return 1;
}
