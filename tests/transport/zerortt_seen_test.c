#include "common/platform/thread/thread.h"
#include "test.h"

/* RFC 8446 8.1 / RFC 9001 9.2: a server must reject 0-RTT for any ticket it
 * has already seen once -- this bounded, process-lifetime, single-process
 * tracker is the thing zerortt_replay_ok's ticket_first_use argument
 * comes from. */

static wired_span zerortt_seen_span(const u8* p, usz n) {
  return wired_span_of(p, n);
}

/* A ticket identity never seen before is a first use. */
static void test_seen_fresh_is_first_use(void) {
  zerortt_seen s;
  const u8     id[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  zerortt_seen_init(&s);
  CHECK(zerortt_seen_check(&s, zerortt_seen_span(id, sizeof id)) == 1);
}

/* The same identity presented a second time is a replay, not a first use. */
static void test_seen_replay_is_not_first_use(void) {
  zerortt_seen s;
  const u8     id[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  zerortt_seen_init(&s);
  CHECK(zerortt_seen_check(&s, zerortt_seen_span(id, sizeof id)) == 1);
  CHECK(zerortt_seen_check(&s, zerortt_seen_span(id, sizeof id)) == 0);
  CHECK(zerortt_seen_check(&s, zerortt_seen_span(id, sizeof id)) == 0);
}

/* Two distinct identities are each their own first use, independently. */
static void test_seen_distinct_identities_independent(void) {
  zerortt_seen s;
  const u8     a[4] = {0xaa, 0xaa, 0xaa, 0xaa};
  const u8     b[4] = {0xbb, 0xbb, 0xbb, 0xbb};
  zerortt_seen_init(&s);
  CHECK(zerortt_seen_check(&s, zerortt_seen_span(a, sizeof a)) == 1);
  CHECK(zerortt_seen_check(&s, zerortt_seen_span(b, sizeof b)) == 1);
  CHECK(zerortt_seen_check(&s, zerortt_seen_span(a, sizeof a)) == 0);
  CHECK(zerortt_seen_check(&s, zerortt_seen_span(b, sizeof b)) == 0);
}

/* Once the fixed-capacity ring wraps, the oldest entry is evicted and its
 * identity is treated as a fresh first use again on re-presentation
 * (ponytail: bounded memory over perfect long-window replay detection --
 * acceptable since a ticket also expires on its own lifetime). */
static void test_seen_capacity_evicts_oldest(void) {
  zerortt_seen s;
  u8           id[ZERORTT_SEEN_CAP + 1][4];
  zerortt_seen_init(&s);
  for (usz i = 0; i < ZERORTT_SEEN_CAP + 1; i++) {
    id[i][0] = (u8)i;
    id[i][1] = (u8)(i >> 8);
    id[i][2] = 0xEE;
    id[i][3] = 0xEE;
    CHECK(zerortt_seen_check(&s, zerortt_seen_span(id[i], 4)) == 1);
  }
  /* The very first identity was evicted to make room -- it is seen as fresh
   * again. */
  CHECK(zerortt_seen_check(&s, zerortt_seen_span(id[0], 4)) == 1);
}

/* RFC 8446 8.1 across threads: srvthreads workers share one tracker, so two
 * workers presented the same ticket at the same moment must still accept it
 * exactly once -- the look-up and the record are one atomic step. Two
 * threads race over the same ZRS_RACE_N identities; every identity counts
 * one first use in total, never two. */
#define ZRS_RACE_N 1500
static zerortt_seen g_zrs_race;
static int          g_zrs_go;

typedef struct {
  u8  salt;
  usz firsts;
} zrs_race_arg;

static void zrs_race_fn(void* p) {
  zrs_race_arg* a = p;
  u8            id[4];
  while (!__atomic_load_n(&g_zrs_go, __ATOMIC_ACQUIRE)) {
  }
  for (usz i = 0; i < ZRS_RACE_N; i++) {
    id[0] = (u8)i;
    id[1] = (u8)(i >> 8);
    id[2] = a->salt;
    id[3] = 0x7e;
    a->firsts += (usz)zerortt_seen_check(&g_zrs_race, zerortt_seen_span(id, 4));
  }
}

static void test_seen_two_threads_accept_once(void) {
  for (u8 round = 0; round < 4; round++) {
    wired_thread t[2];
    zrs_race_arg a[2] = {{round, 0}, {round, 0}};
    zerortt_seen_init(&g_zrs_race);
    __atomic_store_n(&g_zrs_go, 0, __ATOMIC_RELEASE);
    CHECK(wired_thread_start(&t[0], zrs_race_fn, &a[0]) == 0);
    CHECK(wired_thread_start(&t[1], zrs_race_fn, &a[1]) == 0);
    __atomic_store_n(&g_zrs_go, 1, __ATOMIC_RELEASE);
    wired_thread_join(&t[0]);
    wired_thread_join(&t[1]);
    CHECK(a[0].firsts + a[1].firsts == ZRS_RACE_N);
    CHECK(g_zrs_race.count <= ZERORTT_SEEN_CAP);
  }
}

void test_zerortt_seen(void) {
  test_seen_two_threads_accept_once();
  test_seen_fresh_is_first_use();
  test_seen_replay_is_not_first_use();
  test_seen_distinct_identities_independent();
  test_seen_capacity_evicts_oldest();
}
