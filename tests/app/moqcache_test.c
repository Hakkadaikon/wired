#include "app/moqt/cache/moqcache.h"

#include "test.h"

/* Object cache for FETCH (draft-ietf-moq-transport-19 10.12.3): whole-
 * group, oldest-first eviction inside a fixed arena, and the response
 * items a FETCH cursor reads. A "budget" of B bytes below is an arena of
 * B payload bytes plus one MOQCACHE_HDR per record that has to fit. */

#define MC_TAG 7

static u8 mc_arena[2 * (MOQCACHE_HDR + MOQCACHE_OBJ_MAX)];
static u8 mc_payload[MOQCACHE_OBJ_MAX + 1];

static moqctl_loc mc_loc(u64 g, u64 o) {
  moqctl_loc l = {g, o};
  return l;
}

static int mc_loc_eq(moqctl_loc a, moqctl_loc b) {
  return a.group == b.group && a.object == b.object;
}

static void mc_put(moqcache* c, u64 tag, u64 g, u64 o, usz n) {
  for (usz i = 0; i < n; i++) mc_payload[i] = (u8)(g * 16 + o);
  moqcache_append(c, tag, g, o, wired_span_of(mc_payload, n));
}

/* 1 iff {g, o} of tag is cached. */
static int mc_has(const moqcache* c, u64 tag, u64 g, u64 o) {
  moqcache_item it;
  moqcache_item_at(c, tag, mc_loc(g, o), mc_loc(g, o + 1), &it);
  return !it.unknown && mc_loc_eq(it.loc, mc_loc(g, o));
}

static void mc_init(moqcache* c, usz cap) { moqcache_init(c, mc_arena, cap); }

/* The budget holds exactly, nothing is evicted before it must be,
 * and the next Object evicts the old group whole. */
static void test_moqcache_budget_evicts_only_when_needed(void) {
  moqcache c;
  mc_init(&c, 2 * (MOQCACHE_HDR + 2));
  mc_put(&c, MC_TAG, 0, 0, 2);
  mc_put(&c, MC_TAG, 0, 1, 2);
  CHECK(c.used == c.cap);
  CHECK(mc_has(&c, MC_TAG, 0, 0) && mc_has(&c, MC_TAG, 0, 1));
  mc_put(&c, MC_TAG, 1, 0, 1);
  CHECK(!mc_has(&c, MC_TAG, 0, 0) && !mc_has(&c, MC_TAG, 0, 1));
  CHECK(mc_has(&c, MC_TAG, 1, 0));
  CHECK(c.used == MOQCACHE_HDR + 1);
}

/* The oldest whole group goes first; younger ones stay whole. */
static void test_moqcache_evicts_oldest_group(void) {
  moqcache c;
  mc_init(&c, 4 * (MOQCACHE_HDR + 1));
  mc_put(&c, MC_TAG, 0, 0, 1);
  mc_put(&c, MC_TAG, 0, 1, 1);
  mc_put(&c, MC_TAG, 1, 0, 1);
  mc_put(&c, MC_TAG, 1, 1, 1);
  mc_put(&c, MC_TAG, 2, 0, 1);
  CHECK(!mc_has(&c, MC_TAG, 0, 0) && !mc_has(&c, MC_TAG, 0, 1));
  CHECK(mc_has(&c, MC_TAG, 1, 0) && mc_has(&c, MC_TAG, 1, 1));
  CHECK(mc_has(&c, MC_TAG, 2, 0));
}

/* A group that cannot fit the budget is not cached at all, nor
 * any later Object of it. */
static void test_moqcache_group_over_budget_dropped(void) {
  moqcache c;
  mc_init(&c, 2 * MOQCACHE_HDR + 3);
  mc_put(&c, MC_TAG, 0, 0, 2);
  CHECK(mc_has(&c, MC_TAG, 0, 0));
  mc_put(&c, MC_TAG, 0, 1, 2);
  CHECK(!mc_has(&c, MC_TAG, 0, 0) && !mc_has(&c, MC_TAG, 0, 1));
  mc_put(&c, MC_TAG, 0, 2, 1);
  CHECK(!mc_has(&c, MC_TAG, 0, 2));
  mc_put(&c, MC_TAG, 1, 0, 1); /* the next group caches again */
  CHECK(mc_has(&c, MC_TAG, 1, 0));
}

/* One Object larger than the budget drops its group; its later
 * Objects stay out and the group reads as one unknown range. */
static void test_moqcache_object_over_budget(void) {
  moqcache      c;
  moqcache_item it;
  mc_init(&c, MOQCACHE_HDR + 3);
  mc_put(&c, MC_TAG, 0, 0, 4);
  mc_put(&c, MC_TAG, 0, 1, 1);
  CHECK(!mc_has(&c, MC_TAG, 0, 0) && !mc_has(&c, MC_TAG, 0, 1));
  moqcache_item_at(&c, MC_TAG, mc_loc(0, 0), mc_loc(0, 2), &it);
  CHECK(it.unknown);
  CHECK(mc_loc_eq(it.loc, mc_loc(0, 1)));
  CHECK(mc_loc_eq(it.next, mc_loc(0, 2)));
}

/* Boundary: MOQCACHE_OBJ_MAX is cached, one byte more is not. */
static void test_moqcache_obj_max(void) {
  moqcache c;
  mc_init(&c, sizeof mc_arena);
  mc_put(&c, MC_TAG, 0, 0, MOQCACHE_OBJ_MAX);
  CHECK(mc_has(&c, MC_TAG, 0, 0));
  mc_put(&c, MC_TAG, 1, 0, MOQCACHE_OBJ_MAX + 1);
  CHECK(!mc_has(&c, MC_TAG, 1, 0));
}

/* Boundary: a cache with no arena caches nothing. */
static void test_moqcache_no_arena(void) {
  moqcache c;
  moqcache_init(&c, 0, 0);
  mc_put(&c, MC_TAG, 0, 0, 1);
  CHECK(c.used == 0);
  CHECK(!mc_has(&c, MC_TAG, 0, 0));
}

/* Tracks share one oldest-first order; release drops only its tag. */
static void test_moqcache_tags_share_arena(void) {
  moqcache c;
  mc_init(&c, 3 * (MOQCACHE_HDR + 1));
  mc_put(&c, 1, 0, 0, 1);
  mc_put(&c, 2, 0, 0, 1);
  mc_put(&c, 1, 1, 0, 1);
  mc_put(&c, 2, 1, 0, 1);
  CHECK(!mc_has(&c, 1, 0, 0));
  CHECK(mc_has(&c, 2, 0, 0) && mc_has(&c, 1, 1, 0) && mc_has(&c, 2, 1, 0));
  moqcache_release(&c, 2);
  CHECK(!mc_has(&c, 2, 0, 0) && !mc_has(&c, 2, 1, 0));
  CHECK(mc_has(&c, 1, 1, 0));
  CHECK(c.used == MOQCACHE_HDR + 1);
}

/* Cached Objects are items with their payload, in order. */
static void test_moqcache_items_cached(void) {
  moqcache      c;
  moqcache_item it;
  moqctl_loc    end = mc_loc(0, 2);
  mc_init(&c, sizeof mc_arena);
  mc_put(&c, MC_TAG, 0, 0, 3);
  mc_put(&c, MC_TAG, 0, 1, 1);
  moqctl_loc cur = moqcache_skip(&c, MC_TAG, mc_loc(0, 0), end);
  CHECK(mc_loc_eq(cur, mc_loc(0, 0)));
  moqcache_item_at(&c, MC_TAG, cur, end, &it);
  CHECK(!it.unknown && it.payload.n == 3 && it.payload.p[0] == 0x00);
  CHECK(mc_loc_eq(it.next, mc_loc(0, 1)));
  moqcache_item_at(&c, MC_TAG, it.next, end, &it);
  CHECK(!it.unknown && it.payload.n == 1 && it.payload.p[0] == 0x01);
  CHECK(mc_loc_eq(moqcache_skip(&c, MC_TAG, it.next, end), end));
}

/* An evicted prefix is one unknown range up to the first cached
 * group, then the cached Objects follow. */
static void test_moqcache_items_evicted_prefix(void) {
  moqcache      c;
  moqcache_item it;
  moqctl_loc    end = mc_loc(1, 2);
  mc_init(&c, 2 * (MOQCACHE_HDR + 1));
  mc_put(&c, MC_TAG, 0, 0, 1);
  mc_put(&c, MC_TAG, 0, 1, 1);
  mc_put(&c, MC_TAG, 1, 0, 1);
  mc_put(&c, MC_TAG, 1, 1, 1);
  moqctl_loc cur = moqcache_skip(&c, MC_TAG, mc_loc(0, 0), end);
  CHECK(mc_loc_eq(cur, mc_loc(0, 0)));
  moqcache_item_at(&c, MC_TAG, cur, end, &it);
  CHECK(it.unknown && mc_loc_eq(it.loc, mc_loc(0, MOQCACHE_OBJ_ID_MAX)));
  CHECK(mc_loc_eq(it.next, mc_loc(1, 0)));
  moqcache_item_at(&c, MC_TAG, it.next, end, &it);
  CHECK(!it.unknown && mc_loc_eq(it.loc, mc_loc(1, 0)));
}

/* Inside a cached group a missing Object does not exist (groups are
 * cached whole): skip passes it, and past the last group reaches end. */
static void test_moqcache_skip_nonexistent(void) {
  moqcache c;
  mc_init(&c, sizeof mc_arena);
  mc_put(&c, MC_TAG, 0, 0, 1);
  mc_put(&c, MC_TAG, 0, 2, 1);
  CHECK(mc_loc_eq(
      moqcache_skip(&c, MC_TAG, mc_loc(0, 1), mc_loc(0, 3)), mc_loc(0, 2)));
  CHECK(mc_loc_eq(
      moqcache_skip(&c, MC_TAG, mc_loc(0, 3), mc_loc(2, 0)), mc_loc(2, 0)));
}

/* Nothing cached: the whole range is one unknown range. */
static void test_moqcache_items_empty(void) {
  moqcache      c;
  moqcache_item it;
  mc_init(&c, sizeof mc_arena);
  moqctl_loc cur = moqcache_skip(&c, MC_TAG, mc_loc(0, 0), mc_loc(2, 0));
  CHECK(mc_loc_eq(cur, mc_loc(0, 0)));
  moqcache_item_at(&c, MC_TAG, cur, mc_loc(2, 0), &it);
  CHECK(it.unknown && mc_loc_eq(it.loc, mc_loc(1, MOQCACHE_OBJ_ID_MAX)));
  CHECK(mc_loc_eq(it.next, mc_loc(2, 0)));
}

/* A dropped group is unknown to its end, then the next group serves. */
static void test_moqcache_items_tombstone(void) {
  moqcache      c;
  moqcache_item it;
  moqctl_loc    end = mc_loc(1, 1);
  mc_init(&c, 2 * MOQCACHE_HDR + 3);
  mc_put(&c, MC_TAG, 0, 0, 2);
  mc_put(&c, MC_TAG, 0, 1, 2);
  mc_put(&c, MC_TAG, 1, 0, 1);
  moqcache_item_at(&c, MC_TAG, mc_loc(0, 0), end, &it);
  CHECK(it.unknown && mc_loc_eq(it.loc, mc_loc(0, MOQCACHE_OBJ_ID_MAX)));
  CHECK(mc_loc_eq(it.next, mc_loc(1, 0)));
  CHECK(mc_loc_eq(moqcache_skip(&c, MC_TAG, it.next, end), mc_loc(1, 0)));
  moqcache_item_at(&c, MC_TAG, it.next, end, &it);
  CHECK(!it.unknown && mc_loc_eq(it.loc, mc_loc(1, 0)));
}

void test_moqcache(void) {
  test_moqcache_budget_evicts_only_when_needed();
  test_moqcache_evicts_oldest_group();
  test_moqcache_group_over_budget_dropped();
  test_moqcache_object_over_budget();
  test_moqcache_obj_max();
  test_moqcache_no_arena();
  test_moqcache_tags_share_arena();
  test_moqcache_items_cached();
  test_moqcache_items_evicted_prefix();
  test_moqcache_skip_nonexistent();
  test_moqcache_items_empty();
  test_moqcache_items_tombstone();
}
