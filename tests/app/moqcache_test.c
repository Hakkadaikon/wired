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
  for (usz i = 0; i < n; i++) {
    mc_payload[i] = (u8)(g * 16 + o);
  }
  moqcache_append(c, tag, g, o, wired_span_of(mc_payload, n));
}

/* 1 iff {g, o} of tag is cached. */
static int mc_has(moqcache* c, u64 tag, u64 g, u64 o) {
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
 * cached whole): skip passes it, and stops at the next group, which was
 * never received. */
static void test_moqcache_skip_nonexistent(void) {
  moqcache c;
  mc_init(&c, sizeof mc_arena);
  mc_put(&c, MC_TAG, 0, 0, 1);
  mc_put(&c, MC_TAG, 0, 2, 1);
  CHECK(mc_loc_eq(
      moqcache_skip(&c, MC_TAG, mc_loc(0, 1), mc_loc(0, 3)), mc_loc(0, 2)));
  CHECK(mc_loc_eq(
      moqcache_skip(&c, MC_TAG, mc_loc(0, 3), mc_loc(2, 0)), mc_loc(1, 0)));
}

/* draft-23 2.1.2: a Group never received between two cached ones is
 * Unknown, not nonexistent ("a gap ... does not by itself convey any
 * information"): skip stops at it and it is one unknown range. */
static void test_moqcache_missing_group_unknown(void) {
  moqcache      c;
  moqcache_item it;
  mc_init(&c, sizeof mc_arena);
  mc_put(&c, MC_TAG, 0, 0, 1);
  mc_put(&c, MC_TAG, 2, 0, 1);
  moqctl_loc cur = moqcache_skip(&c, MC_TAG, mc_loc(0, 1), mc_loc(3, 0));
  CHECK(mc_loc_eq(cur, mc_loc(1, 0)));
  moqcache_item_at(&c, MC_TAG, cur, mc_loc(3, 0), &it);
  CHECK(it.unknown && mc_loc_eq(it.loc, mc_loc(1, MOQCACHE_OBJ_ID_MAX)));
  CHECK(mc_loc_eq(it.next, mc_loc(2, 0)));
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

/* Another track's open group picked for eviction becomes a tombstone:
 * its later Objects stay out (never a partial group), and a cursor inside
 * it only moves forward. */
static void test_moqcache_evicted_open_group_dead(void) {
  moqcache      c;
  moqcache_item it;
  mc_init(&c, 3 * (MOQCACHE_HDR + 1));
  mc_put(&c, 1, 0, 0, 1);
  mc_put(&c, 2, 0, 0, 1);
  mc_put(&c, 1, 0, 1, 1);
  mc_put(&c, 2, 0, 1, 1); /* evicts track 1's open group 0 */
  CHECK(mc_has(&c, 2, 0, 0) && mc_has(&c, 2, 0, 1));
  mc_put(&c, 1, 0, 2, 1);
  CHECK(!mc_has(&c, 1, 0, 0) && !mc_has(&c, 1, 0, 1));
  CHECK(!mc_has(&c, 1, 0, 2));
  moqcache_item_at(&c, 1, mc_loc(0, 1), mc_loc(0, 3), &it);
  CHECK(it.unknown && mc_loc_eq(it.loc, mc_loc(0, 2)));
  CHECK(mc_loc_eq(it.next, mc_loc(0, 3)));
  CHECK(c.used <= c.cap);
}

/* An open group's tombstone is kept while its group is open; when it
 * leaves no room, the arriving Object's own group is dropped whole
 * instead of writing past the arena. */
static void test_moqcache_open_tombstone_kept(void) {
  moqcache c;
  mc_init(&c, 2 * MOQCACHE_HDR + 1);
  mc_put(&c, 1, 0, 0, 1);
  mc_put(&c, 2, 0, 0, 0);
  mc_put(&c, 1, 0, 1, 0); /* track 2's group 0 dies, track 1's no fit */
  CHECK(c.used <= c.cap);
  CHECK(!mc_has(&c, 1, 0, 0) && !mc_has(&c, 1, 0, 1));
  mc_put(&c, 2, 0, 1, 0);
  CHECK(!mc_has(&c, 2, 0, 1));
  CHECK(c.used <= c.cap);
}

/* A forward walk over one tag (interleaved with another) returns every
 * Object in order, and resumes past the records it already passed; a
 * walk restarted from the beginning is served the same. */
static void test_moqcache_walk_resumes(void) {
  moqcache      c;
  moqcache_item it;
  moqctl_loc    end = mc_loc(3, 0);
  mc_init(&c, sizeof mc_arena);
  for (u64 g = 0; g < 3; g++) {
    for (u64 o = 0; o < 2; o++) {
      mc_put(&c, 2, g, o, 1);
      mc_put(&c, MC_TAG, g, o, 1);
    }
  }
  for (int pass = 0; pass < 2; pass++) {
    u64 n = 0;
    for (moqctl_loc cur = moqcache_skip(&c, MC_TAG, mc_loc(0, 0), end);
         moqctl_loc_less(cur, end);
         cur = moqcache_skip(&c, MC_TAG, it.next, end)) {
      moqcache_item it2;
      moqcache_item_at(&c, 2, cur, end, &it2); /* the other tag in between */
      CHECK(!it2.unknown && it2.payload.p[0] == (u8)(n / 2 * 16 + n % 2));
      moqcache_item_at(&c, MC_TAG, cur, end, &it);
      CHECK(!it.unknown && it.payload.p[0] == (u8)(n / 2 * 16 + n % 2));
      n++;
    }
    CHECK(n == 6);
    CHECK(c.hint_off > 0);
  }
}

/* Eviction slides the records down: a lookup that was resumable before
 * is served from the moved records, never a stale offset. */
static void test_moqcache_evict_drops_resume(void) {
  moqcache      c;
  moqcache_item it;
  mc_init(&c, 4 * (MOQCACHE_HDR + 1));
  mc_put(&c, MC_TAG, 0, 0, 1);
  mc_put(&c, MC_TAG, 0, 1, 1);
  mc_put(&c, MC_TAG, 1, 0, 1);
  mc_put(&c, MC_TAG, 1, 1, 1);
  moqcache_item_at(&c, MC_TAG, mc_loc(1, 0), mc_loc(2, 0), &it);
  mc_put(&c, MC_TAG, 2, 0, 1); /* evicts group 0 */
  moqcache_item_at(&c, MC_TAG, mc_loc(1, 0), mc_loc(2, 0), &it);
  CHECK(!it.unknown && mc_loc_eq(it.loc, mc_loc(1, 0)));
  CHECK(!it.unknown && it.payload.p[0] == 0x10);
}

/* ===== Gone ranges (draft-23 7.1, 10.3) ===== */

/* The item of MC_TAG at {g, o} up to end: kind 0 an Object, 1 Unknown,
 * 2 Gone; *next where the item stops. */
static int mc_kind(
    moqcache* c, u64 g, u64 o, moqctl_loc end, moqctl_loc* next) {
  moqcache_item it;
  moqcache_item_at(c, MC_TAG, mc_loc(g, o), end, &it);
  *next = it.next;
  CHECK(mc_loc_eq(it.loc, it.unknown ? moqctl_loc_prev(it.next) : it.loc));
  return it.unknown ? 1 + (it.gone != 0) : 0;
}

/* A Gone range {2, 0}..{2, 5} inside an Unknown stretch {1, 0}..{3, max}:
 * the Unknown range before it stops where it starts, a cursor at or
 * inside it reads Gone up to its end, Unknown again after it; another
 * track and a cached Object (7.1: an Object received later is cached and
 * served) are not Gone. */
static void test_moqcache_gone_partial(void) {
  moqcache      c;
  moqcache_item it;
  moqctl_loc    n;
  moqctl_loc    end = mc_loc(4, 0);
  mc_init(&c, sizeof mc_arena);
  mc_put(&c, MC_TAG, 4, 0, 1);
  moqcache_gone_add(&c, MC_TAG, mc_loc(2, 0), mc_loc(2, 5), ~(u64)0);
  moqcache_gone_add(&c, MC_TAG, mc_loc(4, 0), mc_loc(4, 0), ~(u64)0);
  CHECK(mc_kind(&c, 1, 0, end, &n) == 1 && mc_loc_eq(n, mc_loc(2, 0)));
  CHECK(mc_kind(&c, 2, 0, end, &n) == 2 && mc_loc_eq(n, mc_loc(2, 6)));
  CHECK(mc_kind(&c, 2, 3, end, &n) == 2 && mc_loc_eq(n, mc_loc(2, 6)));
  CHECK(mc_kind(&c, 2, 3, mc_loc(2, 4), &n) == 2 && mc_loc_eq(n, mc_loc(2, 4)));
  CHECK(mc_kind(&c, 2, 6, end, &n) == 1 && mc_loc_eq(n, mc_loc(4, 0)));
  CHECK(mc_kind(&c, 4, 0, mc_loc(4, 1), &n) == 0);
  moqcache_item_at(&c, MC_TAG + 1, mc_loc(2, 0), end, &it);
  CHECK(it.unknown && !it.gone);
}

/* A range ending at a Group's last possible Object takes the whole Group:
 * the next item starts the next Group. */
static void test_moqcache_gone_whole_group(void) {
  moqcache   c;
  moqctl_loc n;
  mc_init(&c, sizeof mc_arena);
  moqcache_gone_add(
      &c, MC_TAG, mc_loc(2, 0), mc_loc(2, MOQCACHE_OBJ_ID_MAX), ~(u64)0);
  CHECK(mc_kind(&c, 2, 0, mc_loc(5, 0), &n) == 2 && mc_loc_eq(n, mc_loc(3, 0)));
}

/* 10.3: "The same limit applies to cached Does Not Exist and Gone
 * states" -- at its expiry the range reads Unknown again (2.1.2). */
static void test_moqcache_gone_expires(void) {
  moqcache   c;
  moqctl_loc n;
  mc_init(&c, sizeof mc_arena);
  c.now = 100;
  moqcache_gone_add(&c, MC_TAG, mc_loc(1, 0), mc_loc(1, 3), 200);
  c.now = 199;
  CHECK(mc_kind(&c, 1, 0, mc_loc(2, 0), &n) == 2);
  c.now = 200;
  CHECK(mc_kind(&c, 1, 0, mc_loc(2, 0), &n) == 1 && mc_loc_eq(n, mc_loc(2, 0)));
}

/* A full table drops its oldest range, which reads Unknown again -- never
 * a wrong answer; a cache with no arena keeps none. */
static void test_moqcache_gone_full(void) {
  moqcache   c;
  moqctl_loc n;
  mc_init(&c, sizeof mc_arena);
  for (u64 g = 0; g <= MOQCACHE_GONE_MAX; g++) {
    moqcache_gone_add(&c, MC_TAG, mc_loc(g, 0), mc_loc(g, 0), ~(u64)0);
  }
  CHECK(mc_kind(&c, 0, 0, mc_loc(0, 1), &n) == 1);
  CHECK(mc_kind(&c, 1, 0, mc_loc(1, 1), &n) == 2);
  CHECK(mc_kind(&c, MOQCACHE_GONE_MAX, 0, mc_loc(99, 0), &n) == 2);
  mc_init(&c, 0);
  moqcache_gone_add(&c, MC_TAG, mc_loc(1, 0), mc_loc(1, 0), ~(u64)0);
  CHECK(mc_kind(&c, 1, 0, mc_loc(1, 1), &n) == 1);
}

/* The size memo never changes what is cached: a random run of Objects
 * over three tracks -- continued groups, new groups, evictions, a group
 * too big to keep -- leaves the same arena whether each append trusts the
 * memo or walks the records, and whenever the memo is on it equals the
 * walk. */
static void test_moqcache_memo_matches_walk(void) {
  static u8 a1[6000], a2[6000];
  moqcache  c1, c2;
  u32       rng  = 0x6d656d6f;
  usz       hits = 0;
  u64       g[3] = {1, 1, 1};
  moqcache_init(&c1, a1, sizeof a1);
  moqcache_init(&c2, a2, sizeof a2);
  for (usz i = 0; i < 4000; i++) {
    usz t, n;
    rng = rng * 1664525u + 1013904223u;
    t   = (rng >> 28) % 3;
    n   = (rng >> 8) % 700;
    g[t] += (rng >> 20) % 5 == 0; /* mostly the same group again */
    hits += (usz)moqcache_memo_hit(&c1, 20 + t, g[t]);
    if (c1.memo_on) {
      int dead = 0;
      CHECK(
          moqcache_group_bytes(&c1, c1.memo_tag, c1.memo_group, &dead) ==
          c1.memo_bytes);
      CHECK(!dead);
    }
    c2.memo_on = 0; /* the reference always walks */
    mc_put(&c1, 20 + t, g[t], i, n);
    mc_put(&c2, 20 + t, g[t], i, n);
    CHECK(c1.used == c2.used);
  }
  CHECK(hits > 1000);
  for (usz i = 0; i < c1.used; i++) {
    CHECK(a1[i] == a2[i]);
  }
}

void test_moqcache(void) {
  test_moqcache_memo_matches_walk();
  test_moqcache_gone_partial();
  test_moqcache_gone_whole_group();
  test_moqcache_gone_expires();
  test_moqcache_gone_full();
  test_moqcache_walk_resumes();
  test_moqcache_evict_drops_resume();
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
  test_moqcache_missing_group_unknown();
  test_moqcache_items_empty();
  test_moqcache_items_tombstone();
  test_moqcache_evicted_open_group_dead();
  test_moqcache_open_tombstone_kept();
}
