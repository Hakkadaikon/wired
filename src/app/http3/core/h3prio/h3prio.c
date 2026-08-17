#include "app/http3/core/h3prio/h3prio.h"

/* RFC 9218 4.1/10: candidate index a sorts strictly ahead of b -- in_use
 * dominates (a live candidate always precedes a dead slot), then ascending
 * urgency, then ascending stream_id breaks a same-urgency tie. */
static int prio_before(const h3prio_candidate* c, usz a, usz b) {
  if (c[a].in_use != c[b].in_use) return c[a].in_use > c[b].in_use;
  if (c[a].urgency != c[b].urgency) return c[a].urgency < c[b].urgency;
  return c[a].stream_id < c[b].stream_id;
}

/* 1 while the insertion-sort scan at j (holding candidate `key`) must keep
 * shifting right: there is an earlier slot AND it outranks key. Split out
 * so the while loop below carries only one branch, not a bundled &&. */
static int shift_needed(
    const h3prio_candidate* c, const usz* order, usz key, usz j) {
  return j > 0 && prio_before(c, key, order[j - 1]);
}

/* One candidate's insertion into the already-sorted order[0..i): shift every
 * ranked-after entry right by one, then drop key into the gap. */
static void order_insert_one(const h3prio_candidate* c, usz* order, usz i) {
  usz key = order[i];
  usz j   = i;
  while (shift_needed(c, order, key, j)) {
    order[j] = order[j - 1];
    j--;
  }
  order[j] = key;
}

/* Insertion-sort order[0..n) in place against prio_before's ranking --
 * n is bounded by a fixed slot table (<=40 in practice), so O(n^2) is
 * simple and plenty fast; a merge/qsort here would be over-engineering. */
static void order_insert(const h3prio_candidate* c, usz* order, usz n) {
  for (usz i = 1; i < n; i++) order_insert_one(c, order, i);
}

void h3prio_order(const h3prio_candidate* c, usz n, usz* order) {
  for (usz i = 0; i < n; i++) order[i] = i;
  order_insert(c, order, n);
}
