#include "test.h"

/* Only the contiguous prefix from 0 is delivered; data past a gap waits. */
static void test_reasm_contiguous_only(void) {
  reasm r;
  reasm_init(&r);
  reasm_insert(&r, 0, wired_span_of((const u8*)"abc", 3));
  reasm_insert(&r, 6, wired_span_of((const u8*)"ghi", 3)); /* gap */
  CHECK(reasm_deliver(&r) == 3); /* stops at the hole */
  reasm_insert(&r, 3, wired_span_of((const u8*)"def", 3)); /* fill */
  CHECK(reasm_deliver(&r) == 9); /* now flows past it */
  CHECK(r.buf[4] == 'e' && r.buf[7] == 'h');
}

/* Overlapping inserts are idempotent and don't move delivered backward. */
static void test_reasm_idempotent(void) {
  reasm r;
  reasm_init(&r);
  reasm_insert(&r, 0, wired_span_of((const u8*)"hello", 5));
  CHECK(reasm_deliver(&r) == 5);
  reasm_insert(&r, 2, wired_span_of((const u8*)"llo", 3)); /* overlap */
  CHECK(reasm_deliver(&r) == 5);                           /* unchanged */
}

/* Resource-exhaustion pinning (quiche/quinn-proto/s2n-quic/quicly CVE class):
 * reasm is a fixed REASM_CAP=4096 byte/have array, not a growable per-range
 * allocation; an insert whose [offset, offset+len) spills past the fixed
 * buffer must be rejected outright, regardless of how large offset/len (an
 * attacker-controlled STREAM/CRYPTO frame field) are. */
static void test_reasm_insert_rejects_over_cap(void) {
  reasm r;
  reasm_init(&r);
  u8 byte = 1;
  /* one byte at the last in-bounds offset: fits. */
  CHECK(reasm_insert(&r, REASM_CAP - 1, wired_span_of(&byte, 1)) == 1);
  /* one byte at the first out-of-bounds offset: rejected. */
  CHECK(reasm_insert(&r, REASM_CAP, wired_span_of(&byte, 1)) == 0);
  /* a huge attacker-controlled offset (well within the 62-bit varint range)
   * is rejected the same way, not wrapped/truncated into bounds. */
  CHECK(reasm_insert(&r, (u64)1 << 40, wired_span_of(&byte, 1)) == 0);
}

void test_flow(void) {
  test_reasm_contiguous_only();
  test_reasm_idempotent();
  test_reasm_insert_rejects_over_cap();
}
