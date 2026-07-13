#include "app/http3/server/srvbigbuf/srvbigbuf.h"

#include "test.h"

/* @file
 * Big-body buffer pool: claim/release lifecycle over caller-owned storage.
 * Test list:
 * - fresh pool: first claim returns row 0
 * - two claims return distinct rows, row_cap bytes apart
 * - claim on an exhausted pool returns 0
 * - release makes the row claimable again
 * - release is idempotent and ignores out-of-range indices
 * - a claimed row is writable across its full row_cap span
 * - row() returns the row pointer for any valid idx, 0 out of range
 */

static u8 sbb_rows[WIRED_SRVBIGBUF_ROWS * WIRED_SRVBIGBUF_ROW_CAP];

/* Fresh pool: the first claim hands out row 0. */
static void test_srvbigbuf_first_claim_is_row0(void) {
  wired_srvbigbuf p;
  int             idx = -1;
  wired_srvbigbuf_init(&p, sbb_rows, WIRED_SRVBIGBUF_ROW_CAP);
  CHECK(wired_srvbigbuf_claim(&p, &idx) == sbb_rows);
  CHECK(idx == 0);
}

/* Two claims return distinct rows spaced exactly row_cap apart. */
static void test_srvbigbuf_two_claims_distinct_rows(void) {
  wired_srvbigbuf p;
  int             a = -1;
  int             b = -1;
  u8*             pa;
  u8*             pb;
  wired_srvbigbuf_init(&p, sbb_rows, WIRED_SRVBIGBUF_ROW_CAP);
  pa = wired_srvbigbuf_claim(&p, &a);
  pb = wired_srvbigbuf_claim(&p, &b);
  CHECK(a == 0);
  CHECK(b == 1);
  CHECK(pb == pa + WIRED_SRVBIGBUF_ROW_CAP);
}

/* Claiming past the row count returns 0 (pool exhausted -- a normal
 * outcome; the caller falls back to its 16KB slot). */
static void test_srvbigbuf_exhausted_claim_returns_0(void) {
  wired_srvbigbuf p;
  int             idx = -1;
  wired_srvbigbuf_init(&p, sbb_rows, WIRED_SRVBIGBUF_ROW_CAP);
  for (int i = 0; i < WIRED_SRVBIGBUF_ROWS; i++) {
    CHECK(wired_srvbigbuf_claim(&p, &idx) != 0);
  }
  CHECK(wired_srvbigbuf_claim(&p, &idx) == 0);
}

/* Releasing row 0 makes the next claim reuse it. */
static void test_srvbigbuf_release_then_reclaim(void) {
  wired_srvbigbuf p;
  int             idx = -1;
  wired_srvbigbuf_init(&p, sbb_rows, WIRED_SRVBIGBUF_ROW_CAP);
  for (int i = 0; i < WIRED_SRVBIGBUF_ROWS; i++) {
    CHECK(wired_srvbigbuf_claim(&p, &idx) != 0);
  }
  wired_srvbigbuf_release(&p, 0);
  CHECK(wired_srvbigbuf_claim(&p, &idx) == sbb_rows);
  CHECK(idx == 0);
}

/* Double release and out-of-range indices are ignored: the pool still
 * hands out exactly ROWS rows afterwards. */
static void test_srvbigbuf_release_idempotent_and_range_checked(void) {
  wired_srvbigbuf p;
  int             idx = -1;
  wired_srvbigbuf_init(&p, sbb_rows, WIRED_SRVBIGBUF_ROW_CAP);
  wired_srvbigbuf_release(&p, 0);  /* not claimed: no-op */
  wired_srvbigbuf_release(&p, 0);  /* again: still a no-op */
  wired_srvbigbuf_release(&p, -1); /* out of range: ignored */
  wired_srvbigbuf_release(&p, WIRED_SRVBIGBUF_ROWS);
  for (int i = 0; i < WIRED_SRVBIGBUF_ROWS; i++) {
    CHECK(wired_srvbigbuf_claim(&p, &idx) != 0);
    CHECK(idx == i);
  }
  CHECK(wired_srvbigbuf_claim(&p, &idx) == 0);
}

/* A claimed row is writable at both ends of its row_cap span, and the two
 * rows do not overlap (row 1's first byte is past row 0's last). */
static void test_srvbigbuf_row_span_writable(void) {
  wired_srvbigbuf p;
  int             a = -1;
  int             b = -1;
  u8*             pa;
  u8*             pb;
  wired_srvbigbuf_init(&p, sbb_rows, WIRED_SRVBIGBUF_ROW_CAP);
  pa                              = wired_srvbigbuf_claim(&p, &a);
  pb                              = wired_srvbigbuf_claim(&p, &b);
  pa[0]                           = 0xAA;
  pa[WIRED_SRVBIGBUF_ROW_CAP - 1] = 0xAB;
  pb[0]                           = 0xBA;
  pb[WIRED_SRVBIGBUF_ROW_CAP - 1] = 0xBB;
  CHECK(sbb_rows[0] == 0xAA);
  CHECK(sbb_rows[WIRED_SRVBIGBUF_ROW_CAP - 1] == 0xAB);
  CHECK(sbb_rows[WIRED_SRVBIGBUF_ROW_CAP] == 0xBA);
  CHECK(sbb_rows[2 * WIRED_SRVBIGBUF_ROW_CAP - 1] == 0xBB);
}

/* row() returns each row's pointer whether claimed or released, and 0 for
 * out-of-range indices. */
static void test_srvbigbuf_row_lookup(void) {
  wired_srvbigbuf p;
  int             idx = -1;
  wired_srvbigbuf_init(&p, sbb_rows, WIRED_SRVBIGBUF_ROW_CAP);
  CHECK(wired_srvbigbuf_row(&p, 0) == sbb_rows);
  CHECK(wired_srvbigbuf_row(&p, 1) == sbb_rows + WIRED_SRVBIGBUF_ROW_CAP);
  CHECK(wired_srvbigbuf_claim(&p, &idx) == wired_srvbigbuf_row(&p, 0));
  wired_srvbigbuf_release(&p, 0);
  CHECK(wired_srvbigbuf_row(&p, 0) == sbb_rows);
  CHECK(wired_srvbigbuf_row(&p, -1) == 0);
  CHECK(wired_srvbigbuf_row(&p, WIRED_SRVBIGBUF_ROWS) == 0);
}

void test_srvbigbuf(void) {
  test_srvbigbuf_first_claim_is_row0();
  test_srvbigbuf_two_claims_distinct_rows();
  test_srvbigbuf_exhausted_claim_returns_0();
  test_srvbigbuf_release_then_reclaim();
  test_srvbigbuf_release_idempotent_and_range_checked();
  test_srvbigbuf_row_span_writable();
  test_srvbigbuf_row_lookup();
}
