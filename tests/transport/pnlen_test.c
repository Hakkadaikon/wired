#include "test.h"

/* RFC 9000 Appendix A.2: smallest length so 2*num_unacked < 2^(8b). */
static void test_pnlen_boundaries(void) {
  /* no packets acked -> num_unacked == pn+1-ish large, but A.2 uses the
   * raw difference; with largest_acked ~0 the difference is small. */
  CHECK(quic_pnlen_needed(0, ~0ULL) == 1); /* num_unacked = 1 */

  /* 1-byte ceiling: num_unacked 0x7f fits, 0x80 needs 2. */
  CHECK(quic_pnlen_needed(0x7f, 0) == 1);
  CHECK(quic_pnlen_needed(0x80, 0) == 2);

  /* 2-byte ceiling: 0x7fff fits, 0x8000 needs 3. */
  CHECK(quic_pnlen_needed(0x7fff, 0) == 2);
  CHECK(quic_pnlen_needed(0x8000, 0) == 3);

  /* 3-byte ceiling: 0x7fffff fits, 0x800000 needs 4. */
  CHECK(quic_pnlen_needed(0x7fffff, 0) == 3);
  CHECK(quic_pnlen_needed(0x800000, 0) == 4);

  /* saturates at 4 beyond the 4-byte range. */
  CHECK(quic_pnlen_needed(0xffffffffULL, 0) == 4);
}

void test_pnlen(void) { test_pnlen_boundaries(); }
