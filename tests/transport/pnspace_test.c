#include "test.h"

/* All spaces start at 0. */
static void test_pnspace_starts_at_zero(void) {
  pnspace s;
  pnspace_init(&s);
  CHECK(pnspace_next(&s, QUIC_PNS_INITIAL) == 0);
  CHECK(pnspace_next(&s, QUIC_PNS_HANDSHAKE) == 0);
  CHECK(pnspace_next(&s, QUIC_PNS_APP) == 0);
}

/* Each space counts independently: pulling from one does not advance others. */
static void test_pnspace_independent(void) {
  pnspace s;
  pnspace_init(&s);
  CHECK(pnspace_next(&s, QUIC_PNS_INITIAL) == 0);
  CHECK(pnspace_next(&s, QUIC_PNS_INITIAL) == 1);
  CHECK(pnspace_next(&s, QUIC_PNS_INITIAL) == 2);
  /* Handshake untouched by Initial activity */
  CHECK(pnspace_next(&s, QUIC_PNS_HANDSHAKE) == 0);
  CHECK(pnspace_next(&s, QUIC_PNS_HANDSHAKE) == 1);
  /* App still independent */
  CHECK(pnspace_next(&s, QUIC_PNS_APP) == 0);
  /* Initial resumes from where it left off */
  CHECK(pnspace_next(&s, QUIC_PNS_INITIAL) == 3);
}

/* RFC 9000 12.3: once the packet number for sending reaches 2^62-1, the
 * space is exhausted and the sender must not issue another one. */
static void test_pnspace_exhausted_at_limit(void) {
  pnspace s;
  pnspace_init(&s);
  CHECK(pnspace_exhausted(&s, QUIC_PNS_APP) == 0);
  s.next[QUIC_PNS_APP] = QUIC_PN_LIMIT; /* about to issue the last legal pn */
  CHECK(pnspace_exhausted(&s, QUIC_PNS_APP) == 0);
  CHECK(pnspace_next(&s, QUIC_PNS_APP) == QUIC_PN_LIMIT);
  /* the space just issued 2^62-1, the last legal packet number */
  CHECK(pnspace_exhausted(&s, QUIC_PNS_APP) == 1);
  /* other spaces are untouched */
  CHECK(pnspace_exhausted(&s, QUIC_PNS_INITIAL) == 0);
}

void test_pnspace(void) {
  test_pnspace_starts_at_zero();
  test_pnspace_independent();
  test_pnspace_exhausted_at_limit();
}
