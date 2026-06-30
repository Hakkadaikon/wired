#include "test.h"

/* RFC 9000 13.1: each space records its own received PNs and builds its own
 * ACK ranges; recording in one space does not affect another. */
static void test_pnspaces_recv_ranges_per_space(void) {
  quic_pnspaces_recv s;
  quic_pnspaces_recv_init(&s);

  /* No reception yet => no ranges. */
  u64 largest  = 99, ranges[8];
  usz n_ranges = 0;
  CHECK(quic_pnspaces_ack_ranges(&s, 0, &largest, ranges, &n_ranges, 8) == 0);

  /* Receive 8,9,10 in Initial (0); 5 in Application (2). */
  quic_pnspaces_on_recv(&s, 0, 10);
  quic_pnspaces_on_recv(&s, 0, 9);
  quic_pnspaces_on_recv(&s, 0, 8);
  quic_pnspaces_on_recv(&s, 2, 5);

  /* Initial's ack ranges: largest 10, one contiguous block of 3 (len 2). */
  CHECK(quic_pnspaces_ack_ranges(&s, 0, &largest, ranges, &n_ranges, 8) == 1);
  CHECK(largest == 10);
  CHECK(n_ranges == 1);
  CHECK(ranges[0] == 2); /* First ACK Range = count - 1 */

  /* Application is independent: only pn 5, unaffected by Initial. */
  CHECK(quic_pnspaces_ack_ranges(&s, 2, &largest, ranges, &n_ranges, 8) == 1);
  CHECK(largest == 5);
  CHECK(n_ranges == 1);
  CHECK(ranges[0] == 0);

  /* Handshake (1) received nothing. */
  CHECK(quic_pnspaces_ack_ranges(&s, 1, &largest, ranges, &n_ranges, 8) == 0);
}

void test_pnspaces_recv(void) { test_pnspaces_recv_ranges_per_space(); }
