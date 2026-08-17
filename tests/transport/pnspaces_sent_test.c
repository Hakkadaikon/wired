#include "test.h"

/* RFC 9000 13: an ACK in one space never reclaims another space's sent packets.
 */
static void test_pnspaces_sent_ack_stays_in_space(void) {
  pnspaces_sent s;
  pnspaces_sent_init(&s);

  /* Send pn 0 in Initial (0) and pn 0 in Handshake (1). */
  sentpkt_out p0 = {0, 0, 1, 100};
  CHECK(pnspaces_on_send(&s, 0, &p0) == 1);
  CHECK(pnspaces_on_send(&s, 1, &p0) == 1);
  CHECK(pnspaces_sent_count(&s, 0) == 1);
  CHECK(pnspaces_sent_count(&s, 1) == 1);

  /* ACK pn 0 in Handshake: first range covers just pn 0. */
  u64             acked[8];
  usz             n_acked   = 0;
  u64             ranges[1] = {0};
  pnspaces_ack_in in        = {1, {0, ranges, 1}};
  pnspaces_on_ack(&s, &in, (u64out){acked, &n_acked});

  /* Handshake's pn 0 removed; Initial's pn 0 untouched. */
  CHECK(n_acked == 1);
  CHECK(acked[0] == 0);
  CHECK(pnspaces_sent_count(&s, 1) == 0);
  CHECK(pnspaces_sent_count(&s, 0) == 1); /* Initial unaffected */
}

void test_pnspaces_sent(void) { test_pnspaces_sent_ack_stays_in_space(); }
