#include "test.h"

static void test_conn_handshake(void) {
  conn c;
  conn_init(&c);
  CHECK(c.phase == QUIC_PHASE_INITIAL);
  CHECK(
      conn_step(&c, QUIC_CONN_EV_HS_PROGRESS) &&
      c.phase == QUIC_PHASE_HANDSHAKE);
  CHECK(
      conn_step(&c, QUIC_CONN_EV_HS_CONFIRMED) &&
      c.phase == QUIC_PHASE_CONFIRMED);
}

/* Phases never run backwards (conn_phase_no_regress). */
static void test_conn_no_regress(void) {
  conn c;
  conn_init(&c);
  conn_step(&c, QUIC_CONN_EV_HS_PROGRESS);
  conn_step(&c, QUIC_CONN_EV_HS_CONFIRMED);
  /* no event drives Confirmed back to Handshake/Initial */
  CHECK(
      !conn_step(&c, QUIC_CONN_EV_HS_PROGRESS) &&
      c.phase == QUIC_PHASE_CONFIRMED);
}

/* Closing converges to Closed and never reopens (conn_closed_never_reopens). */
static void test_conn_close(void) {
  conn c;
  conn_init(&c);
  conn_step(&c, QUIC_CONN_EV_HS_PROGRESS);
  CHECK(conn_step(&c, QUIC_CONN_EV_CLOSE) && c.phase == QUIC_PHASE_CLOSING);
  CHECK(conn_step(&c, QUIC_CONN_EV_CLOSED) && c.phase == QUIC_PHASE_CLOSED);
  CHECK(
      !conn_step(&c, QUIC_CONN_EV_HS_PROGRESS) && c.phase == QUIC_PHASE_CLOSED);
}

/* Per-space packet numbers are strictly monotonic and spaces are
 * independent (conn_pn_per_space_non_decreasing, conn_pn_spaces_independent).
 */
static void test_conn_pn_monotonic_independent(void) {
  conn c;
  conn_init(&c);
  u64 a, b, d;
  CHECK(conn_next_pn(&c, QUIC_PN_INITIAL, &a) && a == 0);
  CHECK(conn_next_pn(&c, QUIC_PN_INITIAL, &b) && b == 1);
  /* a different space is unaffected by Initial's counter */
  CHECK(conn_next_pn(&c, QUIC_PN_HANDSHAKE, &d) && d == 0);
}

/* Application space is refused before the handshake is confirmed
 * (conn_no_app_packet_before_confirmed). */
static void test_conn_app_space_gated(void) {
  conn c;
  conn_init(&c);
  u64 pn;
  CHECK(!conn_next_pn(&c, QUIC_PN_APPLICATION, &pn)); /* Initial phase */
  conn_step(&c, QUIC_CONN_EV_HS_PROGRESS);
  CHECK(!conn_next_pn(&c, QUIC_PN_APPLICATION, &pn)); /* Handshake phase */
  conn_step(&c, QUIC_CONN_EV_HS_CONFIRMED);
  CHECK(conn_next_pn(&c, QUIC_PN_APPLICATION, &pn) && pn == 0);
}

void test_conn(void) {
  test_conn_handshake();
  test_conn_no_regress();
  test_conn_close();
  test_conn_pn_monotonic_independent();
  test_conn_app_space_gated();
}
