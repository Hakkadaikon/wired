#include "test.h"

/* RFC 9000 10.2: an open connection may send application data. */
static void test_open_sends_appdata(void) {
  quic_life l;
  quic_life_init(&l, 10, 2);
  CHECK(quic_life_send_kind(&l) == QUIC_SEND_APPDATA);
}

/* RFC 9000 10.2.1: closing sends ONLY a CONNECTION_CLOSE, never app data. */
static void test_closing_sends_cc_only(void) {
  quic_life l;
  quic_life_init(&l, 10, 2);
  quic_life_close(&l);
  CHECK(quic_life_send_kind(&l) == QUIC_SEND_CC);
}

/* RFC 9000 10.2.2: draining sends nothing at all. */
static void test_draining_sends_nothing(void) {
  quic_life l;
  quic_life_init(&l, 10, 2);
  quic_life_on_peer_close(&l);
  CHECK(quic_life_send_kind(&l) == QUIC_SEND_NONE);
}

/* RFC 9000 10.2: closed sends nothing at all. */
static void test_closed_sends_nothing(void) {
  quic_life l;
  quic_life_init(&l, 10, 10);
  quic_life_on_reset(&l); /* -> CLOSED */
  CHECK(quic_life_send_kind(&l) == QUIC_SEND_NONE);
}

/* RFC 9000 10.2.1: the close timer is due at exactly 3*PTO (close_max), and
 * not one tick before. */
static void test_closing_due_exactly_at_close_max(void) {
  quic_life l;
  quic_life_init(&l, 10, 2);
  quic_life_close(&l);
  quic_life_tick(&l);              /* close_ticks = 1 < 2 */
  CHECK(!quic_life_close_due(&l)); /* not before the limit */
  quic_life_tick(&l);              /* close_ticks = 2 == 2 */
  CHECK(quic_life_close_due(&l));  /* due at exactly 3*PTO */
}

/* RFC 9000 10.2.2: draining is likewise due at exactly close_max. */
static void test_draining_due_exactly_at_close_max(void) {
  quic_life l;
  quic_life_init(&l, 10, 2);
  quic_life_on_peer_close(&l);
  quic_life_tick(&l);
  CHECK(!quic_life_close_due(&l));
  quic_life_tick(&l);
  CHECK(quic_life_close_due(&l));
}

/* RFC 9000 10.1: the idle timer is due at exactly idle_max, not before. */
static void test_idle_due_exactly_at_idle_max(void) {
  quic_life l;
  quic_life_init(&l, 3, 5);
  quic_life_tick(&l);
  quic_life_tick(&l); /* idle_ticks = 2 < 3 */
  CHECK(!quic_life_idle_due(&l));
}

void test_termgate(void) {
  test_open_sends_appdata();
  test_closing_sends_cc_only();
  test_draining_sends_nothing();
  test_closed_sends_nothing();
  test_closing_due_exactly_at_close_max();
  test_draining_due_exactly_at_close_max();
  test_idle_due_exactly_at_idle_max();
}
