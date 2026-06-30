#include "test.h"

static void test_flow_send(void) {
  quic_flow_send f;
  quic_flow_send_init(&f, 1000);
  CHECK(quic_flow_send_avail(&f) == 1000);
  CHECK(quic_flow_send_record(&f, 600) == 1);
  CHECK(quic_flow_send_avail(&f) == 400);
  CHECK(quic_flow_send_record(&f, 500) == 0); /* exceeds limit, rejected */
  CHECK(f.sent == 600);
  quic_flow_send_update_max(&f, 2000);
  CHECK(quic_flow_send_avail(&f) == 1400);
  quic_flow_send_update_max(&f, 100); /* never lowers */
  CHECK(f.max_data == 2000);
}

static void test_flow_recv(void) {
  quic_flow_recv f;
  quic_flow_recv_init(&f, 1000);
  CHECK(f.max_data == 1000);
  CHECK(quic_flow_recv_consume(&f, 400) == 1400); /* credit slides forward */
}

/* Only the contiguous prefix from 0 is delivered; data past a gap waits. */
static void test_reasm_contiguous_only(void) {
  quic_reasm r;
  quic_reasm_init(&r);
  quic_reasm_insert(&r, 0, (const u8 *)"abc", 3);
  quic_reasm_insert(&r, 6, (const u8 *)"ghi", 3); /* gap at [3,6) */
  CHECK(quic_reasm_deliver(&r) == 3);             /* stops at the hole */
  quic_reasm_insert(&r, 3, (const u8 *)"def", 3); /* fill the hole */
  CHECK(quic_reasm_deliver(&r) == 9);             /* now flows past it */
  CHECK(r.buf[4] == 'e' && r.buf[7] == 'h');
}

/* Overlapping inserts are idempotent and don't move delivered backward. */
static void test_reasm_idempotent(void) {
  quic_reasm r;
  quic_reasm_init(&r);
  quic_reasm_insert(&r, 0, (const u8 *)"hello", 5);
  CHECK(quic_reasm_deliver(&r) == 5);
  quic_reasm_insert(&r, 2, (const u8 *)"llo", 3); /* overlap */
  CHECK(quic_reasm_deliver(&r) == 5);             /* unchanged */
}

/* The sender is blocked when it wants more than the limit allows. */
static void test_flow_blocked(void) {
  quic_flow_send f;
  quic_flow_send_init(&f, 100);
  CHECK(quic_flow_send_blocked(&f, 0) == 0);   /* nothing to send */
  CHECK(quic_flow_send_blocked(&f, 100) == 0); /* exactly fits */
  CHECK(quic_flow_send_blocked(&f, 101) == 1); /* over the limit: blocked */
  quic_flow_send_record(&f, 100);              /* limit reached */
  CHECK(quic_flow_send_blocked(&f, 1) == 1);   /* no room left: blocked */
  quic_flow_send_update_max(&f, 150);
  CHECK(quic_flow_send_blocked(&f, 50) == 0); /* room again */
}

void test_flow(void) {
  test_flow_send();
  test_flow_recv();
  test_flow_blocked();
  test_reasm_contiguous_only();
  test_reasm_idempotent();
}
