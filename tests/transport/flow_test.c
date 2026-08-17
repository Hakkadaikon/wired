#include "test.h"

static void test_flow_send(void) {
  flow_send f;
  flow_send_init(&f, 1000);
  CHECK(flow_send_avail(&f) == 1000);
  CHECK(flow_send_record(&f, 600) == 1);
  CHECK(flow_send_avail(&f) == 400);
  CHECK(flow_send_record(&f, 500) == 0); /* exceeds limit, rejected */
  CHECK(f.sent == 600);
  flow_send_update_max(&f, 2000);
  CHECK(flow_send_avail(&f) == 1400);
  flow_send_update_max(&f, 100); /* never lowers */
  CHECK(f.max_data == 2000);
}

static void test_flow_recv(void) {
  flow_recv f;
  flow_recv_init(&f, 1000);
  CHECK(f.max_data == 1000);
  CHECK(flow_recv_consume(&f, 400) == 1400); /* credit slides forward */
}

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

/* The sender is blocked when it wants more than the limit allows. */
static void test_flow_blocked(void) {
  flow_send f;
  flow_send_init(&f, 100);
  CHECK(flow_send_blocked(&f, 0) == 0);   /* nothing to send */
  CHECK(flow_send_blocked(&f, 100) == 0); /* exactly fits */
  CHECK(flow_send_blocked(&f, 101) == 1); /* over the limit: blocked */
  flow_send_record(&f, 100);              /* limit reached */
  CHECK(flow_send_blocked(&f, 1) == 1);   /* no room left: blocked */
  flow_send_update_max(&f, 150);
  CHECK(flow_send_blocked(&f, 50) == 0); /* room again */
}

void test_flow(void) {
  test_flow_send();
  test_flow_recv();
  test_flow_blocked();
  test_reasm_contiguous_only();
  test_reasm_idempotent();
}
