#include "test.h"

static void test_rtx_fifo(void) {
  rtx_queue q;
  rtx_init(&q);
  CHECK(rtx_push(&q, (const u8*)"aaa", 3) == 1);
  CHECK(rtx_push(&q, (const u8*)"bb", 2) == 1);
  u8 out[8];
  CHECK(rtx_pop(&q, out, sizeof(out)) == 3 && out[0] == 'a');
  CHECK(rtx_pop(&q, out, sizeof(out)) == 2 && out[0] == 'b');
  CHECK(rtx_pop(&q, out, sizeof(out)) == 0); /* empty */
}

/* Lost frames pushed then drained in order, ready for resend under new pn. */
static void test_rtx_drains_in_order(void) {
  rtx_queue q;
  rtx_init(&q);
  for (u8 i = 0; i < 10; i++) rtx_push(&q, &i, 1);
  u8 out[4];
  for (u8 i = 0; i < 10; i++)
    CHECK(rtx_pop(&q, out, sizeof(out)) == 1 && out[0] == i);
}

static void test_rtx_full_and_oversize(void) {
  rtx_queue q;
  rtx_init(&q);
  u8 byte = 0x42;
  for (usz i = 0; i < RTX_SLOTS; i++) CHECK(rtx_push(&q, &byte, 1) == 1);
  CHECK(rtx_push(&q, &byte, 1) == 0); /* full */
  /* pop into too-small buffer is refused without losing the frame */
  rtx_queue q2;
  rtx_init(&q2);
  u8 big[10];
  rtx_push(&q2, big, 10);
  u8 small[4];
  CHECK(rtx_pop(&q2, small, 4) == 0);
  CHECK(q2.count == 1);
}

void test_rtx(void) {
  test_rtx_fifo();
  test_rtx_drains_in_order();
  test_rtx_full_and_oversize();
}
