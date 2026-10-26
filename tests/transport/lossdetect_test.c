#include "test.h"

/* Packet threshold: lost exactly when largest_acked - pn >= 3. */
static void test_loss_by_packet_boundary(void) {
  CHECK(loss_by_packet(10, 7) == 1);  /* gap 3 */
  CHECK(loss_by_packet(10, 8) == 0);  /* gap 2 */
  CHECK(loss_by_packet(10, 10) == 0); /* same packet */
  CHECK(loss_by_packet(3, 0) == 1);   /* gap 3 from zero */
}

void test_lossdetect(void) { test_loss_by_packet_boundary(); }
