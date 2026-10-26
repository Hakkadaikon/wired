#include "test.h"

/* RFC 9369 5: a ticket resumes on the same version. */
static void test_ticket_same_version(void) {
  CHECK(ticket_version_ok(VERSION_1, VERSION_1) == 1);
  CHECK(ticket_version_ok(VERSION_2, VERSION_2) == 1);
}

/* RFC 9369 5: "not accept one issued from a different version" -- even a
 * compatible one. */
static void test_ticket_other_version_rejected(void) {
  CHECK(ticket_version_ok(VERSION_1, VERSION_2) == 0);
  CHECK(ticket_version_ok(VERSION_2, VERSION_1) == 0);
  CHECK(ticket_version_ok(VERSION_1, 0xdeadbeefu) == 0);
}

void test_ticketversion(void) {
  test_ticket_same_version();
  test_ticket_other_version_rejected();
}
