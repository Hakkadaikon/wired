#include "test.h"

/* In a long header, version and both CIDs are plaintext (RFC 9312 3). */
static void test_observable_long(void) {
  CHECK(observable_field(OBS_VERSION, 1) == 1);
  CHECK(observable_field(OBS_DCID, 1) == 1);
  CHECK(observable_field(OBS_SCID, 1) == 1);
  CHECK(observable_field(OBS_SPIN, 1) == 0); /* no spin in long */
}

/* In a short header, only the spin bit and the DCID are observable. */
static void test_observable_short(void) {
  CHECK(observable_field(OBS_SPIN, 0) == 1);
  CHECK(observable_field(OBS_DCID, 0) == 1);
  CHECK(observable_field(OBS_SCID, 0) == 0); /* no SCID in short */
  CHECK(observable_field(OBS_VERSION, 0) == 0);
}

/* Protected fields are never observable, either form. */
static void test_observable_protected(void) {
  CHECK(observable_field(OBS_KEYPHASE, 0) == 0);
  CHECK(observable_field(OBS_PAYLOAD, 0) == 0);
  CHECK(observable_field(OBS_PAYLOAD, 1) == 0);
}

void test_observable(void) {
  test_observable_long();
  test_observable_short();
  test_observable_protected();
}
