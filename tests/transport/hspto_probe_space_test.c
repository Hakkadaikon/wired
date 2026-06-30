#include "test.h"

/* RFC 9002 6.2.2.1: probe the lowest space with in-flight data; Initial
 * outranks Handshake before confirmation. */

static void test_hspto_probe_initial_preferred(void) {
  CHECK(quic_hspto_probe_space(1, 1, 0) == QUIC_HSPTO_SPACE_INITIAL);
}

static void test_hspto_probe_handshake_when_no_initial(void) {
  CHECK(quic_hspto_probe_space(0, 1, 0) == QUIC_HSPTO_SPACE_HANDSHAKE);
}

static void test_hspto_probe_application_when_confirmed(void) {
  CHECK(quic_hspto_probe_space(1, 1, 1) == QUIC_HSPTO_SPACE_APPLICATION);
}

static void test_hspto_probe_application_when_nothing_early(void) {
  CHECK(quic_hspto_probe_space(0, 0, 0) == QUIC_HSPTO_SPACE_APPLICATION);
}

void test_hspto_probe_space(void) {
  test_hspto_probe_initial_preferred();
  test_hspto_probe_handshake_when_no_initial();
  test_hspto_probe_application_when_confirmed();
  test_hspto_probe_application_when_nothing_early();
}
