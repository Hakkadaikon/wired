#include "app/http3/core/h3/frame.h"
#include "test.h"

/* The HTTP/2-reserved identifiers 0x02..0x05 are forbidden in HTTP/3. */
static void test_settings_reserved(void) {
  CHECK(h3_setting_allowed(0x02) == 0);
  CHECK(h3_setting_allowed(0x03) == 0);
  CHECK(h3_setting_allowed(0x04) == 0);
  CHECK(h3_setting_allowed(0x05) == 0);
}

/* Known and boundary identifiers are allowed. */
static void test_settings_allowed(void) {
  CHECK(h3_setting_allowed(0x00) == 1); /* below */
  CHECK(h3_setting_allowed(0x01) == 1); /* just below */
  CHECK(h3_setting_allowed(0x06) == 1); /* MAX_FIELD_SECTION_SIZE */
  CHECK(h3_setting_allowed(QUIC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE) == 1);
  CHECK(h3_setting_allowed(0x07) == 1); /* just above */
}

/* Unknown / large identifiers are allowed (ignored, not an error). */
static void test_settings_unknown(void) {
  CHECK(h3_setting_allowed(0x21) == 1); /* a GREASE-ish id */
  CHECK(h3_setting_allowed(0xffffffffffffffffUL) == 1);
}

/* RFC 9297 2.1.1 / 9297-012: "The value of the SETTINGS_H3_DATAGRAM setting
 * MUST be either 0 or 1. ... If ... received with a value that is neither 0
 * nor 1, the receiver MUST terminate the connection with error
 * H3_SETTINGS_ERROR." A setting id other than SETTINGS_H3_DATAGRAM (0x33) is
 * out of scope for this check -- any value is fine regardless. */
static void test_settings_h3_datagram_value_ok(void) {
  CHECK(h3_setting_h3_datagram_value_ok(0x33, 0) == 1);
  CHECK(h3_setting_h3_datagram_value_ok(0x33, 1) == 1);
  CHECK(h3_setting_h3_datagram_value_ok(0x33, 2) == 0);
  CHECK(h3_setting_h3_datagram_value_ok(0x33, 0xffffffffffffffffUL) == 0);
  /* a different id is not this setting at all -- any value passes */
  CHECK(h3_setting_h3_datagram_value_ok(0x06, 2) == 1);
  CHECK(h3_setting_h3_datagram_value_ok(0x08, 0xffffffffffffffffUL) == 1);
}

void test_settings_check(void) {
  test_settings_reserved();
  test_settings_allowed();
  test_settings_unknown();
  test_settings_h3_datagram_value_ok();
}
