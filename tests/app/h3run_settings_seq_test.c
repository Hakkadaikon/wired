#include "test.h"

/* RFC 9114 7.2.4: the first control frame must be SETTINGS (0x04). */
static void test_settings_first_required(void) {
  quic_h3_settings_state s = {0};
  CHECK(
      quic_h3_settings_first(&s, 0x01) ==
      0); /* CANCEL_PUSH: H3_MISSING_SETTINGS */

  quic_h3_settings_state ok = {0};
  CHECK(quic_h3_settings_first(&ok, QUIC_H3_FRAME_SETTINGS) == 1);
}

/* RFC 9114 7.2.4: SETTINGS occurs exactly once. */
static void test_settings_once(void) {
  quic_h3_settings_state s = {0};
  CHECK(quic_h3_settings_first(&s, QUIC_H3_FRAME_SETTINGS) == 1);
  CHECK(
      quic_h3_settings_first(&s, QUIC_H3_FRAME_SETTINGS) ==
      0); /* 2nd SETTINGS */
}

void test_h3run_settings_seq(void) {
  test_settings_first_required();
  test_settings_once();
}
