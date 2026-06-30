#include "app/http3/core/h3conn/establish.h"
#include "test.h"

/* RFC 9114 6.2 / 7.2.4: open_control yields a control stream that the peer
 * accepts as starting with SETTINGS; round-trips through peer_settings_ok. */
void test_h3conn_establish(void) {
  u8  cs[64];
  usz n = 0;

  CHECK(quic_h3conn_open_control(cs, sizeof(cs), &n));
  CHECK(n > 0);
  CHECK(quic_h3conn_peer_settings_ok(cs, n));

  /* cap too small for the control stream */
  CHECK(!quic_h3conn_open_control(cs, 0, &n));

  /* a non-control stream type (0x01 push) is rejected */
  {
    u8 bad[4] = {0x01, 0x04, 0x00, 0x00};
    CHECK(!quic_h3conn_peer_settings_ok(bad, sizeof(bad)));
  }
  /* control type but first frame is not SETTINGS (0x01 DATA) */
  {
    u8 bad[4] = {0x00, 0x01, 0x01, 0x00};
    CHECK(!quic_h3conn_peer_settings_ok(bad, sizeof(bad)));
  }
  /* truncated: only the type byte */
  {
    u8 only[1] = {0x00};
    CHECK(!quic_h3conn_peer_settings_ok(only, sizeof(only)));
  }
}
