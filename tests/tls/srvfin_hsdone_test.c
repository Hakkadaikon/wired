#include "test.h"
#include "tls/handshake/roles/srvfin/hsdone.h"

/* HANDSHAKE_DONE is sent once: only when complete and not already sent. The
 * frame is a single 0x1e byte. */
void test_srvfin_hsdone(void) {
  CHECK(quic_srvfin_should_send_handshake_done(1, 0) == 1);
  CHECK(quic_srvfin_should_send_handshake_done(0, 0) == 0); /* not complete */
  CHECK(quic_srvfin_should_send_handshake_done(1, 1) == 0); /* already sent */
  CHECK(quic_srvfin_should_send_handshake_done(0, 1) == 0);

  u8  out[4];
  usz n = 0;
  CHECK(quic_srvfin_handshake_done_frame(out, sizeof out, &n) == 1);
  CHECK(n == 1);
  CHECK(out[0] == 0x1e);

  /* no room: nothing written, returns 0 */
  CHECK(quic_srvfin_handshake_done_frame(out, 0, &n) == 0);
}
