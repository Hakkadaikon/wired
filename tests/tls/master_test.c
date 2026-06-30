#include "test.h"

/* Master Secret is deterministic for a given handshake secret and differs
 * from the handshake secret it was derived from. */
void test_master(void) {
  u8 ecdhe[32];
  for (usz i = 0; i < 32; i++) ecdhe[i] = (u8)(i + 3);
  u8 hs[32];
  quic_tls_handshake_secret(ecdhe, hs);

  u8 ms_a[32], ms_b[32];
  quic_tls_master_secret(hs, ms_a);
  quic_tls_master_secret(hs, ms_b);
  for (usz i = 0; i < 32; i++) CHECK(ms_a[i] == ms_b[i]); /* deterministic */

  int differ = 0;
  for (usz i = 0; i < 32; i++) differ |= (ms_a[i] != hs[i]);
  CHECK(differ); /* master secret != handshake secret */
}
