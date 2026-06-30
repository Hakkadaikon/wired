#include "test.h"

/* RFC 9001 6.1: the next secret is a deterministic function of the current
 * one, and successive updates advance it. */
void test_kuderive(void) {
  u8 cur[32];
  for (usz i = 0; i < 32; i++) cur[i] = (u8)i;

  u8 a[32], b[32];
  quic_ku_next_secret(cur, a);
  quic_ku_next_secret(cur, b);
  for (usz i = 0; i < 32; i++) CHECK(a[i] == b[i]); /* deterministic */

  int differs = 0;
  for (usz i = 0; i < 32; i++) differs |= (a[i] != cur[i]);
  CHECK(differs); /* advances away from the input */

  u8 c[32];
  quic_ku_next_secret(a, c);
  differs = 0;
  for (usz i = 0; i < 32; i++) differs |= (c[i] != a[i]);
  CHECK(differs); /* a second update advances again */
}
