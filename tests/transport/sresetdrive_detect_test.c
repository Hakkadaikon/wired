#include "test.h"

/* RFC 9000 10.3.1: trailing token matches -> reset; mismatch and short don't.
 */
void test_sresetdrive_detect(void) {
  u8 token[SRESETDRIVE_TOKEN];
  for (u8 i = 0; i < SRESETDRIVE_TOKEN; i++) token[i] = (u8)(0xa0 + i);

  u8 pkt[SRESETDRIVE_MIN];
  for (usz i = 0; i < 5; i++) pkt[i] = (u8)i; /* header room */
  for (u8 i = 0; i < SRESETDRIVE_TOKEN; i++) pkt[5 + i] = token[i];
  CHECK(sresetdrive_is_reset(pkt, SRESETDRIVE_MIN, token) == 1);

  pkt[SRESETDRIVE_MIN - 1] ^= 0x01; /* corrupt last token byte */
  CHECK(sresetdrive_is_reset(pkt, SRESETDRIVE_MIN, token) == 0);

  /* one byte under the 21-byte minimum is never a reset */
  CHECK(sresetdrive_is_reset(pkt, SRESETDRIVE_MIN - 1, token) == 0);
}
