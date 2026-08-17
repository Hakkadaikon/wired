#include "test.h"

/* verify_data is deterministic and check accepts it; a tampered Finished or a
 * different transcript is rejected. */
static void test_finished(void) {
  u8 base[HKDF_PRK];
  u8 th[SHA256_DIGEST];
  for (usz i = 0; i < HKDF_PRK; i++) base[i] = (u8)(i + 1);
  for (usz i = 0; i < SHA256_DIGEST; i++) th[i] = (u8)(0xA0 + i);

  u8 vd[TLS_VERIFY_DATA], vd2[TLS_VERIFY_DATA];
  tls_finished_verify_data(base, th, vd);
  tls_finished_verify_data(base, th, vd2);
  for (usz i = 0; i < TLS_VERIFY_DATA; i++) CHECK(vd[i] == vd2[i]);

  CHECK(tls_finished_check(base, th, vd) == 1); /* matching Finished */

  u8 tampered[TLS_VERIFY_DATA];
  for (usz i = 0; i < TLS_VERIFY_DATA; i++) tampered[i] = vd[i];
  tampered[0] ^= 0x01;
  CHECK(tls_finished_check(base, th, tampered) == 0);

  /* a different transcript hash must not verify against vd */
  u8 th2[SHA256_DIGEST];
  for (usz i = 0; i < SHA256_DIGEST; i++) th2[i] = th[i];
  th2[0] ^= 0xFF;
  CHECK(tls_finished_check(base, th2, vd) == 0);
}
