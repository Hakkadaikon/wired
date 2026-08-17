#include "test.h"

/* RFC 9001 6.6: integrity limits are 2^52 (AES-GCM) and 2^36 (ChaCha20). */
void test_aeadintegrity(void) {
  u64 g = AEAD_INTEGRITY_LIMIT_AESGCM;
  CHECK(!aead_integrity_exceeded(g - 1, 0)); /* one below: still ok */
  CHECK(aead_integrity_exceeded(g, 0));      /* at limit: must close */
  CHECK(aead_integrity_exceeded(g + 1, 0));

  u64 c = AEAD_INTEGRITY_LIMIT_CHACHA;
  CHECK(!aead_integrity_exceeded(c - 1, 1));
  CHECK(aead_integrity_exceeded(c, 1));

  /* the ChaCha20 integrity limit is well below the AES-GCM one */
  CHECK(!aead_integrity_exceeded(c, 0));
}
