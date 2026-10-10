#include "tls/keys/keyring/keyring.h"

#include "common/bytes/util/be.h"
#include "crypto/symmetric/hash/hash/hmac.h"

void keyring_key(
    const u8 seed[KEYRING_KEY], u64 now, u64 back, u8 out[KEYRING_KEY]) {
  u8 e[8];
  be_put_be64(e, now / KEYRING_PERIOD_SECS - back);
  hmac_sha256(wired_span_of(seed, KEYRING_KEY), wired_span_of(e, 8), out);
}
