#include "app/http3/server/srvkeys/srvkeys.h"

#include "common/bytes/util/bytes.h"
#include "common/platform/rng/rng.h"
#include "crypto/symmetric/hash/hash/hmac.h"

/* [0] ticket seed, [1] Retry-token seed, [2] NEW_TOKEN key. */
static u8  g_srvkeys[3][SRVKEYS_LEN];
static int g_srvkeys_drawn;

/* The draw happens once, on the starting thread, before any worker exists
 * (see srvkeys.h); the acquire/release pair keeps a later reader on another
 * thread from seeing the flag before the bytes. */
int srvkeys_ready(void) {
  if (__atomic_load_n(&g_srvkeys_drawn, __ATOMIC_ACQUIRE)) {
    return 1;
  }
  if (!rng_bytes(&g_srvkeys[0][0], sizeof g_srvkeys)) {
    return 0;
  }
  __atomic_store_n(&g_srvkeys_drawn, 1, __ATOMIC_RELEASE);
  return 1;
}

const u8* srvkeys_ticket(void) {
  srvkeys_ready();
  return g_srvkeys[0];
}

const u8* srvkeys_retry(void) {
  srvkeys_ready();
  return g_srvkeys[1];
}

const u8* srvkeys_newtoken(void) {
  srvkeys_ready();
  return g_srvkeys[2];
}

/* The NEW_TOKEN key is HMAC(seed, label), not the seed itself: the seed
 * already keys the Retry keyring (HMAC(seed, be64(epoch))). */
int wired_srvkeys_set_token_key(const u8 seed[SRVKEYS_LEN]) {
  static const u8 label[] = "wired newtoken key";
  if (!srvkeys_ready()) {
    return 0;
  }
  bytes_memcpy(g_srvkeys[1], seed, SRVKEYS_LEN);
  hmac_sha256(
      wired_span_of(seed, SRVKEYS_LEN), wired_span_of(label, sizeof label - 1),
      g_srvkeys[2]);
  return 1;
}
