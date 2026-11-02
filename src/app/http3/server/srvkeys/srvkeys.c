#include "app/http3/server/srvkeys/srvkeys.h"

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

/* Zero static storage is an empty tracker (zerortt_seen_init's state). */
static zerortt_seen  g_srvkeys_newtok_seen;
static zerortt_seen* g_srvkeys_newtok_tab = &g_srvkeys_newtok_seen;

zerortt_seen* srvkeys_newtoken_seen(void) { return g_srvkeys_newtok_tab; }

int srvkeys_newtoken_share(void) {
  return zerortt_seen_share(&g_srvkeys_newtok_tab, &g_srvkeys_newtok_seen);
}

/* Both keys are HMAC(seed, purpose label), never the seed itself, so the
 * Retry seed and NEW_TOKEN key differ from each other. Use a secret
 * separate from ticket_key; reusing it is not catastrophic, because the
 * labels keep every derived key distinct from the ticket keys. */
int wired_srvkeys_set_token_key(const u8 seed[SRVKEYS_LEN]) {
  static const u8 retry[]    = "wired retry key";
  static const u8 newtoken[] = "wired newtoken key";
  wired_span      key        = wired_span_of(seed, SRVKEYS_LEN);
  /* the three keys are drawn together: draw first, or a later ready()
   * would overwrite the keys set here */
  if (!srvkeys_ready()) {
    return 0;
  }
  hmac_sha256(key, wired_span_of(retry, sizeof retry - 1), g_srvkeys[1]);
  hmac_sha256(key, wired_span_of(newtoken, sizeof newtoken - 1), g_srvkeys[2]);
  return 1;
}
