#include "tls/keys/xkeys/xkeys.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"
#include "tls/handshake/core/tls/cipher.h"

static int xkeys_fits(u16 suite) {
  return suite == TLS_AES_128_GCM_SHA256 && gcmx86_supported();
}

/* x already holds contexts for exactly k's keys (constant-time: both
 * operands are secret). */
static int xkeys_current(const xkeys* x, const initial_keys* k) {
  return x->on && !ct_diff16(x->key, k->key) && !ct_diff16(x->hpkey, k->hp);
}

static void xkeys_build(xkeys* x, const initial_keys* k) {
  gcmx86_init(&x->aead, k->key);
  gcmx86_init(&x->hp, k->hp);
  bytes_memcpy(x->key, k->key, sizeof x->key);
  bytes_memcpy(x->hpkey, k->hp, sizeof x->hpkey);
  x->on = 1;
}

void xkeys_sync(xkeys* x, u16 suite, const initial_keys* k) {
  if (!xkeys_fits(suite)) {
    x->on = 0;
    return;
  }
  if (!xkeys_current(x, k)) {
    xkeys_build(x, k);
  }
}

const xkeys* xkeys_usable(const xkeys* x) { return x->on ? x : 0; }

const gcmx86* xkeys_aead(const xkeys* x) { return x ? &x->aead : 0; }

void xkeys_hp_mask(const xkeys* x, const u8 sample[16], u8 mask[5]) {
  u8 block[16];
  gcmx86_ecb(&x->hp, sample, block);
  bytes_memcpy(mask, block, 5);
}
