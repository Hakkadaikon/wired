#ifndef XKEYS_XKEYS_H
#define XKEYS_XKEYS_H

#include "crypto/symmetric/aead/gcmx86/gcmx86.h"
#include "tls/handshake/core/tls/initial.h"

/** The AES-NI contexts of one 1-RTT key generation (RFC 9001 5.3 packet
 * key, 5.4.3 header-protection key), built once so that no packet re-runs
 * the AES key schedule. Lives next to the generation's initial_keys and is
 * brought in line with them by xkeys_sync before use; it holds copies of
 * the raw keys it was built from, so a rotation that xkeys_sync has not
 * seen yet can never seal or open under a stale key. */
typedef struct {
  gcmx86 aead;      /**< the packet key, expanded */
  gcmx86 hp;        /**< the header-protection key, expanded (its H unused) */
  u8     key[16];   /**< the packet key aead was built from */
  u8     hpkey[16]; /**< the header-protection key hp was built from */
  u8     on;        /**< 1: aead and hp are valid for key and hpkey */
} xkeys;

/** Bring x in line with k under the negotiated suite: valid (on = 1) for
 * TLS_AES_128_GCM_SHA256 on a CPU with AES-NI and PCLMULQDQ, rebuilt only
 * when k's keys differ from the ones x holds; off for every other case,
 * which keeps the raw-key path. */
void xkeys_sync(xkeys* x, u16 suite, const initial_keys* k);

/** RFC 9001 6.5: x's expanded keys and the raw copies leave memory; x is
 * off until the next xkeys_sync. */
void xkeys_wipe(xkeys* x);

/** x when it may be used, else 0. */
const xkeys* xkeys_usable(const xkeys* x);

/** x's packet-key context, or 0 when x is 0. */
const gcmx86* xkeys_aead(const xkeys* x);

/** RFC 9001 5.4.3: mask = AES-ECB(hp key, sample)[0..4]. */
void xkeys_hp_mask(const xkeys* x, const u8 sample[16], u8 mask[5]);

#endif
