#ifndef WIRED_CERTCACHE_CERTCACHE_H
#define WIRED_CERTCACHE_CERTCACHE_H

#include "app/http3/server/srvboot/srvboot.h"

/** @file
 * RFC 5280 4.1: process-lifetime cache of the self-signed end-entity
 * certificate. A wired_srvboot_id's inputs (cert_seed, san_ipv4, now_secs)
 * are fixed for the process and the ECDSA signature is deterministic
 * (RFC 6979), so every per-connection rebuild produces byte-identical DER --
 * build it once at startup and hand every connection the same 1-entry chain
 * instead of paying the key derivation and signing on each accept. */

/** The cached certificate: DER storage, the 1-entry chain view over it that
 * a wired_srvboot_id borrows, and whether it has been built. The holder must
 * outlive every connection using the chain (an env-lifetime member). */
typedef struct {
  u8 der[512];         /**< certificate DER (owned; same sizing rationale as
                        * quic_sdrv.cert_buf) */
  wired_span chain[1]; /**< 1-entry chain view over der, once primed */
  int        primed;   /**< 1 once der/chain hold a built certificate */
} wired_certcache;

/** Build the self-signed certificate for id once and point id->chain at the
 * cached copy, so later boots take the external-chain path instead of
 * rebuilding. No-op when id already carries a chain (an externally issued
 * certificate, or a cache primed earlier). The CertificateVerify signing key
 * stays id->cert_seed either way, which is also the key the cached
 * certificate's SPKI was derived from.
 * @param c the cache; must outlive every connection booted from id
 * @param id the server identity to prime (chain/chain_count rewritten) */
void wired_certcache_prime(wired_certcache* c, wired_srvboot_id* id);

#endif
