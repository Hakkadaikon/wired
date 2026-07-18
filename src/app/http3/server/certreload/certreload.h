#ifndef WIRED_CERTRELOAD_CERTRELOAD_H
#define WIRED_CERTRELOAD_CERTRELOAD_H

#include "app/http3/server/srvboot/srvboot.h"
#include "common/bytes/span/span.h"

/** @file
 * Load (or reload) a server's certificate chain and P-256 signing key from a
 * cert.pem (fullchain, leaf first, RFC 7468 5) and key.pem (SEC1 or PKCS#8
 * EC private key, RFC 7468 4) pair on disk. Shared by the example app's
 * startup path and by a running server's SIGHUP-triggered hot reload
 * (`app/http3/server/srvrun`), so the parsing logic exists exactly once. */

/** At most this many CERTIFICATE blocks are read from a fullchain cert.pem
 * (leaf + intermediates). Sized past quic-interop-runner's amplificationlimit
 * case, which deliberately serves a 9-certificate chain to inflate the
 * server's Handshake flight for its RFC 9000 8.1 anti-amplification check;
 * matches QUIC_TLS_CERT_CHAIN_MAX (sdrv/cert.h) so a chain this loader
 * accepts is never rejected downstream at the TLS flight-build layer. */
#define WIRED_CERTRELOAD_CHAIN_MAX 10

/** Caller-owned storage a load fills: the DER bytes of every chain
 * certificate (concatenated), spans into that buffer (leaf first), and the
 * decoded P-256 private scalar. All views wired_srvboot_id would hold must
 * outlive the id — keep this struct alive for as long as the identity built
 * from it is in use. */
typedef struct {
  /** concatenated DER of every chain cert. Sized past a real 9-cert
   * amplificationlimit chain's cert.pem (13594 bytes of PEM/base64; DER is
   * more compact) with headroom. */
  u8        chain_der[16384];
  quic_span chain[WIRED_CERTRELOAD_CHAIN_MAX]; /**< views into chain_der */
  u8        priv[32];                          /**< P-256 private scalar */
} wired_certreload_store;

/** Read cert_path/key_path, decode the PEM chain and private key into store,
 * and point id->chain/chain_count/cert_seed at store's fields. id's other
 * fields (priv/pub/scid/random) are left untouched.
 * @param cert_path NUL-terminated path to a fullchain PEM (leaf first)
 * @param key_path  NUL-terminated path to a PEM P-256 private key
 * @param store     caller-owned storage; must outlive id's use
 * @param id        updated in place on success; left unmodified on failure
 * @return 1 on success; 0 if either file cannot be read, the PEM/DER is
 *   malformed, or the chain has zero certificates. */
int wired_certreload_load(
    const char*             cert_path,
    const char*             key_path,
    wired_certreload_store* store,
    wired_srvboot_id*       id);

/**
 * If cert_path is set (non-NULL, non-empty), load the certificate/key pair
 * via wired_certreload_load into store/id, replacing id's self-signed
 * identity with the loaded one. wired_die()s with a diagnostic if cert_path
 * is set but the load fails (e.g. key_path missing or unreadable). A no-op
 * when cert_path is unset — id keeps whatever identity the caller already
 * set (typically a demo self-signed one).
 *
 * @param cert_path NUL-terminated certificate PEM path, or 0/empty to skip
 * @param key_path  NUL-terminated private key PEM path
 * @param store     destination for the loaded chain/key material
 * @param id        server identity to update on success
 */
void wired_certreload_load_or_selfsigned(
    const char*             cert_path,
    const char*             key_path,
    wired_certreload_store* store,
    wired_srvboot_id*       id);

#endif
